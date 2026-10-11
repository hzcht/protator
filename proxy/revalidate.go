package proxy

import (
	"context"
	"fmt"
	"log"
	"sort"
	"sync"
	"sync/atomic"
	"time"
)

// RevalidateLoop periodically re-checks every live proxy and drops the dead ones.
//
// The per-pass budget is paced by measured throughput, not just by the
// configured ceiling: with revalidate_max_per_pass = 30000 and a realistic
// 10–20 checks/s, a pass takes 25–50 minutes while revalidate_interval is 15m,
// and passes run serially — so without pacing the effective cadence is the
// pass length, never the config. Each pass re-estimates checks/sec from its
// own wall time and sizes the next budget to fit a share of the interval. The
// configured cap stays a hard ceiling.
func RevalidateLoop(ctx context.Context, cfg *Config, checker *Checker, bucket *Bucket, debug *DebugProxies) {
	t := time.NewTicker(cfg.Storage.RevalidateInterval.Duration)
	defer t.Stop()
	var rate float64 // measured checks/sec; 0 until the first pass finishes
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			budget := cfg.Storage.RevalidateMaxPerPass
			if rate > 0 {
				fit := int(rate * cfg.Storage.RevalidateInterval.Duration.Seconds() * revalidateIntervalShare)
				if fit < 1 {
					fit = 1
				}
				if budget <= 0 || fit < budget {
					budget = fit
				}
			}
			start := time.Now()
			checked := RevalidateMany(ctx, checker, bucket, bucket.Snapshot(), cfg.Storage.RevalidateWorkers, cfg.Storage.RevalidateFreshServers.Duration, budget, debug)
			elapsed := time.Since(start)
			if checked > 0 && elapsed > 0 {
				rate = float64(checked) / elapsed.Seconds()
			}
			// Stamped on completion, not from RevalPasses (which counts
			// starts): a healthy pass legitimately outruns 2×interval+30s, so
			// a start-stamped beat reports revalidate_stale at the tail of
			// every long pass — and admin-forced revals kept it fresh even
			// when this loop was wedged.
			Stats.RevalLoopDone.Add(1)
			log.Printf("revalidate: done %d in %s (%.1f checks/s, next budget %d)", checked, elapsed, rate, budget)
		}
	}
}

// revalidateIntervalShare is how much of each revalidation interval one pass
// may occupy. Below 1.0 so a pass that runs exactly to budget still leaves
// room for the checker to serve fresh candidates and the pool re-probe, which
// share the same workers.
const revalidateIntervalShare = 0.8

// RevalidateNow forces an immediate re-check of exactly these proxies, off the
// periodic schedule. It is the backing for the admin "revalidate" action, which
// used to delete the selected entries from the bucket instead: a proxy marked
// Good in the candidate pool is never re-emitted by Batch, so "revalidating" a
// proxy actually dropped it from service until the collector rediscovered it.
// Dead entries are still dropped; live ones are only re-stamped.
func RevalidateNow(ctx context.Context, checker *Checker, bucket *Bucket, proxies []*Proxy, workers int, debug *DebugProxies) {
	defer RecoverPanic("revalidate: forced")
	if len(proxies) == 0 {
		return
	}
	Stats.ForcedReval.Add(int64(len(proxies)))
	RevalidateMany(ctx, checker, bucket, proxies, workers, 0, 0, debug)
}

// RevalidateMany re-checks every live proxy and drops the dead ones.
// Stale entries (oldest successful check first) go first so the queue's
// freshness converges even if a cycle never finishes.
//
// snap is consumed in place (the recent-served filter compacts it), so it must
// be a slice the caller owns — RevalidateLoop passes bucket.Snapshot().
//
// It returns how many proxies were actually checked, so the loop can pace the
// next pass by measured throughput.
func RevalidateMany(ctx context.Context, checker *Checker, bucket *Bucket, snap []*Proxy, workers int, fresh time.Duration, maxPerPass int, debug *DebugProxies) int {
	// Passive telemetry: proxies that actually served a client dial in the
	// freshness window are alive by real traffic, so skip re-checking them.
	now := time.Now()
	if fresh > 0 {
		filtered := snap[:0]
		skipped := 0
		for _, p := range snap {
			if t := p.LastServed(); !t.IsZero() && now.Sub(t) < fresh {
				skipped++
				continue
			}
			filtered = append(filtered, p)
		}
		snap = filtered
		if skipped > 0 {
			log.Printf("revalidate: skipped %d recently-served proxies (passive telemetry)", skipped)
		}
	}
	if ctx.Err() != nil {
		return 0
	}
	sort.Slice(snap, func(i, j int) bool {
		return snap[i].LastCheck().Before(snap[j].LastCheck())
	})
	// Per-pass budget: re-check the oldest (stalest) up to the cap so every
	// pass always converges and the tail keeps rotating. A 50k full sweep on
	// some cycle would otherwise drift forever.
	if maxPerPass > 0 && len(snap) > maxPerPass {
		log.Printf("revalidate: capping pass to %d (of %d)", maxPerPass, len(snap))
		snap = snap[:maxPerPass]
	}
	if workers < 1 {
		workers = 1
	}
	Stats.RevalPasses.Add(1)
	// RevalChecked is fed from the per-item counter below, not from
	// len(snap): a pass abandoned on cancel never checked most of its
	// snapshot, and the planned count fed both the metric and the loop's
	// throughput estimate (the next budget sized itself from work that
	// never happened).
	var done atomic.Int64
	in := make(chan *Proxy, 1024)
	var wg sync.WaitGroup
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			// Per item, not per worker: a panic on one proxy must cost that
			// proxy, not the whole worker and its share of the channel.
			for p := range in {
				if ctx.Err() != nil {
					// Drain, do not act: the remaining work will be picked up
					// by the next pass, and acting on it now outlives the
					// shutdown budget (Revalidate builds its own contexts).
					continue
				}
				if err := revalidateOne(ctx, checker, bucket, debug, p); err != nil {
					log.Printf("revalidate: %s: %v", p.URL(), err)
				}
				done.Add(1)
			}
		}()
	}
	stopped := false
	for _, p := range snap {
		// abandon the whole feed as soon as the context is gone; a bare
		// break only leaves the select (and then spins the rest of the
		// snapshot doing nothing).
		select {
		case in <- p:
		case <-ctx.Done():
			stopped = true
		}
		if stopped {
			break
		}
	}
	close(in)
	wg.Wait()
	checked := int(done.Load())
	Stats.RevalChecked.Add(int64(checked))
	return checked
}

// revalidateOne re-checks a single queue member, dropping it when the check
// fails. It recovers per proxy so one bad entry cannot take a worker — and the
// rest of its batch — down with it.
//
// Revalidate stamps lastCheck on the resident via MarkAlive (warm tier) but
// deliberately does NOT promote into the hot tail: a bulk sweep of tens of
// thousands would flood the curated tail with merely-"validated once" entries
// and crowd out the truly serving-proven ones. Hot stays reserved for real
// traffic.
func revalidateOne(ctx context.Context, checker *Checker, bucket *Bucket, debug *DebugProxies, p *Proxy) (err error) {
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("panic: %v", r)
		}
	}()
	if err := checker.Revalidate(p); err != nil {
		if bucket.Remove(p) {
			Stats.RevalDropped.Add(1)
			log.Printf("revalidate: dropped %s (%v)", p.URL(), err)
		}
		return nil
	}
	debug.Add(p.URL())
	return nil
}
