package proxy

import (
	"context"
	"fmt"
	"log"
	"sort"
	"sync"
	"time"
)

// RevalidateLoop periodically re-checks every live proxy and drops the dead ones.
func RevalidateLoop(ctx context.Context, cfg *Config, checker *Checker, bucket *Bucket, debug *DebugProxies) {
	t := time.NewTicker(cfg.Storage.RevalidateInterval.Duration)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			start := time.Now()
			RevalidateMany(ctx, checker, bucket, bucket.Snapshot(), cfg.Storage.RevalidateWorkers, cfg.Storage.RevalidateFreshServers.Duration, cfg.Storage.RevalidateMaxPerPass, debug)
			log.Printf("revalidate: done %d in %s", bucket.Len(), time.Since(start))
		}
	}
}

// RevalidateNow forces an immediate re-check of exactly these proxies, off the
// periodic schedule. It is the backing for the admin "revalidate" action, which
// used to delete the selected entries from the bucket instead: a proxy marked
// Good in the candidate pool is never re-emitted by Batch, so "revalidating" a
// proxy actually dropped it from service until the collector rediscovered it.
// Dead entries are still dropped; live ones are only re-stamped.
func RevalidateNow(ctx context.Context, checker *Checker, bucket *Bucket, proxies []*Proxy, workers int, debug *DebugProxies) {
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
func RevalidateMany(ctx context.Context, checker *Checker, bucket *Bucket, snap []*Proxy, workers int, fresh time.Duration, maxPerPass int, debug *DebugProxies) {
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
		return
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
	Stats.RevalChecked.Add(int64(len(snap)))
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
