package main

import (
	"context"
	"log"
	"sort"
	"sync"
	"time"

	"protator/proxy"
)

// startBackgroundLoops launches the periodic housekeeping goroutines:
// queue saves, live-count telemetry (with an empty-queue watchdog), candidate
// pool re-probing and full revalidation of the live queue.
func startBackgroundLoops(ctx context.Context, cfg *proxy.Config, bucket *proxy.Bucket, pool *proxy.CandidatePool, checker *proxy.Checker, debug *debugProxies, candidates chan<- proxy.Candidate, wakeCollector chan<- struct{}) {
	go saveLoop(ctx, cfg, bucket)
	go statsLoop(ctx, cfg, bucket, wakeCollector)
	go poolReprobeLoop(ctx, cfg, pool, candidates)
	go revalidateLoop(ctx, cfg, checker, bucket, debug)
}

// saveLoop periodically persists the live queue.
// Only saves when the queue has changed since the last save (dirty flag).
func saveLoop(ctx context.Context, cfg *proxy.Config, bucket *proxy.Bucket) {
	t := time.NewTicker(cfg.Storage.SaveInterval.Duration)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			if bucket.IsDirty() {
				saveQueue(cfg, bucket)
			}
		}
	}
}

// statsLoop logs the live/hot proxy counts once a minute and watches for a
// completely empty queue: after two consecutive empty minutes it emits a
// critical "DEAD" marker and kicks an emergency collector cycle (the regular
// cycle_sleep would otherwise leave the proxy unusable for half an hour).
func statsLoop(ctx context.Context, cfg *proxy.Config, bucket *proxy.Bucket, wakeCollector chan<- struct{}) {
	t := time.NewTicker(time.Minute)
	defer t.Stop()
	empty := false
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			live := bucket.Len()
			log.Printf("queue: live proxies = %d (hot %d)", live, bucket.HotLen())
			if live == 0 {
				if empty {
					log.Printf("queue: CRITICAL empty for 2+ minutes - proxy is unusable; waking collector")
					select {
					case wakeCollector <- struct{}{}:
					default:
					}
				} else {
					empty = true
				}
				continue
			}
			empty = false
		}
	}
}

// poolReprobeLoop re-checks a batch of previously failed candidates; one that
// finally validates is moved into the bucket and dropped from re-probing.
// The batch size is adaptive: it aims to use ~70% of the checker's throughput
// capacity per interval, leaving headroom for the collector's fresh candidates.
func poolReprobeLoop(ctx context.Context, cfg *proxy.Config, pool *proxy.CandidatePool, candidates chan<- proxy.Candidate) {
	t := time.NewTicker(cfg.Collector.PoolRetryInterval.Duration)
	defer t.Stop()

	// Estimate checker throughput: workers / avg_check_time.
	// A full check takes ~10-15s wall time, but races internally.
	// Conservative: each worker completes ~4 checks/minute = 0.067/sec.
	// So 600 workers ≈ 40 checks/sec theoretical max.
	// But with retries, timeouts, failures: real throughput ~10-15/sec.
	// We'll measure actual throughput dynamically.
	const checksPerWorkerPerMin = 4.0
	estThroughput := float64(cfg.Checker.Workers) * checksPerWorkerPerMin / 60.0 // checks/sec
	if estThroughput < 1 {
		estThroughput = 10 // fallback
	}

	intervalSec := cfg.Collector.PoolRetryInterval.Duration.Seconds()
	// Target: use 70% of checker capacity for re-probe, rest for collector
	targetFraction := 0.7

	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			// The checker is the bottleneck (a full check costs ~12 requests
			// through the proxy), so the re-probe must never fill the channel:
			// a full channel blocks the collector's fresh candidates, which are
			// the whole point of the system. Send only what fits right now.
			room := cap(candidates) - len(candidates)
			if room <= 0 {
				log.Printf("pool: skipped, candidate channel full (%d/%d) — fresh candidates keep priority",
					len(candidates), cap(candidates))
				continue
			}

			// Adaptive batch: target = throughput * interval * fraction
			// But cap at configured max and available room
			targetBatch := int(estThroughput * intervalSec * targetFraction)
			if targetBatch < 1 {
				targetBatch = 1
			}
			maxBatch := cfg.Collector.PoolRetryBatch
			if targetBatch > maxBatch {
				targetBatch = maxBatch
			}
			if targetBatch > room {
				targetBatch = room
			}

			cands := pool.Batch(targetBatch)
			if len(cands) == 0 {
				continue
			}
			emitted := emitPoolBatch(ctx, candidates, cands)
			if emitted < len(cands) {
				// The collector filled the channel mid-batch; the rest stays in
				// the pool for the next tick. Losing them is not an option, and
				// waiting on them would stall fresh collection.
				log.Printf("pool: re-probing %d persisted candidates (%d left for next tick, total %d)",
					emitted, len(cands)-emitted, pool.Len())
				continue
			}
			log.Printf("pool: re-probing %d persisted candidates (total %d, batch target %d, est throughput %.1f/s)",
				emitted, pool.Len(), targetBatch, estThroughput)
		}
	}
}

// emitPoolBatch moves re-probed candidates into the validation pipeline
// without ever blocking: the room check in poolReprobeLoop is only a snapshot
// and the collector can fill the channel mid-batch. It returns how many were
// accepted; the caller leaves the rest in the pool for the next tick.
func emitPoolBatch(ctx context.Context, out chan<- proxy.Candidate, cands []proxy.Candidate) int {
	emitted := 0
	for _, c := range cands {
		select {
		case out <- c:
			emitted++
		case <-ctx.Done():
			return emitted
		default:
			return emitted
		}
	}
	return emitted
}

// revalidateLoop periodically re-checks every live proxy and drops the dead ones.
func revalidateLoop(ctx context.Context, cfg *proxy.Config, checker *proxy.Checker, bucket *proxy.Bucket, debug *debugProxies) {
	t := time.NewTicker(cfg.Storage.RevalidateInterval.Duration)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			start := time.Now()
			revalidateMany(ctx, checker, bucket, bucket.Snapshot(), cfg.Storage.RevalidateWorkers, cfg.Storage.RevalidateFreshServers.Duration, cfg.Storage.RevalidateMaxPerPass, debug)
			log.Printf("revalidate: done %d in %s", bucket.Len(), time.Since(start))
		}
	}
}

// revalidateMany re-checks every live proxy and drops the dead ones.
// Stale entries (oldest successful check first) go first so the queue's
// freshness converges even if a cycle never finishes.
func revalidateMany(ctx context.Context, checker *proxy.Checker, bucket *proxy.Bucket, snap []*proxy.Proxy, workers int, fresh time.Duration, maxPerPass int, debug *debugProxies) {
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
	in := make(chan *proxy.Proxy, 1024)
	var wg sync.WaitGroup
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for p := range in {
				if err := checker.Revalidate(p); err != nil {
					if bucket.Remove(p) {
						log.Printf("revalidate: dropped %s (%v)", p.URL(), err)
					}
					continue
				}
				// Revalidate stamps lastCheck on the resident via MarkAlive (warm
				// tier) but deliberately does NOT promote into the hot tail: a
				// bulk sweep of tens of thousands would flood the curated tail
				// with merely-"validated once" entries and crowd out the
				// truly serving-proven ones. Hot stays reserved for real traffic.
				debug.Add(p.URL())
			}
		}()
	}
	for _, p := range snap {
		select {
		case in <- p:
		case <-ctx.Done():
			break
		}
	}
	close(in)
	wg.Wait()
}

func saveQueue(cfg *proxy.Config, bucket *proxy.Bucket) {
	if err := proxy.SaveBucketAtomic(cfg.Storage.QueueFile, bucket.Snapshot(), cfg.Storage.MaxBytes); err != nil {
		log.Printf("save: %v", err)
		return
	}
	bucket.MarkClean()
}
