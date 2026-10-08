package main

import (
	"context"
	"log"
	"time"

	"protator/proxy"
)

// startBackgroundLoops launches the periodic housekeeping goroutines:
// queue saves, live-count telemetry (with an empty-queue watchdog), candidate
// pool re-probing and full revalidation of the live queue. The re-probe and
// revalidation policies live in proxy/ (poolloop.go, revalidate.go); this is
// only the wiring.
func startBackgroundLoops(ctx context.Context, cfg *proxy.Config, bucket *proxy.Bucket, pool *proxy.CandidatePool, checker *proxy.Checker, debug *proxy.DebugProxies, candidates chan<- proxy.Candidate, wakeCollector chan<- struct{}) {
	go saveLoop(ctx, cfg, bucket)
	go statsLoop(ctx, cfg, bucket, wakeCollector)
	go proxy.PoolReprobeLoop(ctx, cfg, pool, candidates)
	go proxy.RevalidateLoop(ctx, cfg, checker, bucket, debug)
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

func saveQueue(cfg *proxy.Config, bucket *proxy.Bucket) {
	if err := proxy.SaveBucketAtomic(cfg.Storage.QueueFile, bucket.Snapshot(), cfg.Storage.MaxBytes); err != nil {
		log.Printf("save: %v", err)
		return
	}
	bucket.MarkClean()
}
