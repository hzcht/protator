package main

import (
	"context"
	"log"
	"runtime"
	"time"

	"protator/proxy"
)

// startBackgroundLoops launches the periodic housekeeping goroutines:
// queue saves, live-count telemetry (with an empty-queue watchdog), candidate
// pool re-probing and full revalidation of the live queue. The re-probe and
// revalidation policies live in proxy/ (poolloop.go, revalidate.go); this is
// only the wiring.
//
// beats, when non-nil, is stamped by the save path so the admin page can say
// when the queue was last persisted.
func startBackgroundLoops(ctx context.Context, cfg *proxy.Config, bucket *proxy.Bucket, pool *proxy.CandidatePool, checker *proxy.Checker, debug *proxy.DebugProxies, candidates chan<- proxy.Candidate, wakeCollector chan<- struct{}, beats *beats) {
	go saveLoop(ctx, cfg, bucket, beats)
	go statsLoop(ctx, cfg, bucket, pool, candidates, wakeCollector)
	go proxy.PoolReprobeLoop(ctx, cfg, pool, candidates)
	go proxy.RevalidateLoop(ctx, cfg, checker, bucket, debug)
}

// saveLoop periodically persists the live queue.
// Only saves when the queue has changed since the last save (dirty flag).
func saveLoop(ctx context.Context, cfg *proxy.Config, bucket *proxy.Bucket, beats *beats) {
	defer proxy.RecoverPanic("save loop")
	t := time.NewTicker(cfg.Storage.SaveInterval.Duration)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			if bucket.IsDirty() {
				saveQueue(cfg, bucket)
				if beats != nil {
					beats.save.Store(time.Now().UnixNano())
				}
			}
		}
	}
}

// statsLoop logs the live counts and the per-second rates once a minute, and
// watches for a completely empty queue: after two consecutive empty minutes it
// emits a critical marker and kicks an emergency collector cycle (the regular
// cycle_sleep would otherwise leave the proxy unusable for half an hour).
//
// The rates matter: "live proxies = 41234" cannot tell an operator whether
// the pool is improving. A pool whose dial-failure rate is climbing while its
// served rate is flat is dying, and that is visible only in the rates.
func statsLoop(ctx context.Context, cfg *proxy.Config, bucket *proxy.Bucket, pool *proxy.CandidatePool, candidates chan<- proxy.Candidate, wakeCollector chan<- struct{}) {
	defer proxy.RecoverPanic("stats loop")
	t := time.NewTicker(time.Minute)
	defer t.Stop()
	empty := false
	prev := proxy.Stats.Snapshot()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			live := bucket.Len()
			cur := proxy.Stats.Snapshot()
			log.Printf("queue: live=%d hot=%d proven=%d pool=%d cands=%d/%d | serve req/s=%.2f dialfail/s=%.2f evict/s=%.2f ok/s=%.2f block/s=%.2f | checks/s=%.2f pass/s=%.2f | goroutines=%d",
				live, bucket.HotLen(), bucket.ProvenCount(), pool.Len(),
				len(candidates), cap(candidates),
				perSec(cur["requests_total"], prev["requests_total"]),
				perSec(cur["dial_failures_total"], prev["dial_failures_total"]),
				perSec(cur["evictions_total"], prev["evictions_total"]),
				perSec(cur["served_ok_total"], prev["served_ok_total"]),
				perSec(cur["block_pages_total"], prev["block_pages_total"]),
				perSec(cur["checks_total"], prev["checks_total"]),
				perSec(cur["checks_passed_total"], prev["checks_passed_total"]),
				runtime.NumGoroutine(),
			)
			prev = cur
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

// perSec is the per-second delta between two counter samples taken a minute
// apart. It is the shape every rate in this program takes.
func perSec(now, prev int64) float64 {
	if now <= prev {
		return 0
	}
	return float64(now-prev) / 60
}

func saveQueue(cfg *proxy.Config, bucket *proxy.Bucket) {
	if err := proxy.SaveBucketAtomic(cfg.Storage.QueueFile, bucket.Snapshot(), cfg.Storage.MaxBytes); err != nil {
		log.Printf("save: %v", err)
		return
	}
	bucket.MarkClean()
}
