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
	// Both policy loops are bare goroutines started here; a panic in either
	// without RecoverPanic would take the whole process down (through main's
	// deferred saves) — same contract as every other spawned goroutine.
	go func() {
		defer proxy.RecoverPanic("pool reprobe loop")
		proxy.PoolReprobeLoop(ctx, cfg, pool, candidates)
	}()
	go func() {
		defer proxy.RecoverPanic("revalidate loop")
		proxy.RevalidateLoop(ctx, cfg, checker, bucket, debug)
	}()
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
				if saveQueue(cfg, bucket) && beats != nil {
					// Stamped on success only: a full disk / locked file that
					// keeps failing must show save_stale, not a green beat
					// that lies "persisted a minute ago".
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
	badMinutes := 0
	prev := proxy.Stats.Snapshot()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			live := bucket.Len()
			cur := proxy.Stats.Snapshot()
			req := perSec(cur["requests_total"], prev["requests_total"])
			fail := perSec(cur["dial_failures_total"], prev["dial_failures_total"])
			log.Printf("queue: live=%d hot=%d proven=%d pool=%d cands=%d/%d | serve req/s=%.2f dialfail/s=%.2f evict/s=%.2f ok/s=%.2f block/s=%.2f | checks/s=%.2f pass/s=%.2f | goroutines=%d",
				live, bucket.HotLen(), bucket.ProvenCount(), pool.Len(),
				len(candidates), cap(candidates),
				req,
				fail,
				perSec(cur["evictions_total"], prev["evictions_total"]),
				perSec(cur["served_ok_total"], prev["served_ok_total"]),
				perSec(cur["block_pages_total"], prev["block_pages_total"]),
				perSec(cur["checks_total"], prev["checks_total"]),
				perSec(cur["checks_passed_total"], prev["checks_passed_total"]),
				runtime.NumGoroutine(),
			)
			prev = cur
			// The pool is dying faster than revalidation replaces it: most
			// dials fail while requests keep coming. Two bad minutes in a row
			// shout and kick an emergency collector cycle, same as the empty
			// watchdog below. The request floor keeps a quiet proxy from
			// alerting on a handful of failed dials.
			if req >= alertMinReqPerSec && fail/req > alertFailRatio {
				badMinutes++
			} else {
				badMinutes = 0
			}
			if badMinutes >= 2 {
				log.Printf("queue: CRITICAL dial failures %.0f%% of requests for 2+ minutes - pool is dying; waking collector",
					100*fail/req)
				select {
				case wakeCollector <- struct{}{}:
					proxy.Stats.CollectorWakes.Add(1)
				default:
				}
				badMinutes = 0 // re-arm: shout at most every 2 minutes
			}
			if live == 0 {
				if empty {
					log.Printf("queue: CRITICAL empty for 2+ minutes - proxy is unusable; waking collector")
					select {
					case wakeCollector <- struct{}{}:
						proxy.Stats.CollectorWakes.Add(1)
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

// Alert thresholds for the dying-pool watchdog in statsLoop: fire when more
// than half the dials fail for two minutes running, and only when there is
// enough traffic for the ratio to mean anything (a quiet proxy must not alert
// on a handful of failed dials).
const (
	alertFailRatio    = 0.5
	alertMinReqPerSec = 1.0
)

// perSec is the per-second delta between two counter samples taken a minute
// apart. It is the shape every rate in this program takes.
func perSec(now, prev int64) float64 {
	if now <= prev {
		return 0
	}
	return float64(now-prev) / 60
}

// saveQueue persists the live queue and reports whether the write succeeded
// (the heartbeat and the dirty flag both key off that).
func saveQueue(cfg *proxy.Config, bucket *proxy.Bucket) bool {
	// Clear the dirty flag BEFORE snapshotting: mutations that land during
	// the (hundreds of ms) write then re-dirty it, so they are picked up by
	// the next tick. Clearing after the write used to drop them silently
	// until the next unrelated mutation.
	bucket.MarkClean()
	if err := proxy.SaveBucketAtomic(cfg.Storage.QueueFile, bucket.Snapshot(), cfg.Storage.MaxBytes); err != nil {
		log.Printf("save: %v", err)
		proxy.Stats.SaveFailures.Add(1)
		bucket.MarkDirty() // retry next tick; do not pretend the file is current
		return false
	}
	return true
}
