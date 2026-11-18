package main

import (
	"context"
	"log"
	"runtime"
	"strings"
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
func startBackgroundLoops(ctx context.Context, cfg *proxy.Config, bucket *proxy.Bucket, pool *proxy.CandidatePool, collector *proxy.Collector, checker *proxy.Checker, debug *proxy.DebugProxies, candidates chan<- proxy.Candidate, wakeCollector chan<- struct{}, beats *beats) {
	go saveLoop(ctx, cfg, bucket, beats)
	go statsLoop(ctx, cfg, bucket, pool, collector, candidates, wakeCollector)
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
func statsLoop(ctx context.Context, cfg *proxy.Config, bucket *proxy.Bucket, pool *proxy.CandidatePool, collector *proxy.Collector, candidates chan<- proxy.Candidate, wakeCollector chan<- struct{}) {
	defer proxy.RecoverPanic("stats loop")
	t := time.NewTicker(time.Minute)
	defer t.Stop()
	empty := false
	badMinutes := 0
	prev := proxy.Stats.Snapshot()
	lastZeroYieldLog := time.Time{}
	trend := newQueueTrend(queueTrendMinutes)
	lastShrinkLog := time.Time{}
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
			sample := queueSample{
				live:         live,
				checksPassed: cur["checks_passed_total"],
				revalDropped: cur["reval_dropped_total"],
			}
			trend.add(sample)
			if before, ok := trend.hourAgo(); ok && queueShrinking(before, sample) && time.Since(lastShrinkLog) >= time.Hour {
				// One line an hour, with the intake numbers that explain the
				// loss: checks_passed climbing while live falls means the queue
				// is leaking entries between validation and admission;
				// reval_dropped climbing means revalidation is simply eating
				// faster than the collector feeds it.
				log.Printf("queue: shrunk %.0f%% in the last hour (live %d -> %d; checks_passed +%d, reval_dropped +%d, hot=%d, proven=%d) - intake is not keeping up",
					float64(before.live-sample.live)*100/float64(before.live),
					before.live, sample.live,
					sample.checksPassed-before.checksPassed,
					sample.revalDropped-before.revalDropped,
					bucket.HotLen(), bucket.ProvenCount())
				proxy.Stats.QueueShrinkWarnings.Add(1)
				lastShrinkLog = time.Now()
			}
			prev = cur
			// Zero-yield visibility: a source fetched N times with nothing to
			// show is burning a fetch slot and a worker, but scoring only
			// deprioritises it — nothing said so out loud. Count it every
			// minute (the gauge is cheap) and log the sample at most every
			// ten minutes so a list of dead sources cannot flood the log.
			if collector != nil {
				cycles := cfg.Collector.SiteZeroYieldCycles
				if cycles < 1 {
					cycles = 3
				}
				n, sample := collector.Stats().ZeroYield(cycles, 5)
				proxy.Stats.CollectorZeroYield.Store(int64(n))
				if n > 0 && time.Since(lastZeroYieldLog) >= 10*time.Minute {
					more := ""
					if n > len(sample) {
						more = " (+more)"
					}
					log.Printf("collector: %d sources with %d+ cycles and zero candidates (not cooling): %s%s",
						n, cycles, strings.Join(sample, " "), more)
					lastZeroYieldLog = time.Now()
				}
			} else {
				proxy.Stats.CollectorZeroYield.Store(0)
			}
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

// Queue-contraction watchdog (see statsLoop). queue_live falling 4000 -> 1325
// over four and a half hours was invisible: the empty-queue alarm only fires
// at zero, and every other counter watches what arrives, not what leaves.
//
// The window is 61 samples so the oldest one is exactly an hour old when the
// ring is full; a smaller ring would compare against 59 minutes and quietly
// change its own definition of "an hour".
const (
	queueTrendMinutes   = 61
	queueShrinkMinBase  = 200
	queueShrinkFraction = 0.25
)

// queueSample is one minute of the queue's life: its size and the two counters
// that explain where the losses went.
type queueSample struct {
	live         int
	checksPassed int64
	revalDropped int64
}

// queueTrend is a fixed ring of once-a-minute samples, sized just wide enough
// to answer "how big was the queue an hour ago". A ring, not a slice: the stats
// loop runs for weeks, and the watchdog must not grow a minute of history per
// minute of uptime.
type queueTrend struct {
	samples []queueSample
	head    int
	n       int
}

func newQueueTrend(minutes int) *queueTrend {
	if minutes < 1 {
		minutes = 1
	}
	return &queueTrend{samples: make([]queueSample, minutes)}
}

// add records the newest sample, evicting the oldest when the ring is full.
func (t *queueTrend) add(s queueSample) {
	if t.n < len(t.samples) {
		t.samples[(t.head+t.n)%len(t.samples)] = s
		t.n++
		return
	}
	t.samples[t.head] = s
	t.head = (t.head + 1) % len(t.samples)
}

// hourAgo returns the oldest sample once the ring has been fed for a full
// hour. Before that the watchdog has nothing to compare against and stays
// silent: a restart must not look like a collapse.
func (t *queueTrend) hourAgo() (queueSample, bool) {
	if t.n < len(t.samples) {
		return queueSample{}, false
	}
	return t.samples[t.head], true
}

// queueShrinking is the watchdog's verdict: a quarter of the queue is gone
// within an hour, from a base large enough for the percentage to mean
// something. Deliberately a rate, not an absolute floor: a healthy pool may
// legitimately run small, and an empty queue already has its own alarm.
func queueShrinking(prev, now queueSample) bool {
	if prev.live < queueShrinkMinBase || now.live >= prev.live {
		return false
	}
	return float64(prev.live-now.live) >= float64(prev.live)*queueShrinkFraction
}

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
	snap := bucket.Snapshot()
	if err := proxy.SaveBucketAtomic(cfg.Storage.QueueFile, snap, cfg.Storage.MaxBytes); err != nil {
		log.Printf("save: %v", err)
		proxy.Stats.SaveFailures.Add(1)
		bucket.MarkDirty() // retry next tick; do not pretend the file is current
		return false
	}
	// Same snapshot: the index must describe the queue file exactly as it was
	// just written, not a later state. A failure here costs a cold start, so
	// it is logged and counted but never re-dirties the queue.
	if err := proxy.SaveProvenIndex(cfg.Storage.ProvenFile, snap, time.Now(), cfg.Server.PickFreshWindow.Duration); err != nil {
		log.Printf("save: proven index: %v", err)
		proxy.Stats.ProvenWriteFailures.Add(1)
	}
	return true
}
