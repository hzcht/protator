package proxy

import (
	"context"
	"log"
	"time"
)

// PoolReprobeLoop re-checks a batch of previously failed candidates; one that
// finally validates is moved into the bucket and dropped from re-probing.
// The batch size is adaptive: it aims to use ~70% of the checker's throughput
// capacity per interval, leaving headroom for the collector's fresh candidates.
func PoolReprobeLoop(ctx context.Context, cfg *Config, pool *CandidatePool, candidates chan<- Candidate) {
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
			// a full channel blocks the collector's fresh candidates, which
			// are the whole point of the system. Send only what fits right now.
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
// without ever blocking: the room check in PoolReprobeLoop is only a snapshot
// and the collector can fill the channel mid-batch. It returns how many were
// accepted; the caller leaves the rest in the pool for the next tick.
func emitPoolBatch(ctx context.Context, out chan<- Candidate, cands []Candidate) int {
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
