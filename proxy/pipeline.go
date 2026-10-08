package proxy

import (
	"context"
	"log"
	"time"
)

// RunCheckLoop consumes candidates until the channel closes: failed
// validations go to the persisted pool, successes into the bucket (and the
// audit file). One goroutine per configured checker worker.
//
// The log cadence counts this worker's own successes rather than pool.Len():
// once the pool rotates at its cap, Len stops changing, and a modulo over it
// would fire on every single line.
func RunCheckLoop(candidates <-chan Candidate, checker *Checker, pool *CandidatePool, bucket *Bucket, debug *DebugProxies, cfg *Config) {
	persisted := 0
	for cand := range candidates {
		p, err := checker.Check(cand)
		if err != nil {
			if pool.Add(cand) {
				persisted++
				if persisted%1000 == 0 {
					log.Printf("checker: pool=%d candidates persisted", pool.Len())
				}
			}
			continue
		}
		pool.Good(cand)
		debug.Add(p.URL())
		// Attribute the proxy to the sites.txt entry it came from before it
		// enters the bucket: the bucket keeps per-source live counts and the
		// admin page reports them, and the attribution is frozen from here on.
		p.SetSource(cand.Source)
		if bucket.Add(p) {
			AppendGood(cfg.Storage.GoodFile, p.URL())
			if bucket.Len()%1000 == 0 {
				log.Printf("checker: added %s queue=%d", p.URL(), bucket.Len())
			}
		}
	}
}

// RevalidateSeeded feeds the seeded proxies into the validation pipeline once,
// at a controlled rate and up to a cap. Dumping all 65k seeds into the channel
// at once floods the checker: the fresh candidates from the collector and the
// pool re-probe then cannot get through (the re-probe loop sends only what
// fits and skips the tick otherwise). The seeds are mostly dead anyway — the
// periodic revalidation pass churns them — so there is no reason to let them
// starve everything else at startup.
func RevalidateSeeded(ctx context.Context, candidates chan<- Candidate, snap []*Proxy, rate, maxSeeds int) {
	if rate <= 0 {
		rate = 200 // seeds per second
	}
	// A huge rate divides down to a zero interval, which time.NewTicker
	// rejects with a panic. Clamp the rate instead of guarding the ticker:
	// no seed rate below ~1000/s is meaningfully different from "as fast as
	// the channel drains", and the rejection is total (process exits).
	if rate > 1000 {
		rate = 1000
	}
	if maxSeeds > 0 && len(snap) > maxSeeds {
		snap = snap[:maxSeeds]
	}
	interval := time.Second / time.Duration(rate)
	t := time.NewTicker(interval)
	defer t.Stop()
	for _, p := range snap {
		select {
		case candidates <- Candidate{Host: p.Host, Port: p.Port, Schema: p.Schema, Source: p.Source()}:
		case <-ctx.Done():
			return
		}
		<-t.C
	}
}
