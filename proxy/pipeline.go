package proxy

import (
	"context"
	"fmt"
	"log"
	"sync"
	"time"
)

// ExitReason reports why RunCheckLoop returned. The supervisor in main needs
// it: a worker that stopped because it was told to, or because the candidate
// channel is closed, must not be restarted — the second would return
// immediately and spin the supervisor forever.
type ExitReason int

const (
	ExitStopped       ExitReason = iota // stop was closed: process shutdown
	ExitChannelClosed                   // the candidates channel is closed
	ExitPanicStreak                     // too many consecutive candidate panics
)

// String implements fmt.Stringer for log lines.
func (r ExitReason) String() string {
	switch r {
	case ExitStopped:
		return "stopped"
	case ExitChannelClosed:
		return "candidate channel closed"
	case ExitPanicStreak:
		return "panic streak"
	}
	return "unknown"
}

// RunCheckLoop consumes candidates until the channel closes, stop is closed or
// a panic streak forces the worker out. Failed validations go to the persisted
// pool, successes into the bucket (and the audit file). One goroutine per
// configured checker worker.
//
// stop matters: the channel is never closed for the life of the process, so
// without it the workers keep accepting candidates after shutdown has closed
// the pool and the audit file. Every later Add then took the per-line append
// fallback — reopening the file that Close had just compacted and flushed —
// and the audit handle was never closed again.
//
// The log cadence counts this worker's own successes rather than pool.Len():
// once the pool rotates at its cap, Len stops changing, and a modulo over it
// would fire on every single line.
//
// A recovered panic costs the candidate, not the worker: with hundreds of
// workers parsing arbitrary scraped content, killing a worker per panic would
// silently shrink the pipeline's capacity over days. The streak cap bounds the
// damage a *repeatable* panic can do — a panic that fires on every candidate
// would otherwise log forever and burn a core doing it — by giving up on that
// worker (the supervisor in main restarts it).
func RunCheckLoop(candidates <-chan Candidate, checker *Checker, pool *CandidatePool, bucket *Bucket, debug *DebugProxies, cfg *Config, stop <-chan struct{}, done *sync.WaitGroup) ExitReason {
	defer done.Done()
	persisted := 0
	panics := 0
	for {
		var cand Candidate
		// No default branch: the select must block. With one, a worker whose
		// channel is momentarily empty falls through and calls runOne on a
		// zero Candidate, so hundreds of idle workers spin the CPU at 100%
		// for most of the process's life (a few candidates per second cannot
		// keep 600 workers busy).
		select {
		case c, ok := <-candidates:
			if !ok {
				return ExitChannelClosed
			}
			cand = c
		case <-stop:
			return ExitStopped
		}
		if err := runOne(cand, checker, pool, bucket, debug, cfg, &persisted); err != nil {
			RecoverPanic(fmt.Sprintf("checker: candidate %s:%d: %v", cand.Host, cand.Port, err))
			if panics++; panics >= panicStreakLimit {
				log.Printf("checker: %d panics in a row without a clean candidate; giving up this worker", panics)
				return ExitPanicStreak
			}
			continue
		}
		panics = 0
	}
}

// panicStreakLimit is how many consecutive candidate panics a worker tolerates
// before it exits. High enough that a rare bad page costs one candidate, low
// enough that a deterministic panic (a malformed candidate shape that always
// crashes the same path) stops logging and spinning within a second.
const panicStreakLimit = 20

// runOne validates one candidate. It returns a non-nil error only after
// recovering a panic, so the caller can log which candidate lost the worker.
func runOne(cand Candidate, checker *Checker, pool *CandidatePool, bucket *Bucket, debug *DebugProxies, cfg *Config, persisted *int) (err error) {
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("panic: %v", r)
		}
	}()
	p, err := checker.Check(cand)
	if err != nil {
		if pool.Add(cand) {
			*persisted++
			if *persisted%1000 == 0 {
				log.Printf("checker: pool=%d candidates persisted", pool.Len())
			}
		}
		return nil
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
	return nil
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
