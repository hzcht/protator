package proxy

import (
	"context"
	"path/filepath"
	"testing"
	"time"
)

// newTestPool returns a CandidatePool backed by a temp file, closed on test
// end — the standard construction for pool tests.
func newTestPool(t *testing.T) *CandidatePool {
	t.Helper()
	path := filepath.Join(t.TempDir(), "candidates.lst")
	cp := NewCandidatePool(path, 0, 0)
	t.Cleanup(func() { cp.Close() })
	return cp
}

// poolReprobeCfg builds a Config for PoolReprobeLoop with a test-friendly
// ticker interval and batch cap.
func poolReprobeCfg(interval time.Duration, batch int) *Config {
	return &Config{Collector: CollectorConfig{
		PoolRetryInterval: Duration{interval},
		PoolRetryBatch:    batch,
	}}
}

// seedPoolCandidates adds n distinct TEST-NET candidates (no dials: the pool
// only stores addresses and the loop only emits into a channel) and returns
// them in insertion order.
func seedPoolCandidates(t *testing.T, cp *CandidatePool, n int) []Candidate {
	t.Helper()
	cands := make([]Candidate, n)
	for i := range cands {
		cands[i] = Candidate{
			Host:   "192.0.2." + itoa(200+i),
			Port:   8080,
			Schema: "http",
		}
		if !cp.Add(cands[i]) {
			t.Fatalf("seed %d: Add unexpectedly dropped (duplicate key?)", i)
		}
	}
	return cands
}

// PoolReprobeLoop must stop when its context is cancelled — it runs for the
// whole process lifetime in production, and a leaked loop would keep a
// goroutine and a ticker alive across restarts.
func TestPoolReprobeLoopCancelReturns(t *testing.T) {
	cp := newTestPool(t)
	seedPoolCandidates(t, cp, 2)

	ch := make(chan Candidate, 4)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		PoolReprobeLoop(ctx, poolReprobeCfg(5*time.Millisecond, 100), cp, ch)
	}()

	time.Sleep(30 * time.Millisecond) // let several ticks pass first
	cancel()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("PoolReprobeLoop did not return after ctx cancel")
	}
}

// An empty pool must not emit anything and must not misbehave: the loop
// ticks, finds nothing, and keeps waiting.
func TestPoolReprobeLoopEmptyPoolEmitsNothing(t *testing.T) {
	cp := newTestPool(t)

	ch := make(chan Candidate, 4)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go PoolReprobeLoop(ctx, poolReprobeCfg(5*time.Millisecond, 100), cp, ch)

	time.Sleep(50 * time.Millisecond) // ~10 ticks
	select {
	case c := <-ch:
		t.Fatalf("empty pool emitted %+v", c)
	default:
	}
}

// The re-probe must never fill the candidate channel — a full channel blocks
// the collector's fresh candidates, which take priority. Emissions are capped
// by the room available right now; once the channel is full the loop skips
// instead of blocking, and the pool keeps every candidate (emission is
// rotation-based; removal happens only on a successful validation).
//
// The ticker is driven by wall-clock ticks, so per-tick batch sizes are not
// observable; the window is sized to run many ticks so the total is
// deterministic: room-limited emissions add up to exactly the channel
// capacity, whether they came in one room-sized batch or one-at-a-time from
// the fallback throughput estimate.
func TestPoolReprobeLoopRoomCapFullSkip(t *testing.T) {
	const (
		chCap    = 4
		seeded   = 6
		interval = 5 * time.Millisecond
	)
	cp := newTestPool(t)
	seedPoolCandidates(t, cp, seeded)

	origChecks := Stats.Checks.Load()
	t.Cleanup(func() { Stats.Checks.Store(origChecks) })

	ch := make(chan Candidate, chCap)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go PoolReprobeLoop(ctx, poolReprobeCfg(interval, 100), cp, ch)

	// Pump the checker counter so the measured throughput estimate explodes
	// and the computed batch target exceeds everything: what bounds the
	// emissions must then be the room in the channel, not the estimate.
	// Main owns `stop`: closing it stops the pumper.
	stop := make(chan struct{})
	go func() {
		for {
			select {
			case <-stop:
				return
			default:
				Stats.Checks.Add(100000)
				time.Sleep(10 * time.Millisecond)
			}
		}
	}()

	time.Sleep(200 * time.Millisecond) // ~40 ticks at 5ms
	cancel()
	close(stop)

	// Drain non-blocking: exactly chCap items came through, no more.
	got := make([]Candidate, 0, chCap+1)
	for {
		select {
		case c := <-ch:
			got = append(got, c)
			continue
		default:
		}
		break
	}
	if len(got) != chCap {
		t.Fatalf("received %d emissions, want exactly the channel capacity %d", len(got), chCap)
	}
	seen := make(map[string]bool, len(got))
	for _, c := range got {
		seen[c.Host] = true
	}
	if len(seen) != chCap {
		t.Fatalf("received %d distinct hosts across %d emissions, want distinct rotation", len(seen), len(got))
	}
	if cp.Len() != seeded {
		t.Fatalf("pool lost candidates on emit: Len = %d, want %d", cp.Len(), seeded)
	}
}

// emitPoolBatch never blocks: it sends while there is room and gives up at
// the first full slot, leaving the rest of the batch to the next tick. The
// accepted candidates are a prefix of the batch (in-order sends).
func TestEmitPoolBatchPartial(t *testing.T) {
	ch := make(chan Candidate, 1)
	cands := []Candidate{
		{Host: "192.0.2.1", Port: 80, Schema: "http"},
		{Host: "192.0.2.2", Port: 80, Schema: "http"},
		{Host: "192.0.2.3", Port: 80, Schema: "http"},
	}
	got := emitPoolBatch(context.Background(), ch, cands)
	if got != 1 {
		t.Fatalf("emitted %d, want 1 (channel cap 1, non-blocking)", got)
	}
	select {
	case c := <-ch:
		if c.Host != cands[0].Host {
			t.Fatalf("first emitted = %s, want %s (in-order prefix)", c.Host, cands[0].Host)
		}
	default:
		t.Fatal("channel empty after successful emit")
	}
}
