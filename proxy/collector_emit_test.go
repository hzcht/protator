package proxy

import (
	"context"
	"testing"
	"time"
)

// A send that had to wait for channel space counts as blocked backpressure,
// with its wait charged in nanoseconds; a send with room available moves
// nothing.
func TestEmitBlockedCounters(t *testing.T) {
	c := &Collector{cfg: &Config{}, seen: map[string]time.Time{}}
	cands := []Candidate{{Host: "192.0.2.1", Port: 8080}}

	beforeBlocked := Stats.CollectorEmitBlocked.Load()
	beforeWait := Stats.CollectorEmitWaitNS.Load()

	// Unbuffered channel, receiver arrives after a delay: emit is the sender,
	// so it must block until the receiver shows up. (Receiving first deadlocks:
	// nothing can send before emit runs.)
	out := make(chan Candidate)
	recv := make(chan struct{})
	go func() {
		time.Sleep(50 * time.Millisecond)
		<-out
		close(recv)
	}()
	n := c.emit(context.Background(), "http://blocked.test/list", cands, out)
	<-recv
	if n != 1 {
		t.Fatalf("emit delivered %d candidates, want 1", n)
	}
	if got := Stats.CollectorEmitBlocked.Load() - beforeBlocked; got != 1 {
		t.Fatalf("CollectorEmitBlocked delta = %d, want 1", got)
	}
	if got := Stats.CollectorEmitWaitNS.Load() - beforeWait; got < int64(50*time.Millisecond) {
		t.Fatalf("CollectorEmitWaitNS delta = %d, want >= 50ms of nanos", got)
	}

	// Fast path: room in the channel, nothing counted.
	beforeBlocked = Stats.CollectorEmitBlocked.Load()
	fast := []Candidate{{Host: "192.0.2.2", Port: 8080}}
	buf := make(chan Candidate, 4)
	if n := c.emit(context.Background(), "http://fast.test/list", fast, buf); n != 1 {
		t.Fatalf("fast emit delivered %d candidates, want 1", n)
	}
	if got := Stats.CollectorEmitBlocked.Load(); got != beforeBlocked {
		t.Fatalf("fast send counted as blocked: %d -> %d", beforeBlocked, got)
	}
}
