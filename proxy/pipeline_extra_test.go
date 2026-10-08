package proxy

import (
	"context"
	"testing"
	"time"
)

// The startup seed dump must be paced: flooding 65k seeds into the candidate
// channel at once starves the collector's fresh candidates and blocks the pool
// re-probe loop. This asserts the pacer actually paces.
func TestRevalidateSeededIsRateLimited(t *testing.T) {
	const n = 100
	snap := make([]*Proxy, n)
	for i := range snap {
		snap[i] = &Proxy{Schema: "http", Host: "10.1.1.1", Port: 8080 + i}
	}
	cands := make(chan Candidate, n)
	// 100 seeds at 1000/sec must take at least ~90ms, not return instantly.
	// (An instant return is the flood this guards against.)
	start := time.Now()
	go RevalidateSeeded(context.Background(), cands, snap, 1000, 0)
	for i := 0; i < n; i++ {
		<-cands
	}
	if elapsed := time.Since(start); elapsed < 90*time.Millisecond {
		t.Errorf("100 seeds at 1000/sec returned in %s; the pacer is not pacing", elapsed)
	}
}

// A rate of 0 must fall back to the default rather than dividing by zero.
func TestRevalidateSeededDefaultRate(t *testing.T) {
	snap := []*Proxy{{Schema: "http", Host: "10.2.2.2", Port: 80}}
	cands := make(chan Candidate, 1)
	done := make(chan struct{})
	go func() {
		RevalidateSeeded(context.Background(), cands, snap, 0, 0)
		close(done)
	}()
	select {
	case <-cands:
	case <-time.After(2 * time.Second):
		t.Fatal("default rate did not feed the seed")
	}
	<-done
}
