package main

import (
	"context"
	"testing"
	"time"

	"protator/proxy"
)

// The startup seed dump must be paced: flooding 65k seeds into the candidate
// channel at once starves the collector's fresh candidates and blocks the pool
// re-probe loop. This asserts the pacer actually paces.
func TestRevalidateSeededIsRateLimited(t *testing.T) {
	const n = 100
	snap := make([]*proxy.Proxy, n)
	for i := range snap {
		snap[i] = &proxy.Proxy{Schema: "http", Host: "10.1.1.1", Port: 8080 + i}
	}
	cands := make(chan proxy.Candidate, n)
	// 100 seeds at 1000/sec must take at least ~90ms, not return instantly.
	// (An instant return is the flood this guards against.)
	start := time.Now()
	go revalidateSeeded(context.Background(), cands, snap, 1000, 0)
	for i := 0; i < n; i++ {
		<-cands
	}
	if elapsed := time.Since(start); elapsed < 90*time.Millisecond {
		t.Errorf("100 seeds at 1000/sec returned in %s; the pacer is not pacing", elapsed)
	}
}

// A rate of 0 must fall back to the default rather than dividing by zero.
func TestRevalidateSeededDefaultRate(t *testing.T) {
	snap := []*proxy.Proxy{{Schema: "http", Host: "10.2.2.2", Port: 80}}
	cands := make(chan proxy.Candidate, 1)
	done := make(chan struct{})
	go func() {
		revalidateSeeded(context.Background(), cands, snap, 0, 0)
		close(done)
	}()
	select {
	case <-cands:
	case <-time.After(2 * time.Second):
		t.Fatal("default rate did not feed the seed")
	}
	<-done
}

// The candidate pool must stop growing once it hits the cap: a pool the
// checker cannot churn is dead weight, and new candidates should be dropped
// rather than persisted forever.
func TestCandidatePoolCap(t *testing.T) {
	dir := t.TempDir()
	pool := proxy.NewCandidatePool(dir+"/c.lst", 1<<20, 10)
	t.Cleanup(func() { pool.Close() })
	for i := 0; i < 10; i++ {
		if !pool.Add(proxy.Candidate{Host: "10.9.9.9", Port: 1000 + i}) {
			t.Fatalf("candidate %d rejected before the cap", i)
		}
	}
	if pool.Len() != 10 {
		t.Fatalf("pool grew to %d, want the cap of 10", pool.Len())
	}
	// Once full, new candidates are dropped (the checker has no capacity for
	// them), but the pool stays usable.
	if pool.Add(proxy.Candidate{Host: "10.9.9.9", Port: 9999}) {
		t.Error("pool accepted a candidate beyond the cap")
	}
	if got := pool.Batch(5); len(got) != 5 {
		t.Errorf("Batch returned %d, want 5", len(got))
	}
}
