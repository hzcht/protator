package main

import (
	"context"
	"testing"
	"time"

	"protator/proxy"
)

// The re-probe must never wedge the loop on a full channel: the room check in
// poolReprobeLoop is only a snapshot and the collector can fill the channel
// mid-batch. Leftovers stay in the pool for the next tick.
func TestEmitPoolBatchNeverBlocks(t *testing.T) {
	cands := []proxy.Candidate{
		{Host: "10.3.3.1", Port: 80},
		{Host: "10.3.3.2", Port: 80},
	}

	full := make(chan proxy.Candidate, 1)
	full <- proxy.Candidate{Host: "10.3.3.9", Port: 80}
	done := make(chan int, 1)
	go func() { done <- emitPoolBatch(context.Background(), full, cands) }()
	select {
	case n := <-done:
		if n != 0 {
			t.Errorf("emitted %d into a full channel, want 0", n)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("emitPoolBatch blocked on a full channel")
	}

	roomy := make(chan proxy.Candidate, 2)
	if n := emitPoolBatch(context.Background(), roomy, cands); n != 2 {
		t.Fatalf("emitted %d, want 2", n)
	}

	// A cancelled context stops the batch instead of hanging on it.
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	stuck := make(chan proxy.Candidate)
	if n := emitPoolBatch(ctx, stuck, cands); n != 0 {
		t.Errorf("emitted %d after cancel, want 0", n)
	}
}
