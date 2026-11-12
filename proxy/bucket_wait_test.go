package proxy

import (
	"context"
	"errors"
	"testing"
	"time"
)

// waitQueue is the only blocking path in the picker. Its contract has three
// exits (queue notification, context cancellation, safety-poll expiry) and a
// caller-owned timer that must survive all three without a stale tick. These
// tests are the cancellation coverage the review pass (problems.md §23 item 4)
// found missing.

// A request parked on an empty queue must return as soon as its context ends,
// not after the next safety poll.
func TestWaitQueueCancelReturnsCtxErr(t *testing.T) {
	b := NewBucket(0)
	timer := time.NewTimer(emptyQueuePoll)
	defer timer.Stop()

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- b.waitQueue(ctx, timer) }()

	time.Sleep(10 * time.Millisecond) // parked
	start := time.Now()
	cancel()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("waitQueue = %v, want context.Canceled", err)
		}
		if d := time.Since(start); d >= emptyQueuePoll/2 {
			t.Fatalf("cancel wake took %v; that is the safety poll, not cancellation", d)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("waitQueue did not return after cancel")
	}
}

// The queue notification normally beats the poll; a waiter that only wakes on
// the 500 ms tick would add that latency to every cold first request.
func TestWaitQueueSignalWakesBeforePoll(t *testing.T) {
	b := NewBucket(0)
	timer := time.NewTimer(emptyQueuePoll)
	defer timer.Stop()

	done := make(chan error, 1)
	go func() { done <- b.waitQueue(context.Background(), timer) }()

	time.Sleep(10 * time.Millisecond) // parked
	start := time.Now()
	b.poke()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("waitQueue = %v, want nil on notification", err)
		}
		if d := time.Since(start); d >= emptyQueuePoll/2 {
			t.Fatalf("signal wake took %v; that is the safety poll, not the notification", d)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("waitQueue missed the queue notification")
	}
}

// With no notification and no cancellation the safety poll is the only exit:
// it must actually fire, or a missed edge would park the request forever.
func TestWaitQueuePollExpiry(t *testing.T) {
	b := NewBucket(0)
	timer := time.NewTimer(emptyQueuePoll)
	defer timer.Stop()

	start := time.Now()
	if err := b.waitQueue(context.Background(), timer); err != nil {
		t.Fatalf("waitQueue = %v, want nil on poll expiry", err)
	}
	if d := time.Since(start); d < emptyQueuePoll*9/10 {
		t.Fatalf("poll returned after %v, before the %v tick", d, emptyQueuePoll)
	}
}

// The same timer serves every iteration of a picker loop. A stale tick left by
// one path would make the next Reset fire immediately; a missed drain would
// leak the tick into the following wait. Run the three exits back to back on
// one timer and end with a fresh notification to prove it still works.
func TestWaitQueueTimerReuse(t *testing.T) {
	b := NewBucket(0)
	timer := time.NewTimer(emptyQueuePoll)
	defer timer.Stop()
	done := make(chan error, 1)

	// 1) Notification path.
	go func() { done <- b.waitQueue(context.Background(), timer) }()
	time.Sleep(10 * time.Millisecond)
	b.poke()
	if err := <-done; err != nil {
		t.Fatalf("notification pass: %v", err)
	}

	// 2) Poll path right after: a stale tick would return well before the tick.
	start := time.Now()
	if err := b.waitQueue(context.Background(), timer); err != nil {
		t.Fatalf("poll pass: %v", err)
	}
	if d := time.Since(start); d < emptyQueuePoll*9/10 {
		t.Fatalf("timer reuse lost the poll interval: returned after %v", d)
	}

	// 3) Cancellation path on the same timer.
	ctx, cancel := context.WithCancel(context.Background())
	go func() { done <- b.waitQueue(ctx, timer) }()
	time.Sleep(10 * time.Millisecond)
	cancel()
	if err := <-done; !errors.Is(err, context.Canceled) {
		t.Fatalf("cancel pass: %v, want context.Canceled", err)
	}

	// 4) The timer is still usable: a notification wakes the next waiter.
	go func() { done <- b.waitQueue(context.Background(), timer) }()
	time.Sleep(10 * time.Millisecond)
	b.poke()
	if err := <-done; err != nil {
		t.Fatalf("post-cancel notification pass: %v", err)
	}
}

// A cancelled waiter must be gone, not merely returned: a later Add (which
// pokes) must not block on a full signal buffer, and the next pick must see
// the fresh entry immediately.
func TestRandomCancelLeavesNoWaiter(t *testing.T) {
	b := NewBucket(0)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		_, err := b.Random(ctx)
		done <- err
	}()

	time.Sleep(20 * time.Millisecond) // parked on the empty queue
	cancel()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("Random = %v, want context.Canceled", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Random did not return after cancel")
	}

	// poke is edge-triggered with a one-slot buffer: with no waiter it must
	// not block, and a repeated poke must not either.
	b.poke()
	b.poke()

	b.Add(&Proxy{Schema: "http", Host: "192.0.2.10", Port: 8080})
	p, err := b.Random(context.Background())
	if err != nil {
		t.Fatalf("Random after Add: %v", err)
	}
	if p == nil || p.Host != "192.0.2.10" {
		t.Fatalf("Random after Add = %+v, want the seeded entry", p)
	}
}
