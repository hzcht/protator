package main

import (
	"sync/atomic"
	"testing"
	"time"

	"protator/proxy"
)

// waitFor polls until cond is true or the deadline passes.
func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatalf("timed out waiting for %s", what)
}

// A worker that dies of a panic streak must be restarted: a pool whose
// capacity silently decays starves the queue, and nothing else in the process
// notices a missing goroutine out of hundreds.
func TestCheckerWorkerSupervisorRestarts(t *testing.T) {
	w := &checkerWorkers{
		stop:   make(chan struct{}),
		exited: make(chan exitMsg, 8),
	}
	var exits int32 = 1
	w.run = func(int) proxy.ExitReason {
		if atomic.AddInt32(&exits, -1) >= 0 {
			return proxy.ExitPanicStreak // die exactly once
		}
		<-w.stop // then behave: run until shutdown
		return proxy.ExitStopped
	}

	w.wg.Add(1)
	go w.supervise(1)

	waitFor(t, "the worker restart", func() bool { return w.restarts.Load() == 1 })

	w.stopAndWait() // must return, not hang: the supervisor drained the reports
	if got := w.restarts.Load(); got != 1 {
		t.Fatalf("restarts = %d, want 1", got)
	}
}

// A closed candidate channel is the one exit a restart cannot fix: the worker
// would return immediately and the supervisor would spin, logging a restart
// per iteration. It must let the pool drain to zero instead.
func TestCheckerWorkerSupervisorDoesNotRestartAfterChannelClose(t *testing.T) {
	w := &checkerWorkers{
		stop:   make(chan struct{}),
		exited: make(chan exitMsg, 8),
	}
	w.run = func(int) proxy.ExitReason { return proxy.ExitChannelClosed }

	w.wg.Add(1)
	go w.supervise(2)

	// The supervisor exits on its own once every worker has reported a close.
	w.wg.Wait()
	if got := w.restarts.Load(); got != 0 {
		t.Fatalf("restarts = %d, want 0 (a closed channel must not be restarted)", got)
	}
}

// stopAndWait must stay correct when called after the workers already exited.
func TestCheckerWorkerStopIsIdempotent(t *testing.T) {
	w := &checkerWorkers{
		stop:   make(chan struct{}),
		exited: make(chan exitMsg, 2),
	}
	w.run = func(int) proxy.ExitReason { return proxy.ExitStopped }

	w.wg.Add(1)
	go w.supervise(1)
	w.stopAndWait()
	w.stopAndWait() // must not panic on a double close
}
