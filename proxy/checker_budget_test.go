package proxy

import (
	"net"
	"sync"
	"testing"
	"time"
)

// TestAttemptBudgetClipsToCandidate pins the split between the two clocks: a
// single attempt may never outlive the candidate, and it never exceeds
// total_timeout even when the candidate still has time to spare.
func TestAttemptBudgetClipsToCandidate(t *testing.T) {
	c := testChecker(nil, "9.9.9.9") // TotalT = 5s
	if c.cfg.Checker.TotalT.Duration != 5*time.Second {
		t.Fatalf("fixture changed: TotalT = %s", c.cfg.Checker.TotalT.Duration)
	}

	// Candidate nearly out of time: the attempt inherits the remainder.
	if got := c.attemptBudget(time.Now().Add(2 * time.Second)); got > 2*time.Second || got < 1500*time.Millisecond {
		t.Fatalf("attemptBudget(2s left) = %s, want ~2s", got)
	}
	// Plenty of candidate time left: total_timeout is still the ceiling.
	if got := c.attemptBudget(time.Now().Add(time.Minute)); got != 5*time.Second {
		t.Fatalf("attemptBudget(1m left) = %s, want 5s", got)
	}
	// Past the deadline: non-positive, so attempt() refuses instead of dialing.
	if got := c.attemptBudget(time.Now().Add(-time.Second)); got > 0 {
		t.Fatalf("attemptBudget(past deadline) = %s, want <= 0", got)
	}
}

// TestAttemptRefusesExhaustedBudget: an exhausted candidate must file as
// budget, not as a dead proxy — the two mean different things to an operator.
func TestAttemptRefusesExhaustedBudget(t *testing.T) {
	c := testChecker(nil, "9.9.9.9")
	_, err := c.attempt(Candidate{Host: "1.2.3.4", Port: 8080}, "http", time.Now().Add(-time.Second))
	if err == nil {
		t.Fatal("attempt with an exhausted budget returned a proxy")
	}
	if got := stageOf(err); got != stageBudget {
		t.Fatalf("stage = %v, want budget", got)
	}
}

// TestCheckPreDialsOnceForEveryProtocol is the regression test for the cost
// that made 600 workers produce 5 checks/s: a candidate without a schema used
// to run a fresh TCP pre-dial for every protocol in probe_order, so one dead
// host cost four SYN waits before any HTTP budget was spent.
func TestCheckPreDialsOnceForEveryProtocol(t *testing.T) {
	c := testChecker(nil, "9.9.9.9")
	c.allowBogon = true
	c.cfg.Checker.ProbeOrder = []string{"http", "socks5", "socks4", "https"}

	dialsBefore := Stats.CheckTCPDials.Load()
	failsBefore := Stats.CheckFailPredial.Load()

	cand := Candidate{Host: "127.0.0.1", Port: closedPort(t)}
	start := time.Now()
	if p, err := c.Check(cand); err == nil {
		t.Fatalf("check through a closed port accepted %v", p)
	}
	if el := time.Since(start); el > 8*time.Second {
		t.Fatalf("dead candidate took %s; it must fail at the first pre-dial", el)
	}
	if got := Stats.CheckTCPDials.Load() - dialsBefore; got != 1 {
		t.Fatalf("pre-dial attempts = %d, want 1 for all four protocols", got)
	}
	if got := Stats.CheckFailPredial.Load() - failsBefore; got != 1 {
		t.Fatalf("predial failures = %d, want 1", got)
	}
}

// TestCheckGivesUpAtBudget: a listener that accepts TCP and then says nothing
// is the case the budget exists for. With total_timeout at 30s and the budget
// at 1s the check must return in about a second, not in half a minute.
func TestCheckGivesUpAtBudget(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	var mu sync.Mutex
	var held []net.Conn // accepted and deliberately never answered
	defer func() {
		mu.Lock()
		for _, c := range held {
			c.Close()
		}
		mu.Unlock()
	}()
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			mu.Lock()
			held = append(held, conn)
			mu.Unlock()
		}
	}()

	c := testChecker(nil, "9.9.9.9")
	c.allowBogon = true
	c.cfg.Checker.ProbeOrder = []string{"http"}
	c.cfg.Checker.Budget = Duration{time.Second}
	c.cfg.Checker.TotalT = Duration{30 * time.Second}

	cand := Candidate{Host: "127.0.0.1", Port: ln.Addr().(*net.TCPAddr).Port}
	start := time.Now()
	_, err = c.Check(cand)
	el := time.Since(start)
	if err == nil {
		t.Fatal("check through a silent upstream passed")
	}
	if el > 10*time.Second {
		t.Fatalf("check took %s, budget was 1s", el)
	}
	if got := stageOf(err); got != stageIP {
		t.Fatalf("stage = %v, want ip", got)
	}
}
