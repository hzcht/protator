package proxy

import (
	"context"
	"net"
	"path/filepath"
	"runtime/metrics"
	"sync"
	"testing"
	"time"
)

// cpuSeconds reads the process-wide CPU time. The idle-worker assertion below
// needs it because a spinning goroutine has no observable side effect: it
// burns a core, and that is all.
func cpuSeconds() float64 {
	s := []metrics.Sample{{Name: "/cpu/classes/total:cpu-seconds"}}
	metrics.Read(s)
	return s[0].Value.Float64()
}

// An idle worker must block on the channel, not spin. The loop used to carry a
// default branch, so a worker whose channel was momentarily empty fell through
// and re-ran the whole validation path on a zero Candidate — hundreds of
// goroutines at 100% CPU for most of the process's life, since a few
// candidates per second cannot keep 600 workers busy.
func TestRunCheckLoopBlocksWhenIdle(t *testing.T) {
	cfg := &Config{}
	cfg.Checker.ProbeOrder = []string{"http"}
	cfg.Collector.MaxCandidates = 100
	chk := &Checker{cfg: cfg, selfIP: net.ParseIP("9.9.9.9"), ipRe: reAnyIP, allowBogon: true}

	dir := t.TempDir()
	pool := NewCandidatePool(filepath.Join(dir, "pool.lst"), 1<<20, 1000)
	defer pool.Close()
	bucket := NewBucket(100)
	debug := NewDebugProxies(filepath.Join(dir, "dbg.txt"), 10)

	cands := make(chan Candidate, 1)
	stop := make(chan struct{})
	done := &sync.WaitGroup{}
	done.Add(1)
	go RunCheckLoop(cands, chk, pool, bucket, debug, cfg, stop, done)

	// One real (immediately-refused) candidate: it proves the worker is alive
	// and has drained the channel before the idle window starts.
	cands <- Candidate{Host: "127.0.0.1", Port: 18080, Schema: "http"}

	before := cpuSeconds()
	time.Sleep(150 * time.Millisecond)
	spent := cpuSeconds() - before

	close(stop)
	finished := make(chan struct{})
	go func() { done.Wait(); close(finished) }()
	select {
	case <-finished:
	case <-time.After(2 * time.Second):
		t.Fatal("worker did not stop on the stop channel")
	}

	if spent > 0.1 {
		t.Fatalf("an idle worker burned %.0f%% of a core over 150ms; the loop is spinning instead of blocking", spent*100/0.15)
	}
}

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
