package proxy

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// A panicking cycle must cost that cycle, not the collector: Run's per-cycle
// RecoverPanic is what keeps the only producer of fresh candidates alive when
// something inside a cycle blows up. Without it the collector dies silently
// and the queue starves over days.
//
// The panic source is a stand-in: a negative fetch_workers panics at
// make(chan) before any site is touched, so the test stays network-free while
// exercising the real recover site (the cycle closure in Run).
func TestCollectorRunSurvivesPanickingCycle(t *testing.T) {
	sites := filepath.Join(t.TempDir(), "sites.txt")
	if err := os.WriteFile(sites, []byte("https://example.org/list.html\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	cfg := &Config{}
	cfg.Collector.SitesFile = sites
	cfg.Collector.CycleSleep = Duration{5 * time.Millisecond}
	cfg.Collector.SiteMaxFails = 3
	cfg.Collector.SiteCooldown = Duration{time.Minute}
	cfg.Collector.FetchWorkers = -1 // panics inside the cycle body

	col, err := NewCollector(cfg, nil)
	if err != nil {
		t.Fatal(err)
	}

	before := Stats.RecoverPanics.Load()
	out := make(chan Candidate, 4)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan struct{})
	go func() {
		defer close(done)
		col.Run(ctx, out, nil)
	}()

	time.Sleep(200 * time.Millisecond) // many panicking cycles at 5ms
	cancel()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("Run did not return after cancel")
	}

	if n := Stats.RecoverPanics.Load() - before; n < 2 {
		t.Fatalf("RecoverPanics delta = %d, want >= 2: the first panicking cycle must not kill the loop", n)
	}
}
