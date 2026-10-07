package proxy

import (
	"context"
	"fmt"
	"testing"
	"time"
)

// The state after a restart with a large persisted queue: thousands of entries
// seeded from proxy.lst that carry no proof *in this process lifetime*, plus the
// few hundred that revalidation has already re-proved. This is the picker test
// that matters most, because it is the state the pool spends most of its life
// in: the queue is huge and the working tail is a rounding error in it.
func TestPickerPrefersProvenOverSeededBulk(t *testing.T) {
	const (
		seeded   = 20000
		proven   = 300
		picks    = 2000
		validAge = 10 * time.Minute // validated once, ten minutes ago
	)
	b := NewBucket(seeded)
	// Proven entries are created first, so the dedup in Add keeps them (and
	// the stamp that proves them) instead of dropping the stamp on a duplicate.
	for i := 0; i < proven; i++ {
		p := &Proxy{Schema: "http", Host: hostAt(i), Port: 8080}
		b.Add(p)
		// Revalidation has been through them, ten minutes ago.
		p.stampCheck(time.Now().Add(-validAge).UnixNano())
	}
	for i := proven; i < seeded; i++ {
		b.Add(&Proxy{Schema: "http", Host: hostAt(i), Port: 8080})
	}

	ctx := context.Background()
	hits := 0
	for i := 0; i < picks; i++ {
		p, err := b.PickHealthy(ctx, 8, nil)
		if err != nil {
			t.Fatal(err)
		}
		if !p.LastCheck().IsZero() {
			hits++
		}
	}
	rate := float64(hits) / float64(picks)
	t.Logf("picked a re-proved proxy in %.1f%% of %d picks (proven share of the queue: %.2f%%)",
		rate*100, picks, float64(proven)/float64(seeded)*100)
	// The seeded bulk has no proof at all: a pick that lands there sends the
	// client's request through an unvalidated proxy. Rejection sampling over a
	// 1.5% minority cannot fix that, so the picker has to be told where to look.
	if rate < 0.9 {
		t.Errorf("only %.1f%% of picks hit a proven proxy; the pool is serving the unproven bulk", rate*100)
	}
}

// A pick must never return a proxy that is already carrying the configured
// number of tunnels, unless there is nothing else: a burst of client requests
// concentrated on one flaky proxy is exactly the instability to avoid.
func hostAt(i int) string {
	return fmt.Sprintf("10.%d.%d.%d", i/65536, i/256%256, i%256)
}

// With nothing proven at all — a cold start before revalidation has reached
// anything — the picker must still return something. Refusing to serve would
// turn a thin pool into a hard outage, and an unproven proxy is still a
// legitimate last resort.
func TestPickerFallsBackWhenNothingIsProven(t *testing.T) {
	b := NewBucket(100)
	for i := 0; i < 20; i++ {
		b.Add(&Proxy{Schema: "http", Host: fmt.Sprintf("3.3.3.%d", i+1), Port: 80})
	}
	ctx := context.Background()
	seen := map[string]bool{}
	for i := 0; i < 50; i++ {
		p, err := b.PickHealthy(ctx, 8, nil)
		if err != nil {
			t.Fatalf("picker refused to serve from a 20-entry unproven queue: %v", err)
		}
		if p == nil {
			t.Fatal("nil proxy")
		}
		seen[p.Host] = true
	}
	if len(seen) < 2 {
		t.Errorf("fallback is not random: %d distinct proxies in 50 picks", len(seen))
	}
}

// An expired proof must stop counting. A window that never closes is just as
// wrong as one that is too short: it keeps the picker aiming at proxies that
// were proven once and are dead now.
func TestPickerIgnoresExpiredProof(t *testing.T) {
	b := NewBucket(100)
	b.SetFreshnessWindows(time.Minute, 2*time.Minute)
	old := &Proxy{Schema: "http", Host: "4.4.4.1", Port: 80}
	b.Add(old)
	old.stampCheck(time.Now().Add(-30 * time.Minute).UnixNano())
	for i := 0; i < 50; i++ {
		b.Add(&Proxy{Schema: "http", Host: fmt.Sprintf("5.5.5.%d", i+1), Port: 80})
	}
	// Nothing qualifies: the proven pool must be empty, so the picker falls
	// back rather than preferring the long-dead entry.
	if got := b.freshPool(time.Now()); len(got) != 0 {
		t.Errorf("freshPool returned %d entries, want 0 (the only proof is 30m old, window is 2m)", len(got))
	}
}

// A freshly served proxy outranks one that merely validated, and the hot tail
// is preferred over both.
func TestPickerRanksProofStrength(t *testing.T) {
	b := NewBucket(100)
	green := &Proxy{Schema: "http", Host: "6.6.6.1", Port: 80}
	green.MarkServeOK(10 * time.Millisecond)
	warm := &Proxy{Schema: "http", Host: "6.6.6.2", Port: 80}
	warm.MarkAlive(10 * time.Millisecond)
	quiet := &Proxy{Schema: "http", Host: "6.6.6.3", Port: 80}
	b.Add(green)
	b.Add(warm)
	b.Add(quiet)
	now := time.Now().UnixNano()
	if r := b.freshnessRank(now, green); r != freshGreen {
		t.Errorf("served proxy rank = %d, want freshGreen(%d)", r, freshGreen)
	}
	if r := b.freshnessRank(now, warm); r != freshWarm {
		t.Errorf("validated proxy rank = %d, want freshWarm(%d)", r, freshWarm)
	}
	if r := b.freshnessRank(now, quiet); r != freshStale {
		t.Errorf("unproven proxy rank = %d, want freshStale(%d)", r, freshStale)
	}
	pool := b.freshPool(time.Now())
	if len(pool) != 2 {
		t.Fatalf("freshPool = %d entries, want 2 (green + warm)", len(pool))
	}
	for _, p := range pool {
		if p == quiet {
			t.Error("freshPool included an unproven entry")
		}
	}
	// Anything already carrying proof enters the hot tail on Add. The tail is
	// ordered by recency of proof (newest first), not by proof strength; the
	// strength ranking is applied at pick time by freshnessRank.
	if got := hosts(b.hot); len(got) != 2 {
		t.Fatalf("hot = %v, want both proven entries", got)
	}
	quietNow := &Proxy{Schema: "http", Host: "6.6.6.4", Port: 80}
	b.Add(quietNow)
	if got := hosts(b.hot); len(got) != 2 {
		t.Errorf("adding an unproven entry changed the hot tail: %v", got)
	}
}

func TestPickerSpreadsLoadAcrossProvenPool(t *testing.T) {
	b := NewBucket(10)
	var proven []*Proxy
	for i := 0; i < 5; i++ {
		p := &Proxy{Schema: "http", Host: fmt.Sprintf("2.2.2.%d", i+1), Port: 80}
		p.MarkAlive(10 * time.Millisecond)
		b.Add(p)
		proven = append(proven, p)
	}
	ctx := context.Background()
	// Load one proxy up; the picker should route around it.
	busy := proven[0]
	for i := 0; i < 8; i++ {
		busy.MarkInFlight()
	}
	hits := 0
	for i := 0; i < 100; i++ {
		p, err := b.PickHealthy(ctx, 8, nil)
		if err != nil {
			t.Fatal(err)
		}
		if p == busy {
			hits++
		}
	}
	t.Logf("picked the saturated proxy %d/100 times", hits)
	if hits > 5 {
		t.Errorf("kept picking a saturated proxy (%d/100); load is not being spread", hits)
	}
}
