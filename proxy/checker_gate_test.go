package proxy

import (
	"testing"
	"time"
)

// The serve-grade gate: a validation that passed but answered slower than the
// serving budget must not rank as warm proven stock.
func TestFreshnessRankDowngradesSlowCheck(t *testing.T) {
	b := NewBucket(0)
	p := &Proxy{}
	now := time.Now().UnixNano()

	p.MarkAlive(10 * time.Millisecond)
	if got := b.freshnessRank(now, p); got != freshWarm {
		t.Fatalf("fresh check: rank = %d, want freshWarm (%d)", got, freshWarm)
	}

	p.MarkCheckSlow(true)
	if got := b.freshnessRank(now, p); got != freshStale {
		t.Fatalf("slow check: rank = %d, want freshStale (%d)", got, freshStale)
	}

	// The flag describes the most recent check: a later fast check clears it.
	p.MarkCheckSlow(false)
	if got := b.freshnessRank(now, p); got != freshWarm {
		t.Fatalf("recovered fast check: rank = %d, want freshWarm", got)
	}
}

// Serving proof outranks the slow gate: real traffic is a stronger statement
// than any check.
func TestFreshnessRankServingProofBeatsSlowCheck(t *testing.T) {
	b := NewBucket(0)
	p := &Proxy{}
	now := time.Now().UnixNano()

	p.MarkCheckSlow(true)
	p.MarkServeOK(10 * time.Millisecond)
	if got := b.freshnessRank(now, p); got != freshGreen {
		t.Fatalf("served despite slow check: rank = %d, want freshGreen (%d)", got, freshGreen)
	}
}
