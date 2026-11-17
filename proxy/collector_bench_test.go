package proxy

// Benchmarks for the collector's candidate dedup. Measurement only: the
// emit path runs seenRecently per candidate (thousands per cycle) and
// markSeen per emitted one, both under seenMu, with the schema://host:port
// key built inline — that string build is part of what the dedup costs, so
// it stays inside the timed calls rather than being prebuilt away.

import (
	"fmt"
	"testing"
	"time"
)

const (
	// benchSeenSeed is the size of the resident seen set: one cycle's worth
	// of already-emitted candidates (~20k) that every new lookup goes up
	// against.
	benchSeenSeed = 20000
	// benchSeenMiss is the size of the fresh-candidate pool: distinct keys
	// rotated through between resyncs, disjoint from the seed set's hosts.
	benchSeenMiss = 20000
)

// benchSeenCands builds n distinct http candidates on the given first octet,
// so the seed set and the miss pool can never share a key.
func benchSeenCands(octet, n int) []Candidate {
	cands := make([]Candidate, n)
	for i := range cands {
		cands[i] = Candidate{
			Schema: "http",
			Host:   fmt.Sprintf("%d.%d.%d.%d", octet, (i>>16)&0xff, (i>>8)&0xff, i&0xff),
			Port:   8080,
		}
	}
	return cands
}

// cloneSeen copies the pristine seed set: the resync source for the miss
// benchmark, built once and never mutated.
func cloneSeen(src map[string]time.Time) map[string]time.Time {
	dst := make(map[string]time.Time, len(src))
	for k, v := range src {
		dst[k] = v
	}
	return dst
}

// BenchmarkSeenDedup is the per-candidate dedup workload:
//
//   - hit: a repeat candidate (most candidates in a cycle are re-extracts of
//     hosts seen minutes ago) — one seenRecently lookup, no insert.
//   - miss: a fresh candidate — the emit pair, seenRecently (false) then
//     markSeen (insert), the exact sequence the emit loop runs.
//
// The miss pool rotates over benchSeenMiss distinct keys; once a full pool
// has been marked, the seen map is resynced to the pristine seed under a
// stopped timer, so the next rotation misses again and the map holds its
// seed size instead of growing with b.N.
func BenchmarkSeenDedup(b *testing.B) {
	seedCands := benchSeenCands(10, benchSeenSeed)
	seed := &Collector{seen: make(map[string]time.Time, benchSeenSeed)}
	for _, cand := range seedCands {
		seed.markSeen(cand) // the real key builder: seeds and lookups cannot drift
	}
	missCands := benchSeenCands(11, benchSeenMiss)

	b.Run("hit", func(b *testing.B) {
		col := &Collector{seen: cloneSeen(seed.seen)}
		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			if !col.seenRecently(seedCands[i%benchSeenSeed]) {
				b.Fatal("seeded candidate was a dedup miss")
			}
		}
	})

	b.Run("miss", func(b *testing.B) {
		col := &Collector{seen: cloneSeen(seed.seen)}
		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			if i%benchSeenMiss == 0 && i > 0 {
				b.StopTimer()
				col.seen = cloneSeen(seed.seen)
				b.StartTimer()
			}
			cand := missCands[i%benchSeenMiss]
			if !col.seenRecently(cand) {
				col.markSeen(cand)
			}
		}
	})
}
