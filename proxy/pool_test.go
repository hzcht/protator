package proxy

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestCandidatePoolAddBatchGood(t *testing.T) {
	path := filepath.Join(t.TempDir(), "candidates.lst")
	cp := NewCandidatePool(path, 0, 0)
	t.Cleanup(func() { cp.Close() })

	if !cp.Add(Candidate{Host: "1.1.1.1", Port: 80, Schema: "http"}) {
		t.Fatal("first add expected true")
	}
	if cp.Add(Candidate{Host: "1.1.1.1", Port: 80, Schema: ""}) {
		t.Fatal("duplicate key (http vs bare normalize to same line) expected false")
	}
	if !cp.Add(Candidate{Host: "2.2.2.2", Port: 1080, Schema: "socks5"}) {
		t.Fatal("socks5 add expected true")
	}
	if cp.Len() != 2 {
		t.Fatalf("Len = %d, want 2", cp.Len())
	}

	b := cp.Batch(1)
	if len(b) != 1 || b[0].Host != "1.1.1.1" {
		t.Fatalf("first batch = %+v, want 1.1.1.1:80", b)
	}
	b = cp.Batch(1)
	if len(b) != 1 || b[0].Host != "2.2.2.2" || b[0].Schema != "socks5" {
		t.Fatalf("second batch = %+v, want socks5 2.2.2.2", b)
	}
	// rotation: third batch wraps back to the first entry.
	b = cp.Batch(1)
	if len(b) != 1 || b[0].Host != "1.1.1.1" {
		t.Fatalf("rotation batch = %+v, want wrap to 1.1.1.1", b)
	}

	cp.Good(Candidate{Host: "1.1.1.1", Port: 80, Schema: "http"})
	for i := 0; i < 4; i++ {
		b = cp.Batch(3)
		for _, c := range b {
			if c.Host == "1.1.1.1" {
				t.Fatalf("good candidate still in batch: %+v", c)
			}
		}
	}
}

// A re-probed candidate must come back with the source it was found on: that
// attribution is what credits the real site in the bucket's per-source counts
// once the candidate finally validates. Legacy lines (no tab suffix) stay
// unattributed instead of inventing a source.
func TestCandidatePoolKeepsSource(t *testing.T) {
	path := filepath.Join(t.TempDir(), "candidates.lst")
	cp := NewCandidatePool(path, 0, 0)
	t.Cleanup(func() { cp.Close() })
	if !cp.Add(Candidate{Host: "5.5.5.5", Port: 8080, Source: "https://src.example/list.txt"}) {
		t.Fatal("sourced add expected true")
	}
	b := cp.Batch(1)
	if len(b) != 1 || b[0].Source != "https://src.example/list.txt" {
		t.Fatalf("batch source = %+v, want the sites.txt entry", b)
	}
	// The source survives a restart through the pool file, and Good() still
	// matches by proxy key regardless of the suffix.
	cp.flush()
	cp2 := NewCandidatePool(path, 0, 0)
	t.Cleanup(func() { cp2.Close() })
	b = cp2.Batch(1)
	if len(b) != 1 || b[0].Source != "https://src.example/list.txt" {
		t.Fatalf("reloaded batch source = %+v, want the sites.txt entry", b)
	}
	cp2.Good(Candidate{Host: "5.5.5.5", Port: 8080})
	if b := cp2.Batch(1); len(b) != 0 {
		t.Fatalf("good candidate still in batch after reload: %+v", b)
	}

	// A legacy line without the suffix parses as before and yields no source.
	legacy := filepath.Join(t.TempDir(), "legacy.lst")
	os.WriteFile(legacy, []byte("6.6.6.6:3128\n"), 0o644)
	cp3 := NewCandidatePool(legacy, 0, 0)
	t.Cleanup(func() { cp3.Close() })
	b = cp3.Batch(1)
	if len(b) != 1 || b[0].Host != "6.6.6.6" || b[0].Source != "" {
		t.Fatalf("legacy batch = %+v, want unattributed 6.6.6.6", b)
	}
}

func TestCandidatePoolReloads(t *testing.T) {
	path := filepath.Join(t.TempDir(), "candidates.lst")
	cp := NewCandidatePool(path, 0, 0)
	t.Cleanup(func() { cp.Close() })
	cp.Add(Candidate{Host: "3.3.3.3", Port: 8080, Schema: "http"})
	cp.Add(Candidate{Host: "4.4.4.4", Port: 3128, Schema: "https"})
	cp.flush()

	// Reload from disk: entries survive, protocol is preserved.
	cp2 := NewCandidatePool(path, 0, 0)
	t.Cleanup(func() { cp2.Close() })
	if cp2.Len() != 2 {
		t.Fatalf("reloaded Len = %d, want 2", cp2.Len())
	}
	b := cp2.Batch(2)
	found := map[string]bool{}
	for _, c := range b {
		found[c.Host] = true
		if c.Host == "4.4.4.4" && c.Schema != "https" {
			t.Fatalf("schema lost on reload: %+v", c)
		}
		if c.Host == "3.3.3.3" && c.Schema != "http" {
			t.Fatalf("bare line reloaded with schema %q, want http", c.Schema)
		}
	}
	if !found["3.3.3.3"] || !found["4.4.4.4"] {
		t.Fatalf("reload missing entries: %+v", found)
	}
}

func TestCandidatePoolIgnoresGarbageLines(t *testing.T) {
	path := filepath.Join(t.TempDir(), "candidates.lst")
	os.WriteFile(path, []byte("not a proxy line\n1.1.1.1:80\nsocks5://2.2.2.2:1080\n"), 0o644)
	cp := NewCandidatePool(path, 0, 0)
	t.Cleanup(func() { cp.Close() })
	if cp.Len() != 2 {
		t.Fatalf("Len = %d, want 2 (garbage skipped)", cp.Len())
	}
	cp.Add(Candidate{Host: "1.1.1.1", Port: 80, Schema: ""})
	if cp.Len() != 2 {
		t.Fatalf("Add of already-persisted key bumped Len to %d", cp.Len())
	}
	if !cp.Add(Candidate{Host: "5.5.5.5", Port: 1234, Schema: ""}) {
		t.Fatal("new add after reload expected true")
	}
}

// The pool must stay usable at the cap instead of refusing work: it rotates
// (oldest evicted, newest kept), and the rotation survives a reload. Dropping
// the newest entries вЂ” the old behaviour вЂ” threw away exactly the transient
// failures the pool exists to keep, while the oldest (already re-probed many
// times) squatted on the capacity forever.
func TestCandidatePoolRotatesAtCap(t *testing.T) {
	path := filepath.Join(t.TempDir(), "candidates.lst")
	pool := NewCandidatePool(path, 1<<20, 10)
	t.Cleanup(func() { pool.Close() })
	for i := 0; i < 10; i++ {
		if !pool.Add(Candidate{Host: "10.9.9.9", Port: 1000 + i}) {
			t.Fatalf("candidate %d rejected before the cap", i)
		}
	}
	if pool.Len() != 10 {
		t.Fatalf("pool grew to %d, want the cap of 10", pool.Len())
	}

	// At the cap the newest candidate still lands and the oldest is evicted.
	if !pool.Add(Candidate{Host: "10.9.9.9", Port: 9999}) {
		t.Fatal("pool refused a candidate at the cap")
	}
	if pool.Len() != 10 {
		t.Fatalf("Len = %d after rotation, want 10", pool.Len())
	}
	keys := map[int]bool{}
	for _, c := range pool.Batch(20) {
		keys[c.Port] = true
	}
	if keys[1000] {
		t.Error("oldest candidate survived the rotation")
	}
	if !keys[9999] {
		t.Error("newest candidate missing after the rotation")
	}

	// The rotation is persisted: a reload must not resurrect the evicted line
	// and must still accept new candidates (the old build froze forever once
	// the file exceeded the cap).
	pool.flush()
	reloaded := NewCandidatePool(path, 1<<20, 10)
	t.Cleanup(func() { reloaded.Close() })
	if reloaded.Len() != 10 {
		t.Fatalf("reloaded Len = %d, want 10", reloaded.Len())
	}
	if !reloaded.Add(Candidate{Host: "10.9.9.9", Port: 1000}) {
		t.Fatal("reloaded pool refused a candidate it had evicted")
	}
}

// A pool file written by an older build (over the cap, e.g. the production
// 391k-line file under a 200k cap) must not freeze the pool on load: the tail
// is kept and rewritten, so writes resume immediately.
func TestCandidatePoolTrimsOversizedFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "candidates.lst")
	var buf strings.Builder
	for i := 0; i < 30; i++ {
		fmt.Fprintf(&buf, "10.8.8.8:%d\n", 1000+i)
	}
	os.WriteFile(path, []byte(buf.String()), 0o644)

	cp := NewCandidatePool(path, 1<<20, 10)
	t.Cleanup(func() { cp.Close() })
	if cp.Len() != 10 {
		t.Fatalf("Len = %d, want the last 10 lines", cp.Len())
	}
	b := cp.Batch(10)
	for _, c := range b {
		if c.Port < 1020 {
			t.Fatalf("kept a head line past the tail: %+v", c)
		}
	}
	if !cp.Add(Candidate{Host: "10.7.7.7", Port: 80}) {
		t.Fatal("oversized file froze the pool: Add was refused")
	}
	if lines, _ := readLines(path); len(lines) != 10 {
		t.Fatalf("file has %d lines after trim, want the compacted 10", len(lines))
	}
}

// Rotation must not let the file grow without bound: once enough entries have
// been evicted, the file is rewritten from memory.
func TestCandidatePoolCompactsUnderRotation(t *testing.T) {
	path := filepath.Join(t.TempDir(), "candidates.lst")
	pool := NewCandidatePool(path, 1<<20, 10)
	t.Cleanup(func() { pool.Close() })
	total := 10 + compactEvictThreshold
	for i := 0; i < total; i++ {
		if !pool.Add(Candidate{Host: "10.9.9.9", Port: 1000 + i}) {
			t.Fatalf("add %d refused", i)
		}
	}
	if lines, _ := readLines(path); len(lines) != 10 {
		t.Fatalf("file has %d lines, want 10 (compaction did not run)", len(lines))
	}
}
