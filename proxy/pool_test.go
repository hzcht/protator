package proxy

import (
	"os"
	"path/filepath"
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
