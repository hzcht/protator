package proxy

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestProvenIndexRoundTripRestoresWarmTier(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "proven.idx")

	fresh := mustProxy(t, "http://10.1.0.1:8080")
	fresh.SetSource("https://list.example/page1")
	fresh.SetGeoIP("DE", "AS64500 Hetzner")
	fresh.MarkAlive(40 * time.Millisecond)
	fresh.MarkServeOK(30 * time.Millisecond)

	old := mustProxy(t, "http://10.1.0.2:8080")
	now := time.Now()
	// Two hours old: cannot pass freshnessRank's 20m window, so the writer
	// must not carry it, and a reader must not warm it.
	old.RestoreProof(now.Add(-2*time.Hour).UnixNano(), 0, 0)

	if err := SaveProvenIndex(path, []*Proxy{fresh, old}, now, 20*time.Minute); err != nil {
		t.Fatalf("save: %v", err)
	}
	idx, bad, err := LoadProvenIndex(path)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if bad != 0 {
		t.Fatalf("malformed lines = %d, want 0", bad)
	}
	if len(idx) != 1 {
		t.Fatalf("indexed %d entries, want 1 (the stale one must be dropped)", len(idx))
	}

	// A restarted process: same URLs, no proof in memory.
	b := NewBucket(10)
	if !b.Add(mustProxy(t, "http://10.1.0.1:8080")) {
		t.Fatal("seed add failed")
	}
	if !b.Add(mustProxy(t, "http://10.1.0.2:8080")) {
		t.Fatal("seed add failed")
	}
	restored, aging, discarded := ApplyProvenIndex(b, idx, now, 20*time.Minute)
	if restored != 1 || aging != 0 || discarded != 0 {
		t.Fatalf("restored=%d aging=%d discarded=%d, want 1/0/0", restored, aging, discarded)
	}

	var warm *Proxy
	for _, p := range b.Snapshot() {
		if p.Host == "10.1.0.1" {
			warm = p
		}
	}
	if warm == nil {
		t.Fatal("restored entry not in the queue")
	}
	if !b.IsProven(warm) {
		t.Fatal("restored entry does not count as proven")
	}
	if got := warm.Source(); got != "https://list.example/page1" {
		t.Errorf("source = %q, want the persisted one", got)
	}
	if got := warm.GetCountry(); got != "DE" {
		t.Errorf("country = %q, want DE", got)
	}
	if warm.Latency() <= 0 {
		t.Error("latency EMA not restored")
	}
}

func TestApplyProvenIndexSkipsStaleRecords(t *testing.T) {
	b := NewBucket(10)
	p := mustProxy(t, "http://10.2.0.1:8080")
	if !b.Add(p) {
		t.Fatal("add failed")
	}
	idx := map[string]provenRecord{
		p.Key(): {Key: p.Key(), LastCheck: time.Now().Add(-time.Hour).UnixNano()},
	}
	restored, aging, discarded := ApplyProvenIndex(b, idx, time.Now(), 20*time.Minute)
	if restored != 0 || aging != 0 || discarded != 1 {
		t.Fatalf("restored=%d aging=%d discarded=%d, want 0/0/1", restored, aging, discarded)
	}
	if b.IsProven(p) {
		t.Fatal("a stale record must not make the entry proven")
	}
}

// A record between one and two freshness windows old is not proof of life, but
// it is still the best ordering information a restart can get: RevalidateMany
// sorts oldest-first, so applying it puts the entry at the front of the next
// pass instead of behind the whole unstamped queue. It must never read as
// proven, though — that is what would make a stale file look healthy.
func TestApplyProvenIndexKeepsAgingEntriesUnproven(t *testing.T) {
	b := NewBucket(10)
	p := mustProxy(t, "http://10.3.0.1:8080")
	if !b.Add(p) {
		t.Fatal("add failed")
	}
	window := 20 * time.Minute
	idx := map[string]provenRecord{
		p.Key(): {
			Key:       p.Key(),
			LastCheck: time.Now().Add(-30 * time.Minute).UnixNano(), // 1.5 windows
			Latency:   int64(120 * time.Millisecond),
			Source:    "https://list.example/page2",
			Country:   "NL",
		},
	}
	restored, aging, discarded := ApplyProvenIndex(b, idx, time.Now(), window)
	if restored != 0 || aging != 1 || discarded != 0 {
		t.Fatalf("restored=%d aging=%d discarded=%d, want 0/1/0", restored, aging, discarded)
	}
	if b.IsProven(p) {
		t.Fatal("an aging record must not make the entry proven")
	}
	if p.lastCheckNanos() == 0 {
		t.Fatal("aging record was not applied: staleness ordering lost")
	}
	if got := p.Source(); got != "https://list.example/page2" {
		t.Errorf("source = %q, want the persisted one", got)
	}
	if got := p.GetCountry(); got != "NL" {
		t.Errorf("country = %q, want NL", got)
	}
}

func TestLoadProvenIndexTolerant(t *testing.T) {
	dir := t.TempDir()

	missing := filepath.Join(dir, "absent.idx")
	idx, _, err := LoadProvenIndex(missing)
	if err != nil || idx != nil {
		t.Fatalf("missing file: idx=%v err=%v, want nil/nil", idx, err)
	}

	path := filepath.Join(dir, "broken.idx")
	body := provenHeader + "\n" +
		"http://ok.example:8080\t1700000000000000000\t0\t0\tsrc\tUS\tAS1\n" +
		"too\tfew\tfields\n" +
		"http://bad-nums.example:8080\tnotanumber\t0\t0\tsrc\tUS\tAS1\n" +
		"\n"
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	idx, bad, err := LoadProvenIndex(path)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if len(idx) != 1 {
		t.Fatalf("parsed %d entries, want 1", len(idx))
	}
	if bad != 2 {
		t.Fatalf("malformed lines = %d, want 2", bad)
	}
	if rec := idx["http://ok.example:8080"]; rec.Country != "US" || rec.ASN != "AS1" {
		t.Fatalf("record = %+v, want geo preserved", rec)
	}
}

// A proxy can be green from real serving traffic alone: audit-seeded entries
// often carry lastOK and no check stamp in this process. freshnessRank counts
// that as proof, so dropping it from the sidecar cost every restart the
// strongest evidence in the pool.
func TestSaveProvenIndexKeepsServingOnlyProof(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "proven.idx")
	now := time.Now()

	served := mustProxy(t, "http://10.4.0.1:8080")
	served.MarkServeOK(25 * time.Millisecond)
	if served.lastCheckNanos() != 0 {
		t.Fatal("test setup: serving-only proof has a check stamp")
	}
	never := mustProxy(t, "http://10.4.0.2:8080")
	if err := SaveProvenIndex(path, []*Proxy{served, never}, now, 20*time.Minute); err != nil {
		t.Fatalf("save: %v", err)
	}
	idx, bad, err := LoadProvenIndex(path)
	if err != nil || bad != 0 {
		t.Fatalf("load: idx=%d bad=%d err=%v", len(idx), bad, err)
	}
	if len(idx) != 1 {
		t.Fatalf("indexed %d entries, want 1 (no stamp = no proof)", len(idx))
	}

	b := NewBucket(10)
	restarted := mustProxy(t, "http://10.4.0.1:8080")
	if !b.Add(restarted) {
		t.Fatal("seed add failed")
	}
	restored, aging, discarded := ApplyProvenIndex(b, idx, now, 20*time.Minute)
	if restored != 1 || aging != 0 || discarded != 0 {
		t.Fatalf("restored=%d aging=%d discarded=%d, want 1/0/0", restored, aging, discarded)
	}
	if !b.IsProven(restarted) {
		t.Fatal("serving-only proof was not restored as proof of life")
	}
	if restarted.lastOKNanos() == 0 {
		t.Fatal("serving stamp was not restored")
	}
}
