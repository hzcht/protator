package proxy

import (
	"os"
	"testing"
)

// liveExtractor builds an extractor from the shipped main/regexp.txt so these
// tests exercise the real per-site patterns rather than a copy.
func liveExtractor(t *testing.T) *Extractor {
	t.Helper()
	lines, err := LoadRegexLines("../config/regexp.txt")
	if err != nil {
		t.Fatalf("LoadRegexLines: %v", err)
	}
	e, err := NewExtractor(lines)
	if err != nil {
		t.Fatalf("NewExtractor: %v", err)
	}
	return e
}

// The fixture is a verbatim copy of one page of the live geonode API. Records
// list a dozen keys between "ip" and "port" and quote the port, so a pattern
// that assumes the two are adjacent extracts nothing.
func TestExtractGeonodeAPI(t *testing.T) {
	data, err := os.ReadFile("testdata/geonode.json")
	if err != nil {
		t.Skipf("fixture missing: %v", err)
	}
	cands := liveExtractor(t).Extract(data)
	if len(cands) < 20 {
		t.Fatalf("got %d candidates from the geonode API page, want at least 20", len(cands))
	}
	for _, c := range cands {
		if !validHost(c.Host) {
			t.Fatalf("invalid host %q", c.Host)
		}
		if c.Port < 1 || c.Port > 65535 {
			t.Fatalf("invalid port %d for %s", c.Port, c.Host)
		}
	}
	t.Logf("extracted %d candidates, e.g. %s:%d (%s)", len(cands),
		cands[0].Host, cands[0].Port, cands[0].Schema)
}

// Records must not be paired across object boundaries: the "ip" of one entry
// with the "port" of the next is a different proxy and must never be emitted.
func TestExtractGeonodeDoesNotCrossRecords(t *testing.T) {
	body := []byte(`{"data":[
	  {"_id":"a","ip":"1.2.3.4","country":"XX","port":"1111"},
	  {"_id":"b","ip":"5.6.7.8","country":"YY","port":"2222"}]}`)
	cands := liveExtractor(t).Extract(body)
	got := map[string]int{}
	for _, c := range cands {
		got[c.Host] = c.Port
	}
	want := map[string]int{"1.2.3.4": 1111, "5.6.7.8": 2222}
	if len(got) != len(want) {
		t.Fatalf("got %v, want %v", got, want)
	}
	for h, p := range want {
		if got[h] != p {
			t.Errorf("%s: got port %d, want %d", h, got[h], p)
		}
	}
}
