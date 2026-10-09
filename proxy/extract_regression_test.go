package proxy

import (
	"encoding/base64"
	"os"
	"strings"
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

// A whole-body base64 blob is a real publishing format for proxy lists (it
// dodges content sniffing), so the extractor must decode it before giving up.
// The padded and unpadded variants both have to work.
func TestExtractBase64Body(t *testing.T) {
	plain := "1.2.3.4:8080" + "\n" + "5.6.7.8:3128" + "\n" + "9.9.9.9:1080" + "\n" + "10.1.2.3:80" + "\n"
	e, err := NewExtractor(nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct{ name, body string }{
		{"padded", base64.StdEncoding.EncodeToString([]byte(plain))},
		{"unpadded", strings.TrimRight(base64.StdEncoding.EncodeToString([]byte(plain)), "=")},
	} {
		cands := e.Extract([]byte(tc.body))
		if len(cands) != 4 {
			t.Errorf("%s: got %d candidates, want 4 (%+v)", tc.name, len(cands), cands)
		}
	}

	// A page that merely *looks* like base64 (plain text) must not be decoded:
	// the plain-text pass already owns it, and decoding would double the work.
	got := e.Extract([]byte(plain))
	if len(got) != 4 {
		t.Fatalf("plain body: got %d candidates, want 4", len(got))
	}
	// A real HTML page with base64-ish fragments stays untouched: the stray
	// markup means the plain-text pass owns it, and the shipped per-site
	// patterns still find the table row.
	html := "<html><body><table><tr><td>1.2.3.4</td><td>8080</td></tr></table></body></html>abcABC+/="
	e2 := liveExtractor(t)
	if got := e2.Extract([]byte(html)); len(got) != 1 {
		t.Fatalf("html body: got %d candidates, want 1", len(got))
	}
}
