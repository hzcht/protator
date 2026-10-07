package proxy

import (
	"os"
	"strings"
	"testing"
)

func TestDecodeJSWritesExamples(t *testing.T) {
	// All calls below are verbatim from a real proxynova listing page; the
	// expected strings are what a JS engine prints for them. Together they
	// cover every obfuscation shape the site uses.
	cases := []struct {
		in, want string
	}{
		// string slicing with computed bounds
		{`document.write("5.11229.951.149.129.255.15.11".substring(23-11, 36-11).concat("797".substring(0+0, 4-2)))`, "149.129.255.179"},
		{`document.write("8.13".substring(0+0, 2+2).concat("7.08238.133.2077.082331".substring(9-3, 19-4)))`, "8.138.133.207"},
		{`document.write("120.26.104.112..040".substring(0+0, 18-7).concat("1464".substring(0+0, 4-1)))`, "120.26.104.146"},
		// reversed pieces
		{`document.write("3.82.951.15".split("").reverse().join("").concat(atob("OQ==")))`, "51.159.28.39"},
		{`document.write("190.97017".substring(0+0, 9-3).concat(".342.".split("").reverse().join("")))`, "190.97.243."},
		// repeat() used as a no-op padding trick
		{`document.write("45.15.10".repeat(1).substring(0).concat(".174".repeat(1).substring(0)))`, "45.15.10.174"},
		// three concatenated terms
		{`document.write("91".repeat(2).substring(2).concat(atob("LjE0NA==")).concat("390.30.93390..3".substring(3+0, 5+4)))`, "91.144.30.93"},
		{`document.write(document.write("190.97017".substring(0+0, 9-3).concat(".342.".split("").reverse().join("")).concat(atob("MjA="))))`, "190.97.243.20"},
		// character-code arrays shifted through a map callback
		{`document.write([58,62,64,55].map((code) => String.fromCharCode(code-9)).join("").concat(atob("MjAuMQ==")).concat([54,54,52,55,54].map((code) => String.fromCharCode(code-6)).join("")))`, "157.20.100.10"},
		{`document.write([58,48,51,54,56,48,52,50,50,48].map((code) => String.fromCharCode(code-2)).join("").concat("553".substring(2-1, 3+0)))`, "8.146.200.53"},
		{`document.write(String.fromCharCode(49,46,50,46,51,46,52))`, "1.2.3.4"},
		{`document.write("1.2.3.4")`, "1.2.3.4"},
	}
	for _, c := range cases {
		if got := decodeJSWrites(c.in); got != c.want {
			t.Errorf("decodeJSWrites(%q)\n got %q\nwant %q", c.in, got, c.want)
		}
	}
}

func TestDecodeJSWritesLeavesUnknownAlone(t *testing.T) {
	// Anything the evaluator does not fully understand must survive
	// byte-for-byte, so a plain pattern (or extractSpys) can still see it.
	for _, in := range []string{
		`document.write(window.location = "1.2.3.4")`,
		`document.write(fetch("/api?q=" + encodeURIComponent(ip)))`,
		`document.write("5.11".split(",").reverse().join("."))`,
		`document.write([1,2,3].map((c) => String.fromCharCode(c + 1000)).join(""))`,
		`document.write("1.2.3.4".padStart(15, "0"))`,
		`var a = 1;`,
	} {
		if got := decodeJSWrites(in); got != in {
			t.Errorf("decodeJSWrites(%q) = %q, want unchanged", in, got)
		}
	}
}

func TestExtractProxynovaStylePage(t *testing.T) {
	body := []byte(`<tr data-proxy-id="1">
	  <td align="left" title="2,100,264"><script>document.write("3.82.951.15".split("").reverse().join("").concat(atob("OQ==")))</script></td>
	  <td align="left"><a href="/proxy-server-list/port-79/" title="Port 79 proxies">79</a></td>
	</tr>`)
	// Same shape as the entries in main/regexp.txt.
	e, err := NewExtractor([]string{
		`<td[^>]*>\s*(?:<script[^>]*>\s*)?([0-9]{1,3}(?:\.[0-9]{1,3}){3})\s*(?:</script>\s*)?</td>\s*<td[^>]*>\s*<a[^>]*>\s*([0-9]{1,5})\s*</a>`,
	})
	if err != nil {
		t.Fatalf("NewExtractor: %v", err)
	}
	cands := e.Extract(body)
	if len(cands) != 1 {
		t.Fatalf("got %d candidates, want 1: %+v", len(cands), cands)
	}
	if cands[0].Host != "51.159.28.39" || cands[0].Port != 79 {
		t.Errorf("got %s:%d, want 51.159.28.39:79", cands[0].Host, cands[0].Port)
	}
}

// The fixture is a verbatim copy of a real proxynova listing page: 35 rows,
// each address hidden behind a document.write() expression.
func TestExtractRealProxynovaPage(t *testing.T) {
	data, err := os.ReadFile("testdata/proxynova.html")
	if err != nil {
		t.Skipf("fixture missing: %v", err)
	}
	cands := liveExtractor(t).Extract(data)
	if len(cands) != 35 {
		t.Errorf("got %d candidates from the real page, want 35 (one per row)", len(cands))
	}
	// Every emitted candidate must be usable, not table debris.
	for _, c := range cands {
		if !validHost(c.Host) {
			t.Fatalf("invalid host %q", c.Host)
		}
		if c.Port < 1 || c.Port > 65535 {
			t.Fatalf("invalid port %d for %s", c.Port, c.Host)
		}
	}
	t.Logf("extracted %d/%d rows (e.g. %s:%d)", len(cands), 35, cands[0].Host, cands[0].Port)
}

func TestDecodeJSWritesRealPage(t *testing.T) {
	data, err := os.ReadFile("testdata/proxynova.html")
	if err != nil {
		t.Skipf("fixture missing: %v", err)
	}
	raw := string(data)
	decoded := decodeJSWrites(raw)
	if decoded == raw {
		t.Fatal("fixture produced no document.write rewrite")
	}
	// The rewrite must not have eaten surrounding markup.
	if strings.Count(decoded, "</td>") < strings.Count(raw, "</td>") {
		t.Errorf("decoded page lost table cells: %d -> %d",
			strings.Count(raw, "</td>"), strings.Count(decoded, "</td>"))
	}
}
