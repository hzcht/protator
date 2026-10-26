package proxy

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The gate in extract() may only skip a pass that would have found nothing:
// a gate that drops a possible match loses a proxy with no log line to show
// for it. This walks every shipped pattern and every universal pass over bodies
// of each shape and asserts that whatever the gate skipped really was empty.
// The gate is allowed to be pessimistic (run a pass that finds nothing); it is
// never allowed to be wrong.
//
// The IPv4 and universal gates are evaluated on the same text extract() would
// see: the share-link blanking only ever removes text, so a quad (or a "://",
// or a "[") present before blanking is present after it only if it survived —
// checking the unblanked body is therefore the stricter direction.
func TestExtractGatesNeverDropMatches(t *testing.T) {
	e := liveExtractor(t)

	raw, err := os.ReadFile(filepath.Join("testdata", "proxynova.html"))
	if err != nil {
		t.Fatal(err)
	}
	bodies := map[string]string{
		"real page":   string(raw),
		"junk html":   "<html><head><style>.a{color:red}</style><script>var x=42;</script><body>Nothing here</body></html>",
		"bare list":   "1.2.3.4:8080\n5.6.7.8:3128\n10.0.0.1:1080\n",
		"table":       "<html><table><tr><td>1.2.3.4</td><td>8080</td></tr></table></html>",
		"spys":        "1.2.3.4<script>document.write(\"80\"+(a^b)+(c^d))</script><script>var a=1;var b=2;var c=3;var d=4;</script>",
		"share links": "trojan://secret@example.com:443?type=tcp#x\nvless://01234567-89ab-cdef-0123-456789abcdef@1.2.3.4:8443?security=tls\n",
		"ipv6 list":   "[2001:db8::1]:8080\n[::1]:9050\n",
		"scheme list": "socks5://1.2.3.4:1080\nhttp://5.6.7.8:8080\n",
	}

	for name, body := range bodies {
		text := decodeJSWrites(body)
		ipv4 := hasIPv4Token(text)

		// Share-link gates (evaluated before blanking).
		if !containsFoldASCII(text, "trojan://") {
			if got := reTrojanURL.FindAllStringIndex(text, -1); len(got) > 0 {
				t.Errorf("%s: gate skipped trojan pass but it matches %q", name, text[got[0][0]:got[0][1]])
			}
		}
		if !containsFoldASCII(text, "vless://") {
			if got := reVLESSURL.FindAllStringIndex(text, -1); len(got) > 0 {
				t.Errorf("%s: gate skipped vless pass but it matches %q", name, text[got[0][0]:got[0][1]])
			}
		}
		// Universal gates (evaluated after blanking; blanking only removes
		// text, so checking the unblanked body is the stricter direction).
		if !ipv4 {
			if got := reBareV4.FindAllStringSubmatchIndex(text, -1); len(got) > 0 {
				t.Errorf("%s: IPv4 gate skipped reBareV4 but it matches %q", name, text[got[0][0]:got[0][1]])
			}
			var spys []Candidate
			extractSpys(text, func(c Candidate) bool { spys = append(spys, c); return true })
			if len(spys) > 0 {
				t.Errorf("%s: IPv4 gate skipped the spys pass but it yields %v", name, spys)
			}
		}
		if !strings.Contains(text, "://") {
			if got := reSchemeV4.FindAllStringSubmatch(text, -1); len(got) > 0 {
				t.Errorf("%s: \"://\" gate skipped reSchemeV4 but it matches %q", name, got[0][0])
			}
		}
		if !strings.Contains(text, "[") {
			if got := reBareV6.FindAllStringSubmatch(text, -1); len(got) > 0 {
				t.Errorf("%s: \"[\" gate skipped reBareV6 but it matches %q", name, got[0][0])
			}
		}

		// Every site pattern the gate skipped must really be empty.
		for i, re := range e.patterns {
			if !e.skips(i, ipv4) {
				continue
			}
			if got := re.FindAllStringSubmatchIndex(text, -1); len(got) > 0 {
				t.Errorf("%s: gate skipped pattern %d (%s) but it matches at %d",
					name, i, re.String(), got[0][0])
			}
		}
	}
}
