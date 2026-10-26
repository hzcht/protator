package proxy

import (
	"fmt"
	"net"
	"regexp"
	"strings"
)

// ipv4RE matches a single IPv4 octet (0-255). Building block of the universal
// patterns below; keep it minimal since every use is wrapped in \b / full-string
// context that already bounds the match.
const ipv4RE = `(?:25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])`

// Universal patterns always applied by the extractor (in this order).
var (
	reSchemeV4 = regexp.MustCompile(`(?i)\b(https?|socks5h?|socks4a?)://(` + ipv4RE + `(?:\.` + ipv4RE + `){3}):([0-9]{1,5})\b`)
	reBareV4   = regexp.MustCompile(`\b(` + ipv4RE + `(?:\.` + ipv4RE + `){3}):([0-9]{1,5})\b`)
	reBareV6   = regexp.MustCompile(`\[([0-9a-fA-F:]{2,45})\]:([0-9]{1,5})\b`)

	// spys.one-style JS-obfuscated ports:
	//   1.2.3.4<script>document.write("..."+(varA^varB)+(varC^varD)...)</script>
	// with the variables defined in another script block on the same page
	// (plain ints or digit^var expressions). Each (a^b) term evaluates to
	// one port digit.
	reSpysWrite  = regexp.MustCompile(`(?i)\b(` + ipv4RE + `(?:\.` + ipv4RE + `){3})\s*<script[^>]*>\s*document\.write\(\s*"[^"]*"\s*((?:\+\s*\(\s*[A-Za-z][A-Za-z0-9]*\s*\^\s*[A-Za-z][A-Za-z0-9]*\s*\)){1,5})\s*\)`)
	reSpysTerm   = regexp.MustCompile(`\(\s*([A-Za-z][A-Za-z0-9]*)\s*\^\s*([A-Za-z][A-Za-z0-9]*)\s*\)`)
	reSpysAssign = regexp.MustCompile(`\b([A-Za-z][A-Za-z0-9]*)\s*=\s*([0-9]+|[A-Za-z][A-Za-z0-9]*\s*\^\s*[A-Za-z0-9]+|[0-9]+\s*\^\s*[A-Za-z][A-Za-z0-9]*)\s*;`)
	// Bounded gap: an unbounded (.*?) over an 8 MB adversarial body keeps a
	// fetch worker scanning for a closing tag that never comes (RE2 has no
	// catastrophic backtracking, but the linear scan per page is enough to
	// pin workers when a handful of pages cooperate). Real spys.as XOR
	// blocks are a few hundred bytes; 1000 is the RE2 per-repeat cap.
	reSpysScript = regexp.MustCompile(`(?is)<script[^>]*>(.{0,1000})</script>`)

	// trojan://password@host:port?params#remarks share links. One repeat,
	// capped at the RE2 per-repeat limit: real entries run 100–350 chars
	// (grpc serviceNames are the longest), so 1000 leaves wide margin.
	// No capture groups — parseTrojanURL splits the token itself, because
	// passwords may contain @ and hosts may be domains, neither of which a
	// 1–2 group ip+port shape can express.
	reTrojanURL = regexp.MustCompile(`(?i)\btrojan://[^\s"'<>]{1,1000}`)

	// vless://uuid@host:port?params#remarks share links. Same shape and
	// same bound as trojan; parseVLESSURL splits the token itself.
	reVLESSURL = regexp.MustCompile(`(?i)\bvless://[^\s"'<>]{1,1000}`)
)

// Extractor pulls host:port candidates out of scraped page bodies using the
// universal patterns above plus the per-site patterns from regexp.txt.
type Extractor struct {
	patterns []*regexp.Regexp
	// startsIPv4[i] is true when patterns[i] literally begins with the
	// canonical IPv4 group, so it cannot match a body without a dotted quad.
	// Derived at compile time; see startsWithIPv4Group.
	//
	// A gate exists because every site pattern is a full pass over the body
	// (61 of them measured 215 of the 260 ms a real 128 KB page costs). It may
	// only ever be wrong in the safe direction: a gate that lets an impossible
	// pattern through costs time, one that drops a possible match silently
	// loses candidates — so it is a necessary condition derived from the
	// pattern's own source, never a guess, and TestExtractGatesNeverDropMatches
	// asserts the empty side of it.
	startsIPv4 []bool
}

// NewExtractor compiles the extra regexes from regexp.txt.
func NewExtractor(regexLines []string) (*Extractor, error) {
	e := &Extractor{}
	for _, line := range regexLines {
		re, err := regexp.Compile(line)
		if err != nil {
			return nil, fmt.Errorf("bad regex %q: %w", line, err)
		}
		e.patterns = append(e.patterns, re)
		e.startsIPv4 = append(e.startsIPv4, startsWithIPv4Group(line))
	}
	return e, nil
}

// Extract returns unique candidates found in the page body.
//
// Two bodies are searched: the page as served, and — when the whole body is a
// base64 blob — its decoded form. Many list mirrors publish the plain text
// encoded (it dodges naive scrapers and GitHub's content-type sniffing), and
// without the second pass the entire source reads as one opaque token.
func (e *Extractor) Extract(body []byte) []Candidate {
	out := e.extract(decodeJSWrites(string(body)))
	if decoded := tryBase64Text(body); decoded != "" {
		out = mergeCandidates(out, e.extract(decodeJSWrites(decoded)))
	}
	return out
}

// mergeCandidates appends src to dst, skipping duplicates. An entry that only
// exists in dst without a schema is upgraded from src's if src knows one.
func mergeCandidates(dst, src []Candidate) []Candidate {
	index := make(map[string]int, len(dst))
	for i, c := range dst {
		index[c.key()] = i
	}
	for _, c := range src {
		if i, ok := index[c.key()]; ok {
			if dst[i].Schema == "" && c.Schema != "" {
				dst[i].Schema = c.Schema
			}
			continue
		}
		index[c.key()] = len(dst)
		dst = append(dst, c)
	}
	return dst
}

// extract runs the universal and per-site patterns over one text body and
// returns the candidates it found, in order of first appearance.
func (e *Extractor) extract(text string) []Candidate {
	index := make(map[string]int) // candidate key -> position in result
	var out []Candidate

	emit := func(c Candidate) bool {
		key := c.key()
		if i, ok := index[key]; ok {
			if out[i].Schema == "" && c.Schema != "" {
				out[i].Schema = c.Schema
				return true
			}
			return false
		}
		index[key] = len(out)
		out = append(out, c)
		return true
	}

	// 0) trojan:// and vless:// share links, before everything else. The
	// tokens are blanked out of the text the remaining passes see (same
	// length, so all indices stay valid): a bare 1.2.3.4:443 inside a share
	// link is the same socket, and emitting it as an unknown-schema
	// candidate burns a full multi-protocol check for an entry that can
	// never validate without its credential. The credentialed entry already
	// covers it.
	var buf []byte // lazily the blanked copy; nil when no share links found
	blank := func(from, to int) {
		if buf == nil {
			buf = []byte(text)
		}
		for i := from; i < to; i++ {
			buf[i] = ' '
		}
	}
	// Gate 0: both share-link patterns are "scheme://…" under (?i), so a
	// case-folded literal search decides whether they can match at all. This
	// runs before blanking — blanking is what removes them from the text the
	// later passes see.
	if containsFoldASCII(text, "trojan://") {
		for _, loc := range reTrojanURL.FindAllStringIndex(text, -1) {
			if c, ok := parseTrojanURL(text[loc[0]:loc[1]]); ok {
				emit(c)
			}
			blank(loc[0], loc[1])
		}
	}
	if containsFoldASCII(text, "vless://") {
		for _, loc := range reVLESSURL.FindAllStringIndex(text, -1) {
			if c, ok := parseVLESSURL(text[loc[0]:loc[1]]); ok {
				emit(c)
			}
			blank(loc[0], loc[1])
		}
	}
	if buf != nil {
		text = string(buf)
	}

	// One pre-scan decides for everything below that needs a dotted quad
	// (reBareV4, the spys pass and every site pattern whose source starts with
	// the IPv4 group). Computed after blanking: blanking only ever removes
	// text, so a quad seen before it might already be gone.
	ipv4 := hasIPv4Token(text)

	// 1) scheme://ip:port (explicit protocol) — every match contains "://"
	if strings.Contains(text, "://") {
		for _, m := range reSchemeV4.FindAllStringSubmatch(text, -1) {
			if len(m) != 4 {
				continue
			}
			port, ok := parsePort(m[3])
			if !ok {
				continue
			}
			emit(Candidate{Host: m[2], Port: port, Schema: normScheme(m[1])})
		}
	}
	// 2) bare ip:port — use indices to reject partial IP matches (e.g. 29.30.31.3 from 29.30.31.32)
	// Without a dotted quad in the body neither this pass nor the spys pass
	// can produce anything, so both are skipped by the one pre-scan above.
	if ipv4 {
		for _, m := range reBareV4.FindAllStringSubmatchIndex(text, -1) {
			if len(m) != 6 {
				continue
			}
			host := text[m[2]:m[3]]
			if !validHost(host) {
				continue
			}
			// Reject partial IP matches: if the IP is followed by .digit in the original text,
			// it's a prefix of a longer dotted quad (e.g. 29.30.31.3 from 29.30.31.32).
			if m[3] < len(text) && text[m[3]] == '.' {
				if m[3]+1 < len(text) && text[m[3]+1] >= '0' && text[m[3]+1] <= '9' {
					continue
				}
			}
			portStr := text[m[4]:m[5]]
			port, ok := parsePort(portStr)
			if !ok {
				continue
			}
			emit(Candidate{Host: host, Port: port})
		}
	}
	// 3) [ipv6]:port — every match starts with "["
	if strings.Contains(text, "[") {
		for _, m := range reBareV6.FindAllStringSubmatch(text, -1) {
			if len(m) != 3 {
				continue
			}
			host := m[1]
			if net.ParseIP(host) == nil {
				continue
			}
			port, ok := parsePort(m[2])
			if !ok {
				continue
			}
			emit(Candidate{Host: host, Port: port})
		}
	}
	// 3b) spys.one-style JS-obfuscated ports (computed, no browser needed).
	// reSpysWrite starts with the IPv4 group, so it needs the same quad.
	if ipv4 {
		extractSpys(text, emit)
	}

	// 4) site-specific patterns from regexp.txt. Each one is a full pass over
	// the body — 61 of them measured 215 of the 260 ms a real 128 KB page
	// costs — so the ones whose own source proves them impossible to match are
	// skipped. Patterns that merely start with a literal ("<td…") are NOT
	// gated: Go's regexp already jumps from literal-prefix to literal-prefix
	// internally, and measuring that gate at 1 ms of 184 ms said so.
	for i, re := range e.patterns {
		if e.skips(i, ipv4) {
			continue
		}
		idxs := re.FindAllStringSubmatchIndex(text, -1)
		for _, m := range idxs {
			switch {
			case len(m) >= 6: // two groups: ip + port in either order
				g1 := text[m[2]:m[3]]
				g2 := text[m[4]:m[5]]
				var host, portStr string
				if looksLikeIP(g1) {
					host, portStr = g1, g2
				} else if looksLikeIP(g2) {
					host, portStr = g2, g1
				} else {
					continue
				}
				if !validHost(host) {
					continue
				}
				port, ok := parsePort(portStr)
				if !ok {
					continue
				}
				emit(Candidate{Host: host, Port: port, Schema: schemaNear(text, m[0], m[1])})
			case len(m) == 4: // one group: an IP with the port in surrounding text
				host := text[m[2]:m[3]]
				if !looksLikeIP(host) || !validHost(host) {
					continue
				}
				port, ok := portBefore(text[m[0]:m[2]])
				if !ok {
					continue
				}
				emit(Candidate{Host: host, Port: port, Schema: schemaNear(text, m[0], m[1])})
			}
		}
	}
	return out
}

func portBefore(s string) (int, bool) {
	end := len(s)
	for end > 0 {
		if s[end-1] < '0' || s[end-1] > '9' {
			end--
			continue
		}
		start := end
		for start > 0 && s[start-1] >= '0' && s[start-1] <= '9' {
			start--
		}
		if p, ok := parsePort(s[start:end]); ok {
			return p, true
		}
		end = start
	}
	return 0, false
}

// normScheme maps umbrella scheme names onto dialer names.
func normScheme(s string) string {
	switch strings.ToLower(s) {
	case "socks", "socks4a", "socks4":
		return "socks4"
	case "socks5h", "socks5":
		return "socks5"
	case "http":
		return "http"
	case "https":
		return "https"
	}
	return "http"
}

// validHost checks that host is a literal IPv4 address.
//
// This used to call net.ResolveIPAddr, which walks the resolver for anything
// that is not a literal — a hostname would come back non-nil and pass as a
// "valid host". What the extractor actually wants is a literal: every match is
// an IP:port pair served by a proxy list, so a hostname-shaped match is noise.
func validHost(host string) bool {
	ip := net.ParseIP(host)
	return ip != nil && ip.To4() != nil
}

func looksLikeIP(s string) bool {
	return strings.Count(s, ".") == 3 && strings.Trim(s, "0123456789.") == ""
}

func parsePort(s string) (int, bool) {
	if len(s) < 1 || len(s) > 5 {
		return 0, false
	}
	var v int
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c < '0' || c > '9' {
			return 0, false
		}
		v = v*10 + int(c-'0')
	}
	if v < 1 || v > 65535 {
		return 0, false
	}
	return v, true
}

// schemaNear inspects a small window around a per-site pattern match for an
// explicit protocol token (poor man's context sniffing).
func schemaNear(text string, start, end int) string {
	lo := start - 80
	if lo < 0 {
		lo = 0
	}
	hi := end + 80
	if hi > len(text) {
		hi = len(text)
	}
	ctx := strings.ToLower(text[lo:hi])
	switch {
	case strings.Contains(ctx, "socks5"), strings.Contains(ctx, "socks 5"):
		return "socks5"
	case strings.Contains(ctx, "socks4"), strings.Contains(ctx, "socks 4"):
		return "socks4"
	case strings.Contains(ctx, "https"):
		return "https"
	}
	return ""
}
