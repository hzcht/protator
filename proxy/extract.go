package proxy

import (
	"encoding/base64"
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
	reSpysScript = regexp.MustCompile(`(?is)<script[^>]*>(.*?)</script>`)
)

// Extractor pulls host:port candidates out of scraped page bodies using the
// universal patterns above plus the per-site patterns from regexp.txt.
type Extractor struct {
	patterns []*regexp.Regexp
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
	index := make(map[string]int) // host:port -> position in result
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

	// 1) scheme://ip:port (explicit protocol)
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
	// 2) bare ip:port — use indices to reject partial IP matches (e.g. 29.30.31.3 from 29.30.31.32)
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
	// 3) [ipv6]:port
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
	// 3b) spys.one-style JS-obfuscated ports (computed, no browser needed)
	extractSpys(text, emit)

	// 4) site-specific patterns from regexp.txt
	for _, re := range e.patterns {
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

// maxBase64Body bounds what will be decoded. A 200 MB page is not a base64
// blob worth the CPU, and a mirror that publishes that much encoded text is not
// a mirror.
const maxBase64Body = 8 << 20

// tryBase64Text decodes body when the whole thing is one base64 blob. It
// returns "" for anything else: the payload has to be *entirely* base64
// alphabet plus whitespace, because a single stray byte means decoding a page
// whose real content is the plain text on the first pass anyway.
//
// Padding is optional. Many mirrors emit unpadded base64 (long URLs, streaming
// writers), and rejecting those loses the source entirely.
func tryBase64Text(body []byte) string {
	if len(body) < 64 || len(body) > maxBase64Body {
		return ""
	}
	var buf []byte
	for _, c := range body {
		switch {
		case c == '\r', c == '\n', c == '\t', c == ' ':
			// Whitespace between lines is normal in a wrapped blob.
		case isBase64Byte(c):
			buf = append(buf, c)
		default:
			return "" // real page content: the plain-text pass owns this
		}
	}
	dec, err := base64.RawStdEncoding.DecodeString(string(buf))
	if err != nil {
		if dec, err = base64.StdEncoding.DecodeString(string(buf)); err != nil {
			return ""
		}
	}
	if !looksLikeProxyText(dec) {
		return ""
	}
	return string(dec)
}

func isBase64Byte(c byte) bool {
	switch {
	case c >= 'A' && c <= 'Z', c >= 'a' && c <= 'z', c >= '0' && c <= '9':
		return true
	case c == '+', c == '/', c == '=':
		return true
	}
	return false
}

// looksLikeProxyText is the false-positive guard for the base64 pass. A body
// made of base64 alphabet characters decodes to noise almost every time, and
// extracting from noise is pure CPU. What a proxy list looks like: repeated
// port numbers after addresses, one per line.
func looksLikeProxyText(b []byte) bool {
	digits, colons, newlines := 0, 0, 0
	for _, c := range b {
		if c == 0 {
			return false // binary payload, not a list
		}
		switch c {
		case '\n':
			newlines++
		case ':':
			colons++
		}
		if c >= '0' && c <= '9' {
			digits++
		}
	}
	return newlines >= 2 && digits >= 8 || colons >= 16 && digits >= 16
}

// portBefore returns the last valid port number in the text preceding a match
// group (used by single-group patterns like "port-8080 ... 1.2.3.4").
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

// extractSpys decodes spys.one-style JS-obfuscated ports without a browser:
// each document.write("..."+(a^b)+(c^d)...) term after an IP evaluates to one
// port digit, with the variables defined in script blocks on the same page.
func extractSpys(text string, emit func(Candidate) bool) {
	writes := reSpysWrite.FindAllStringSubmatchIndex(text, -1)
	if len(writes) == 0 {
		return
	}
	env := collectSpysVars(text)
	for _, m := range writes {
		if len(m) < 6 {
			continue
		}
		host := text[m[2]:m[3]]
		if !validHost(host) {
			continue
		}
		terms := reSpysTerm.FindAllStringSubmatch(text[m[4]:m[5]], -1)
		if len(terms) == 0 {
			continue
		}
		var digits strings.Builder
		memo := make(map[string]int, 32)
		ok := true
		for _, t := range terms {
			a, aok := spysResolve(t[1], env, memo, 0)
			b, bok := spysResolve(t[2], env, memo, 0)
			if !aok || !bok {
				ok = false
				break
			}
			d := a ^ b
			if d < 0 || d > 9 {
				ok = false // not a port digit: pattern misapplied
				break
			}
			digits.WriteByte(byte('0' + d))
		}
		if !ok {
			continue
		}
		port, ok := parsePort(digits.String())
		if !ok {
			continue
		}
		emit(Candidate{Host: host, Port: port, Schema: schemaNear(text, m[0], m[1])})
	}
}

// collectSpysVars gathers name=value assignments from page script blocks.
func collectSpysVars(text string) map[string]string {
	raw := make(map[string]string, 64)
	for _, sm := range reSpysScript.FindAllStringSubmatch(text, -1) {
		if len(sm) != 2 {
			continue
		}
		for _, am := range reSpysAssign.FindAllStringSubmatch(sm[1], -1) {
			if len(am) != 3 {
				continue
			}
			raw[am[1]] = am[2]
		}
	}
	return raw
}

// spysResolve evaluates a variable to an int (literal or xor expression).
func spysResolve(name string, raw map[string]string, memo map[string]int, depth int) (int, bool) {
	if v, ok := memo[name]; ok {
		return v, true
	}
	if depth > 4 {
		return 0, false
	}
	expr, ok := raw[name]
	if !ok {
		return 0, false
	}
	if v, ok := spysOperand(expr, raw, memo, depth); ok {
		memo[name] = v
		return v, true
	}
	return 0, false
}

// spysOperand evaluates either an int literal or a binary a^b expression.
func spysOperand(expr string, raw map[string]string, memo map[string]int, depth int) (int, bool) {
	expr = strings.TrimSpace(expr)
	if expr == "" {
		return 0, false
	}
	if strings.Contains(expr, "^") {
		parts := strings.SplitN(expr, "^", 2)
		a, aok := spysValue(strings.TrimSpace(parts[0]), raw, memo, depth+1)
		b, bok := spysValue(strings.TrimSpace(parts[1]), raw, memo, depth+1)
		if !aok || !bok {
			return 0, false
		}
		return a ^ b, true
	}
	return spysValue(expr, raw, memo, depth+1)
}

// spysValue resolves a single token: int literal or variable reference.
func spysValue(tok string, raw map[string]string, memo map[string]int, depth int) (int, bool) {
	isNum := len(tok) > 0
	for i := 0; i < len(tok); i++ {
		if tok[i] < '0' || tok[i] > '9' {
			isNum = false
			break
		}
	}
	if isNum {
		var v int
		for i := 0; i < len(tok); i++ {
			v = v*10 + int(tok[i]-'0')
		}
		return v, true
	}
	return spysResolve(tok, raw, memo, depth)
}
