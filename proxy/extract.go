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
func (e *Extractor) Extract(body []byte) []Candidate {
	text := decodeJSWrites(string(body))
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

// validHost checks that an IPv4 is a real address (octets <= 255).
func validHost(host string) bool {
	h, err := net.ResolveIPAddr("ip4", host)
	return err == nil && h != nil
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
