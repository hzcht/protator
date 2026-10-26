package proxy

import "strings"

// The collector gate: which passes of Extract() may be skipped for a given
// body, and the cheap scans that decide it. The contract is one-sided — a gate
// may only skip a pass that provably cannot match (extract_gate_test.go).

// ipv4TokenPrefix is exactly how config/regexp.txt writes an IPv4 group at the
// head of a pattern (docs/REGEX.md). A source starting with it cannot match a
// text without a dotted quad in it. A gate derived from anything *less* than
// this position — the group occurring somewhere inside the pattern — would not
// be sound: the group may sit in an alternation branch or a min-0 group.
const ipv4TokenPrefix = `([0-9]{1,3}(?:\.[0-9]{1,3}){3})`

// startsWithIPv4Group reports whether src opens with the canonical IPv4 group.
func startsWithIPv4Group(src string) bool {
	return strings.HasPrefix(src, ipv4TokenPrefix)
}

// skips reports whether pattern i provably cannot match a body without a
// dotted quad. Split out of extract so the one invariant that matters is
// testable: a gate may only ever skip a pass that would have found nothing
// (TestExtractGatesNeverDropMatches runs the pattern anyway and asserts it
// comes back empty).
//
// ipv4 is the body's hasIPv4Token result, computed once per body.
func (e *Extractor) skips(i int, ipv4 bool) bool {
	if ipv4 || i < 0 || i >= len(e.startsIPv4) {
		return false
	}
	return e.startsIPv4[i]
}

// hasIPv4Token reports whether s contains a dotted quad (four 1–3 digit
// groups). It is the fast half of the gate: one linear byte scan instead of
// reBareV4's pass. Every offset is tried and each group is taken greedily,
// which is complete — a shorter digit run would leave a digit where the
// pattern expects the dot, so it cannot match either. False positives are
// harmless (the regex then finds nothing); false negatives are impossible.
func hasIPv4Token(s string) bool {
	for i := 0; i+7 <= len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			continue
		}
		j := i
		for group := 0; group < 4; group++ {
			start := j
			for j < len(s) && j-start < 3 && s[j] >= '0' && s[j] <= '9' {
				j++
			}
			if j == start {
				break
			}
			if group == 3 {
				return true
			}
			if j >= len(s) || s[j] != '.' {
				break
			}
			j++
		}
	}
	return false
}

func asciiLowerByte(c byte) byte {
	if c >= 'A' && c <= 'Z' {
		return c + 32
	}
	return c
}

func asciiUpperByte(c byte) byte {
	if c >= 'a' && c <= 'z' {
		return c - 32
	}
	return c
}

// containsFoldASCII is bytes.Contains with ASCII case folding, for the share
// links whose patterns carry (?i): a plain Contains would skip a page
// published as TROJAN:// — a dropped candidate, which is the one failure mode
// a gate is not allowed to have.
func containsFoldASCII(s, pat string) bool {
	m, n := len(pat), len(s)
	if m == 0 {
		return true
	}
	if m > n {
		return false
	}
	first, firstUp := pat[0], asciiUpperByte(pat[0])
	for i := 0; i+m <= n; i++ {
		if c := s[i]; c != first && c != firstUp {
			continue
		}
		j := 1
		for ; j < m; j++ {
			c := s[i+j]
			if c != pat[j] && c != asciiLowerByte(pat[j]) && c != asciiUpperByte(pat[j]) {
				break
			}
		}
		if j == m {
			return true
		}
	}
	return false
}
