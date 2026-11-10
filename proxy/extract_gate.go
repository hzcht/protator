package proxy

import (
	"regexp/syntax"
	"strings"
)

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

// patternRequiresIPv4 reports whether *every* match of src must consume a
// dotted quad produced by the canonical group. Compare against the canonical
// subtree by its canonical rendering; structurally equal sources render equal.
func patternRequiresIPv4(src string) bool {
	tree, err := syntax.Parse(src, syntax.Perl)
	if err != nil {
		return false
	}
	return requiresIPv4Sub(tree, canonicalIPv4())
}

// requiresIPv4Sub checks one parsed node against the canonical IPv4 subtree:
// a node requires the quad when it cannot match without that subtree turning
// up somewhere in the consumption.
func requiresIPv4Sub(re *syntax.Regexp, canon *syntax.Regexp) bool {
	if isCanonicalIPv4(re, canon) {
		return true
	}
	switch re.Op {
	case syntax.OpCapture:
		return requiresIPv4Sub(re.Sub[0], canon)
	case syntax.OpConcat:
		for _, sub := range re.Sub {
			if requiresIPv4Sub(sub, canon) {
				return true
			}
		}
		return false
	case syntax.OpAlternate:
		for _, sub := range re.Sub {
			if !requiresIPv4Sub(sub, canon) {
				return false
			}
		}
		return len(re.Sub) > 0
	case syntax.OpStar, syntax.OpQuest:
		return false // the subtree may be skipped entirely
	case syntax.OpPlus:
		return requiresIPv4Sub(re.Sub[0], canon)
	case syntax.OpRepeat:
		// {0,n} is a star in disguise (syntax.Parse normalizes it); {1,n}+ keeps it.
		if re.Min >= 1 {
			return requiresIPv4Sub(re.Sub[0], canon)
		}
		return false
	case syntax.OpLiteral, syntax.OpCharClass, syntax.OpAnyCharNotNL, syntax.OpAnyChar,
		syntax.OpEmptyMatch, syntax.OpNoMatch, syntax.OpBeginLine, syntax.OpEndLine,
		syntax.OpBeginText, syntax.OpEndText, syntax.OpWordBoundary, syntax.OpNoWordBoundary:
		return false
	}
	return false
}

// skips reports whether pattern i provably cannot match a body without a
// dotted quad. Split out of extract so the one invariant that matters is
// testable: a gate may only ever skip a pass that would have found nothing
// (TestExtractGatesNeverDropMatches runs the pattern anyway and asserts it
// comes back empty).
//
// ipv4 is the body's hasIPv4Token result, computed once per body. The gate is
// structural — startsIPv4 proves the head, needsIPv4 proves a *required*
// group anywhere in the parse — both derived from the pattern's own source.
func (e *Extractor) skips(i int, ipv4 bool) bool {
	if ipv4 || i < 0 || i >= len(e.passes) {
		return false
	}
	p := &e.passes[i]
	return p.startsIPv4 || p.needsIPv4
}

// hasAtDigit reports whether any '@' in s is immediately followed by an
// ASCII digit. Both credentialed patterns put the quad directly after the
// '@' and the quad's first octet is always a digit, so this is a necessary
// condition for either to match — a page of email addresses never reaches
// the engine. One IndexByte walk; false positives are harmless.
func hasAtDigit(s string) bool {
	for i := 0; ; {
		j := strings.IndexByte(s[i:], '@')
		if j < 0 || i+j+1 >= len(s) {
			return false
		}
		i += j
		if c := s[i+1]; c >= '0' && c <= '9' {
			return true
		}
		i++
	}
}

// hasAnySchemeToken reports whether s contains "http" or "socks" in any
// ASCII-case spelling — a necessary condition for the universal
// `(?:https?|socks…?)://` pass. As with every gate, a false true only runs
// the pass; a false false would drop candidates and is what the contract
// test pins against.
func hasAnySchemeToken(s string) bool {
	return containsFoldASCII(s, "http") || containsFoldASCII(s, "socks")
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

// asciiLowerByte/asciiUpperByte are the ASCII-only case map containsFoldASCII
// folds with. Deliberately not unicode.ToLower: the scheme grammar is ASCII,
// and a Unicode fold would accept bytes the regexes and the dialer do not.
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

// containsFoldASCII is bytes.Contains with ASCII case folding. URI schemes
// are ASCII by grammar, and their regexes use explicit [aA] byte classes for
// the same reason: Go's (?i) would also admit Unicode LONG S and KELVIN SIGN,
// which the dial/serialization pipeline does not recognize as scheme bytes.
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
