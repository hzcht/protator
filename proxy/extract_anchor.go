package proxy

import (
	"regexp"
	"regexp/syntax"
)

// The anchored fast path for the passes whose match *starts* on an IPv4 quad:
// the site patterns whose source opens with the canonical group and the
// universal bare pass. Every match they can produce starts on a dotted quad,
// so the engine's byte-by-byte hunt over the whole body can be replaced by
// probes at the quad offsets, collected once per body.
//
// Completeness is one argument, made piece by piece:
//
//   - one scan per body (appendIPv4Tokens) finds a superset of the match
//     starts. Each group of a regex quad ends right before a dot, i.e. on the
//     full digit run between the dots, and that run is what the greedy token
//     scan takes; so wherever a pattern matches, the scan has a token.
//   - probing is guarded by the same leftmost scan policy as FindAll: a token
//     inside the span of an already-accepted match is skipped (the cursor in
//     findAtQuadTokens). No match can start at or before the previous match's
//     end by FindAll's own construction, so skipping those tokens drops only
//     matches FindAll would have suppressed — never one it emits.
//   - the probe window per token walks a tail plan derived from the pattern's
//     own parse: every tail child advances the walk by the child's *maximum*
//     match length, and an unbounded single-class repeat (`\s*`, `[^>]*`) by
//     the first byte outside that class — the engine's own shorter runs and
//     backtracking cannot consume past that byte. By induction the walk stays
//     at or past the engine's position, so the pattern is too short to escape
//     its window.
//
// Only *leading* quads are anchored. A quad that sits mid-pattern (the
// credential shapes) would need a backward window over a variable-length
// head, and head lengths differ per real match: two overlapping matches can
// then carry different quads and win the leftmost race in different orders.
// That cannot be shown equivalent to FindAll, so those passes keep the legacy
// full-body run (problems.md §21, "deliberately not done"). The zero-width
// keystones allowed in front of the quad are likewise restricted to `\b`,
// whose slice-relative meaning is reproduced exactly by a one-byte precheck;
// `\A`, `^`, `$` read the whole-string position and a window slice would lie
// about them, so a hint with such a keystone is not built at all.
//
// A tail that cannot be bounded (a star over anything but one class, a repeat
// with absurd bounds) yields no hint and keeps the legacy pass — the fast
// path is an optimization, not a contract.

// ipv4QuadMaxLen is the longest text the canonical quad can consume
// ("999.999.999.999"); octet-class quads are shorter, so a plan built from
// the canonical quad is a valid (looser) bound for any of them.
const ipv4QuadMaxLen = 15

// ipTokenSparsity bounds when the anchored path pays off. A page that is
// mostly digits yields a token at nearly every offset, and one bounded probe
// per token costs more than a single linear pass. Above one token per ~64
// bytes the token list is thrown away and every anchored-capable pass runs
// the plain full-body match.
const ipTokenSparsity = 64

// probeWindowSlack pads every window end: the window edge, a trailing \b,
// whatever the plan's constant-point arithmetic might round down.
const probeWindowSlack = 16

// maxPlanLength caps the total window a plan may produce before the pattern
// is declared unbounded in practice: a probe that scans megabytes per token
// is not an optimization, it is the legacy pass with extra steps.
const maxPlanLength = 1 << 20

// tailStep is one plan step: a fixed maximum advance, or an unbounded
// char-class run the walk must scan for.
type tailStep struct {
	stretch bool
	advance int
	mask    [4]uint64
}

// probeHint is the parse-derived plan for one anchored pass: how to emulate
// the keystones in front of the quad (wordGuard) and how far past it the
// engine's consumption can reach (tail).
type probeHint struct {
	// wordGuard is true when the pattern opens with \b. A window slice
	// starts at the token and cannot see the preceding byte, so the probe
	// re-checks it by hand: a word byte there makes the real \b fail.
	wordGuard bool
	// tail walks the fixed/class-run steps after the quad. Its first step is
	// the quad itself.
	tail []tailStep
}

// appendIPv4Tokens collects the offsets where a greedy dotted-quad scan
// succeeds. It walks the same byte loop as hasIPv4Token — one loop collecting
// starts instead of returning early — so a quad a pattern could start on is
// never missing from the list; the anchor equivalence test runs the pair over
// every fixture body and additionally asserts bool == (tokens non-empty).
func appendIPv4Tokens(dst []int, s string) []int {
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
				dst = append(dst, i)
				break
			}
			if j >= len(s) || s[j] != '.' {
				break
			}
			j++
		}
	}
	return dst
}

// canonicalIPv4 renders what the canonical group parses to.
func canonicalIPv4() *syntax.Regexp {
	canon, _ := syntax.Parse(ipv4TokenPrefix, syntax.Perl)
	return canon.Sub[0]
}

// isCanonicalIPv4 is the structural equality the hint builder uses: the node
// is a capture group whose rendering equals the canonical group's own
// subtree rendering. Structurally equal sources render equal.
func isCanonicalIPv4(re *syntax.Regexp, canon *syntax.Regexp) bool {
	return re.Op == syntax.OpCapture && re.Sub[0].String() == canon.String()
}

// buildQuadHint turns a pattern that *opens* on the canonical IPv4 group
// (optionally after \b keystones) into its per-token probe plan. nil means
// the shape is not a leading quad, or its tail cannot be bounded, and the
// pattern stays on the legacy full-body pass.
func buildQuadHint(src string) *probeHint {
	tree, err := syntax.Parse(src, syntax.Perl)
	if err != nil {
		return nil
	}
	if tree.Op != syntax.OpConcat {
		return nil
	}
	// Zero-width keystones first: the universal pass opens with \b before
	// the quad; site patterns start on the group itself. Any other
	// zero-width kind (\A, ^, $) reads the whole-string position, which a
	// window slice cannot reproduce, so the hint is refused.
	guard := false
	i := 0
	for i < len(tree.Sub) && maxLenOf(tree.Sub[i]) == 0 {
		switch tree.Sub[i].Op {
		case syntax.OpWordBoundary:
			guard = true
		case syntax.OpEmptyMatch:
			// Empty alternation branches; harmless either way.
		default:
			return nil
		}
		i++
	}
	if i >= len(tree.Sub) || !isCanonicalIPv4(tree.Sub[i], canonicalIPv4()) {
		return nil
	}
	tail := tailPlanOf(tree.Sub[i+1:])
	if tail == nil {
		return nil
	}
	return &probeHint{wordGuard: guard, tail: tail}
}

// tailPlanOf turns the children after the quad into walk steps. The quad's
// own step comes first (its canonical maximum). nil means the tail cannot be
// bounded: a star over anything but one class, or a plan whose walk grows past
// maxPlanLength — such patterns keep the legacy pass.
//
// The cap is on the plan's *total*, not on each repeat. A per-repeat cap alone
// let a source of many large-but-individually-legal steps build a window of
// megabytes per token (measured: 300 × {0,1000} gave 1.2 MB), which is slower
// than the single legacy pass it replaces.
//
// Position assertions in the tail (^, $, \b, \B) need no special case. The
// tail starts after the quad, which is never empty, so ^ and \A cannot match
// at the slice's offset 0 any more than at the real offset t > 0. The window
// end sits at least probeWindowSlack past the longest match the plan allows,
// so $ and \z can only fire where the real text continues (or at the real
// text end, when the window is clipped there), and \b/\B read the same
// neighbouring bytes. Only *head* keystones can see a wrong position — the
// slice starts at the token — which is why buildQuadHint refuses everything
// but \b there and emulates that one with wordGuard.
func tailPlanOf(subs []*syntax.Regexp) []tailStep {
	plan := []tailStep{{advance: ipv4QuadMaxLen}} // the quad itself
	total := ipv4QuadMaxLen
	for _, sub := range subs {
		var mask [4]uint64
		if isClassRun(sub, &mask) {
			plan = append(plan, tailStep{stretch: true, mask: mask})
			continue
		}
		n := maxLenOf(sub)
		if n < 0 {
			return nil
		}
		total += n
		if total > maxPlanLength {
			return nil // the plan is not actually bounded in any useful sense
		}
		plan = append(plan, tailStep{advance: n})
	}
	return plan
}

// isClassRun reports whether node is an unbounded repeat over exactly one
// char class — `\s*`, `[^>]*`, `[^0-9]+` — and fills mask with the class's
// bytes. Bounded repeats ({0,40}) are not runs: maxLenOf bounds them exactly.
func isClassRun(re *syntax.Regexp, mask *[4]uint64) bool {
	switch re.Op {
	case syntax.OpStar, syntax.OpPlus:
	case syntax.OpRepeat:
		if re.Max >= 0 {
			return false
		}
	default:
		return false
	}
	sub := re.Sub[0]
	if sub.Op != syntax.OpCharClass {
		return false
	}
	*mask = classBytes(sub)
	return true
}

// classBytes flattens a parsed char class into a 256-bit byte membership set.
// Ranges up to 0x7F are marked byte-exact; a range reaching 0x80 or beyond
// marks every high byte, because a UTF-8 rune in it must consume some byte of
// 0x80..0xFF wherever the scan can rest (the walk bounds, it is not tight).
func classBytes(re *syntax.Regexp) [4]uint64 {
	var m [4]uint64
	if re.Op != syntax.OpCharClass {
		return m
	}
	for i := 0; i+1 < len(re.Rune); i += 2 {
		lo, hi := re.Rune[i], re.Rune[i+1]
		if hi < 0 {
			continue
		}
		if lo < 0 {
			lo = 0
		}
		for b := lo; b <= hi && b < 0x80; b++ {
			m[b>>6] |= 1 << (b & 63)
		}
		if hi >= 0x80 {
			for b := 0x80; b < 0x100; b++ {
				m[b>>6] |= 1 << (b & 63)
			}
		}
	}
	return m
}

// maxLenOf upper-bounds the byte length a parsed node can match, or -1 when
// unbounded. Char classes and dots report 4 (one rune, up to four UTF-8
// bytes) even though these bodies are ASCII — the window only has to be big,
// not tight.
func maxLenOf(re *syntax.Regexp) int {
	switch re.Op {
	case syntax.OpLiteral:
		if re.Flags&syntax.FoldCase != 0 {
			// (?i) folds rune for rune through Unicode.SimpleFold, and a
			// fold variant can be longer than the source rune: 'k' matches
			// KELVIN SIGN (3 bytes), 's' matches LONG S (2). Budget the
			// 4-byte UTF-8 maximum per rune, or a window derived from the
			// source bytes can end inside a match the engine still makes
			// (TestAnchoredWindowCoversFoldedLiterals).
			return 4 * len(re.Rune)
		}
		return len(string(re.Rune))
	case syntax.OpCharClass, syntax.OpAnyChar, syntax.OpAnyCharNotNL:
		return 4
	case syntax.OpCapture:
		return maxLenOf(re.Sub[0])
	case syntax.OpConcat:
		total := 0
		for _, sub := range re.Sub {
			n := maxLenOf(sub)
			if n < 0 {
				return -1
			}
			total += n
		}
		return total
	case syntax.OpAlternate:
		best := 0
		for _, sub := range re.Sub {
			n := maxLenOf(sub)
			if n < 0 {
				return -1
			}
			if n > best {
				best = n
			}
		}
		return best
	case syntax.OpEmptyMatch, syntax.OpNoMatch, syntax.OpBeginLine, syntax.OpEndLine,
		syntax.OpBeginText, syntax.OpEndText, syntax.OpWordBoundary, syntax.OpNoWordBoundary:
		return 0
	case syntax.OpQuest:
		return maxLenOf(re.Sub[0])
	case syntax.OpRepeat:
		if re.Max < 0 {
			return -1
		}
		n := maxLenOf(re.Sub[0])
		if n < 0 {
			return -1
		}
		if n > 0 && re.Max > maxPlanLength/n {
			return -1
		}
		return n * re.Max
	}
	// Star, plus, anything unaccounted: unbounded, stay on the legacy pass.
	return -1
}

// findAtQuadTokens runs re anchored at each token offset — for a leading-quad
// hint the quad is the pattern's own start, so a match may only start at the
// token — over a window its tail plan cannot escape. The cursor mirrors
// FindAll's leftmost scan policy: matches may not start inside the span of a
// previous match, and FindAll's next search begins at the previous match's
// end, which is exactly the tokens this loop skips. A nil hint or a nil token
// list runs re the legacy way over the whole text, so callers may branch on
// the hint alone.
func findAtQuadTokens(re *regexp.Regexp, text string, tokens []int, h *probeHint) [][]int {
	if h == nil || len(tokens) == 0 {
		return re.FindAllStringSubmatchIndex(text, -1)
	}
	// The anchored path is an optimization only while its windows stay cheap
	// in total: legacy scans the body once, this loop once per token. A
	// class-run tail (`[^>]*`) walks to the end of the body, so a page that is
	// sparse in quads but long past them gets the whole body as every token's
	// window — T*N engine scans instead of N. Measured: one 8 MB page ran one
	// Extract for ~10 h, pegged a core and froze the collector in wg.Wait.
	// The budget is the break-even the sparsity rule already assumes (T <=
	// N/64, so a window under 64 bytes pays for itself): spend at most one
	// body's worth of window, then hand the pattern to the legacy pass, which
	// runs the same engine under the same leftmost policy over the same text.
	budget := len(text)
	var out [][]int
	cursor := 0
	for _, t := range tokens {
		if t < cursor {
			continue
		}
		if h.wordGuard && t > 0 && isWordByte(text[t-1]) {
			continue // the real \b fails here; the slice cannot see text[t-1]
		}
		end := probeEnd(text, t, h.tail)
		if end-t > budget {
			return re.FindAllStringSubmatchIndex(text, -1)
		}
		budget -= end - t
		m := re.FindStringSubmatchIndex(text[t:end])
		if len(m) < 2 || m[0] != 0 {
			continue
		}
		for k := range m {
			m[k] += t
		}
		cursor = m[1]
		out = append(out, m)
	}
	return out
}

// probeEnd walks the plan from the token offset and returns the window end:
// at or past any byte this pattern could have matched by then.
func probeEnd(text string, t int, plan []tailStep) int {
	q := t
	for _, step := range plan {
		if step.stretch {
			for q < len(text) && step.mask[text[q]>>6]&(1<<(text[q]&63)) != 0 {
				q++
			}
			continue
		}
		q += step.advance
	}
	e := q + probeWindowSlack
	if e > len(text) {
		e = len(text)
	}
	return e
}

// isWordByte is Go regexp's ASCII \w set — the audience a leading \b actually
// checks against.
func isWordByte(c byte) bool {
	return c == '_' ||
		(c >= '0' && c <= '9') ||
		(c >= 'a' && c <= 'z') ||
		(c >= 'A' && c <= 'Z')
}

// reBareV4ProbeSrc substitutes the canonical quad for the bare pass's own
// octet-class quad: the canonical quad is longer (15 vs 13 bytes), so the
// plan's window stays a sound bound. The tail (":port\b") is the real one.
// The equivalence test runs reBareV4 itself through findAtQuadTokens with
// this hint over every fixture body, so a constant drifting from the real
// tail fails a test instead of losing a match.
const reBareV4ProbeSrc = `\b` + ipv4TokenPrefix + `:([0-9]{1,5})\b`

// reBareV4Hint is the leading-quad plan for the universal bare pass.
var reBareV4Hint = buildQuadHint(reBareV4ProbeSrc)
