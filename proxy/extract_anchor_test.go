package proxy

import (
	"os"
	"path/filepath"
	"regexp"
	"regexp/syntax"
	"strings"
	"testing"
	"time"
)

// The site-pattern loop may take the anchored fast path only if it is
// indistinguishable from the legacy full-body FindAll: same matches, same
// spans, same order. These bodies cover the IP-leading shapes, boundary
// corners a window slice alone could get wrong, and the dense-digit page
// where the sparsity fallback switches to the legacy pass.
func TestSiteAnchoredPathMatchesFindAll(t *testing.T) {
	e := liveExtractor(t)
	lines, err := LoadRegexLines("../config/regexp.txt")
	if err != nil {
		t.Fatal(err)
	}
	if len(lines) != len(e.passes) {
		t.Fatalf("pattern count drift: %d lines vs %d compiled", len(lines), len(e.passes))
	}

	raw, err := os.ReadFile(filepath.Join("testdata", "proxynova.html"))
	if err != nil {
		t.Fatal(err)
	}
	// dense: a quad at almost every offset exercises the cursor-overlap rule
	// and the sparsity fallback; shifted: a match a shorter quad would occupy;
	// wordy/underscore: a word byte before the quad that a window slice
	// cannot see — the universal pass's \b must still drop those probes.
	var dense strings.Builder
	for i := 0; i < 400; i++ {
		dense.WriteString("1.2.3.4:8080")
	}
	bodies := map[string]string{
		"real page":  string(raw),
		"junk html":  "<html><head><style>.a{color:red}</style><script>var x=42;</script><body>Nothing here</body></html>",
		"bare list":  "1.2.3.4:8080\n5.6.7.8:3128\n10.0.0.1:1080\n",
		"table":      "<html><table><tr><td>1.2.3.4</td><td>8080</td></tr></table></html>",
		"spys":       "1.2.3.4<script>document.write(\"80\"+(a^b)+(c^d))</script><script>var a=1;var b=2;var c=3;var d=4;</script>",
		"share link": "vless://01234567-89ab-cdef-0123-456789abcdef@1.2.3.4:8443?security=tls\n",
		"nbsp cell":  "1.2.3.4&nbsp;&nbsp;8080 tail",
		"em cell":    "1.2.3.4<em>8080</em> tail",
		"port after": "1.2.3.4 ... port: 8080 tail",
		"sep dash":   "1.2.3.4 - 8080 tail",
		"shifted":    "1.2.3.45:8080 tail",
		"wordy":      "a1.2.3.4:8080 tail",
		"underscore": "_1.2.3.4:8080 tail",
		"edge start": "1.2.3.4:8080",
		"edge end":   "tail 1.2.3.4:8080",
		"csv":        "1.2.3.4,8080,US,anonymous\n5.6.7.8,3128,GB,elite\n",
		"dense":      dense.String(),
	}

	for name, body := range bodies {
		text := decodeJSWrites(body)
		tokens := appendIPv4Tokens(nil, text)

		// Every pattern extract() would anchor: legacy vs anchored. A nil
		// hint means legacy on the anchored side too — trivially equal, and
		// the hint consistency pin below guards which patterns may get one.
		for i := range e.passes {
			p := &e.passes[i]
			if p.hint == nil && p.startsIPv4 {
				t.Errorf("%s: pattern %d opens with the quad but its tail reads unbounded: %s", name, i, lines[i])
			}
			want := p.re.FindAllStringSubmatchIndex(text, -1)
			got := findAtQuadTokens(p.re, text, tokens, p.hint)
			if !sameSpans(want, got) {
				t.Errorf("%s: pattern %d anchored path diverges\nwant %v\ngot  %v\nsrc %s",
					name, i, want, got, lines[i])
			}
		}

		// The universal bare pass, legacy vs anchored (hint carries the \b
		// emulation for the window slice).
		want := reBareV4.FindAllStringSubmatchIndex(text, -1)
		got := findAtQuadTokens(reBareV4, text, tokens, reBareV4Hint)
		if !sameSpans(want, got) {
			t.Errorf("%s: reBareV4 anchored path diverges\nwant %v\ngot  %v", name, want, got)
		}
	}
}

// sameSpans compares FindAll results (or nil) element-wise.
func sameSpans(want, got [][]int) bool {
	if len(want) != len(got) {
		return false
	}
	for i := range want {
		if len(want[i]) != len(got[i]) {
			return false
		}
		for j := range want[i] {
			if want[i][j] != got[i][j] {
				return false
			}
		}
	}
	return true
}

// The anchored fast path exists only for leading quads; a quad in the middle
// of a pattern gets no hint because the equivalence with FindAll cannot be
// proven for variable-length heads (extract_anchor.go). This pins which
// shipped pattern shapes may end up anchored: literal-\b or bare heads only.
func TestQuadHintsLeadOnly(t *testing.T) {
	lines, err := LoadRegexLines("../config/regexp.txt")
	if err != nil {
		t.Fatal(err)
	}

	anchored := 0
	for i, line := range lines {
		starts := startsWithIPv4Group(line)
		// Synthetic keystones must not leak: since lines[i] opens with the
		// group when starts is set, buildQuadHint may only succeed for those
		// same lines (the parse is derived from the same source).
		hint := buildQuadHint(line)
		if hint == nil && starts {
			t.Errorf("pattern %d opens with the quad but got no probe plan: %s", i, line)
		}
		if hint != nil {
			if !starts {
				t.Errorf("pattern %d got a probe plan but does not open with the quad: %s", i, line)
			}
			anchored++
		}
	}
	if anchored == 0 {
		t.Error("no shipped pattern is anchored; the fast path has no audience")
	}

	// The universal bare pass anchors through the canonical-quad substitute;
	// the equivalence test above runs the real reBareV4 through it.
	if reBareV4Hint == nil {
		t.Fatal("reBareV4Hint missing: the bare pass would never anchor")
	}
	if len(reBareV4Hint.tail) != 4 { // quad, ":", port, \b
		t.Errorf("reBareV4Hint tail plan out of shape: %v", reBareV4Hint.tail)
	}

	// Mid-quad and non-canonical-quad shapes must stay hint-free.
	for name, src := range map[string]string{
		"bare cred":   reBareCredV4.String(),
		"scheme cred": reSchemeCredV4.String(),
		"spys write":  reSpysWrite.String(),
		"quad at end": "port: 8080 ip " + ipv4TokenPrefix,
		"anchor head": `\A` + ipv4TokenPrefix + `:80`,
	} {
		if h := buildQuadHint(src); h != nil {
			t.Errorf("%s: buildQuadHint must refuse to anchor a mid-pattern quad, got %v for %s", name, h, src)
		}
	}
}

// TestNeedsIPv4GateCoversShippedPatterns: every shipped pattern except the
// IPv6 table one embeds the canonical quad, so on a quad-less page the gate
// must skip them all (that is where the 165 ms junk-page number went), and a
// pattern without the group must never be marked as requiring it.
func TestNeedsIPv4GateCoversShippedPatterns(t *testing.T) {
	e := liveExtractor(t)
	lines, err := LoadRegexLines("../config/regexp.txt")
	if err != nil {
		t.Fatal(err)
	}
	if len(lines) != len(e.passes) {
		t.Fatalf("pattern count drift: %d lines vs %d compiled", len(lines), len(e.passes))
	}
	ungated := 0
	var stragglers []string
	for i, line := range lines {
		has := strings.Contains(line, ipv4TokenPrefix)
		if e.passes[i].needsIPv4 && !has {
			t.Errorf("pattern %d marked needsIPv4 but has no canonical group: %s", i, line)
		}
		if !e.passes[i].needsIPv4 && has {
			t.Errorf("pattern %d has the canonical group but was left ungated: %s", i, line)
		}
		if !e.passes[i].needsIPv4 {
			ungated++
			stragglers = append(stragglers, line)
		}
	}
	// Exactly one straggler, and it is the IPv6 table shape.
	if ungated != 1 || !strings.Contains(stragglers[0], `[0-9a-fA-F:]`) {
		t.Fatalf("expected exactly the IPv6 table pattern to stay ungated, got %d: %q", ungated, stragglers)
	}
}

// The structural analysis on hand shapes: required, optional, alternation
// branches and repeat bounds each have to land exactly.
func TestPatternRequiresIPv4Shapes(t *testing.T) {
	quad := ipv4TokenPrefix
	cases := []struct {
		name string
		src  string
		want bool
	}{
		{"plain concat", quad + "foo", true},
		{"nested non-cap", "(?:" + quad + ")", true},
		{"double non-cap", "(?:(?:" + quad + "))", true},
		{"optional group", "(?:" + quad + ")?", false},
		{"star", "(?:" + quad + ")*", false},
		{"plus", "(?:" + quad + ")+", true},
		{"repeat min0", "(?:" + quad + "){0,2}", false},
		{"repeat min1", "(?:" + quad + "){1,2}", true},
		{"alternate all require", quad + "|" + quad + "[a-z]", true},
		{"alternate one escape", "{" + quad + "|abc}", false},
		{"literal only", "abc", false},
		{"quad at tail", "rgb" + quad, true},
	}
	for _, tc := range cases {
		if got := patternRequiresIPv4(tc.src); got != tc.want {
			t.Errorf("%s: patternRequiresIPv4(%s) = %v, want %v", tc.name, tc.src, got, tc.want)
		}
	}
}

// (?i) folds rune for rune through Unicode.SimpleFold, and a fold variant can
// be longer than the source rune: 'k' matches KELVIN SIGN (3 bytes for 1),
// 's' matches LONG S (2 for 1). maxLenOf must budget the 4-byte UTF-8 maximum
// per rune, or the anchored window can end before a match FindAll still finds.
// Before the fix the anchored side returned no match for the Kelvin body.
func TestAnchoredWindowCoversFoldedLiterals(t *testing.T) {
	src := ipv4TokenPrefix + `:` + strings.Repeat(`(?i)k`, 20)
	re := regexp.MustCompile(src)
	h := buildQuadHint(src)
	if h == nil {
		t.Fatal("a folded literal is a bounded tail; the hint must exist")
	}
	body := "1.2.3.4:" + strings.Repeat("\u212A", 20)
	want := re.FindAllStringSubmatchIndex(body, -1)
	if len(want) != 1 {
		t.Fatalf("fixture must match once under the legacy pass, got %v", want)
	}
	got := findAtQuadTokens(re, body, appendIPv4Tokens(nil, body), h)
	if !sameSpans(want, got) {
		t.Errorf("folded literal escaped the probe window: want %v got %v", want, got)
	}

	lit, err := syntax.Parse(`(?i)kk`, syntax.Perl)
	if err != nil {
		t.Fatal(err)
	}
	if n := maxLenOf(lit); n != 8 {
		t.Errorf("maxLenOf((?i)kk) = %d, want 8 (4 bytes per rune under FoldCase)", n)
	}
}

// maxPlanLength caps the window a plan may produce, and the cap is on the
// plan's total, not on each repeat. RE2 limits a single repeat to 1000, so a
// source of many individually-legal steps used to build a window of megabytes
// per quad token — slower than the single legacy pass it replaces. Such a
// pattern must keep the legacy pass, and every accepted plan must stay inside
// the documented bound.
func TestAnchoredPlanTotalIsBounded(t *testing.T) {
	src := ipv4TokenPrefix + strings.Repeat(`[0-9]{0,1000}`, 300)
	if h := buildQuadHint(src); h != nil {
		total := 0
		for _, s := range h.tail {
			total += s.advance
		}
		t.Fatalf("plan total %d bytes exceeds maxPlanLength=%d and was not refused", total, maxPlanLength)
	}

	// Shape a shipped pattern has: quad, ":", a bounded port, a word guard.
	h := buildQuadHint(ipv4TokenPrefix + `:[0-9]{1,5}\b`)
	if h == nil {
		t.Fatal("a short bounded tail must still anchor")
	}
	total := 0
	for _, s := range h.tail {
		total += s.advance
	}
	if total > maxPlanLength {
		t.Errorf("accepted plan total %d exceeds maxPlanLength=%d", total, maxPlanLength)
	}
	// The port step is budgeted generously: maxLenOf prices a char class at
	// four UTF-8 bytes per rune, so [0-9]{1,5} contributes 20. The window only
	// has to be big, not tight.
	if want := ipv4QuadMaxLen + 1 + 5*4; total != want {
		t.Errorf("plan total = %d, want %d", total, want)
	}
}

// FuzzAnchoredMatchesFindAll throws arbitrary bodies at the anchor: the
// equivalence with FindAll must hold for every input, not only the named
// fixtures. `go test ./proxy/ -run '^$' -fuzz FuzzAnchoredMatchesFindAll`
// runs the mutation; the seeds execute in the normal suite.
func FuzzAnchoredMatchesFindAll(f *testing.F) {
	lines, err := LoadRegexLines("../config/regexp.txt")
	if err != nil {
		f.Fatal(err)
	}
	e, err := NewExtractor(lines)
	if err != nil {
		f.Fatal(err)
	}
	for _, seed := range []string{
		"1.2.3.4:8080\n",
		"1.2.3.4,8080,US,anonymous\n5.6.7.8,3128,GB,elite\n",
		"1.2.3.4&nbsp;&nbsp;8080 tail",
		"a1.2.3.4:8080 tail",
		"1.2.3.45:8080",
		"vle\u017Fs://x@1.2.3.4:443",
		"1.2.3.4:" + strings.Repeat("\u212A", 4),
		"1.2.3.4:80$ tail",
	} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, body string) {
		if len(body) > 1<<16 {
			t.Skip("bodies are page-sized; the anchor is position-agnostic")
		}
		tokens := appendIPv4Tokens(nil, body)
		if (len(tokens) > 0) != hasIPv4Token(body) {
			t.Fatalf("token scan and hasIPv4Token disagree on %q", body)
		}
		want := reBareV4.FindAllStringSubmatchIndex(body, -1)
		if got := findAtQuadTokens(reBareV4, body, tokens, reBareV4Hint); !sameSpans(want, got) {
			t.Fatalf("reBareV4 anchored diverges on %q: want %v got %v", body, want, got)
		}
		for i := range e.passes {
			p := &e.passes[i]
			if p.hint == nil {
				continue
			}
			want := p.re.FindAllStringSubmatchIndex(body, -1)
			if got := findAtQuadTokens(p.re, body, tokens, p.hint); !sameSpans(want, got) {
				t.Fatalf("pattern %d anchored diverges on %q: want %v got %v\nsrc %s",
					i, body, want, got, p.re)
			}
		}
	})
}

// A class-run tail (`[^>]*`) walks to the end of the body, so on a page that
// is sparse in quads but has no '>' past them every token gets the whole rest
// of the body as its window: T*N engine scans instead of the single N scan the
// legacy pass costs. That is what froze a production collector for ~10 h
// (problems.md). The anchored path must cap its total window at one body and
// hand the pattern to the legacy pass, returning the same matches.
func TestFindAtQuadTokensBoundsTotalWindow(t *testing.T) {
	const (
		quad = "1.2.3.4"
		gap  = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" // 80, no '>'
		reps = 12000                                                                              // ~1 MB, one token per 87 bytes: sparse enough to keep the list
	)
	var b strings.Builder
	b.Grow(reps * (len(quad) + len(gap)))
	for i := 0; i < reps; i++ {
		b.WriteString(quad)
		b.WriteString(gap)
	}
	b.WriteString(quad + "<td>8080") // a real match, past the whole body
	text := b.String()

	tokens := appendIPv4Tokens(nil, text)
	if len(tokens) == 0 || int64(len(tokens)) > int64(len(text))/ipTokenSparsity {
		t.Fatalf("fixture must keep its tokens: %d tokens over %d bytes", len(tokens), len(text))
	}

	const src = `([0-9]{1,3}(?:\.[0-9]{1,3}){3})<[^>]*>([0-9]{1,5})`
	h := buildQuadHint(src)
	if h == nil {
		t.Fatal("fixture pattern must build a probe hint")
	}
	re := regexp.MustCompile(src)

	want := re.FindAllStringSubmatchIndex(text, -1)
	if len(want) == 0 {
		t.Fatal("fixture must contain at least one real match")
	}

	start := time.Now()
	got := findAtQuadTokens(re, text, tokens, h)
	if d := time.Since(start); d > 5*time.Second {
		t.Fatalf("anchored probe took %v: the window budget is not bounding the work", d)
	}
	if !sameSpans(want, got) {
		t.Fatalf("budget fallback lost matches: want %v got %v", want, got)
	}
}
