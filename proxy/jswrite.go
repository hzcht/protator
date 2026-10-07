package proxy

import (
	"encoding/base64"
	"regexp"
	"strconv"
	"strings"
)

// Anti-scraping sites (proxynova and friends) stop serving the address itself
// and hand the browser a small expression that reassembles it:
//
//	document.write("5.11229.951.149.129.255.15.11".substring(23-11, 36-11)
//	                   .concat("797".substring(0+0, 4-2)))
//	document.write("3.82.951.15".split("").reverse().join("").concat(atob("OQ==")))
//	document.write("45.15.10".repeat(1).substring(0).concat(".174".repeat(1).substring(0)))
//
// The pieces are always plain string literals wrapped in a fixed, tiny method
// set, so the whole expression can be evaluated here and rewritten to the text
// it writes. That puts the address back into the surrounding markup, where the
// ordinary table patterns (IP cell + port cell) already know how to find it.
//
// Anything the evaluator does not fully understand is left byte-for-byte
// untouched, so an unexpected obfuscation can never lose data a plain pattern
// would have caught.

// jsWriteCall finds a document.write( ... ) and returns the span of its
// argument expression.
func jsWriteCall(text string, at int) (start, end int, ok bool) {
	const head = "document.write("
	if !strings.HasPrefix(text[at:], head) {
		return 0, 0, false
	}
	i := at + len(head)
	depth := 1
	inStr := false
	for ; i < len(text); i++ {
		c := text[i]
		switch {
		case inStr:
			if c == '\\' {
				i++
			} else if c == '"' {
				inStr = false
			}
		case c == '"':
			inStr = true
		case c == '(':
			depth++
		case c == ')':
			depth--
			if depth == 0 {
				return at + len(head), i, true
			}
		}
	}
	return 0, 0, false
}

// decodeJSWrites rewrites every evaluable document.write(...) in the page to
// the string it writes. XOR-obfuscated port digits (spys.one) are skipped: they
// are decoded by extractSpys, which needs the surrounding script block.
func decodeJSWrites(text string) string {
	// Fast path: the overwhelming majority of pages have no document.write at
	// all, and rebuilding them just to return the same bytes would copy every
	// body in the pipeline.
	if !strings.Contains(text, "document.write(") {
		return text
	}
	var out strings.Builder
	out.Grow(len(text))
	i := 0
	for {
		j := strings.Index(text[i:], "document.write(")
		if j < 0 {
			out.WriteString(text[i:])
			return out.String()
		}
		at := i + j
		argStart, argEnd, ok := jsWriteCall(text, at)
		if !ok {
			out.WriteString(text[i : at+len("document.write(")])
			i = at + len("document.write(")
			continue
		}
		expr := text[argStart:argEnd]
		value, ok := evalJSConcat(expr)
		if !ok || strings.Contains(expr, "^") {
			out.WriteString(text[i : argEnd+1])
		} else {
			out.WriteString(text[i:at])
			out.WriteString(value)
		}
		i = argEnd + 1
	}
}

// evalJSConcat evaluates a chain of terms joined by .concat(...). Every term
// must be understood or the whole expression is rejected.
func evalJSConcat(expr string) (string, bool) {
	expr = strings.TrimSpace(expr)
	// proxynova sometimes wraps a full second expression in a document.write
	// of its own; unwrap and evaluate the inner one.
	if inner, ok := unwrapWrite(expr); ok {
		expr = strings.TrimSpace(inner)
	}
	terms := splitConcat(expr)
	if len(terms) == 0 {
		return "", false
	}
	var sb strings.Builder
	for _, term := range terms {
		v, ok := evalJSTerm(strings.TrimSpace(term))
		if !ok {
			return "", false
		}
		sb.WriteString(v)
	}
	return sb.String(), true
}

// unwrapWrite strips one document.write( ... ) layer from an expression.
func unwrapWrite(expr string) (string, bool) {
	const head = "document.write("
	if !strings.HasPrefix(expr, head) || !strings.HasSuffix(expr, ")") {
		return "", false
	}
	return expr[len(head) : len(expr)-1], true
}

// splitConcat splits an expression on its top-level .concat( ... ) terms.
// Each call's arguments are themselves split, so nested concatenations work.
// An expression without any .concat is a single term.
func splitConcat(expr string) []string {
	var out []string
	depth := 0
	inStr := false
	start := 0
	sawConcat := false
	for i := 0; i < len(expr); i++ {
		c := expr[i]
		switch {
		case inStr:
			if c == '\\' {
				i++
			} else if c == '"' {
				inStr = false
			}
		case c == '"':
			inStr = true
		case c == '(':
			depth++
		case c == ')':
			depth--
			if depth < 0 {
				return nil // unbalanced: not a term chain we understand
			}
		default:
			if depth != 0 || !strings.HasPrefix(expr[i:], ".concat(") {
				continue
			}
			open := i + len(".concat(") - 1
			closing := matchParen(expr, open)
			if closing < 0 {
				return nil
			}
			// A chained call ("A.concat(B).concat(C)") leaves the head of the
			// next .concat empty, because the previous iteration already
			// consumed everything before it.
			if head := expr[start:i]; strings.TrimSpace(head) != "" {
				out = append(out, head)
			} else if len(out) == 0 {
				return nil
			}
			out = append(out, splitConcat(expr[open+1:closing])...)
			sawConcat = true
			i = closing // the for-loop increment steps past this ')'
			start = i + 1
		}
	}
	if !sawConcat {
		if depth != 0 || inStr || strings.TrimSpace(expr) == "" {
			return nil
		}
		return []string{expr}
	}
	if rest := expr[start:]; strings.TrimSpace(rest) != "" {
		out = append(out, rest)
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

// evalJSTerm evaluates one term: a string literal with a method chain, an
// atob() call, a character-code array, or a nested document.write().
func evalJSTerm(term string) (string, bool) {
	term = strings.TrimSpace(term)
	switch {
	case strings.HasPrefix(term, "atob(") && strings.HasSuffix(term, ")"):
		return evalAtob(term[len("atob(") : len(term)-1])
	case strings.HasPrefix(term, "String.fromCharCode(") && strings.HasSuffix(term, ")"):
		return evalFromCharCode(term[len("String.fromCharCode(") : len(term)-1])
	case strings.HasPrefix(term, "["):
		return evalJSArrayTerm(term)
	}
	lit, rest, ok := jsStringLiteral(term)
	if !ok {
		return "", false
	}
	return applyJSMethods(jsStr(lit), rest)
}

// reCharMap is the arrow function proxynova uses to shift a code array:
//
//	(code) => String.fromCharCode(code-9)
var reCharMap = regexp.MustCompile(`^\(\s*[A-Za-z_$][A-Za-z0-9_$]*\s*\)\s*=>\s*String\.fromCharCode\(\s*[A-Za-z_$][A-Za-z0-9_$]*\s*(?:([+-])\s*([0-9]{1,6})\s*)?\)$`)

// evalJSArrayTerm evaluates [58,62,64].map((code) => String.fromCharCode(code-9))
// .join("") and any string methods chained after it.
func evalJSArrayTerm(term string) (string, bool) {
	term = strings.TrimSpace(term)
	open := strings.IndexByte(term, ']')
	if open < 0 {
		return "", false
	}
	codes, ok := parseIntArray(term[1:open])
	if !ok {
		return "", false
	}
	return applyJSMethods(jsVal{nums: codes, isNums: true}, term[open+1:])
}

// parseIntArray parses a flat [1,2,3] literal of small integers.
func parseIntArray(s string) ([]int, bool) {
	s = strings.TrimSpace(s)
	if s == "" {
		return nil, false
	}
	parts := strings.Split(s, ",")
	if len(parts) == 0 || len(parts) > 64 {
		return nil, false
	}
	out := make([]int, 0, len(parts))
	for _, p := range parts {
		n, ok := jsAtom(strings.TrimSpace(p))
		if !ok || n < 0 || n > 0x10FFFF {
			return nil, false
		}
		out = append(out, n)
	}
	return out, true
}

// evalFromCharCode evaluates the argument list of String.fromCharCode(...).
func evalFromCharCode(args string) (string, bool) {
	codes, ok := parseIntArray(args)
	if !ok {
		return "", false
	}
	var sb strings.Builder
	for _, c := range codes {
		if c < 0x20 || c > 0x7e {
			return "", false
		}
		sb.WriteRune(rune(c))
	}
	return sb.String(), true
}

// jsStringLiteral consumes a leading double-quoted literal.
func jsStringLiteral(term string) (val, rest string, ok bool) {
	term = strings.TrimLeft(term, " \t\n")
	if !strings.HasPrefix(term, `"`) {
		return "", "", false
	}
	var sb strings.Builder
	for i := 1; i < len(term); i++ {
		c := term[i]
		if c == '\\' && i+1 < len(term) {
			i++
			sb.WriteByte(term[i])
			continue
		}
		if c == '"' {
			return sb.String(), term[i+1:], true
		}
		sb.WriteByte(c)
	}
	return "", "", false
}

// jsVal is one of: a plain string (the common case), a string array produced
// by split(), or a character-code array literal.
type jsVal struct {
	s      string
	parts  []string
	nums   []int
	isArr  bool
	isNums bool
}

func jsStr(s string) jsVal { return jsVal{s: s} }

func (v jsVal) str() (string, bool) {
	if v.isArr || v.isNums {
		return "", false
	}
	return v.s, true
}

func (v jsVal) Array() []string {
	if v.isArr {
		return v.parts
	}
	return []string{v.s}
}

// applyJSMethods walks the .method(args) chain applied to a value.
func applyJSMethods(v jsVal, rest string) (string, bool) {
	rest = strings.TrimLeft(rest, " \t\n")
	for strings.HasPrefix(rest, ".") {
		rest = rest[1:]
		open := strings.IndexByte(rest, '(')
		if open < 0 {
			return "", false
		}
		name := strings.TrimSpace(rest[:open])
		closeIdx := matchParen(rest, open)
		if closeIdx < 0 {
			return "", false
		}
		args := splitArgs(rest[open+1 : closeIdx])
		next, ok := applyJSMethod(name, v, args)
		if !ok {
			return "", false
		}
		v = next
		rest = strings.TrimLeft(rest[closeIdx+1:], " \t\n")
	}
	if strings.TrimSpace(rest) != "" {
		return "", false
	}
	return v.str()
}

// matchParen returns the index of the ')' closing the '(' at open.
func matchParen(s string, open int) int {
	depth := 0
	inStr := false
	for i := open; i < len(s); i++ {
		c := s[i]
		switch {
		case inStr:
			if c == '\\' {
				i++
			} else if c == '"' {
				inStr = false
			}
		case c == '"':
			inStr = true
		case c == '(':
			depth++
		case c == ')':
			depth--
			if depth == 0 {
				return i
			}
		}
	}
	return -1
}

// splitArgs splits a call's argument list on top-level commas.
func splitArgs(s string) []string {
	var out []string
	depth := 0
	inStr := false
	start := 0
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case inStr:
			if c == '\\' {
				i++
			} else if c == '"' {
				inStr = false
			}
		case c == '"':
			inStr = true
		case c == '(':
			depth++
		case c == ')':
			depth--
		case c == ',' && depth == 0:
			out = append(out, strings.TrimSpace(s[start:i]))
			start = i + 1
		}
	}
	if last := strings.TrimSpace(s[start:]); last != "" || len(out) > 0 {
		out = append(out, last)
	}
	return out
}

func applyJSMethod(name string, v jsVal, args []string) (jsVal, bool) {
	// (code) => String.fromCharCode(code-N) over a code array: the other
	// obfuscation proxynova uses for the first octets of the address.
	if name == "map" {
		if !v.isNums || len(args) != 1 {
			return jsVal{}, false
		}
		m := reCharMap.FindStringSubmatch(strings.TrimSpace(args[0]))
		if m == nil {
			return jsVal{}, false
		}
		shift := 0
		if m[1] == "-" {
			shift = -atoiOr(m[2])
		} else {
			shift = atoiOr(m[2])
		}
		var sb strings.Builder
		for _, c := range v.nums {
			n := c + shift
			// A proxy address is ASCII; anything outside it means the shift
			// was not what it looked like, so leave the page alone.
			if n < 0x20 || n > 0x7e {
				return jsVal{}, false
			}
			sb.WriteRune(rune(n))
		}
		return jsStr(sb.String()), true
	}
	// join/reverse are the only operations a split() result ever sees.
	if name == "reverse" {
		parts := v.Array()
		for i, j := 0, len(parts)-1; i < j; i, j = i+1, j-1 {
			parts[i], parts[j] = parts[j], parts[i]
		}
		if v.isArr {
			return jsVal{parts: parts, isArr: true}, true
		}
		return jsStr(strings.Join(parts, "")), true
	}
	if name == "join" {
		if !v.isArr {
			return v, true
		}
		if len(args) != 1 {
			return jsVal{}, false
		}
		sep, ok := jsStringArg(args[0])
		if !ok {
			return jsVal{}, false
		}
		return jsStr(strings.Join(v.parts, sep)), true
	}
	s, ok := v.str()
	if !ok {
		return jsVal{}, false
	}
	switch name {
	case "substring", "substr":
		// JS clamps both arguments; a missing end means "to the end".
		lo := 0
		hi := len(s)
		if len(args) > 0 {
			n, ok := jsInt(args[0])
			if !ok {
				return jsVal{}, false
			}
			lo = clampJS(n, 0, len(s))
		}
		if len(args) > 1 && strings.TrimSpace(args[1]) != "" {
			n, ok := jsInt(args[1])
			if !ok {
				return jsVal{}, false
			}
			hi = clampJS(n, 0, len(s))
		}
		if lo > hi {
			return jsVal{}, false
		}
		return jsStr(s[lo:hi]), true
	case "slice":
		lo := 0
		hi := len(s)
		if len(args) > 0 {
			n, ok := jsInt(args[0])
			if !ok {
				return jsVal{}, false
			}
			lo = clampJS(n, 0, len(s))
		}
		if len(args) > 1 && strings.TrimSpace(args[1]) != "" {
			n, ok := jsInt(args[1])
			if !ok {
				return jsVal{}, false
			}
			hi = clampJS(n, 0, len(s))
		}
		if lo > hi {
			return jsVal{}, false
		}
		return jsStr(s[lo:hi]), true
	case "repeat":
		if len(args) != 1 {
			return jsVal{}, false
		}
		n, ok := jsInt(args[0])
		if !ok || n < 0 || n > 8 || n*len(s) > 4096 {
			return jsVal{}, false
		}
		return jsStr(strings.Repeat(s, n)), true
	case "split":
		// Only the reverse-a-string idiom is supported.
		if len(args) != 1 {
			return jsVal{}, false
		}
		sep, ok := jsStringArg(args[0])
		if !ok || sep != "" {
			return jsVal{}, false
		}
		parts := make([]string, 0, len(s))
		for i := 0; i < len(s); i++ {
			parts = append(parts, s[i:i+1])
		}
		return jsVal{parts: parts, isArr: true}, true
	case "trim":
		return jsStr(strings.TrimSpace(s)), true
	case "toUpperCase":
		return jsStr(strings.ToUpper(s)), true
	case "toLowerCase":
		return jsStr(strings.ToLower(s)), true
	}
	return jsVal{}, false
}

func clampJS(n, lo, hi int) int {
	if n < lo {
		return lo
	}
	if n > hi {
		return hi
	}
	return n
}

// jsInt evaluates a small integer expression: "12", "23-11", "4-2", "0+0".
func jsInt(expr string) (int, bool) {
	expr = strings.TrimSpace(expr)
	if expr == "" {
		return 0, false
	}
	for _, op := range []byte{'+', '-'} {
		i := strings.IndexByte(expr, op)
		if i < 0 {
			continue
		}
		a, ok1 := jsAtom(expr[:i])
		b, ok2 := jsAtom(expr[i+1:])
		if !ok1 || !ok2 {
			return 0, false
		}
		if op == '+' {
			return a + b, true
		}
		return a - b, true
	}
	return jsAtom(expr)
}

func jsAtom(s string) (int, bool) {
	s = strings.TrimSpace(s)
	n, err := strconv.Atoi(s)
	if err != nil {
		return 0, false
	}
	return n, true
}

func atoiOr(s string) int {
	n, _ := jsAtom(s)
	return n
}

// jsStringArg resolves a call argument that must be a string literal.
func jsStringArg(arg string) (string, bool) {
	v, rest, ok := jsStringLiteral(strings.TrimSpace(arg))
	if !ok || strings.TrimSpace(rest) != "" {
		return "", false
	}
	return v, true
}

// evalAtob decodes atob("..."): standard base64, or base64url.
func evalAtob(arg string) (string, bool) {
	s, ok := jsStringArg(arg)
	if !ok {
		return "", false
	}
	if b, err := base64.StdEncoding.DecodeString(s); err == nil {
		return string(b), true
	}
	if b, err := base64.RawStdEncoding.DecodeString(s); err == nil {
		return string(b), true
	}
	return "", false
}
