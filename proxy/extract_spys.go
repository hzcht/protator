package proxy

import "strings"

// spys.one-style JS-obfuscated ports: the page writes each port digit with
// document.write("..."+(a^b)+(c^d)) and defines a/b/c/d in a script block.
// Reconstructed arithmetically — no browser, no evaluation.

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
