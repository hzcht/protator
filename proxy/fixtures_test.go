package proxy

import "testing"

// shippedRegexLines loads the shipped config/regexp.txt — the one file every
// extractor/regex test has to agree on. Keeping the path here means a move of
// that file is a one-line change instead of a search through the test suite.
func shippedRegexLines(tb testing.TB) []string {
	tb.Helper()
	lines, err := LoadRegexLines("../config/regexp.txt")
	if err != nil {
		tb.Fatalf("LoadRegexLines: %v", err)
	}
	return lines
}

// liveExtractor builds an extractor from the shipped config/regexp.txt so the
// tests exercise the real per-site patterns rather than a copy of them.
//
// It takes testing.TB, not *testing.T, so benchmarks can share it: the
// LoadRegexLines + NewExtractor pair used to be pasted into four files, and
// every copy drifted the moment a path or an error message changed.
func liveExtractor(tb testing.TB) *Extractor {
	tb.Helper()
	e, err := NewExtractor(shippedRegexLines(tb))
	if err != nil {
		tb.Fatalf("NewExtractor: %v", err)
	}
	return e
}
