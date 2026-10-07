package proxy

import (
	"bufio"
	"net"
	"os"
	"strconv"
	"strings"
	"sync"
)

// CandidatePool persists discovered-but-not-yet-validated candidates on disk
// so a transient probe failure never loses an address forever. Lines are
// host:port or scheme://host:port (parseable by ParseProxyLine), optionally
// followed by a tab and the sites.txt URL the candidate came from
// ("addr\t source"). The source suffix is metadata only: it restores the
// candidate's attribution on re-probe so a late validation still credits the
// real source instead of a fake "pool" entry. Lines without the suffix (every
// pool file written before sources were persisted) load with an empty source
// and stay unattributed — honest, unlike inventing one.
type CandidatePool struct {
	path     string
	maxBytes int64
	maxCount int

	mu     sync.Mutex
	keys   map[string]string // proxy key -> line
	lines  []string          // insertion order
	good   map[string]struct{}
	bytes  int64
	cursor int

	// Buffered writer for appending lines to disk.
	// Avoids open/write/close syscall per Add.
	file   *os.File
	writer *bufio.Writer
}

// NewCandidatePool loads an existing pool file (invalid/duplicate lines are
// dropped) and returns a pool that appends to it.
func NewCandidatePool(path string, maxBytes int64, maxCount int) *CandidatePool {
	if maxBytes <= 0 {
		maxBytes = 256 << 20
	}
	if maxCount <= 0 {
		maxCount = 2000000
	}
	cp := &CandidatePool{
		path:     path,
		maxBytes: maxBytes,
		maxCount: maxCount,
		keys:     make(map[string]string),
		good:     make(map[string]struct{}),
	}
	for _, l := range readPoolLines(path) {
		cp.keys[l.key] = l.line
		cp.lines = append(cp.lines, l.line)
		cp.bytes += int64(len(l.line) + 1)
	}
	// Open file for buffered appends.
	if path != "" {
		f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
		if err == nil {
			cp.file = f
			cp.writer = bufio.NewWriter(f)
		}
	}
	return cp
}

// Close flushes and closes the pool file.
func (cp *CandidatePool) Close() {
	cp.mu.Lock()
	defer cp.mu.Unlock()
	if cp.writer != nil {
		cp.writer.Flush()
	}
	if cp.file != nil {
		cp.file.Close()
		cp.file = nil
		cp.writer = nil
	}
}

// flush writes buffered data to disk.
func (cp *CandidatePool) flush() {
	if cp.writer != nil {
		cp.writer.Flush()
	}
}

// Add persists a new candidate unless it is already known or already good.
// Returns true if the line was appended.
func (cp *CandidatePool) Add(c Candidate) bool {
	line := poolPersistLine(c)
	pl, ok := parsePoolLine(line)
	if !ok {
		return false
	}
	cp.mu.Lock()
	defer cp.mu.Unlock()
	if _, has := cp.keys[pl.key]; has {
		return false
	}
	if _, good := cp.good[pl.key]; good {
		return false
	}
	if len(cp.lines) >= cp.maxCount || cp.bytes+int64(len(line)+1) > cp.maxBytes {
		return false
	}
	cp.keys[pl.key] = line
	cp.lines = append(cp.lines, line)
	cp.bytes += int64(len(line) + 1)
	// Buffered write: append to buffer, flush every 1000 adds.
	if cp.writer != nil {
		cp.writer.WriteString(line)
		cp.writer.WriteByte('\n')
		if len(cp.lines)%1000 == 0 {
			cp.writer.Flush()
		}
	} else {
		appendPoolLine(cp.path, line)
	}
	return true
}

// Good remembers that a candidate validated successfully so Batch stops
// re-probing it. The line stays on disk for the history; it is only skipped.
func (cp *CandidatePool) Good(c Candidate) {
	if pl, ok := parsePoolLine(candidateLine(c)); ok {
		cp.mu.Lock()
		cp.good[pl.key] = struct{}{}
		cp.mu.Unlock()
	}
}

// Batch returns up to n not-yet-validated candidates, rotating through the
// pool so the least-recently-probed entries surface first.
func (cp *CandidatePool) Batch(n int) []Candidate {
	if n <= 0 {
		return nil
	}
	cp.mu.Lock()
	defer cp.mu.Unlock()
	if len(cp.lines) == 0 {
		return nil
	}
	var out []Candidate
	examined := 0
	for examined < len(cp.lines) && len(out) < n {
		idx := (cp.cursor + examined) % len(cp.lines)
		examined++
		line := cp.lines[idx]
		if pl, ok := parsePoolLine(line); ok {
			if _, isGood := cp.good[pl.key]; isGood {
				continue
			}
			out = append(out, Candidate{
				Host:   pl.host,
				Port:   pl.port,
				Schema: pl.schema,
				Source: pl.source,
			})
		}
	}
	cp.cursor = (cp.cursor + examined) % len(cp.lines)
	return out
}

// Len returns the number of persisted candidates.
func (cp *CandidatePool) Len() int {
	cp.mu.Lock()
	defer cp.mu.Unlock()
	return len(cp.lines)
}

// candidateLine normalizes a candidate to its persistent form: bare host:port
// for http/unknown (probe_order will re-discover the protocol), scheme-prefixed
// otherwise.
func candidateLine(c Candidate) string {
	if c.Schema == "" || c.Schema == "http" {
		return net.JoinHostPort(c.Host, strconv.Itoa(c.Port))
	}
	return (&Proxy{Schema: c.Schema, Host: c.Host, Port: c.Port}).URL()
}

// poolPersistLine is candidateLine plus the source attribution, separated by
// a tab. A tab can never appear inside a proxy address or a sites.txt URL, so
// the suffix splits unambiguously and legacy lines (no tab) keep parsing.
func poolPersistLine(c Candidate) string {
	base := candidateLine(c)
	if src := cleanPoolSource(c.Source); src != "" {
		return base + "\t" + src
	}
	return base
}

// cleanPoolSource keeps the attribution to a single metadata field: anything
// from the first tab/CR/LF on is cut, so a hostile or malformed source can
// neither smuggle a second line into the pool file nor break the split.
func cleanPoolSource(s string) string {
	if i := strings.IndexAny(s, "\t\r\n"); i >= 0 {
		s = s[:i]
	}
	return s
}

type poolLine struct {
	key    string
	host   string
	port   int
	schema string
	source string
	line   string
}

func parsePoolLine(line string) (poolLine, bool) {
	addr, source := line, ""
	if i := strings.Index(line, "\t"); i >= 0 {
		addr, source = line[:i], cleanPoolSource(line[i+1:])
	}
	p, err := ParseProxyLine(addr)
	if err != nil {
		return poolLine{}, false
	}
	return poolLine{key: p.Key(), host: p.Host, port: p.Port, schema: p.Schema, source: source, line: line}, true
}

func readPoolLines(path string) []poolLine {
	if !fileExists(path) {
		return nil
	}
	lines, err := readLines(path)
	if err != nil {
		return nil
	}
	seen := make(map[string]struct{}, len(lines))
	var out []poolLine
	for _, l := range lines {
		pl, ok := parsePoolLine(l)
		if !ok {
			continue
		}
		if _, has := seen[pl.key]; has {
			continue
		}
		seen[pl.key] = struct{}{}
		out = append(out, pl)
	}
	return out
}

func appendPoolLine(path, line string) {
	if path == "" {
		return
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
	if err != nil {
		return
	}
	defer f.Close()
	f.WriteString(line + "\n")
}
