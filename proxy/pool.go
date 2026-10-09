package proxy

import (
	"bufio"
	"log"
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

	// evictions since the file was last rewritten. The file only ever grows
	// (append-only), while memory stays at the cap, so the two drift apart by
	// one line per rotation; compaction realigns them.
	evicted int

	// drift says the file holds lines memory has dropped (evicted) or is
	// missing lines memory holds (parked during a compaction). Close uses it
	// for the final rewrite: the eviction counter alone cannot answer "is the
	// file behind?", because the last compaction may have reset it a moment
	// ago while appends continued.
	drift bool

	// compacting means a rewrite owns the file right now. Appends cannot go to
	// disk (the rewrite replaces it), so they are parked in pending and flushed
	// into the new file once it is in place. This is what lets compaction drop
	// the pool mutex for the fsync: without it, the rewrite would have to hold
	// mu across a multi-megabyte write and stall every checker worker.
	compacting bool
	pending    []string

	// Buffered writer for appending lines to disk.
	// Avoids open/write/close syscall per Add.
	file   *os.File
	writer *bufio.Writer

	// compactReq asks the compaction goroutine to rewrite the file. cap 1: the
	// rewrite is idempotent, so a request while one is pending is redundant.
	compactReq chan struct{}
	stopComp   chan struct{}
	stopOnce   sync.Once
}

// compactEvictThreshold bounds how far the file may drift ahead of memory
// before it is rewritten: compaction is a full rewrite of the pool (up to
// maxCount lines), so it must not run per Add, but leaving it forever would
// let the file grow without bound under rotation.
const compactEvictThreshold = 8192

// NewCandidatePool loads an existing pool file (invalid/duplicate lines are
// dropped) and returns a pool that appends to it. A file that grew past the
// cap (written by an older build that could not trim) keeps only its tail —
// the freshest candidates — and is rewritten to match, instead of permanently
// rejecting every future Add.
func NewCandidatePool(path string, maxBytes int64, maxCount int) *CandidatePool {
	if maxBytes <= 0 {
		maxBytes = 256 << 20
	}
	if maxCount <= 0 {
		maxCount = 2000000
	}
	cp := &CandidatePool{
		path:       path,
		maxBytes:   maxBytes,
		maxCount:   maxCount,
		keys:       make(map[string]string),
		good:       make(map[string]struct{}),
		compactReq: make(chan struct{}, 1),
		stopComp:   make(chan struct{}),
	}
	loaded := readPoolLines(path)
	if trimmed := len(loaded) - maxCount; trimmed > 0 {
		loaded = loaded[trimmed:]
		cp.evicted = compactEvictThreshold // rewrite on first use
	}
	for _, l := range loaded {
		cp.keys[l.key] = l.line
		cp.lines = append(cp.lines, l.line)
		cp.bytes += int64(len(l.line) + 1)
	}
	// Open file for buffered appends. The error is logged rather than
	// swallowed: without a handle Add falls back to appendPoolLine, and a
	// silent failure there means the pool stops growing on disk with no clue
	// anywhere in the output.
	if path != "" {
		f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
		if err != nil {
			log.Printf("pool: open %s for append: %v (falling back to per-line appends)", path, err)
		} else {
			cp.file = f
			cp.writer = bufio.NewWriter(f)
		}
	}
	// A file trimmed on load has to be rewritten now, before returning: the
	// trim only happened in memory, so leaving the oversized file in place
	// means the next append is written after all the entries that were just
	// dropped from tracking.
	if cp.evicted >= compactEvictThreshold && len(cp.lines) > 0 {
		// A file trimmed on load has to be rewritten before returning: the
		// trim only happened in memory, so appending now would write after
		// every entry that was just dropped from tracking.
		cp.compactLocked()
	}
	// Unconditional, and after the load-time rewrite: compactLocked resets
	// evicted to 0, so putting this in an else-branch left the goroutine
	// unstarted exactly in production (the pool file is over its cap there),
	// which left requestCompact with no consumer and the file growing again.
	go cp.compactLoop(cp.stopComp)
	return cp
}

// Close stops the compaction goroutine, then flushes and closes the pool
// file. A final compaction runs if the file drifted: Close is the last chance
// to rewrite it down to what memory still holds.
//
// Safe to call more than once. The stop flag is a mutex-guarded bool rather
// than a closed-channel check: two concurrent Closes could both observe the
// open channel in a select and one would panic on the second close.
func (cp *CandidatePool) Close() {
	cp.stopOnce.Do(func() { close(cp.stopComp) })
	cp.mu.Lock()
	defer cp.mu.Unlock()
	// Realign the file with memory if it drifted: evicted lines are still on
	// disk and parked lines are not. The eviction counter is not enough on its
	// own — the last compaction resets it, and appends that landed afterwards
	// would leave the file behind with nothing to report it.
	if cp.drift && len(cp.lines) > 0 {
		cp.compactLocked()
	}
	if cp.writer != nil {
		if err := cp.writer.Flush(); err != nil {
			log.Printf("pool: final flush %s: %v", cp.path, err)
		}
	}
	if cp.file != nil {
		if err := cp.file.Close(); err != nil {
			log.Printf("pool: close %s: %v", cp.path, err)
		}
		cp.file = nil
		cp.writer = nil
	}
}

// flush writes buffered data to disk.
func (cp *CandidatePool) flush() {
	if cp.writer != nil {
		if err := cp.writer.Flush(); err != nil {
			log.Printf("pool: flush %s: %v", cp.path, err)
		}
	}
}

// Add persists a new candidate unless it is already known or already good.
// Returns true if the line was appended.
//
// The pool rotates instead of refusing work once full: it exists so "a
// transient probe failure never loses an address forever", so dropping the
// newest failures (what the old cap did) throws away exactly the entries the
// pool is for, while the oldest — already re-probed many times over — squat
// on the capacity forever. When full, the oldest line is evicted to make room;
// the file is rewritten periodically so it does not outgrow the cap.
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
	for len(cp.lines) >= cp.maxCount || cp.bytes+int64(len(line)+1) > cp.maxBytes {
		if !cp.evictOldestLocked() {
			return false // empty pool and the line alone exceeds maxBytes
		}
		cp.evicted++
	}
	cp.keys[pl.key] = line
	cp.lines = append(cp.lines, line)
	cp.bytes += int64(len(line) + 1)
	cp.drift = true
	// Buffered write: append to buffer, flush once it holds enough to be
	// worth the syscall. (A line-count check would misfire under rotation:
	// len(lines) sits at the cap, so the modulo never advances.)
	if cp.compacting {
		// A compaction owns the file; park the line and flush it after the
		// rewrite. It is already tracked in memory, so nothing is lost even if
		// the rewrite fails.
		cp.pending = append(cp.pending, line)
	} else if cp.writer != nil {
		if _, err := cp.writer.WriteString(line + "\n"); err != nil {
			// The line is in memory, so the compaction below will get it on
			// disk eventually; say so rather than losing it quietly.
			log.Printf("pool: write %s: %v", cp.path, err)
		} else if cp.writer.Buffered() > 4096 {
			if err := cp.writer.Flush(); err != nil {
				log.Printf("pool: flush %s: %v", cp.path, err)
			}
		}
	} else {
		appendPoolLine(cp.path, line)
	}
	if cp.evicted >= compactEvictThreshold {
		// Compaction rewrites and fsyncs the whole file, so it must not run
		// while Add holds the pool mutex: every other checker worker blocks
		// for the length of an 8-12 MB fsync, and the pool is already at its
		// cap in production, so this fires every minute or two.
		cp.requestCompact()
	}
	return true
}

// requestCompact asks a background goroutine to compact. If one is already
// running the request is dropped: compaction is idempotent and rewrites from
// current memory, so a later pass picks up anything this one missed.
func (cp *CandidatePool) requestCompact() {
	if cp.path == "" {
		return
	}
	select {
	case cp.compactReq <- struct{}{}:
	default:
	}
}

// compactLoop owns every disk rewrite. A single dedicated goroutine keeps the
// multi-megabyte write and its fsync out of the Add path that hundreds of
// checker workers share.
func (cp *CandidatePool) compactLoop(stop <-chan struct{}) {
	for {
		select {
		case <-stop:
			return
		case <-cp.compactReq:
			cp.compactAsync()
		}
	}
}

// compactAsync rewrites the pool file without holding the pool mutex across
// the I/O.
//
// Holding mu for the whole rewrite — which is what compactLocked does, and
// what this used to do — blocks every Add for the duration of a multi-megabyte
// write plus its fsync, and the pool sits at its cap in production, so that
// fired every minute or two. The rewrite is now: snapshot the line set under
// the lock (a slice copy, milliseconds), drop the lock, write temp + fsync +
// rename, then flush the lines that were appended while it ran.
func (cp *CandidatePool) compactAsync() {
	cp.mu.Lock()
	if cp.evicted < compactEvictThreshold || len(cp.lines) == 0 {
		cp.mu.Unlock()
		return
	}
	// Reset now, not on success: while this rewrite runs, Adds keep appending
	// (and may evict again, requesting the next compaction). Deferring the
	// reset would make every Add during the rewrite request another one.
	cp.evicted = 0
	lines := make([]string, len(cp.lines))
	copy(lines, cp.lines)
	path := cp.path
	if path == "" {
		cp.mu.Unlock()
		return
	}
	cp.compacting = true
	// Detach the append handle: on Windows the rename below fails while any
	// handle to the destination is open, including our own. Lines that arrive
	// while the handle is gone are parked in pending.
	cp.detachFileLocked()
	cp.mu.Unlock()

	if err := writeFileAtomic(path, renderPoolLines(lines)); err != nil {
		log.Printf("pool: compact %s: %v", path, err)
		cp.drift = true // the rewrite failed: the file is still behind
	} else {
		cp.drift = false
	}

	cp.mu.Lock()
	cp.attachFileLocked()
	pending := cp.pending
	cp.pending = nil
	cp.compacting = false
	cp.mu.Unlock()
	// The parked lines are already in cp.lines (memory), so this only brings
	// the file up to date; a failure here costs the next compaction, which
	// rewrites from memory anyway.
	if len(pending) > 0 {
		appendPoolLines(cp.path, pending)
		cp.mu.Lock()
		cp.drift = true // appended after the rewrite: keep drift honest
		cp.mu.Unlock()
	}
	log.Printf("pool: compacted %s (%d lines, %d appended meanwhile)", path, len(lines), len(pending))
}

// renderPoolLines joins the pool file body: one line per entry, LF-terminated.
func renderPoolLines(lines []string) []byte {
	n := 0
	for _, l := range lines {
		n += len(l) + 1
	}
	buf := make([]byte, 0, n)
	for _, l := range lines {
		buf = append(buf, l...)
		buf = append(buf, '\n')
	}
	return buf
}

// detachFileLocked closes and forgets the buffered append handle so the file
// can be renamed. Callers hold mu.
func (cp *CandidatePool) detachFileLocked() {
	if cp.writer != nil {
		cp.writer.Flush()
	}
	if cp.file != nil {
		cp.file.Close()
		cp.file, cp.writer = nil, nil
	}
}

// attachFileLocked reopens the append handle after a rewrite. Callers hold mu.
// A failure is logged, not fatal: Adds fall back to per-line appends, which
// open the file themselves.
func (cp *CandidatePool) attachFileLocked() {
	if cp.path == "" {
		return
	}
	f, err := os.OpenFile(cp.path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
	if err != nil {
		log.Printf("pool: reopen %s for append: %v (falling back to per-line appends)", cp.path, err)
		return
	}
	cp.file = f
	cp.writer = bufio.NewWriter(f)
}

// evictOldestLocked drops the front entry (insertion order) and returns false
// when the pool is already empty. Callers hold mu.
func (cp *CandidatePool) evictOldestLocked() bool {
	if len(cp.lines) == 0 {
		return false
	}
	line := cp.lines[0]
	if pl, ok := parsePoolLine(line); ok {
		delete(cp.keys, pl.key)
		// The address leaves the pool, so its "already validated" marker has
		// nothing left to suppress. Leaving it behind is what made an address
		// that validated once and later died permanently un-retryable.
		delete(cp.good, pl.key)
	}
	cp.lines = cp.lines[1:]
	cp.bytes -= int64(len(line) + 1)
	if cp.bytes < 0 {
		cp.bytes = 0
	}
	if cp.cursor > 0 {
		cp.cursor--
	}
	return true
}

// compactLocked rewrites the pool file from memory (temp + fsync + rename) so
// the file holds exactly the lines still tracked in RAM. It blocks every Add
// for the duration, so it is only for paths where that is acceptable: the
// load-time trim and Close, the process's last act. Steady state uses
// compactAsync.
//
// The append handle is closed first: on Windows a rename fails while any handle
// to the destination is open — including our own. Callers hold mu.
func (cp *CandidatePool) compactLocked() {
	evicted := cp.evicted
	cp.evicted = 0
	cp.drift = false
	if cp.path == "" || len(cp.lines) == 0 {
		return
	}
	cp.detachFileLocked()
	if err := writeFileAtomic(cp.path, renderPoolLines(cp.lines)); err != nil {
		log.Printf("pool: compact %s: %v", cp.path, err)
	} else {
		log.Printf("pool: compacted %s (%d lines, %d evicted)", cp.path, len(cp.lines), evicted)
	}
	cp.attachFileLocked()
}

// Good remembers that a candidate validated successfully so Batch stops
// re-probing it. The line stays on disk for the history; it is only skipped.
//
// The marker is deliberately reversible, and is dropped again in two cases:
// when the address is evicted from the pool (evictOldestLocked), and when Good
// is called for an address the pool no longer tracks at all. Keeping it
// forever meant a proxy that validated once and later died could never be
// persisted again — the exact loss the pool exists to prevent — and grew the
// map without bound.
func (cp *CandidatePool) Good(c Candidate) {
	if pl, ok := parsePoolLine(candidateLine(c)); ok {
		cp.mu.Lock()
		if _, tracked := cp.keys[pl.key]; !tracked {
			// No line in the pool any more, so there is nothing for the marker
			// to suppress.
			delete(cp.good, pl.key)
			cp.mu.Unlock()
			return
		}
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

// readPoolLines loads the persisted pool. A read failure is logged and treated
// as an empty pool, which is the safe direction: the file is never rewritten
// from a partial read, and every address is rediscovered by the collector.
//
// The one failure that must not be silent here is a truncated read: it used to
// come back as "empty", after which fresh Adds duplicated lines still on disk
// and the first compaction rewrote the file down to the new entries only,
// erasing the whole history with nothing but a "compacted" line to show for it.
func readPoolLines(path string) []poolLine {
	if !fileExists(path) {
		return nil
	}
	lines, err := readLines(path)
	if err != nil {
		log.Printf("pool: read %s: %v — treating the pool as empty; the file is left untouched", path, err)
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

// appendPoolLine is the fallback path used when the pool has no buffered
// append handle (no file open, or a compaction owns it). Both failures are
// logged: this runs for every rejected candidate, so a silent no-op here means
// candidates stop being persisted with nothing in the log to show for it.
func appendPoolLine(path, line string) {
	if path == "" {
		return
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
	if err != nil {
		log.Printf("pool: open %s for append: %v (candidates are not being persisted)", path, err)
		return
	}
	defer f.Close()
	if _, err := f.WriteString(line + "\n"); err != nil {
		log.Printf("pool: write %s: %v", path, err)
	}
}

// appendPoolLines appends several lines in one open/close. Used to flush the
// lines parked while a compaction owned the file.
func appendPoolLines(path string, lines []string) {
	if path == "" || len(lines) == 0 {
		return
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
	if err != nil {
		log.Printf("pool: open %s for append: %v (%d candidates are not being persisted)", path, err, len(lines))
		return
	}
	defer f.Close()
	for _, l := range lines {
		if _, err := f.WriteString(l + "\n"); err != nil {
			log.Printf("pool: write %s: %v", path, err)
			return
		}
	}
}
