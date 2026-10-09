package main

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"protator/proxy"
)

// fileLogSink routes every log line to a per-category file under Dir with
// size-based rotation, mirroring everything to os.Stderr so console /
// instance_err.log workflows keep working unchanged.
//
// It also keeps a small in-memory tail per category (logTailLines). The admin
// page serves it on /api/logs: reading a rotated log over SSH is the first
// thing an operator does during an incident, and this makes it one page
// refresh. The tail is bounded, so it costs a fixed amount of memory.
type fileLogSink struct {
	cfg      proxy.LoggingConfig
	mu       sync.Mutex
	files    map[string]*rotatingFile
	tail     map[string]*logTail
	disabled bool
}

// logTailLines is how many recent lines per category are kept in memory. 300
// is about a screenful of a collector cycle and a few KB per file.
const logTailLines = 300

// logTail is a fixed-size ring of recent lines, newest last.
type logTail struct {
	mu    sync.Mutex
	lines []string
}

func (t *logTail) add(line string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.lines = append(t.lines, line)
	if len(t.lines) > logTailLines {
		// Drop from the front in blocks: the buffer is only ever read whole,
		// so a per-line shift is wasted work.
		t.lines = append(t.lines[:0], t.lines[len(t.lines)-logTailLines/2:]...)
	}
}

// last returns the most recent n lines, oldest first.
func (t *logTail) last(n int) []string {
	t.mu.Lock()
	defer t.mu.Unlock()
	if n <= 0 || n > len(t.lines) {
		n = len(t.lines)
	}
	out := make([]string, n)
	copy(out, t.lines[len(t.lines)-n:])
	return out
}

func newFileLogSink(cfg proxy.LoggingConfig) *fileLogSink {
	return &fileLogSink{cfg: cfg, files: make(map[string]*rotatingFile), tail: make(map[string]*logTail)}
}

// Tail returns recent log lines for a category (see the categories the Write
// routing picks: collector, checker, serve, system). It never opens a file, so
// it works even when file logging is disabled.
func (s *fileLogSink) Tail(category string, n int) []string {
	s.mu.Lock()
	t := s.tail[category]
	s.mu.Unlock()
	if t == nil {
		t = &logTail{}
		s.mu.Lock()
		s.tail[category] = t
		s.mu.Unlock()
	}
	// The ring lives per category, so a lookup that misses must not lose the
	// lines already buffered: register it once, then read.
	return t.last(n)
}

// Write implements io.Writer for the stdlib log package. The logger emits one
// line per call; we classify by the leading "cat: " prefix (after the
// timestamp when flags are set), route to the matching file and mirror to
// stderr. The default logger uses LstdFlags so lines look like
// "2026/09/26 00:11:50 collector: ...".
func (s *fileLogSink) Write(p []byte) (int, error) {
	line := string(p)
	// stdlib TLS-handshake noise is dropped here as well as in noiseWriter:
	// any http.Server that ever logs through the global logger without the
	// dampener (a forgotten ErrorLog wiring — exactly how the admin mixed
	// port once flooded stderr every 15s) must not be able to sink the logs.
	// These lines are client-side handshake garbage in all cases (untrusted
	// cert, scanner, wrong scheme); real serving failures are logged by us.
	if strings.Contains(line, "TLS handshake error from") {
		return len(p), nil
	}
	cat := "system"
	switch {
	case hasPrefix(line, "collector:"):
		cat = "collector"
	case hasPrefix(line, "checker:"):
		cat = "checker"
	case hasPrefix(line, "serve:"):
		cat = "serve"
	}

	s.recordTail(cat, line)

	if _, err := os.Stderr.Write(p); err != nil {
		return len(p), err
	}
	if f := s.file(cat); f != nil {
		if _, err := f.Write(p); err != nil {
			return len(p), err
		}
	}
	return len(p), nil
}

// recordTail appends one line to the category's in-memory ring. The ring is
// created on first use so an idle category costs nothing.
func (s *fileLogSink) recordTail(cat, line string) {
	s.mu.Lock()
	t := s.tail[cat]
	if t == nil {
		t = &logTail{}
		s.tail[cat] = t
	}
	s.mu.Unlock()
	t.add(strings.TrimRight(line, "\r\n"))
}

// Close closes every open category file. Tests call this so tempdirs can be
// removed on Windows; the production process just exits.
func (s *fileLogSink) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, f := range s.files {
		f.Close()
	}
	return nil
}

func hasPrefix(line, prefix string) bool {
	if strings.HasPrefix(line, prefix) {
		return true
	}
	// Strip the stdlib "2006/01/02 15:04:05 " leading timestamp plus any
	// extra whitespace, then re-check.
	i := 0
	if len(line) > 20 && line[19] == ' ' {
		i = 20
	}
	for i < len(line) && line[i] == ' ' {
		i++
	}
	return strings.HasPrefix(line[i:], prefix)
}

func (s *fileLogSink) file(cat string) *rotatingFile {
	s.mu.Lock()
	defer s.mu.Unlock()
	if f, ok := s.files[cat]; ok {
		return f
	}
	if s.cfg.Dir == "" {
		s.disabled = true
		return nil
	}
	if err := os.MkdirAll(s.cfg.Dir, 0o755); err != nil {
		// Should never happen in practice; fall back to stderr-only so a
		// logging failure can't take the collector down.
		return nil
	}
	f := newRotatingFile(filepath.Join(s.cfg.Dir, cat+".log"), s.cfg.MaxBytes, s.cfg.Keep)
	s.files[cat] = f
	return f
}

// rotatingFile appends to a single file and, once it exceeds MaxBytes, closes
// it, shifts the previous generations (.log.1 newest .. .log.K oldest) and
// starts a fresh .log. All file I/O is serialized per file.
type rotatingFile struct {
	path     string
	maxBytes int64
	keep     int

	mu   sync.Mutex
	f    *os.File
	size int64
}

func newRotatingFile(path string, maxBytes int64, keep int) *rotatingFile {
	return &rotatingFile{path: path, maxBytes: maxBytes, keep: keep}
}

func (r *rotatingFile) Write(p []byte) (int, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.f == nil {
		if err := r.open(); err != nil {
			return len(p), nil // stderr mirror already has the line
		}
	}
	if r.maxBytes > 0 && r.size+int64(len(p)) > r.maxBytes {
		r.rotate()
	}
	n, err := r.f.Write(p)
	r.size += int64(n)
	return n, err
}

func (r *rotatingFile) open() error {
	f, err := os.OpenFile(r.path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
	if err != nil {
		return err
	}
	st, err := f.Stat()
	if err != nil {
		f.Close()
		return err
	}
	r.f = f
	r.size = st.Size()
	return nil
}

// rotate shifts generations and reopens a fresh file. Oldest (r.path.<keep>)
// is dropped; a missing file halfway is tolerated.
func (r *rotatingFile) rotate() {
	r.f.Close()
	r.f = nil
	for i := r.keep - 1; i >= 1; i-- {
		if _, err := os.Stat(r.gen(i)); err == nil {
			_ = os.Rename(r.gen(i), r.gen(i+1))
		}
	}
	if _, err := os.Stat(r.path); err == nil {
		_ = os.Rename(r.path, r.gen(1))
	}
	r.size = 0
	if err := r.open(); err != nil {
		// Rare; next Write retries opening.
	}
}

func (r *rotatingFile) gen(n int) string {
	return fmt.Sprintf("%s.%d", r.path, n)
}

func (r *rotatingFile) Close() error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.f != nil {
		err := r.f.Close()
		r.f = nil
		return err
	}
	return nil
}

var _ io.Writer = (*fileLogSink)(nil)
var _ io.Writer = (*rotatingFile)(nil)
