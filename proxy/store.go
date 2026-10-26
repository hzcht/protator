package proxy

import (
	"bufio"
	"fmt"
	"io"
	"log"
	neturl "net/url"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
)

// LoadSites reads a list file (one URL per line), skipping comments and blank
// lines, and returns unique entries in stable sorted order. Entries are
// normalized (missing scheme, github blob -> raw) before dedup so that
// duplicates written in different forms collapse.
func LoadSites(path string) ([]string, error) {
	lines, err := readLines(path)
	if err != nil {
		return nil, err
	}
	out := make([]string, 0, len(lines))
	seen := make(map[string]struct{}, len(lines))
	for _, l := range lines {
		l = strings.TrimSpace(l)
		if l == "" || strings.HasPrefix(l, "#") {
			continue
		}
		l = normalizeSiteURL(l)
		if _, ok := seen[l]; ok {
			continue
		}
		seen[l] = struct{}{}
		out = append(out, l)
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("%s does not contain any entries", path)
	}
	sort.Strings(out)
	return out, nil
}

var reGithubBlob = regexp.MustCompile(`^(https?://)github\.com/([^/]+/[^/]+)/blob/([^/]+)/(.+)$`)

// normalizeSiteURL repairs common source-URL defects:
//   - missing scheme ("example.com/x" -> "https://example.com/x")
//   - github blob pages ("github.com/o/r/blob/br/path" ->
//     "raw.githubusercontent.com/o/r/br/path"), which serve HTML instead of
//     the raw list.
//   - scheme and host case, which are case-insensitive per RFC 3986. Lowering
//     them is what makes Add dedupe and Remove match reliably; the path is
//     left alone because it is case-sensitive.
func normalizeSiteURL(u string) string {
	if !strings.Contains(u, "://") {
		u = "https://" + u
	}
	if m := reGithubBlob.FindStringSubmatch(u); m != nil {
		u = "https://raw.githubusercontent.com/" + m[2] + "/" + m[3] + "/" + m[4]
	}
	parsed, err := neturl.Parse(u)
	if err != nil {
		return u
	}
	parsed.Scheme = strings.ToLower(parsed.Scheme)
	parsed.Host = strings.ToLower(parsed.Host)
	return parsed.String()
}

// SiteList is the editable view of a sites file that the admin page edits.
// Comments are preserved (with the text they were written with) and the
// entries keep their file order, so an operator's annotations survive an edit
// made from the browser.
type SiteList struct {
	Path    string
	Entries []SiteEntry
}

// SiteEntry is one line of a sites file. Exactly one of Comment/URL is set.
type SiteEntry struct {
	Comment string // non-empty for a "#" line
	URL     string // non-empty for an entry line
}

// Add appends a URL (normalized) and reports whether it was new. Blank input
// and lines that are only a comment are rejected.
func (l *SiteList) Add(raw string) (bool, error) {
	u := strings.TrimSpace(raw)
	if u == "" {
		return false, fmt.Errorf("empty URL")
	}
	if strings.HasPrefix(u, "#") {
		return false, fmt.Errorf("that is a comment, not a URL")
	}
	u = normalizeSiteURL(u)
	if !validSiteURL(u) {
		return false, fmt.Errorf("not an http(s) URL: %s", raw)
	}
	for i := range l.Entries {
		if l.Entries[i].URL == u {
			return false, nil
		}
	}
	l.Entries = append(l.Entries, SiteEntry{URL: u})
	return true, nil
}

// Remove drops a URL and reports whether it was present. The first match wins,
// so removing twice is a no-op the second time.
func (l *SiteList) Remove(raw string) bool {
	u := normalizeSiteURL(strings.TrimSpace(raw))
	for i := range l.Entries {
		if l.Entries[i].URL == u {
			l.Entries = append(l.Entries[:i], l.Entries[i+1:]...)
			return true
		}
	}
	return false
}

// URLs returns just the entry lines, in file order.
func (l *SiteList) URLs() []string {
	out := make([]string, 0, len(l.Entries))
	for _, e := range l.Entries {
		if e.URL != "" {
			out = append(out, e.URL)
		}
	}
	return out
}

// Render produces the file contents: every line in its original order,
// comments included.
func (l *SiteList) Render() []byte {
	var b strings.Builder
	b.Grow(len(l.Entries) * 96)
	for _, e := range l.Entries {
		if e.Comment != "" {
			b.WriteString(e.Comment)
		} else {
			b.WriteString(e.URL)
		}
		b.WriteByte('\n')
	}
	return []byte(b.String())
}

// LoadSiteList reads a sites file, keeping comments and order. A missing file
// is not an error: it yields an empty list, so a first-run add works.
func LoadSiteList(path string) (*SiteList, error) {
	l := &SiteList{Path: path}
	lines, err := readLines(path)
	if err != nil {
		if os.IsNotExist(err) {
			return l, nil
		}
		return nil, err
	}
	for _, raw := range lines {
		line := strings.TrimRight(raw, "\r")
		trimmed := strings.TrimSpace(line)
		switch {
		case trimmed == "":
			// Blank lines carry no information; the renderer re-derives them.
		case strings.HasPrefix(trimmed, "#"):
			l.Entries = append(l.Entries, SiteEntry{Comment: trimmed})
		default:
			l.Entries = append(l.Entries, SiteEntry{URL: normalizeSiteURL(trimmed)})
		}
	}
	return l, nil
}

// SaveSiteList writes a sites file atomically (temp file in the same dir,
// fsync, rename) so a half-written list is never picked up by the collector's
// next cycle. The previous contents are kept alongside as <path>.bak.
func SaveSiteList(l *SiteList) error {
	if l.Path == "" {
		return fmt.Errorf("no sites file path")
	}
	dir := filepath.Dir(l.Path)
	if dir != "" && dir != "." {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return err
		}
	}
	if old, err := os.ReadFile(l.Path); err == nil {
		_ = writeFileAtomic(l.Path+".bak", old)
	}
	return writeFileAtomic(l.Path, l.Render())
}

// The os.CreateTemp patterns used by the writers in this package. They are
// also the globs SweepOrphanTMP sweeps, so any writer that needs a new pattern
// has to add it there too.
const (
	tmpPatternSites = ".sites-*.tmp"
	tmpPatternQueue = ".queue-*.tmp"
)

func writeFileAtomic(path string, data []byte) error {
	return writeFileAtomicTo(path, tmpPatternSites, func(w io.Writer) error {
		_, err := w.Write(data)
		return err
	})
}

// writeFileAtomicTo is the one way this codebase replaces a file: render runs
// against a temp file created in path's directory, the result is flushed,
// fsynced and renamed over path. A reader therefore sees either the old file
// or the complete new one, never a truncated one, and a crash before the
// rename leaves only the temp file — which SweepOrphanTMP sweeps at the next
// start (the reason every writer must pass one of the known patterns).
// On any error the temp is removed and path keeps its previous contents.
func writeFileAtomicTo(path, pattern string, render func(w io.Writer) error) error {
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, pattern)
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer func() {
		if tmpName != "" {
			tmp.Close()
			os.Remove(tmpName)
		}
	}()
	if err := render(tmp); err != nil {
		return err
	}
	if err := tmp.Sync(); err != nil {
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmpName, path); err != nil {
		return err
	}
	tmpName = ""
	return nil
}

// SweepOrphanTMP removes atomic-write temp files left behind by a crash
// between CreateTemp and rename: `.sites-*.tmp` (writeFileAtomic — sites.txt
// and candidates.lst), `.queue-*.tmp` (SaveBucketAtomic — proxy.lst) and the
// debug-proxies temp (`<basename>.tmp` + random suffix). The defer os.Remove
// in each writer never ran, so the files linger forever, eating disk and
// confusing operators ("is this my queue?"). Only the patterns our own
// writers create are swept — a generic *.tmp glob would eat unrelated user
// files. Safe at startup: no writer has run yet, so every matching file is an
// orphan by definition.
func SweepOrphanTMP(dirs ...string) {
	patterns := []string{tmpPatternSites, tmpPatternQueue, "debug_proxies.txt.tmp*"}
	seen := make(map[string]struct{}, len(dirs))
	for _, dir := range dirs {
		if dir == "" || dir == "." {
			dir = "."
		}
		if _, dup := seen[dir]; dup {
			continue
		}
		seen[dir] = struct{}{}
		for _, pat := range patterns {
			matches, err := filepath.Glob(filepath.Join(dir, pat))
			if err != nil {
				continue
			}
			for _, m := range matches {
				if err := os.Remove(m); err == nil {
					log.Printf("store: swept orphaned temp file %s", m)
				}
			}
		}
	}
}

// validSiteURL keeps the list to things the collector can actually fetch.
func validSiteURL(u string) bool {
	parsed, err := neturl.Parse(u)
	if err != nil {
		return false
	}
	if parsed.Scheme != "http" && parsed.Scheme != "https" {
		return false
	}
	return parsed.Host != ""
}

// ReadQueue parses persisted proxy.lst lines into Proxies. Invalid lines are
// skipped.
func ReadQueue(path string) []*Proxy {
	return readQueueCapped(path, 0)
}

// ReadQueueLast is ReadQueue capped at the last maxLines lines (max <= 0
// means no cap). Used for append-only audit files that grow without bound.
func ReadQueueLast(path string, maxLines int) []*Proxy {
	return readQueueCapped(path, maxLines)
}

// queueLoadFailed latches a *read error* (not "file absent") on the queue
// file: the first dirty save after such a load would overwrite the real file
// with whatever the (empty) in-memory queue holds — an AV lock or a transient
// I/O error turning into permanent data loss. The latch is cleared by the
// next successful load (i.e. the next start) and by an explicit successful
// read of the same path.
var queueLoadFailed atomic.Bool

func readQueueCapped(path string, maxLines int) []*Proxy {
	lines, err := readLines(path)
	if err != nil {
		// Used to vanish silently: an unreadable/missing proxy.lst looked
		// exactly like an empty one, and an incident could not tell "cold
		// start" from "disk error, queue is empty again".
		if !os.IsNotExist(err) {
			log.Printf("queue: cannot read %s: %v (the queue file will NOT be overwritten until a successful load)", path, err)
			Stats.QueueLoadFailures.Add(1)
			queueLoadFailed.Store(true)
		}
		return nil
	}
	queueLoadFailed.Store(false)
	if maxLines > 0 && len(lines) > maxLines {
		lines = lines[len(lines)-maxLines:] // audit files: tail is freshest
	}
	seen := make(map[string]struct{}, len(lines))
	out := make([]*Proxy, 0, len(lines))
	for _, l := range lines {
		p, err := ParseProxyLine(l)
		if err != nil {
			continue
		}
		if _, ok := seen[p.Key()]; ok {
			continue
		}
		seen[p.Key()] = struct{}{}
		out = append(out, p)
	}
	return out
}

// LoadRegexLines reads regexp.txt. Lines starting with '#' are comments.
func LoadRegexLines(path string) ([]string, error) {
	lines, err := readLines(path)
	if err != nil {
		return nil, err
	}
	var out []string
	for _, l := range lines {
		l = strings.TrimSpace(l)
		if l == "" || strings.HasPrefix(l, "#") {
			continue
		}
		out = append(out, l)
	}
	return out, nil
}

// SaveBucketAtomic writes the queue atomically: temp file in the same dir,
// fsync, rename. An oversized queue is trimmed to the budget, keeping its
// newest entries.
func SaveBucketAtomic(path string, proxies []*Proxy, maxBytes int64) error {
	// P67 latch: refuse to overwrite a queue file that failed to load this
	// session. Losing the in-memory state is recoverable; clobbering the on-
	// disk queue with an empty one is not.
	if queueLoadFailed.Load() {
		return fmt.Errorf("queue file %s failed to load this session; refusing to overwrite it", path)
	}
	dir := filepath.Dir(path)
	if dir != "" && dir != "." {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return err
		}
	}

	// Over budget, keep the tail. The slice is in insertion order, so the head
	// is the oldest entries and the tail the most recently validated ones — and
	// on a restart only the tail is worth anything. Keeping the head instead
	// re-seeds every restart with the stalest proxies in the queue and silently
	// drops the freshest, which is the opposite of what the file is for. The
	// candidate pool already rotates at its cap and keeps its newest, and the
	// two halves of the system must agree on which end survives.
	//
	// Measure first, render second. URLLen is the same number as URL() without
	// building the string, so the size pass over a multi-million-entry queue
	// costs no allocation at all; only the surviving tail is ever rendered.
	// (Rendering every entry up front allocated the whole queue — tens of
	// megabytes of short-lived strings on every save.)
	var total int64
	for _, p := range proxies {
		total += int64(p.URLLen()) + 1
	}
	if total > maxBytes {
		// Walk backwards until the suffix stops fitting; O(n), and it stops at
		// the budget instead of measuring the whole queue.
		lo, kept := len(proxies), int64(0)
		for i := len(proxies) - 1; i >= 0; i-- {
			kept += int64(proxies[i].URLLen()) + 1
			if kept > maxBytes {
				break
			}
			lo = i
		}
		// A budget smaller than a single entry leaves nothing worth keeping;
		// writing the newest one beats writing an empty file, which would seed
		// an empty queue on the next start.
		if lo == len(proxies) && len(proxies) > 0 {
			lo = len(proxies) - 1
		}
		log.Printf("save: queue is %d bytes over the %d limit; keeping the newest %d of %d entries",
			total-maxBytes, maxBytes, len(proxies)-lo, len(proxies))
		proxies = proxies[lo:]
	}

	return writeFileAtomicTo(path, tmpPatternQueue, func(w io.Writer) error {
		bw := bufio.NewWriterSize(w, 1<<20)
		var size int64
		// One reusable buffer for the whole save: the URL is built straight
		// into the writer, so a multi-million-entry save allocates nothing
		// per entry.
		line := make([]byte, 0, 128)
		for _, p := range proxies {
			line = p.AppendURL(line[:0])
			if size+int64(len(line))+1 > maxBytes {
				break
			}
			if _, err := bw.Write(line); err != nil {
				return err
			}
			if err := bw.WriteByte('\n'); err != nil {
				return err
			}
			size += int64(len(line)) + 1
		}
		return bw.Flush()
	})
}

// AppendGood appends a line to the "good proxies" audit file.
//
// One cached buffered writer per path, guarded by its own mutex: the writer is
// shared by every checker worker (hundreds of goroutines), and bufio.Writer is
// not concurrency-safe — unsynchronized WriteString/Flush calls interleave at
// the buffer level and garble lines. The mutex is per path, not global, so two
// audit files never contend with each other.
//
// Write and flush errors are logged. This is the only record of what validated,
// so a full disk that silently drops it leaves no trace — the queue save is a
// reconstruction, not a substitute.
var goodWriters sync.Map // path -> *goodWriter

type goodWriter struct {
	path string
	mu   sync.Mutex
	w    *bufio.Writer
	f    *os.File
}

func AppendGood(path, line string) {
	if path == "" {
		return
	}
	gw := openGoodWriter(path)
	if gw == nil {
		return
	}
	gw.mu.Lock()
	defer gw.mu.Unlock()
	if _, err := gw.w.WriteString(line + "\n"); err != nil {
		Stats.GoodWriteFailures.Add(1)
		log.Printf("good: write %s: %v", path, err)
		return
	}
	// Flush past 4 KB to bound memory (and bound loss on a crash).
	if gw.w.Buffered() > 4096 {
		if err := gw.w.Flush(); err != nil {
			Stats.GoodWriteFailures.Add(1)
			log.Printf("good: flush %s: %v", path, err)
		}
	}
}

// CloseGoodWriters flushes and closes every cached audit file, then forgets
// them. Called on shutdown: the buffer only reaches disk past 4 KB, so the tail
// — exactly the newly-found set — would otherwise be lost on every exit.
func CloseGoodWriters() {
	goodWriters.Range(func(k, v interface{}) bool {
		gw := v.(*goodWriter)
		gw.mu.Lock()
		if err := gw.w.Flush(); err != nil {
			Stats.GoodWriteFailures.Add(1)
			log.Printf("good: final flush %s: %v", gw.path, err)
		}
		if err := gw.f.Close(); err != nil {
			Stats.GoodWriteFailures.Add(1)
			log.Printf("good: close %s: %v", gw.path, err)
		}
		gw.mu.Unlock()
		goodWriters.Delete(k)
		return true
	})
}

func openGoodWriter(path string) *goodWriter {
	if v, ok := goodWriters.Load(path); ok {
		return v.(*goodWriter)
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
	if err != nil {
		Stats.GoodWriteFailures.Add(1)
		log.Printf("good: open %s for append: %v (the audit trail is disabled)", path, err)
		return nil
	}
	gw := &goodWriter{path: path, w: bufio.NewWriter(f), f: f}
	if actual, loaded := goodWriters.LoadOrStore(path, gw); loaded {
		// Another worker won the race: close our file handle instead of
		// leaking it (the loser used to keep an orphaned *os.File forever).
		f.Close()
		return actual.(*goodWriter)
	}
	return gw
}

// readLines reads a file into non-empty lines.
//
// A UTF-8 BOM is dropped from the start of every line. The one on the first
// line is what every Windows editor offers to write, and without stripping it
// the first entry of sites.txt comes out as "\ufeff# comment" — no longer a
// comment, so the collector would try to fetch the BOM as part of a URL. The
// rest are cheap insurance against a BOM that arrived by copy-paste.
func readLines(path string) ([]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	var lines []string
	sc := bufio.NewScanner(f)
	// A 64 KB starting window, grown on demand. Every line read here is a
	// proxy address or a site URL; the 1 MB fixed buffer used to be allocated
	// up front on each of the four readers that open at startup, which is
	// memory spent for a line length that never occurs.
	sc.Buffer(make([]byte, 64<<10), 4<<20)
	for sc.Scan() {
		l := strings.TrimPrefix(strings.TrimRight(sc.Text(), "\r"), "\ufeff")
		if strings.TrimSpace(l) == "" {
			continue
		}
		lines = append(lines, l)
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	return lines, nil
}

// fileExists reports whether path exists and is not a directory.
func fileExists(path string) bool {
	info, err := os.Stat(path)
	return err == nil && !info.IsDir()
}
