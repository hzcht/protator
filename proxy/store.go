package proxy

import (
	"bufio"
	"fmt"
	neturl "net/url"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"
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

func writeFileAtomic(path string, data []byte) error {
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, ".sites-*.tmp")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer func() {
		if tmpName != "" {
			os.Remove(tmpName)
		}
	}()
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
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

func readQueueCapped(path string, maxLines int) []*Proxy {
	lines, err := readLines(path)
	if err != nil {
		return nil
	}
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
// fsync, rename. Oversized queues are truncated to keep the file bounded.
func SaveBucketAtomic(path string, proxies []*Proxy, maxBytes int64) error {
	dir := filepath.Dir(path)
	if dir != "" && dir != "." {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return err
		}
	}

	tmp, err := os.CreateTemp(dir, ".queue-*.tmp")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer func() {
		if tmpName != "" {
			os.Remove(tmpName)
		}
	}()

	bw := bufio.NewWriterSize(tmp, 1<<20)
	var size int64
	for _, p := range proxies {
		line := p.URL() + "\n"
		if size+int64(len(line)) > maxBytes {
			break
		}
		if _, err := bw.WriteString(line); err != nil {
			tmp.Close()
			return err
		}
		size += int64(len(line))
	}
	if err := bw.Flush(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
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

// AppendGood appends a line to the "good proxies" audit file.
//
// One cached buffered writer per path, guarded by its own mutex: the writer is
// shared by every checker worker (hundreds of goroutines), and bufio.Writer is
// not concurrency-safe — unsynchronized WriteString/Flush calls interleave at
// the buffer level and garble lines. The mutex is per path, not global, so two
// audit files never contend with each other.
var goodWriters sync.Map // path -> *goodWriter

type goodWriter struct {
	mu sync.Mutex
	w  *bufio.Writer
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
	gw.w.WriteString(line)
	gw.w.WriteByte('\n')
	// Flush past 4 KB to bound memory (and bound loss on a crash).
	if gw.w.Buffered() > 4096 {
		gw.w.Flush()
	}
	gw.mu.Unlock()
}

func openGoodWriter(path string) *goodWriter {
	if v, ok := goodWriters.Load(path); ok {
		return v.(*goodWriter)
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
	if err != nil {
		return nil
	}
	gw := &goodWriter{w: bufio.NewWriter(f)}
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
