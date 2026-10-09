package proxy

import (
	"log"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func writeSites(t *testing.T, path, body string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestSiteListRoundTrip(t *testing.T) {
	path := filepath.Join(t.TempDir(), "sites.txt")
	// Comment, blank lines and a CRLF tail, i.e. what a hand-edited file
	// looks like on Windows.
	writeSites(t, path, "# curated\r\nhttps://a.example/list.txt\r\n\r\nhttps://b.example/list.txt\r\n")

	l, err := LoadSiteList(path)
	if err != nil {
		t.Fatal(err)
	}
	if got := l.URLs(); len(got) != 2 || got[0] != "https://a.example/list.txt" {
		t.Fatalf("URLs = %v", got)
	}
	added, err := l.Add("C.Example/New-List.TXT")
	if err != nil {
		t.Fatalf("Add: %v", err)
	}
	if !added {
		t.Fatal("Add reported no change for a new entry")
	}
	// Scheme and host are lowercased (they are case-insensitive); the path is
	// not (it is case-sensitive).
	if got := l.URLs(); got[2] != "https://c.example/New-List.TXT" {
		t.Fatalf("Add did not normalize: %q", got[2])
	}
	// ... which is also what makes the dup check work: this is b.example.
	if again, err := l.Add("B.EXAMPLE/list.txt"); err != nil || again {
		t.Errorf("Add of an existing URL in different case: added=%v err=%v", again, err)
	}
	if l.Remove("HTTPS://B.EXAMPLE/list.txt") != true {
		t.Error("Remove should match case-insensitively after normalization")
	}
	if l.Remove("https://a.example/list.txt") != true {
		t.Error("Remove of a present entry returned false")
	}
	if l.Remove("https://a.example/list.txt") {
		t.Error("Remove of an absent entry returned true")
	}
}

// The admin editor saves over an existing file, twice in a row in practice, and
// keeps a .bak. That only works if the atomic replace really replaces on this
// platform.
func TestSaveSiteListReplacesAndBacksUp(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "sites.txt")
	writeSites(t, path, "# keep me\nhttps://a.example/1.txt\nhttps://b.example/2.txt\n")

	l, err := LoadSiteList(path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := l.Add("https://c.example/3.txt"); err != nil {
		t.Fatal(err)
	}
	if err := SaveSiteList(l); err != nil {
		t.Fatalf("first save: %v", err)
	}
	// Second save over the file the first one wrote: the replacement path.
	if l.Remove("https://a.example/1.txt") != true {
		t.Fatal("Remove returned false")
	}
	if err := SaveSiteList(l); err != nil {
		t.Fatalf("second save over an existing file: %v", err)
	}

	final, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	body := string(final)
	for _, want := range []string{"# keep me", "https://b.example/2.txt", "https://c.example/3.txt"} {
		if !strings.Contains(body, want) {
			t.Errorf("final file missing %q:\n%s", want, body)
		}
	}
	if strings.Contains(body, "a.example") {
		t.Errorf("removed entry still in the file:\n%s", body)
	}

	// The .bak must hold the revision as it was before the last save (which
	// still had a.example), and it must survive being overwritten.
	bak, err := os.ReadFile(path + ".bak")
	if err != nil {
		t.Fatalf("no backup: %v", err)
	}
	if !strings.Contains(string(bak), "a.example") {
		t.Errorf("backup lost the entry the last save removed:\n%s", bak)
	}
	if !strings.Contains(string(bak), "c.example") {
		t.Errorf("backup is not the previous revision:\n%s", bak)
	}

	// And what the collector reads back must match the editor's own view.
	reread, err := LoadSiteList(path)
	if err != nil {
		t.Fatal(err)
	}
	if got := reread.URLs(); len(got) != 2 {
		t.Errorf("collector reads %v, want the two surviving entries", got)
	}
}

// A BOM is what every Windows editor offers to add, and it silently turns the
// first line of sites.txt into a URL.
func TestLoadSitesStripsBOM(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "sites.txt")
	// BOM at the start of the file (what Windows editors write) plus a stray
	// one on a later line, which is what a copy-paste leaves behind.
	writeSites(t, path, "\ufeff# a comment\r\nhttps://a.example/1.txt\r\n\ufeffhttps://b.example/2.txt\r\n")

	got, err := LoadSites(path)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"https://a.example/1.txt", "https://b.example/2.txt"}
	if len(got) != len(want) {
		t.Fatalf("LoadSites = %q, want %q", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("entry %d = %q, want %q", i, got[i], want[i])
		}
	}

	// The editor's view must agree, and saving it must drop the BOM for good.
	l, err := LoadSiteList(path)
	if err != nil {
		t.Fatal(err)
	}
	if l.Entries[0].Comment != "# a comment" {
		t.Errorf("first line is not a comment: %+v", l.Entries[0])
	}
	if _, err := l.Add("https://c.example/3.txt"); err != nil {
		t.Fatal(err)
	}
	if err := SaveSiteList(l); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if strings.HasPrefix(string(raw), "\ufeff") {
		t.Error("saved file still starts with a BOM")
	}
	if !strings.Contains(string(raw), "# a comment") {
		t.Errorf("comment lost: %s", raw)
	}
	again, err := LoadSites(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(again) != 3 {
		t.Errorf("collector reads %q, want 3 entries", again)
	}
}

func TestSiteListAddRejectsJunk(t *testing.T) {
	path := filepath.Join(t.TempDir(), "sites.txt")
	writeSites(t, path, "https://a.example/1.txt\n")
	l, err := LoadSiteList(path)
	if err != nil {
		t.Fatal(err)
	}
	for _, bad := range []string{
		"", "   ", "# comment", "ftp://x/y", "not a url", "://missing-scheme",
		"file:///etc/passwd", "javascript:alert(1)",
	} {
		if _, err := l.Add(bad); err == nil {
			t.Errorf("Add(%q) was accepted", bad)
		}
	}
	if got := l.URLs(); len(got) != 1 {
		t.Errorf("a rejected add changed the list: %v", got)
	}
}

// The picker's proven tier is only as good as its window: if the window closes
// before the next revalidation pass, the picker has nothing to aim at and
// serves the unverified bulk. That misconfiguration is invisible at runtime, so
// fillDefaults has to say something.
func TestPickFreshWindowMustOutlastRevalidation(t *testing.T) {
	cfg := &Config{}
	cfg.Server.PickFreshWindow = Duration{time.Minute}
	cfg.Storage.RevalidateInterval = Duration{15 * time.Minute}
	logged := captureLog(t, func() { cfg.fillDefaults() })
	if !strings.Contains(logged, "pick_fresh_window") {
		t.Errorf("no warning about pick_fresh_window (1m) < revalidate_interval (15m); log was:\n%s", logged)
	}

	// The default pairing must be consistent, or the warning would fire on
	// every normal start.
	def := &Config{}
	logged = captureLog(t, func() { def.fillDefaults() })
	if strings.Contains(logged, "pick_fresh_window") {
		t.Errorf("the shipped defaults warn about themselves:\n%s", logged)
	}
	if got, reval := def.Server.PickFreshWindow.Duration, def.Storage.RevalidateInterval.Duration; got < reval {
		t.Errorf("default pick_fresh_window (%s) is shorter than revalidate_interval (%s)", got, reval)
	}
}

func captureLog(t *testing.T, fn func()) string {
	t.Helper()
	var sb strings.Builder
	flags := log.Flags()
	log.SetOutput(&sb)
	log.SetFlags(0)
	defer func() {
		log.SetOutput(os.Stderr)
		log.SetFlags(flags)
	}()
	fn()
	return sb.String()
}

func TestSaveSiteListNeedsPath(t *testing.T) {
	if err := SaveSiteList(&SiteList{Entries: []SiteEntry{{URL: "https://x/y"}}}); err == nil {
		t.Error("SaveSiteList without a path should fail")
	}
}

// URLLen must equal len(URL()) for every shape of proxy, including the VLESS
// variant: the queue save measures with it to choose the tail to keep, and an
// off-by-one would silently drop entries from the persisted queue.
func TestURLLenMatchesURL(t *testing.T) {
	proxies := []*Proxy{
		{Schema: "http", Host: "1.2.3.4", Port: 8080},
		{Schema: "", Host: "10.0.0.1", Port: 80},
		{Schema: "socks5", Host: "2001:db8::1", Port: 1080},
		{Schema: "vless", Host: "5.6.7.8", Port: 443},
	}
	for _, p := range proxies {
		if got, want := p.URLLen(), len(p.URL()); got != want {
			t.Errorf("URLLen(%s) = %d, want %d", p.URL(), got, want)
		}
	}
	v := &Proxy{Schema: "vless", Host: "5.6.7.8", Port: 443}
	v.SetVLESS("uuid-here", "", "example.com", "pk", "sid", "")
	if got, want := v.URLLen(), len(v.URL()); got != want {
		t.Errorf("vless URLLen = %d, want %d (url %q)", got, want, v.URL())
	}
}

// An oversized queue keeps its *newest* entries (the tail), and the file must
// stay under the budget. The reverse (keeping the head) re-seeds every restart
// with the stalest entries in the queue.
func TestSaveBucketAtomicKeepsNewestTail(t *testing.T) {
	path := filepath.Join(t.TempDir(), "q.lst")
	var all []*Proxy
	for i := 0; i < 200; i++ {
		all = append(all, &Proxy{Schema: "http", Host: "10.1.2.3", Port: 8000 + i})
	}
	// Budget that fits roughly half of them.
	budget := int64(100 * 30)
	if err := SaveBucketAtomic(path, all, budget); err != nil {
		t.Fatal(err)
	}
	loaded := ReadQueue(path)
	if len(loaded) == 0 || len(loaded) >= len(all) {
		t.Fatalf("loaded %d entries, want a trim of %d", len(loaded), len(all))
	}
	if loaded[0].Port <= all[0].Port {
		t.Fatalf("the kept head is entry port %d, the oldest is %d: the wrong end was trimmed",
			loaded[0].Port, all[0].Port)
	}
	if last := loaded[len(loaded)-1]; last.Port != all[len(all)-1].Port {
		t.Fatalf("the newest entry (port %d) was dropped; kept tail ends at %d",
			all[len(all)-1].Port, last.Port)
	}
	if st, err := os.Stat(path); err == nil && st.Size() > budget {
		t.Fatalf("saved file is %d bytes over the %d budget", st.Size(), budget)
	}
}
