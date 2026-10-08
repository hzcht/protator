package proxy

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestParseProxyLine(t *testing.T) {
	cases := []struct {
		line   string
		schema string
		host   string
		port   int
		ok     bool
	}{
		{"1.2.3.4:8080", "http", "1.2.3.4", 8080, true},
		{"http://1.2.3.4:8080", "http", "1.2.3.4", 8080, true},
		{"socks5://1.2.3.4:1080", "socks5", "1.2.3.4", 1080, true},
		{"socks4://1.2.3.4:4145", "socks4", "1.2.3.4", 4145, true},
		{"https://1.2.3.4:8443", "https", "1.2.3.4", 8443, true},
		{"ftp://1.2.3.4:21", "", "", 0, false},
		{"not-a-proxy", "", "", 0, false},
		{"1.2.3.4", "", "", 0, false},
		{"1.2.3.4:99999", "", "", 0, false},
		{"1.2.3.4:0", "", "", 0, false},
		{"[2001:db8::1]:1080", "http", "2001:db8::1", 1080, true},
		{"#comment", "", "", 0, false},
	}
	for _, c := range cases {
		p, err := ParseProxyLine(c.line)
		if c.ok {
			if err != nil {
				t.Fatalf("%q: unexpected error %v", c.line, err)
			}
			if p.Schema != c.schema || p.Host != c.host || p.Port != c.port {
				t.Fatalf("%q: got %+v", c.line, p)
			}
		} else if err == nil {
			t.Fatalf("%q: expected error, got %+v", c.line, p)
		}
	}
}

func TestExtractUniversal(t *testing.T) {
	e, _ := NewExtractor(nil)
	body := `
plain http://1.2.3.4:3128 and socks5://5.6.7.8:1080
bare 9.9.9.9:8080
invalid 999.1.1.1:80 1.2.3.4:0 1.2.3.4:70000
[fe80::1]:3128
https://10.0.0.2:8443
`
	cands := e.Extract([]byte(body))
	byKey := map[string]string{}
	for _, c := range cands {
		byKey[c.key()] = c.Schema
	}
	if byKey["1.2.3.4:3128"] != "http" {
		t.Fatalf("expected http scheme: %v", byKey)
	}
	if byKey["5.6.7.8:1080"] != "socks5" {
		t.Fatalf("expected socks5 scheme: %v", byKey)
	}
	if byKey["9.9.9.9:8080"] != "" {
		t.Fatalf("expected unknown scheme: %v", byKey)
	}
	if byKey["10.0.0.2:8443"] != "https" {
		t.Fatalf("expected https scheme: %v", byKey)
	}
	if _, ok := byKey["fe80::1:3128"]; !ok {
		t.Fatalf("expected ipv6 candidate: %v", byKey)
	}
	if byKey["999.1.1.1:80"] != "" || byKey["1.2.3.4:0"] != "" || byKey["1.2.3.4:70000"] != "" {
		t.Fatalf("invalid candidates slipped through: %v", byKey)
	}
}

func TestExtractSitePatterns(t *testing.T) {
	e, err := NewExtractor([]string{
		`<td[^>]*>\s*([0-9]{1,3}(?:\.[0-9]{1,3}){3})\s*</td>\s*<td[^>]*>\s*([0-9]{1,5})\s*</td>`,
		`port-[0-9]{1,5}[^0-9]*([0-9]{1,3}(?:\.[0-9]{1,3}){3})`,
		`"ip"\s*:\s*"([0-9]{1,3}(?:\.[0-9]{1,3}){3})"[^}]{0,120}"port"\s*:\s*([0-9]{1,5})`,
	})
	if err != nil {
		t.Fatal(err)
	}
	body := `<table><tr><td>11.22.33.44</td><td>5678</td></tr></table>
port-9999
55.66.77.88
{"ip":"12.34.56.78","port":9000}
`
	cands := e.Extract([]byte(body))
	byHost := map[string]int{}
	for _, c := range cands {
		byHost[c.Host] = c.Port
	}
	if byHost["11.22.33.44"] != 5678 {
		t.Fatalf("table pattern failed: %v", byHost)
	}
	if byHost["55.66.77.88"] != 9999 {
		t.Fatalf("port-before-ip pattern failed: %v", byHost)
	}
	if byHost["12.34.56.78"] != 9000 {
		t.Fatalf("json pattern failed: %v", byHost)
	}
}

func TestBucketDedupAndRemove(t *testing.T) {
	b := NewBucket(10)
	mk := func(s string) *Proxy { p, _ := ParseProxyLine(s); return p }
	if !b.Add(mk("http://1.2.3.4:80")) {
		t.Fatal("first add failed")
	}
	if b.Add(mk("http://1.2.3.4:80")) {
		t.Fatal("duplicate add succeeded")
	}
	// different schema = different proxy (dedup by full URL)
	if !b.Add(mk("socks5://1.2.3.4:80")) {
		t.Fatal("socks5 on same host:port should be a separate proxy")
	}
	if !b.Add(mk("http://2.2.2.2:8080")) {
		t.Fatal("second add failed")
	}
	if b.Len() != 3 {
		t.Fatalf("len = %d", b.Len())
	}
	if !b.Remove(mk("http://1.2.3.4:80")) {
		t.Fatal("remove failed")
	}
	if b.Len() != 2 {
		t.Fatalf("len after remove = %d", b.Len())
	}
	// trim behaviour: bucket bounded at max
	big := NewBucket(2)
	big.Add(mk("http://1.1.1.1:80"))
	big.Add(mk("http://2.2.2.2:80"))
	big.Add(mk("http://3.3.3.3:80"))
	if big.Len() != 2 {
		t.Fatalf("full bucket len = %d", big.Len())
	}
	seen := map[string]bool{}
	for _, p := range big.Snapshot() {
		seen[p.URL()] = true
	}
	if seen["http://3.3.3.3:80"] != true {
		t.Fatalf("newest dropped: %v", seen)
	}
}

func TestBucketRandomWaitsThenReturns(t *testing.T) {
	b := NewBucket(10)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() {
		time.Sleep(100 * time.Millisecond)
		p, _ := ParseProxyLine("http://4.4.4.4:80")
		b.Add(p)
	}()
	got, err := b.Random(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if got.URL() != "http://4.4.4.4:80" {
		t.Fatalf("unexpected proxy %s", got.URL())
	}
}

func TestConfigFromDisk(t *testing.T) {
	cfg, err := LoadConfig(filepath.Join("..", "config", "config.toml"))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Server.Listen != "0.0.0.0:8888" {
		t.Fatalf("listen = %q", cfg.Server.Listen)
	}
	if cfg.Server.ListenHTTPS != "0.0.0.0:8443" {
		t.Fatalf("listen_https = %q", cfg.Server.ListenHTTPS)
	}
	if len(cfg.Checker.SelfIPURLs) == 0 {
		t.Fatal("no self_ip_urls")
	}
	if cfg.Server.DialTimeout.Duration <= 0 {
		t.Fatal("dial timeout default not applied")
	}

	tests, err := LoadTests(filepath.Join("..", "config", "checkers.toml"))
	if err != nil {
		t.Fatal(err)
	}
	if len(tests) == 0 {
		t.Fatal("no tests loaded")
	}
	if tests[0].URL == "" || strings.TrimSpace(tests[0].Name) == "" {
		t.Fatalf("bad test entry: %+v", tests[0])
	}
}

func TestTLSLoadOrCreate(t *testing.T) {
	cert, err := LoadOrCreateTLS("", "")
	if err != nil {
		t.Fatal(err)
	}
	if len(cert.Certificate) == 0 {
		t.Fatal("empty cert")
	}
}

func TestRegexFileCompiles(t *testing.T) {
	lines, err := LoadRegexLines(filepath.Join("..", "config", "regexp.txt"))
	if err != nil {
		t.Fatal(err)
	}
	e, err := NewExtractor(lines)
	if err != nil {
		t.Fatal(err)
	}
	if e == nil {
		t.Fatal("nil extractor")
	}
}

func testChecker(urls []string, selfIP string) *Checker {
	cfg := &Config{}
	cfg.Checker.SelfIPURLs = urls
	cfg.Checker.TCPTimeout = Duration{2 * time.Second}
	cfg.Checker.TotalT = Duration{5 * time.Second}
	return &Checker{cfg: cfg, selfIP: net.ParseIP(selfIP), ipRe: reAnyIP}
}

func TestRejectBogon(t *testing.T) {
	self := net.ParseIP("9.9.9.9")
	for _, h := range []string{"127.0.0.1", "10.0.0.1", "172.16.0.1", "192.168.1.1", "169.254.1.1", "0.0.0.0", "9.9.9.9"} {
		if err := rejectBogon(h, self); err == nil {
			t.Fatalf("%s accepted", h)
		}
	}
	for _, h := range []string{"8.8.8.8", "1.1.1.1", "example.com", "proxy.example.org"} {
		if err := rejectBogon(h, self); err != nil {
			t.Fatalf("%s rejected: %v", h, err)
		}
	}
}

func closedPort(t *testing.T) int {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := ln.Addr().(*net.TCPAddr).Port
	ln.Close()
	return port
}

func TestPreDialRefused(t *testing.T) {
	c := testChecker(nil, "9.9.9.9")
	p2 := &Proxy{Schema: "http", Host: "127.0.0.1", Port: closedPort(t)}
	start := time.Now()
	if err := c.preDial(p2); err == nil {
		t.Fatal("pre-dial to closed port succeeded")
	} else if time.Since(start) > c.cfg.Checker.TCPTimeout.Duration {
		t.Fatalf("pre-dial too slow: %s", time.Since(start))
	}
}

func TestIPThroughRace(t *testing.T) {
	fast := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("1.2.3.4"))
	}))
	defer fast.Close()
	slow := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(300 * time.Millisecond)
		w.Write([]byte("5.6.7.8"))
	}))
	defer slow.Close()

	c := testChecker([]string{slow.URL, fast.URL}, "9.9.9.9")
	client := &http.Client{Timeout: 5 * time.Second}
	p := &Proxy{Schema: "http", Host: "127.0.0.1", Port: 1}
	start := time.Now()
	ip, _, winURL, err := c.ipThrough(client, p)
	if err != nil {
		t.Fatal(err)
	}
	if winURL != fast.URL {
		t.Fatalf("wrong winning URL: %s", winURL)
	}
	if ip.String() != "1.2.3.4" {
		t.Fatalf("wrong winner: %s", ip)
	}
	if d := time.Since(start); d > 250*time.Millisecond {
		t.Fatalf("race did not take the fast service: %s", d)
	}
}

func TestIPThroughTransparent(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("9.9.9.9"))
	}))
	defer srv.Close()
	c := testChecker([]string{srv.URL}, "9.9.9.9")
	client := &http.Client{Timeout: 5 * time.Second}
	p := &Proxy{Schema: "http", Host: "127.0.0.1", Port: 1}
	if _, _, _, err := c.ipThrough(client, p); err == nil {
		t.Fatal("transparent proxy accepted")
	}
}

func TestContentPassRace(t *testing.T) {
	good := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("Example Domain"))
	}))
	defer good.Close()
	slowBad := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(300 * time.Millisecond)
		w.Write([]byte("nothing here"))
	}))
	defer slowBad.Close()

	c := testChecker(nil, "9.9.9.9")
	c.tests = []ContentTest{
		{Name: "slow", URL: slowBad.URL, MustContain: []string{"Example"}},
		{Name: "fast", URL: good.URL, MustContain: []string{"Example Domain"}},
	}
	client := &http.Client{Timeout: 5 * time.Second}
	p := &Proxy{Schema: "http", Host: "127.0.0.1", Port: 1}
	start := time.Now()
	ok, _ := c.contentPass(client, p)
	if !ok {
		t.Fatal("matching test did not pass")
	}
	if d := time.Since(start); d > 250*time.Millisecond {
		t.Fatalf("content race too slow: %s", d)
	}

	c.tests = []ContentTest{{Name: "bad", URL: slowBad.URL, MustContain: []string{"Example"}}}
	if ok, _ := c.contentPass(client, p); ok {
		t.Fatal("non-matching test passed")
	}
}

func TestNeedsConnect(t *testing.T) {
	if !needsConnect("http") || !needsConnect("https") {
		t.Fatal("http/https must require CONNECT")
	}
	if needsConnect("socks5") || needsConnect("socks4") {
		t.Fatal("socks must not require CONNECT")
	}
}

func TestParsePortSingleDigit(t *testing.T) {
	if p, ok := parsePort("8"); !ok || p != 8 {
		t.Fatalf("single-digit port rejected: %d %v", p, ok)
	}
	if _, ok := parsePort("0"); ok {
		t.Fatal("port 0 accepted")
	}
	if _, ok := parsePort("65536"); ok {
		t.Fatal("port 65536 accepted")
	}
}

func TestEvictionNotifiesRemoval(t *testing.T) {
	b := NewBucket(2)
	var removed []string
	b.Subscribe(func(p *Proxy, added bool) {
		if !added {
			removed = append(removed, p.URL())
		}
	})
	mk := func(s string) *Proxy { p, _ := ParseProxyLine(s); return p }
	b.Add(mk("http://1.1.1.1:80"))
	b.Add(mk("http://2.2.2.2:80"))
	b.Add(mk("http://3.3.3.3:80")) // evicts 1.1.1.1
	if len(removed) != 1 || removed[0] != "http://1.1.1.1:80" {
		t.Fatalf("eviction not reported: %v", removed)
	}
	if b.Len() != 2 {
		t.Fatalf("len = %d", b.Len())
	}
}

func TestHealthStats(t *testing.T) {
	p, _ := ParseProxyLine("http://1.2.3.4:8080")
	if p.ConsecFails() != 0 {
		t.Fatal("fresh proxy has fails")
	}
	if !p.LastCheck().IsZero() {
		t.Fatal("fresh proxy has lastCheck")
	}
	p.MarkServeOK(100 * time.Millisecond)
	if p.ConsecFails() != 0 || p.Latency() != 100*time.Millisecond {
		t.Fatalf("bad stats after OK: fails=%d lat=%s", p.ConsecFails(), p.Latency())
	}
	if n := p.MarkServeFail(); n != 1 {
		t.Fatalf("fail count = %d", n)
	}
	if n := p.MarkServeFail(); n != 2 {
		t.Fatalf("fail count = %d", n)
	}
	p.MarkAlive(50 * time.Millisecond)
	if p.ConsecFails() != 0 {
		t.Fatal("MarkAlive did not reset streak")
	}
	if p.LastCheck().IsZero() {
		t.Fatal("MarkAlive did not stamp lastCheck")
	}
}

func TestPickHealthyPrefersHealthy(t *testing.T) {
	b := NewBucket(10)
	mk := func(s string) *Proxy { p, _ := ParseProxyLine(s); return p }
	bad := mk("http://10.0.0.1:80")
	good := mk("http://10.0.0.2:80")
	b.Add(bad)
	b.Add(good)
	for i := 0; i < 5; i++ {
		bad.MarkServeFail()
	}
	good.MarkServeOK(time.Millisecond)
	ctx := context.Background()
	for i := 0; i < 20; i++ {
		got, err := b.PickHealthy(ctx, 64, nil)
		if err != nil {
			t.Fatal(err)
		}
		if got.URL() != good.URL() {
			t.Fatalf("picked failing proxy: %s", got.URL())
		}
	}
	// skip forces the other one. Note that skipping the only proven entry drops
	// the picker back to the unproven bulk rather than failing: serving a
	// never-checked proxy beats refusing the client's request outright.
	got, err := b.PickHealthy(ctx, 64, map[string]struct{}{good.Key(): {}})
	if err != nil {
		t.Fatal(err)
	}
	if got.URL() != bad.URL() {
		t.Fatalf("skip ignored: %s", got.URL())
	}
}

func TestPickHealthyPrefersFresh(t *testing.T) {
	// Serving proof (green) must beat fresh validation (warm), which must beat
	// long-silent or never-proven entries: left to (fails, latency, load), a
	// stale-but-silent queue drowns the working tail.
	b := NewBucket(10)
	mk := func(s string) *Proxy { p, _ := ParseProxyLine(s); return p }
	active := mk("http://10.0.0.3:80")
	warm := mk("http://10.0.0.4:80")
	stale := mk("http://10.0.0.5:80")
	never := mk("http://10.0.0.6:80") // no proof of life at all (boot seed)
	b.Add(active)
	b.Add(warm)
	b.Add(stale)
	b.Add(never)
	active.MarkServeOK(time.Millisecond) // serving proof -> green
	warm.MarkAlive(time.Millisecond)     // validation proof only -> warm
	stale.MarkAlive(time.Millisecond)
	atomic.StoreInt64(&stale.lastCheck, time.Now().Add(-2*time.Hour).UnixNano())

	ctx := context.Background()
	for i := 0; i < 30; i++ {
		got, err := b.PickHealthy(ctx, 64, nil)
		if err != nil {
			t.Fatal(err)
		}
		if got.URL() != active.URL() {
			t.Fatalf("picked %s over serving-proven %s", got.URL(), active.URL())
		}
	}
	// skipping green must fall back to the freshly validated (warm) entry.
	got, err := b.PickHealthy(ctx, 64, map[string]struct{}{active.Key(): {}})
	if err != nil {
		t.Fatal(err)
	}
	if got.URL() != warm.URL() {
		t.Fatalf("warm skip-fallback picked %s, want %s", got.URL(), warm.URL())
	}
	// warm decays: once its validation stamp ages out it leaves the proven pool
	// entirely. With `active` skipped there is nothing proven left, so the
	// picker falls back to the stale tier — and within that tier the unmeasured
	// `never` (zero latency) must lose to the measured ones, whatever the tie
	// between `warm` and `stale` decides.
	atomic.StoreInt64(&warm.lastCheck, time.Now().Add(-2*time.Hour).UnixNano())
	b.freshMu.Lock()
	b.freshAt = time.Time{} // drop the cached proven set: warm is no longer in it
	b.freshMu.Unlock()
	// `active` is still legitimately proven (serving proof), so it stays; the
	// point is that warm is gone.
	pool := b.freshPool(time.Now())
	if len(pool) != 1 || pool[0] != active {
		t.Fatalf("proven pool = %v, want only the serving-proven %s", hosts(pool), active.URL())
	}
	got, err = b.PickHealthy(ctx, 64, map[string]struct{}{active.Key(): {}})
	if err != nil {
		t.Fatal(err)
	}
	if got.URL() == never.URL() {
		t.Fatalf("picked the never-proven %s over measured stale entries", never.URL())
	}
}

func TestBucketHotPoolConcentratesPicks(t *testing.T) {
	// A single promoted (proven by real serving) proxy must beat a hundred
	// unproven queue entries: the picker samples the curated hot tail first,
	// not the dead bulk.
	b := NewBucket(200)
	mk := func(s string) *Proxy { p, _ := ParseProxyLine(s); return p }
	for i := 0; i < 100; i++ {
		b.Add(mk(fmt.Sprintf("http://10.0.%d.%d:80", i%256, (i/256)%256)))
	}
	winner := mk("http://10.9.9.9:80")
	b.Add(winner)
	winner.MarkServeOK(time.Millisecond)
	b.Promote(winner)
	ctx := context.Background()
	for i := 0; i < 20; i++ {
		got, err := b.PickHealthy(ctx, 8, nil)
		if err != nil {
			t.Fatal(err)
		}
		if got != winner {
			t.Fatalf("picked %s instead of hot %s", got.URL(), winner.URL())
		}
	}
	// removing the winner drops it from hot: picks fall back to the bucket.
	b.Remove(winner)
	if got, _ := b.PickHealthy(ctx, 8, nil); got == winner {
		t.Fatal("removed proxy still picked")
	}
}

func TestDialContextEvictsDead(t *testing.T) {
	cfg := &Config{}
	cfg.Server.DialTimeout = Duration{200 * time.Millisecond}
	cfg.Server.TLSHandshake = Duration{200 * time.Millisecond}
	cfg.Server.ResponseHeader = Duration{200 * time.Millisecond}
	cfg.Server.ServeRetries = 1
	cfg.Server.ServeMaxFails = 1
	cfg.Server.PickProbes = 4
	b := NewBucket(10)
	dead, _ := ParseProxyLine("http://127.0.0.1:1")
	b.Add(dead)
	d := NewForwardDialer(b, cfg)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if _, err := d.DialContext(ctx, "tcp", "93.184.216.34:80"); err == nil {
		t.Fatal("dial through dead proxy unexpectedly succeeded")
	}
	if b.Len() != 0 {
		t.Fatal("dead proxy was not evicted after threshold")
	}
}
