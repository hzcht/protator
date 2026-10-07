package proxy

import (
	"bufio"
	"context"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"
)

// startTestConnectProxy runs a minimal CONNECT proxy on 127.0.0.1 for tests.
func startTestConnectProxy(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go handleTestConnect(c)
		}
	}()
	return ln.Addr().String()
}

func handleTestConnect(client net.Conn) {
	br := bufio.NewReader(client)
	line, err := br.ReadString('\n')
	if err != nil {
		client.Close()
		return
	}
	for {
		h, err := br.ReadString('\n')
		if err != nil || h == "\r\n" || h == "\n" {
			break
		}
	}
	parts := strings.SplitN(strings.TrimSpace(line), " ", 3)
	if len(parts) != 3 || strings.ToUpper(parts[0]) != "CONNECT" {
		client.Close()
		return
	}
	up, err := net.DialTimeout("tcp", parts[1], 5*time.Second)
	if err != nil {
		client.Write([]byte("HTTP/1.1 502 Bad Gateway\r\n\r\n"))
		client.Close()
		return
	}
	defer up.Close()
	defer client.Close()
	if _, err := client.Write([]byte("HTTP/1.1 200 Connection established\r\n\r\n")); err != nil {
		return
	}
	go io.Copy(up, br)
	io.Copy(client, up)
}

// TestPipelineSiteToQueue verifies the whole chain: a scraped list page
// yields a candidate, the candidate validates through a (test) proxy, and
// the proxy lands in the queue (memory + disk round-trip).
func TestPipelineSiteToQueue(t *testing.T) {
	proxyAddr := startTestConnectProxy(t)
	proxyPort := strings.Split(proxyAddr, ":")[1]

	// One TLS server plays both self-IP service and content test: its body
	// contains a foreign IP and the expected template.
	svc := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("your ip is 5.6.7.8, Example Domain"))
	}))
	defer svc.Close()

	// List page advertising the test proxy.
	list := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		w.Write([]byte("proxies:\nhttp://127.0.0.1:" + proxyPort + "\n"))
	}))
	defer list.Close()

	cfg := &Config{}
	cfg.Collector.HTTPTimeout = Duration{10 * time.Second}
	cfg.Collector.FetchRetries = 2
	cfg.Collector.SiteMaxFails = 3
	cfg.Collector.SiteCooldown = Duration{time.Minute}
	cfg.Checker.SelfIPURLs = []string{svc.URL}
	cfg.Checker.TCPTimeout = Duration{3 * time.Second}
	cfg.Checker.ConnectT = Duration{3 * time.Second}
	cfg.Checker.TLSHandshake = Duration{3 * time.Second}
	cfg.Checker.ResponseT = Duration{5 * time.Second}
	cfg.Checker.TotalT = Duration{10 * time.Second}

	bucket := NewBucket(100)
	col, err := NewCollector(cfg, bucket)
	if err != nil {
		t.Fatal(err)
	}
	out := make(chan Candidate, 100)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	if n := col.fetch(ctx, list.URL, out); n < 1 {
		t.Fatalf("fetch emitted %d candidates", n)
	}
	var cand Candidate
	select {
	case cand = <-out:
	default:
		t.Fatal("no candidate in channel")
	}
	if cand.Host != "127.0.0.1" || cand.Port == 0 {
		t.Fatalf("bad candidate: %+v", cand)
	}

	checker := &Checker{cfg: cfg, selfIP: net.ParseIP("9.9.9.9"), ipRe: reAnyIP, allowBogon: true}
	checker.tests = []ContentTest{{Name: "svc", URL: svc.URL, MustContain: []string{"Example"}}}
	p, err := checker.Check(cand)
	if err != nil {
		t.Fatalf("check failed: %v", err)
	}
	if !bucket.Add(p) {
		t.Fatal("bucket rejected validated proxy")
	}
	if bucket.Len() != 1 {
		t.Fatalf("queue len = %d", bucket.Len())
	}

	// Disk round-trip.
	qpath := filepath.Join(t.TempDir(), "q.lst")
	if err := SaveBucketAtomic(qpath, bucket.Snapshot(), 1<<20); err != nil {
		t.Fatal(err)
	}
	loaded := ReadQueue(qpath)
	if len(loaded) != 1 || loaded[0].URL() != p.URL() {
		t.Fatalf("round-trip mismatch: %+v", loaded)
	}
}

func TestExtractSpys(t *testing.T) {
	body := `<html><head><script>xa=10;xb=2;xc=5;xd=5;</script></head><body>` +
		`<table><tr><td>1.2.3.4<script>document.write("<font>:</font>"+(xa^xb)+(xc^xd)+(xa^xb)+(xc^xd))</script></td></tr>` +
		`<tr><td>9.9.9.9<script>document.write("<font>:</font>"+(no^such)+(vars^here))</script></td></tr>` +
		`</table></body></html>`
	e, _ := NewExtractor(nil)
	cands := e.Extract([]byte(body))
	if len(cands) != 1 {
		t.Fatalf("expected 1 candidate, got %+v", cands)
	}
	if cands[0].Host != "1.2.3.4" || cands[0].Port != 8080 {
		t.Fatalf("bad spys candidate: %+v", cands[0])
	}
}

func TestExtractProxydbHref(t *testing.T) {
	lines, err := LoadRegexLines(filepath.Join("..", "config", "regexp.txt"))
	if err != nil {
		t.Fatal(err)
	}
	e, err := NewExtractor(lines)
	if err != nil {
		t.Fatal(err)
	}
	row := `<tr><td><a href="/45.144.53.63/6015#https" title="x">45.144.53.63</a></td>` +
		`<td><div style="display:none">12</div><a href="/45.144.53.63/6015#https">6015</a></td></tr>`
	byHost := map[string]int{}
	for _, c := range e.Extract([]byte(row)) {
		byHost[c.Host] = c.Port
	}
	if byHost["45.144.53.63"] != 6015 {
		t.Fatalf("proxydb row not extracted: %v", byHost)
	}
}

func TestNormalizeSiteURL(t *testing.T) {
	cases := map[string]string{
		"https://github.com/TheSpeedX/PROXY-List/blob/master/http.txt": "https://raw.githubusercontent.com/TheSpeedX/PROXY-List/master/http.txt",
		"github.com/o/r/blob/main/x.txt":                               "https://raw.githubusercontent.com/o/r/main/x.txt",
		"digitalcybersoft.com":                                         "https://digitalcybersoft.com",
		"https://raw.githubusercontent.com/a/b/main/c.txt":             "https://raw.githubusercontent.com/a/b/main/c.txt",
	}
	for in, want := range cases {
		if got := normalizeSiteURL(in); got != want {
			t.Fatalf("normalize %q = %q, want %q", in, got, want)
		}
	}
}

// TestAllRegexpTxtPatternsCompiles verifies every non-comment line in
// regexp.txt compiles as a valid Go regexp.
func TestAllRegexpTxtPatternsCompiles(t *testing.T) {
	lines, err := LoadRegexLines(filepath.Join("..", "config", "regexp.txt"))
	if err != nil {
		t.Fatal(err)
	}
	for i, line := range lines {
		if _, err := regexp.Compile(line); err != nil {
			t.Fatalf("line %d: regex %q failed: %v", i+1, line, err)
		}
	}
}

// TestAdditionalPatterns verifies a few of the new patterns work on synthetic HTML.
func TestAdditionalPatterns(t *testing.T) {
	lines, err := LoadRegexLines(filepath.Join("..", "config", "regexp.txt"))
	if err != nil {
		t.Fatal(err)
	}
	e, err := NewExtractor(lines)
	if err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name string
		body string
		want map[string]int
	}{
		{
			name: "data-ip/data-port attributes",
			body: `<tr><td data-ip="1.2.3.4" data-port="8080"></td></tr>`,
			want: map[string]int{"1.2.3.4": 8080},
		},
		{
			name: "ip/port class on tds",
			body: `<tr><td class="ip">5.6.7.8</td><td class="port">3128</td></tr>`,
			want: map[string]int{"5.6.7.8": 3128},
		},
		{
			name: "port-first class on tds",
			body: `<tr><td class="port">8080</td><td class="ip">9.10.11.12</td></tr>`,
			want: map[string]int{"9.10.11.12": 8080},
		},
		{
			name: "proxy-row class on tr",
			body: `<tr class="proxy"><td>13.14.15.16</td><td>8888</td></tr>`,
			want: map[string]int{"13.14.15.16": 8888},
		},
		{
			name: "th then td",
			body: `<tr><th>17.18.19.20</th><td>9999</td></tr>`,
			want: map[string]int{"17.18.19.20": 9999},
		},
		{
			name: "port in span inside td",
			body: `<tr><td>21.22.23.24</td><td><span>8080</span></td></tr>`,
			want: map[string]int{"21.22.23.24": 8080},
		},
		{
			name: "IP in anchor, port in next td",
			body: `<tr><td><a href="/proxy/25.26.27.28">25.26.27.28</a></td><td>1080</td></tr>`,
			want: map[string]int{"25.26.27.28": 1080},
		},
		{
			name: "JSON array of objects",
			body: `[{"ip":"29.30.31.32","port":8080},{"ip":"33.34.35.36","port":3128}]`,
			want: map[string]int{"29.30.31.32": 8080, "33.34.35.36": 3128},
		},
		{
			name: "geonode data array",
			body: `{"data":[{"ip":"37.38.39.40","port":8080,"protocol":"http"}]}`,
			want: map[string]int{"37.38.39.40": 8080},
		},
		{
			name: "tbody",
			body: `<tbody><tr><td>41.42.43.44</td><td>8888</td></tr></tbody>`,
			want: map[string]int{"41.42.43.44": 8888},
		},
		{
			name: "port before IP with separators",
			body: `port-8080 - 45.46.47.48`,
			want: map[string]int{"45.46.47.48": 8080},
		},
		{
			name: "JS object literal",
			body: `{ip:"49.50.51.52",port:8080}`,
			want: map[string]int{"49.50.51.52": 8080},
		},
		{
			name: "protocol=ip=port pattern",
			body: `socks5: 53.54.55.56:1080`,
			want: map[string]int{"53.54.55.56": 1080},
		},
		{
			name: "cyber-gateway style",
			body: `<tr><td>57.58.59.60</td><td>8080</td><td>US</td></tr>`,
			want: map[string]int{"57.58.59.60": 8080},
		},
		{
			name: "aliveproxy style",
			body: `<tr><td>61.62.63.64</td><td>3128</td><td>RU</td></tr>`,
			want: map[string]int{"61.62.63.64": 3128},
		},
		{
			name: "proxyservers style",
			body: `<tr><td>65.66.67.68</td><td>8080</td><td>http</td></tr>`,
			want: map[string]int{"65.66.67.68": 8080},
		},
		{
			name: "proxy-list.org style",
			body: `<tr><td>69.70.71.72</td><td>8080</td><td>elite</td></tr>`,
			want: map[string]int{"69.70.71.72": 8080},
		},
		{
			name: "best-proxies.ru style",
			body: `<tr><td>73.74.75.76</td><td>3128</td><td>Russia</td></tr>`,
			want: map[string]int{"73.74.75.76": 3128},
		},
		{
			name: "JSON with address/port_number keys",
			body: `[{"address":"77.78.79.80","port_number":8080}]`,
			want: map[string]int{"77.78.79.80": 8080},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			cands := e.Extract([]byte(tc.body))
			byHost := map[string]int{}
			for _, c := range cands {
				byHost[c.Host] = c.Port
			}
			for host, port := range tc.want {
				if byHost[host] != port {
					t.Fatalf("pattern failed for %s: got %v, want %v", tc.name, byHost, tc.want)
				}
			}
		})
	}
}

// TestSeedMergesQueueAndAudit verifies startup seeding from both the queue
// file and the append-only good-proxy audit (overlap deduped).
func TestSeedMergesQueueAndAudit(t *testing.T) {
	dir := t.TempDir()
	q := filepath.Join(dir, "proxy.lst")
	g := filepath.Join(dir, "good.log")
	os.WriteFile(q, []byte("http://1.1.1.1:80\nhttp://2.2.2.2:80\n"), 0o644)
	os.WriteFile(g, []byte("http://2.2.2.2:80\nsocks5://3.3.3.3:1080\n"), 0o644)

	b := NewBucket(100)
	if n := b.Seed(ReadQueue(q)); n != 2 {
		t.Fatalf("queue seed = %d", n)
	}
	if n := b.Seed(ReadQueueLast(g, 500000)); n != 1 {
		t.Fatalf("audit seed = %d (overlap must dedup)", n)
	}
	if b.Len() != 3 {
		t.Fatalf("len = %d", b.Len())
	}
}

// TestReadQueueLastCap verifies the audit tail cap.
func TestReadQueueLastCap(t *testing.T) {
	dir := t.TempDir()
	f := filepath.Join(dir, "audit.log")
	var lines []string
	for i := 1; i <= 10; i++ {
		lines = append(lines, "http://10.1.0."+strconv.Itoa(i)+":80")
	}
	os.WriteFile(f, []byte(strings.Join(lines, "\n")+"\n"), 0o644)
	got := ReadQueueLast(f, 3)
	if len(got) != 3 {
		t.Fatalf("capped read = %d", len(got))
	}
	if got[0].Host != "10.1.0.8" || got[2].Host != "10.1.0.10" {
		t.Fatalf("not the tail: %+v", got)
	}
}

// TestCollectorViaProxyChargesFaults verifies that agreements of the collector
// constitute genuine proxy telemetry: a dead direct fetch recovers through a
// healthy proxy (and clears its counter), while a device-junk proxy answering
// 400/501 is charged and evicted just like on the serving path.
func TestCollectorViaProxyChargesFaults(t *testing.T) {
	// Direct URL that refuses instantly, forcing the via-proxy path.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	directDead := "http://" + ln.Addr().String()
	ln.Close()

	// The collector fetches through a plain forward proxy (absolute-form GET),
	// so the fake upstreams must speak that protocol, not CONNECT.
	fwdTo := func(upstream string) string {
		ln, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { ln.Close() })
		go func() {
			for {
				client, err := ln.Accept()
				if err != nil {
					return
				}
				go func(c net.Conn) {
					defer c.Close()
					br := bufio.NewReader(c)
					var req []byte
					for {
						line, err := br.ReadBytes('\n')
						req = append(req, line...)
						if err != nil || string(line) == "\r\n" || string(line) == "\n" {
							break
						}
					}
					if len(req) == 0 {
						return
					}
					up, err := net.DialTimeout("tcp", upstream, 5*time.Second)
					if err != nil {
						return
					}
					defer up.Close()
					// httptest accepts absolute-form request lines; relay the
					// proxy-form request verbatim, then pipe both ways.
					if _, err := up.Write(req); err != nil {
						return
					}
					go io.Copy(up, br)
					io.Copy(c, up)
				}(client)
			}
		}()
		return ln.Addr().String()
	}

	mkCfg := func() *Config {
		cfg := &Config{}
		cfg.Collector.HTTPTimeout = Duration{10 * time.Second}
		cfg.Collector.FetchRetries = 2
		cfg.Collector.SiteMaxFails = 3
		cfg.Collector.SiteCooldown = Duration{time.Minute}
		return cfg
	}

	t.Run("healthy via proxy recovers and clears", func(t *testing.T) {
		goodList := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "text/plain")
			w.Write([]byte("http://10.9.0.1:3128\nhttp://10.9.0.2:8080\n"))
		}))
		defer goodList.Close()
		p := mustProxy(t, "http://"+fwdTo(goodList.Listener.Addr().String()))
		b := NewBucket(16)
		b.Add(p)
		cfg := mkCfg()
		col, err := NewCollector(cfg, b)
		if err != nil {
			t.Fatal(err)
		}
		out := make(chan Candidate, 8)
		ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
		defer cancel()
		n := col.fetch(ctx, directDead, out)
		if n != 2 {
			t.Fatalf("fetch via good proxy emitted %d, want 2", n)
		}
		if p.ConsecFails() != 0 {
			t.Fatalf("healthy via proxy must not carry fails")
		}
		if b.Len() != 1 {
			t.Fatalf("healthy proxy must not be evicted")
		}
	})

	t.Run("device junk proxy charged and evicted", func(t *testing.T) {
		junkSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusBadRequest)
			w.Write([]byte("Bad Request"))
		}))
		defer junkSrv.Close()
		p := mustProxy(t, "http://"+fwdTo(junkSrv.Listener.Addr().String()))
		b := NewBucket(16)
		b.Add(p)
		cfg := mkCfg()
		cfg.Server.ServeMaxFails = 1
		cfg.Collector.FetchRetries = 1
		col, err := NewCollector(cfg, b)
		if err != nil {
			t.Fatal(err)
		}
		out := make(chan Candidate, 8)
		ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
		defer cancel()
		n := col.fetch(ctx, directDead, out)
		if n != -1 {
			t.Fatalf("fetch must fail, got %d", n)
		}
		if p.ConsecFails() != 1 {
			t.Fatalf("junk via proxy must be charged, fails=%d", p.ConsecFails())
		}
		if b.Len() != 0 {
			t.Fatalf("junk proxy must be evicted from the pool")
		}
	})
}
func TestCollectorsRunInParallel(t *testing.T) {
	const n = 6
	var sites []string
	for i := 0; i < n; i++ {
		i := i
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			time.Sleep(300 * time.Millisecond)
			w.Write([]byte("10.2.0." + strconv.Itoa(i+1) + ":8080\n"))
		}))
		defer srv.Close()
		sites = append(sites, srv.URL)
	}
	cfg := &Config{}
	cfg.Collector.HTTPTimeout = Duration{10 * time.Second}
	cfg.Collector.FetchWorkers = n
	cfg.Collector.SiteMaxFails = 100
	cfg.Collector.SiteCooldown = Duration{time.Minute}
	col, err := NewCollector(cfg, nil)
	if err != nil {
		t.Fatal(err)
	}
	out := make(chan Candidate, 100)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	start := time.Now()
	col.cycle(ctx, sites, out)
	if d := time.Since(start); d > 1400*time.Millisecond {
		t.Fatalf("cycle took %s, collectors are not parallel", d)
	}
	close(out)
	got := 0
	for range out {
		got++
	}
	if got != n {
		t.Fatalf("got %d candidates, want %d", got, n)
	}
}
