package main

import (
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"protator/proxy"
)

func newTestAdmin(t *testing.T) (*admin, *proxy.Bucket, string) {
	t.Helper()
	bucket := proxy.NewBucket(100)
	cfg := &proxy.Config{}
	cfg.Collector.SitesFile = filepath.Join(t.TempDir(), "sites.txt")
	if err := os.WriteFile(cfg.Collector.SitesFile, []byte(
		"# curated sources\nhttps://a.example/list.txt\n\nhttps://b.example/list.txt\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	pool := proxy.NewCandidatePool(filepath.Join(t.TempDir(), "pool.lst"), 1<<20, 10)
	t.Cleanup(func() { pool.Close() })
	cfg.Collector.SiteMaxFails = 2
	cfg.Collector.SiteCooldown = proxy.Duration{Duration: 10 * time.Minute}
	a := &admin{cfg: cfg, bucket: bucket, pool: pool, started: time.Now(), ws: newWSHub(), cfgPath: "config/config.toml"}
	return a, bucket, cfg.Collector.SitesFile
}

// call runs a request through the real mux, so routing is covered too.
func (c *adminCall) do(t *testing.T) *httptest.ResponseRecorder {
	t.Helper()
	var body io.Reader
	if c.body != "" {
		body = strings.NewReader(c.body)
	}
	req := httptest.NewRequest(c.method, c.target, body)
	rec := httptest.NewRecorder()
	c.a.routes().ServeHTTP(rec, req)
	return rec
}

type adminCall struct {
	a      *admin
	method string
	target string
	body   string
}

func (a *admin) call(method, target, body string) *adminCall {
	return &adminCall{a: a, method: method, target: target, body: body}
}

// doJSON asserts a JSON response and decodes it.
func doJSON(t *testing.T, a *admin, method, target, body string) (int, map[string]interface{}) {
	t.Helper()
	rec := a.call(method, target, body).do(t)
	if ct := rec.Header().Get("Content-Type"); !strings.HasPrefix(ct, "application/json") {
		t.Fatalf("%s %s: content-type %q, body %s", method, target, ct, rec.Body.String())
	}
	var out map[string]interface{}
	if rec.Body.Len() > 0 {
		if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
			t.Fatalf("%s %s: bad json: %v\n%s", method, target, err, rec.Body.String())
		}
	}
	return rec.Code, out
}

func TestAdminHealthAndReady(t *testing.T) {
	a, _, _ := newTestAdmin(t)
	status, body := doJSON(t, a, http.MethodGet, "/health", "")
	if status != 200 {
		t.Fatalf("/health status %d", status)
	}
	if body["queue_live"].(float64) != 0 {
		t.Fatalf("queue_live = %v", body["queue_live"])
	}
	// An empty queue must report not-ready so a supervisor can act on it.
	if status, _ := doJSON(t, a, http.MethodGet, "/ready", ""); status != http.StatusServiceUnavailable {
		t.Fatalf("/ready status %d, want 503", status)
	}
	// An entry with no proof of life must NOT make the queue ready: a queue of
	// seeded-but-unverified addresses answers "is anything in the queue" with
	// yes while every dial fails. Proof (a served response or a passed check)
	// is what flips it.
	a.bucket.Add(&proxy.Proxy{Schema: "http", Host: "1.2.3.4", Port: 8080})
	if status, _ := doJSON(t, a, http.MethodGet, "/ready", ""); status != http.StatusServiceUnavailable {
		t.Fatalf("/ready status %d after adding an unproven proxy, want 503", status)
	}
	proven, _ := proxy.ParseProxyLine("http://5.6.7.8:8080")
	proven.MarkServeOK(time.Second)
	a.bucket.Add(proven)
	a.bucket.Promote(proven)
	if status, _ := doJSON(t, a, http.MethodGet, "/ready", ""); status != 200 {
		t.Fatalf("/ready status %d, want 200", status)
	}
}

func TestAdminIndexAndAssets(t *testing.T) {
	a, _, _ := newTestAdmin(t)
	rec := a.call(http.MethodGet, "/", "").do(t)
	if rec.Code != 200 {
		t.Fatalf("/ status %d", rec.Code)
	}
	body := rec.Body.String()
	for _, want := range []string{"protator", "Live proxies", "Sources", "sites.txt"} {
		if !strings.Contains(body, want) {
			t.Errorf("index page missing %q", want)
		}
	}
	if rec := a.call(http.MethodGet, "/static/admin.css", "").do(t); rec.Code != 200 ||
		!strings.HasPrefix(rec.Header().Get("Content-Type"), "text/css") {
		t.Errorf("css: status %d type %q", rec.Code, rec.Header().Get("Content-Type"))
	}
	if rec := a.call(http.MethodGet, "/static/admin.js", "").do(t); rec.Code != 200 ||
		!strings.HasPrefix(rec.Header().Get("Content-Type"), "application/javascript") {
		t.Errorf("js: status %d type %q", rec.Code, rec.Header().Get("Content-Type"))
	}
	if rec := a.call(http.MethodGet, "/nope", "").do(t); rec.Code != 404 {
		t.Errorf("unknown path: status %d, want 404", rec.Code)
	}
}

// The whole reason for mixedListener: the same port has to answer a plaintext
// request and a TLS one, so a browser pointed at https:// does not get
// ERR_SSL_RECORD_TOO_LONG.
func TestMixedListenerServesHTTPAndHTTPS(t *testing.T) {
	a, _, _ := newTestAdmin(t)
	cert, err := proxy.LoadOrCreateTLS("", "")
	if err != nil {
		t.Fatal(err)
	}
	ln, err := listenMixed("127.0.0.1:0", &tls.Config{
		Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12,
	})
	if err != nil {
		t.Fatal(err)
	}
	srv := &http.Server{Handler: a.routes(), ReadHeaderTimeout: 5 * time.Second}
	go srv.Serve(ln)
	defer srv.Close()

	addr := ln.Addr().String()
	client := &http.Client{Timeout: 5 * time.Second}
	plain, err := client.Get("http://" + addr + "/health")
	if err != nil {
		t.Fatalf("plain http on the mixed port: %v", err)
	}
	if b := readBody(t, plain); !strings.Contains(b, "queue_live") {
		t.Errorf("plain request body = %q", b)
	}

	// InsecureSkipVerify: the listener uses a generated self-signed cert, the
	// same one the proxy front-end already uses.
	tlsClient := &http.Client{
		Timeout:   5 * time.Second,
		Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}},
	}
	secure, err := tlsClient.Get("https://" + addr + "/health")
	if err != nil {
		t.Fatalf("https on the mixed port: %v", err)
	}
	if b := readBody(t, secure); !strings.Contains(b, `"tls":true`) {
		t.Errorf("tls request body = %q, want tls=true", b)
	}
}

// A connection that dies before sending its first byte must not wedge the
// accept loop for everyone else.
func TestMixedListenerSurvivesSilentClient(t *testing.T) {
	a, _, _ := newTestAdmin(t)
	ln, err := listenMixed("127.0.0.1:0", nil)
	if err != nil {
		t.Fatal(err)
	}
	srv := &http.Server{Handler: a.routes(), ReadHeaderTimeout: 5 * time.Second}
	go srv.Serve(ln)
	defer srv.Close()

	stalled, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	stalled.Close() // connected, then gone without a byte

	resp, err := (&http.Client{Timeout: 5 * time.Second}).Get("http://" + ln.Addr().String() + "/health")
	if err != nil {
		t.Fatalf("after a silent client: %v", err)
	}
	if b := readBody(t, resp); !strings.Contains(b, "queue_live") {
		t.Errorf("body = %q", b)
	}
}

func TestAdminProxiesScopesAndText(t *testing.T) {
	a, bucket, _ := newTestAdmin(t)
	quiet := &proxy.Proxy{Schema: "http", Host: "9.9.9.9", Port: 80}
	quiet.SetSource("https://a.example/list.txt")
	bucket.Add(quiet)
	served := &proxy.Proxy{Schema: "socks5", Host: "1.2.3.4", Port: 1080}
	served.SetSource("https://b.example/list.txt")
	served.MarkServeOK(50 * time.Millisecond)
	bucket.Add(served)

	_, all := doJSON(t, a, http.MethodGet, "/api/proxies?scope=all", "")
	if all["count"].(float64) != 2 {
		t.Errorf("scope=all count = %v, want 2", all["count"])
	}
	_, strict := doJSON(t, a, http.MethodGet, "/api/proxies?scope=served", "")
	if strict["count"].(float64) != 1 {
		t.Fatalf("scope=served count = %v, want 1", strict["count"])
	}
	rows := strict["proxies"].([]interface{})
	first := rows[0].(map[string]interface{})
	if first["url"] != "socks5://1.2.3.4:1080" {
		t.Errorf("url = %v", first["url"])
	}
	if first["source"] != "https://b.example/list.txt" {
		t.Errorf("source = %v, want the sites.txt entry", first["source"])
	}

	rec := a.call(http.MethodGet, "/api/proxies?scope=served&format=text", "").do(t)
	if got := rec.Body.String(); got != "socks5://1.2.3.4:1080\n" {
		t.Errorf("text download = %q", got)
	}
	if cd := rec.Header().Get("Content-Disposition"); !strings.Contains(cd, "live-proxies.txt") {
		t.Errorf("Content-Disposition = %q", cd)
	}

	// An unknown scope must not silently widen the result set.
	rec = a.call(http.MethodGet, "/api/proxies?scope=bogus", "").do(t)
	if !strings.Contains(rec.Body.String(), `"scope":"checked"`) {
		t.Errorf("bogus scope not defaulted: %s", rec.Body.String())
	}
	// A proxy with no proof of life must not show up as alive.
	_, strict = doJSON(t, a, http.MethodGet, "/api/proxies?scope=served", "")
	if strict["count"].(float64) != 1 {
		t.Errorf("unproven proxy counted as served: %v", strict["count"])
	}
}

// A page that stops at the limit must still say how big the scope really is,
// otherwise "1000" reads as "all of them".
func TestAdminProxiesReportsScopeTotal(t *testing.T) {
	a, bucket, _ := newTestAdmin(t)
	for _, host := range []string{"1.1.1.1", "2.2.2.2", "3.3.3.3"} {
		p := &proxy.Proxy{Schema: "http", Host: host, Port: 80}
		p.MarkAlive(10 * time.Millisecond)
		bucket.Add(p)
	}
	_, all := doJSON(t, a, http.MethodGet, "/api/proxies?scope=checked", "")
	if all["count"] != all["total"] {
		t.Errorf("small scope: count %v total %v", all["count"], all["total"])
	}
	_, page := doJSON(t, a, http.MethodGet, "/api/proxies?scope=checked&limit=2", "")
	if page["count"].(float64) != 2 || page["total"].(float64) != 3 {
		t.Errorf("limit=2: count %v total %v, want 2 and 3", page["count"], page["total"])
	}
	// An explicit limit of 0 means "no cap" and must not be confused with the
	// default cap.
	_, uncapped := doJSON(t, a, http.MethodGet, "/api/proxies?scope=checked&limit=0", "")
	if uncapped["count"].(float64) != 3 {
		t.Errorf("limit=0: count %v, want 3", uncapped["count"])
	}
	if status, _ := doJSON(t, a, http.MethodGet, "/api/proxies?limit=-5", ""); status != http.StatusBadRequest {
		t.Errorf("negative limit: status %d, want 400", status)
	}
}

// Two adds at once must not lose one of them: the editor is a read-modify-write
// on a single file.
func TestAdminSitesConcurrentEdits(t *testing.T) {
	a, _, path := newTestAdmin(t)
	const n = 8
	var wg sync.WaitGroup
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			url := fmt.Sprintf("https://src%d.example/list.txt", i)
			a.call(http.MethodPost, "/api/sites", fmt.Sprintf(`{"url":%q}`, url)).do(t)
		}(i)
	}
	wg.Wait()
	_, got := doJSON(t, a, http.MethodGet, "/api/sites", "")
	entries := got["entries"].([]interface{})
	if len(entries) != 2+n {
		t.Fatalf("concurrent adds lost entries: got %d, want %d: %v", len(entries), 2+n, entries)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < n; i++ {
		want := fmt.Sprintf("https://src%d.example/list.txt", i)
		if !strings.Contains(string(raw), want) {
			t.Errorf("%s missing from the file:\n%s", want, raw)
		}
	}
}

func TestAdminSitesEditor(t *testing.T) {
	a, _, path := newTestAdmin(t)

	_, got := doJSON(t, a, http.MethodGet, "/api/sites", "")
	if len(got["entries"].([]interface{})) != 2 {
		t.Fatalf("initial entries: %v", got["entries"])
	}
	if got["comments"].(float64) != 1 {
		t.Errorf("comments = %v, want 1 (the curated-sources line)", got["comments"])
	}

	// Adding the same source twice must not duplicate the line, and must not
	// rewrite the file either.
	if status, res := doJSON(t, a, http.MethodPost, "/api/sites", `{"url":"https://a.example/list.txt"}`); status != 200 || res["changed"] != false {
		t.Errorf("duplicate add: status %d body %v", status, res)
	}
	_, got = doJSON(t, a, http.MethodGet, "/api/sites", "")
	if len(got["entries"].([]interface{})) != 2 {
		t.Fatalf("duplicate add changed the list: %v", got["entries"])
	}

	if status, _ := doJSON(t, a, http.MethodPost, "/api/sites", `{"url":"c.example/new.txt"}`); status != 200 {
		t.Fatalf("add with a missing scheme: status %d", status)
	}
	_, got = doJSON(t, a, http.MethodGet, "/api/sites", "")
	if len(got["entries"].([]interface{})) != 3 {
		t.Fatalf("after add: %v", got["entries"])
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(raw), "https://c.example/new.txt") {
		t.Errorf("normalized URL not written: %s", raw)
	}
	// The operator's comment must survive an edit.
	if !strings.Contains(string(raw), "# curated sources") {
		t.Errorf("comment lost on rewrite: %s", raw)
	}
	// A backup of the previous contents must exist.
	if _, err := os.Stat(path + ".bak"); err != nil {
		t.Errorf("no .bak written: %v", err)
	}
	// What the collector will read back has to match what the editor reports.
	reread, err := proxy.LoadSites(path)
	if err != nil {
		t.Fatalf("LoadSites after edit: %v", err)
	}
	if len(reread) != 3 {
		t.Errorf("collector would read %d entries, editor reported 3", len(reread))
	}

	if status, res := doJSON(t, a, http.MethodDelete, "/api/sites", `{"url":"https://a.example/list.txt"}`); status != 200 || res["changed"] != true {
		t.Errorf("delete: status %d body %v", status, res)
	}
	_, got = doJSON(t, a, http.MethodGet, "/api/sites", "")
	if len(got["entries"].([]interface{})) != 2 {
		t.Fatalf("after delete: %v", got["entries"])
	}
	// Deleting something absent is not an error, just no change.
	if status, res := doJSON(t, a, http.MethodDelete, "/api/sites", `{"url":"https://gone.example/x"}`); status != 200 || res["changed"] != false {
		t.Errorf("delete of an absent URL: status %d body %v", status, res)
	}
}

// Emptying the list would silently stop all collection, so the editor has to
// refuse even when the operator asks for it.
func TestAdminSitesRefusesToEmpty(t *testing.T) {
	a, _, path := newTestAdmin(t)
	if status, _ := doJSON(t, a, http.MethodDelete, "/api/sites", `{"url":"https://a.example/list.txt"}`); status != 200 {
		t.Fatalf("first delete: %d", status)
	}
	if status, _ := doJSON(t, a, http.MethodDelete, "/api/sites", `{"url":"https://b.example/list.txt"}`); status != http.StatusBadRequest {
		t.Fatalf("deleting the last entry: status %d, want 400", status)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(raw), "https://b.example/list.txt") {
		t.Errorf("the refused delete was written anyway: %s", raw)
	}
}

func TestAdminSitesRejectsJunk(t *testing.T) {
	a, _, _ := newTestAdmin(t)
	for _, body := range []string{
		`{"url":""}`,
		`{"url":"   "}`,
		`{"url":"# a comment"}`,
		`{"url":"ftp://example.com/list"}`,
		`{"url":"not a url at all"}`,
		`not json`,
	} {
		if status, _ := doJSON(t, a, http.MethodPost, "/api/sites", body); status != http.StatusBadRequest {
			t.Errorf("add %s: status %d, want 400", body, status)
		}
	}
	// The method allow-list must be advertised rather than silently accepted.
	rec := a.call(http.MethodPatch, "/api/sites", `{}`).do(t)
	if rec.Code != http.StatusMethodNotAllowed {
		t.Errorf("PATCH: status %d, want 405", rec.Code)
	}
}

// Alive and yield_pct must come from the bucket's live counters, not the
// registry's once-per-cycle snapshot: a source whose proxies validated minutes
// ago must already read as productive.
func TestAdminSourcesYieldUsesLiveCounts(t *testing.T) {
	a, bucket, _ := newTestAdmin(t)
	col, err := proxy.NewCollector(&proxy.Config{}, bucket)
	if err != nil {
		t.Fatal(err)
	}
	a.collector = col
	url := "https://a.example/list.txt"
	col.Stats().Record(url, true, 10, 4, "200 ok")
	for _, host := range []string{"7.7.7.1", "7.7.7.2"} {
		p := &proxy.Proxy{Schema: "http", Host: host, Port: 80}
		p.SetSource(url)
		bucket.Add(p)
	}
	rows := a.sources()
	if len(rows) != 1 {
		t.Fatalf("sources = %d rows, want 1", len(rows))
	}
	if rows[0].Alive != 2 {
		t.Errorf("alive = %d, want 2 from the live bucket", rows[0].Alive)
	}
	if rows[0].Yield != 50 {
		t.Errorf("yield_pct = %v, want 50 (2 of 4 emitted still queued)", rows[0].Yield)
	}
	_, body := doJSON(t, a, http.MethodGet, "/api/sources", "")
	if body["with_live_output"].(float64) != 1 {
		t.Errorf("with_live_output = %v, want 1", body["with_live_output"])
	}
}

// The admin mixed port takes TLS handshakes; without the dampener on ErrorLog
// every failed handshake (untrusted self-signed cert, scanners, wrong scheme)
// lands raw in stderr — the flood this guards against.
func TestAdminServerUsesNoiseDampener(t *testing.T) {
	a, _, _ := newTestAdmin(t)
	lg := log.New(io.Discard, "", 0)
	if srv := newAdminServer(a, lg); srv.ErrorLog != lg {
		t.Fatal("admin server bypasses the noise dampener")
	}
}

func TestAdminSources(t *testing.T) {
	a, _, _ := newTestAdmin(t)
	// No collector wired in: the endpoint must still answer with an empty
	// table rather than panicking.
	rec := a.call(http.MethodGet, "/api/sources", "").do(t)
	if rec.Code != 200 {
		t.Fatalf("status %d", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), `"sources":[]`) {
		t.Errorf("body = %s", rec.Body.String())
	}
}

func readBody(t *testing.T, resp *http.Response) string {
	t.Helper()
	defer resp.Body.Close()
	b, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}
	return string(b)
}

// --- metrics -------------------------------------------------------------

// /api/metrics must expose counters, per-second rates from two samples, and
// live gauges. The rate window is the whole point: counters alone cannot tell
// an operator whether serving is getting better or worse.
func TestAdminMetricsCountersAndRates(t *testing.T) {
	a, _, _ := newTestAdmin(t)

	proxy.Stats.Reset()
	proxy.Stats.Requests.Add(100)
	proxy.Stats.Checks.Add(200)
	defer proxy.Stats.Reset()

	status, first := doJSON(t, a, http.MethodGet, "/api/metrics", "")
	if status != 200 {
		t.Fatalf("/api/metrics status %d", status)
	}
	counters := first["counters"].(map[string]interface{})
	if counters["requests_total"].(float64) != 100 {
		t.Fatalf("requests_total = %v", counters["requests_total"])
	}
	if gauges := first["gauges"].(map[string]interface{}); gauges["queue_proven"] == nil {
		t.Errorf("gauges missing queue_proven: %v", gauges)
	}

	// A second sample a moment later must produce a rate for the delta.
	time.Sleep(50 * time.Millisecond)
	proxy.Stats.Requests.Add(50)
	_, second := doJSON(t, a, http.MethodGet, "/api/metrics", "")
	rates := second["rates_per_sec"].(map[string]interface{})
	if rates["requests_total"].(float64) <= 0 {
		t.Fatalf("requests_per_sec = %v, want > 0", rates["requests_total"])
	}

	rec := a.call(http.MethodGet, "/api/metrics?format=text", "").do(t)
	if rec.Code != 200 || !strings.Contains(rec.Body.String(), "requests_total 150") {
		t.Fatalf("text format: status %d body %q", rec.Code, rec.Body.String())
	}
}

// --- logs ----------------------------------------------------------------

// The log tail must come from the same routing the files use, so a collector
// line lands in the collector category rather than everything in system.
func TestAdminLogsTailByCategory(t *testing.T) {
	a, _, _ := newTestAdmin(t)
	dir := t.TempDir()
	a.sink = newFileLogSink(proxy.LoggingConfig{Dir: dir})
	t.Cleanup(func() { _ = a.sink.Close() }) // Windows cannot delete open files

	old := log.Writer()
	log.SetOutput(a.sink)
	defer log.SetOutput(old)

	log.Printf("collector: cycle done (3 sites)")
	log.Printf("checker: pool=10 candidates persisted")

	status, body := doJSON(t, a, http.MethodGet, "/api/logs?category=collector&limit=10", "")
	if status != 200 {
		t.Fatalf("/api/logs status %d", status)
	}
	lines := body["lines"].([]interface{})
	if len(lines) != 1 || !strings.Contains(lines[0].(string), "collector: cycle done") {
		t.Fatalf("collector tail = %v", lines)
	}

	if _, body := doJSON(t, a, http.MethodGet, "/api/logs", ""); len(body["categories"].([]interface{})) == 0 {
		t.Error("category list is empty")
	}
}

// --- config + token ------------------------------------------------------

// The config view must render the effective config and redact secrets, and the
// token must gate it. Both halves matter: an unredacted admin page publishes
// credentials over a listener that was bound for convenience.
func TestAdminConfigRedactsAndTokenGates(t *testing.T) {
	a, _, _ := newTestAdmin(t)
	a.cfg.Server.AdminToken = "s3cret"

	if status, _ := doJSON(t, a, http.MethodGet, "/api/config", ""); status != http.StatusUnauthorized {
		t.Fatalf("without token: status %d, want 401", status)
	}
	if status, _ := doJSON(t, a, http.MethodGet, "/api/config?token=s3cret", ""); status != 200 {
		t.Fatalf("with query token: status %d, want 200", status)
	}
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/config", nil)
	req.Header.Set("Authorization", "Bearer s3cret")
	a.routes().ServeHTTP(rec, req)
	if rec.Code != 200 {
		t.Fatalf("with bearer token: status %d, want 200", rec.Code)
	}

	var out struct {
		EffectiveConfig map[string]map[string]interface{} `json:"effective_config"`
		ConfigPath      string                            `json:"config_path"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatal(err)
	}
	if got := out.EffectiveConfig["server"]["admin_token"]; got != "<set>" {
		t.Fatalf("admin_token = %v, want it redacted", got)
	}
	if out.ConfigPath == "" {
		t.Error("config_path is empty")
	}
}

// --- actions -------------------------------------------------------------

// The wake and cooldown-reset actions must reach the collector: a button that
// only looks wired is worse than no button, because it teaches the operator
// the page lies.
func TestAdminActionEndpoints(t *testing.T) {
	a, bucket, sitesFile := newTestAdmin(t)
	col, err := proxy.NewCollector(a.cfg, bucket)
	if err != nil {
		t.Fatal(err)
	}
	a.collector = col
	wake := make(chan struct{}, 1)
	a.wakeCollector = wake

	// Cooling the source, then clearing the cooldown through the API.
	if col.Stats().Failed(sitesFile) {
		t.Error("a source that was never fetched must not be cooling")
	}
	for i := 0; i < a.cfg.Collector.SiteMaxFails+1; i++ {
		if a.cfg.Collector.SiteMaxFails == 0 {
			break
		}
		col.Stats().Record(sitesFile, false, 0, 0, "boom")
	}
	if !col.Stats().Failed(sitesFile) {
		t.Fatal("the source should be cooling after repeated failures")
	}
	body, err := json.Marshal(map[string]string{"url": sitesFile})
	if err != nil {
		t.Fatal(err)
	}
	if status, _ := doJSON(t, a, http.MethodPost, "/api/sources/cooldown", string(body)); status != 200 {
		t.Fatalf("cooldown reset: status %d", status)
	}
	if col.Stats().Failed(sitesFile) {
		t.Error("cooldown was not cleared")
	}

	select {
	case <-wake:
		t.Fatal("wake was consumed by the cooldown test")
	default:
	}
	if status, _ := doJSON(t, a, http.MethodPost, "/api/collector/wake", ""); status != 200 {
		t.Fatalf("wake: status %d", status)
	}
	select {
	case <-wake:
	default:
		t.Error("the wake channel was never signalled")
	}

	// Method discipline on the mutating endpoints.
	if status, _ := doJSON(t, a, http.MethodGet, "/api/collector/wake", ""); status != http.StatusMethodNotAllowed {
		t.Errorf("GET on wake: status %d, want 405", status)
	}
}
