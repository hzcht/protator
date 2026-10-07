package proxy

import (
	"bufio"
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// startDropConnectProxy is like startTestConnectProxy but establishes the
// tunnel (200) and then immediately kills it: a proxy that dials fine and
// never answers the request — the "response-level" failure class.
func startDropConnectProxy(t *testing.T) string {
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
			go handleTestConnectDrop(c)
		}
	}()
	return ln.Addr().String()
}

func handleTestConnectDrop(client net.Conn) {
	defer client.Close()
	br := bufio.NewReader(client)
	if _, err := br.ReadString('\n'); err != nil {
		return
	}
	for {
		h, err := br.ReadString('\n')
		if err != nil || h == "\r\n" || h == "\n" {
			break
		}
	}
	if _, err := client.Write([]byte("HTTP/1.1 200 Connection established\r\n\r\n")); err != nil {
		return
	}
	time.Sleep(100 * time.Millisecond) // let the client commit its request bytes
}

// startStaticConnectProxy runs a CONNECT proxy that ignores the requested
// target and tunnels every connection to a fixed upstream. Used to pin which
// far target each proxy visits, so failover outcomes are deterministic.
func startStaticConnectProxy(t *testing.T, upstream string) string {
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
			go func(client net.Conn) {
				handleTestConnectStatic(client, upstream)
			}(c)
		}
	}()
	return ln.Addr().String()
}

func handleTestConnectStatic(client net.Conn, upstream string) {
	br := bufio.NewReader(client)
	if _, err := br.ReadString('\n'); err != nil {
		client.Close()
		return
	}
	for {
		h, err := br.ReadString('\n')
		if err != nil || h == "\r\n" || h == "\n" {
			break
		}
	}
	up, err := net.DialTimeout("tcp", upstream, 5*time.Second)
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

func mustProxy(t *testing.T, line string) *Proxy {
	t.Helper()
	p, err := ParseProxyLine(line)
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func testServerConfig(retries, maxFails int) *Config {
	cfg := &Config{}
	cfg.Server.ServeRetries = retries
	cfg.Server.ServeMaxFails = maxFails
	cfg.Server.PickProbes = 2
	cfg.Server.DialTimeout = Duration{2 * time.Second}
	cfg.Server.TLSHandshake = Duration{2 * time.Second}
	cfg.Server.ResponseHeader = Duration{2 * time.Second}
	cfg.Server.MaxIdleConns = 16
	cfg.Server.IdleConnTimeout = Duration{30 * time.Second}
	cfg.Server.ServePinTTL = Duration{time.Minute}
	cfg.Server.ServePinMax = 16
	return cfg
}

// TestProxyTransportRetriesAfterNoResponse verifies the full serving chain:
// a proxy that answers CONNECT but kills the tunnel before any HTTP response
// is charged at the response level, evicted after serve_max_fails, its pin
// dropped, and the request transparently re-served through a healthy proxy.
func TestProxyTransportRetriesAfterNoResponse(t *testing.T) {
	var hits int64
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt64(&hits, 1)
		w.Write([]byte("content-A"))
	}))
	defer target.Close()

	pBad := mustProxy(t, "http://"+startDropConnectProxy(t))
	pGood := mustProxy(t, "http://"+startTestConnectProxy(t))
	b := NewBucket(16)
	if !b.Add(pBad) || !b.Add(pGood) {
		t.Fatal("bucket add")
	}

	cfg := testServerConfig(2, 1)
	fwd := NewForwardDialer(b, cfg)
	pt := NewProxyTransport(cfg, fwd)
	defer pt.base.(*http.Transport).CloseIdleConnections()
	fwd.pins.Set("k", pBad) // force the dying proxy first

	req, err := http.NewRequest("GET", target.URL, nil)
	if err != nil {
		t.Fatal(err)
	}
	req = req.WithContext(WithConnKey(req.Context(), "k"))

	resp, err := pt.RoundTrip(req)
	if err != nil {
		t.Fatalf("RoundTrip: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if string(body) != "content-A" {
		t.Fatalf("body = %q", body)
	}
	if atomic.LoadInt64(&hits) != 1 {
		t.Fatalf("target hits = %d, want 1", hits)
	}
	if pBad.ConsecFails() != 1 {
		t.Fatalf("bad proxy fails = %d, want 1", pBad.ConsecFails())
	}
	if pBad.InFlight() != 0 {
		t.Fatalf("bad proxy in-flight leaked: %d", pBad.InFlight())
	}
	if pGood.ConsecFails() != 0 {
		t.Fatalf("good proxy was marked failed")
	}
	if b.Len() != 1 {
		t.Fatalf("bucket len = %d, want 1 (bad proxy evicted)", b.Len())
	}
	if got := fwd.pins.Get("k"); got != pGood {
		t.Fatal("pin must remap to the healthy proxy after failover")
	}
}

// TestProxyTransportInterstitialRetry verifies the block-page detector: a pin
// pinned to a proxy whose exit targets serve an interstitial page gets remapped
// and the request is re-served through another proxy (the block page comes from
// the far target based on the caller's IP, so the retry needs a different
// exit). The proxies here tunnel to *fixed* upstreams for determinism.
func TestProxyTransportInterstitialRetry(t *testing.T) {
	var blockHits int64
	blockSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt64(&blockHits, 1)
		w.Header().Set("Content-Type", "text/html")
		w.Write([]byte("<html><title>Human verification</title><p>captcha required</p></html>"))
	}))
	defer blockSrv.Close()
	var goodHits int64
	goodSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt64(&goodHits, 1)
		w.Write([]byte("content-B"))
	}))
	defer goodSrv.Close()

	pBlock := mustProxy(t, "http://"+startStaticConnectProxy(t, blockSrv.Listener.Addr().String()))
	pGood := mustProxy(t, "http://"+startStaticConnectProxy(t, goodSrv.Listener.Addr().String()))
	b := NewBucket(16)
	b.Add(pGood) // pBlock lives only behind the pin, not in the pool

	cfg := testServerConfig(2, 3)
	cfg.Server.ServeBlockDetect = true
	cfg.Server.ServeBlockMaxBytes = 4096
	fwd := NewForwardDialer(b, cfg)
	pt := NewProxyTransport(cfg, fwd)
	defer pt.base.(*http.Transport).CloseIdleConnections()
	fwd.pins.Set("k2", pBlock)

	req, err := http.NewRequest("GET", "http://example.com/", nil)
	if err != nil {
		t.Fatal(err)
	}
	req = req.WithContext(WithConnKey(req.Context(), "k2"))

	resp, err := pt.RoundTrip(req)
	if err != nil {
		t.Fatalf("RoundTrip: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if string(body) != "content-B" {
		t.Fatalf("body = %q, want content-B (did not fail over)", body)
	}
	if atomic.LoadInt64(&blockHits) != 1 {
		t.Fatalf("block server hits = %d, want 1", blockHits)
	}
	if atomic.LoadInt64(&goodHits) != 1 {
		t.Fatalf("good server hits = %d, want 1", goodHits)
	}
	if pBlock.ConsecFails() != 0 {
		t.Fatalf("block page must not count as a health failure")
	}
	if got := fwd.pins.Get("k2"); got != pGood {
		t.Fatal("pin must remap to the healthy proxy after a block page")
	}
	if b.Len() != 1 {
		t.Fatalf("bucket len = %d, want 1", b.Len())
	}
}

// TestProxyTransportInterstitialNoAlternative verifies that when the block
// detector fires and no other proxy helps, the final block page is returned
// as-is (upstream content, not an artificial error).
func TestProxyTransportInterstitialNoAlternative(t *testing.T) {
	var blockHits int64
	blockSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt64(&blockHits, 1)
		w.Header().Set("Content-Type", "text/html")
		w.Write([]byte("<p>access denied by capture.captcha.ui</p>"))
	}))
	defer blockSrv.Close()

	p := mustProxy(t, "http://"+startTestConnectProxy(t))
	b := NewBucket(16)
	b.Add(p)

	cfg := testServerConfig(2, 3)
	cfg.Server.ServeBlockDetect = true
	fwd := NewForwardDialer(b, cfg)
	pt := NewProxyTransport(cfg, fwd)
	defer pt.base.(*http.Transport).CloseIdleConnections()

	req, _ := http.NewRequest("GET", blockSrv.URL, nil)
	resp, err := pt.RoundTrip(req)
	if err != nil {
		t.Fatalf("RoundTrip: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if !strings.Contains(string(body), "captcha") {
		t.Fatalf("block page not returned as-is: %q", body)
	}
	if atomic.LoadInt64(&blockHits) != 2 {
		t.Fatalf("block hits = %d, want 2 (first + one retry)", blockHits)
	}
	if p.ConsecFails() != 0 {
		t.Fatalf("block page must not count as a health failure")
	}
}

// TestProxyTransportInterstitialFinalGetsNoCredit verifies the no-alternative
// block-page case settles neutrally: the page is returned as-is, but the proxy
// that served it must not earn proof-of-life — crediting burned IPs with
// MarkServeOK is how they entrenched themselves in the hot tail, and the
// picker samples the tail first.
func TestProxyTransportInterstitialFinalGetsNoCredit(t *testing.T) {
	blockSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		w.Write([]byte("<p>access denied by capture.captcha.ui</p>"))
	}))
	defer blockSrv.Close()

	p := mustProxy(t, "http://"+startTestConnectProxy(t))
	b := NewBucket(16)
	b.Add(p)

	cfg := testServerConfig(2, 3)
	cfg.Server.ServeBlockDetect = true
	fwd := NewForwardDialer(b, cfg)
	pt := NewProxyTransport(cfg, fwd)
	defer pt.base.(*http.Transport).CloseIdleConnections()

	req, _ := http.NewRequest("GET", blockSrv.URL, nil)
	resp, err := pt.RoundTrip(req)
	if err != nil {
		t.Fatalf("RoundTrip: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if !strings.Contains(string(body), "captcha") {
		t.Fatalf("block page not returned as-is: %q", body)
	}
	if p.OKTotal() != 0 {
		t.Fatalf("proxy earned %d successes for serving a block page", p.OKTotal())
	}
	if !p.LastServed().IsZero() {
		t.Fatalf("proxy stamped lastOK for serving a block page")
	}
	if b.HotLen() != 0 {
		t.Fatalf("hot tail = %d, want 0 (block page is not proof of life)", b.HotLen())
	}
	if p.ConsecFails() != 0 {
		t.Fatalf("block page must not count as a health failure either")
	}
}

// TestProxyTransportChargesDeviceJunk verifies that a proxy whose far target
// answers with a tiny 400 (a Plex/UPnP/device, not a forwarding proxy — the
// class that swamped the live pool: it always "works" so it was never evicted)
// is charged as a serving failure, evicted after serve_max_fails, its pin
// dropped, and the request transparently re-served through a healthy proxy.
func TestProxyTransportChargesDeviceJunk(t *testing.T) {
	var junkHits int64
	junkSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt64(&junkHits, 1)
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte("Bad Request"))
	}))
	defer junkSrv.Close()
	var goodHits int64
	goodSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt64(&goodHits, 1)
		w.Write([]byte("content-C"))
	}))
	defer goodSrv.Close()

	pJunk := mustProxy(t, "http://"+startStaticConnectProxy(t, junkSrv.Listener.Addr().String()))
	pGood := mustProxy(t, "http://"+startStaticConnectProxy(t, goodSrv.Listener.Addr().String()))
	b := NewBucket(16)
	b.Add(pGood) // pJunk lives only behind the pin, not in the pool

	cfg := testServerConfig(2, 1)
	cfg.Server.ServeBlockDetect = true
	fwd := NewForwardDialer(b, cfg)
	pt := NewProxyTransport(cfg, fwd)
	defer pt.base.(*http.Transport).CloseIdleConnections()
	fwd.pins.Set("k3", pJunk)

	req, err := http.NewRequest("GET", "http://example.com/", nil)
	if err != nil {
		t.Fatal(err)
	}
	req = req.WithContext(WithConnKey(req.Context(), "k3"))

	resp, err := pt.RoundTrip(req)
	if err != nil {
		t.Fatalf("RoundTrip: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if string(body) != "content-C" {
		t.Fatalf("body = %q, want content-C (did not fail over)", body)
	}
	if atomic.LoadInt64(&junkHits) != 1 {
		t.Fatalf("junk server hits = %d, want 1", junkHits)
	}
	if atomic.LoadInt64(&goodHits) != 1 {
		t.Fatalf("good server hits = %d, want 1", goodHits)
	}
	if pJunk.ConsecFails() != 1 {
		t.Fatalf("junk proxy fails = %d, want 1", pJunk.ConsecFails())
	}
	if pGood.ConsecFails() != 0 {
		t.Fatalf("good proxy was marked failed")
	}
	if b.Len() != 1 {
		t.Fatalf("bucket len = %d, want 1 (junk proxy evicted)", b.Len())
	}
	if got := fwd.pins.Get("k3"); got != pGood {
		t.Fatal("pin must remap to the healthy proxy after junk failover")
	}
}

// TestProxyTransportDeviceJunkNoAlternative verifies the no-alternative case:
// when every proxy answers with device junk, the last junk response is returned
// as-is (upstream content, not an artificial error) and each junk proxy was
// charged.
func TestProxyTransportDeviceJunkNoAlternative(t *testing.T) {
	var junkHits int64
	junkSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt64(&junkHits, 1)
		w.WriteHeader(http.StatusNotImplemented)
		w.Write([]byte("501 method not implemented"))
	}))
	defer junkSrv.Close()

	p := mustProxy(t, "http://"+startStaticConnectProxy(t, junkSrv.Listener.Addr().String()))
	b := NewBucket(16)
	b.Add(p)

	cfg := testServerConfig(2, 3)
	cfg.Server.ServeBlockDetect = true
	fwd := NewForwardDialer(b, cfg)
	pt := NewProxyTransport(cfg, fwd)
	defer pt.base.(*http.Transport).CloseIdleConnections()

	req, _ := http.NewRequest("GET", "http://example.com/", nil)
	resp, err := pt.RoundTrip(req)
	if err != nil {
		t.Fatalf("RoundTrip: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if !strings.Contains(string(body), "501") {
		t.Fatalf("junk response not returned as-is: %q", body)
	}
	if atomic.LoadInt64(&junkHits) != 2 {
		t.Fatalf("junk hits = %d, want 2 (first + one retry)", junkHits)
	}
	if p.ConsecFails() != 2 {
		t.Fatalf("junk proxy fails = %d, want 2 (charged on every retried pick)", p.ConsecFails())
	}
}

type stubRoundTrip struct {
	responses []struct {
		resp *http.Response
		err  error
	}
	calls int
}

func (s *stubRoundTrip) RoundTrip(req *http.Request) (*http.Response, error) {
	i := s.calls
	s.calls++
	if i < len(s.responses) {
		return s.responses[i].resp, s.responses[i].err
	}
	return &http.Response{StatusCode: 200, Header: http.Header{}, Body: io.NopCloser(strings.NewReader("ok")), ContentLength: 2}, nil
}

// TestProxyTransportNoRetryWhenUnattributable verifies that a transport-level
// failure with no proxy attribution (no dial ever happened) is not retried.
func TestProxyTransportNoRetryWhenUnattributable(t *testing.T) {
	p := mustProxy(t, "http://127.0.0.1:1")
	b := NewBucket(16)
	b.Add(p)

	cfg := testServerConfig(3, 1)
	fwd := NewForwardDialer(b, cfg)
	pt := NewProxyTransport(cfg, fwd)
	stub := &stubRoundTrip{responses: []struct {
		resp *http.Response
		err  error
	}{{err: errors.New("boom before dial")}}}
	pt.base = stub

	req, _ := http.NewRequest("GET", "http://example.com/", nil)
	resp, err := pt.RoundTrip(req)
	if err == nil {
		t.Fatal("expected error")
	}
	if resp != nil {
		resp.Body.Close()
	}
	if stub.calls != 1 {
		t.Fatalf("base called %d times, want 1 (no retry without attribution)", stub.calls)
	}
	if p.ConsecFails() != 0 {
		t.Fatalf("proxy must not be marked failed")
	}
}

func sr(status int, ct, body string) *http.Response {
	return &http.Response{
		StatusCode:    status,
		Header:        http.Header{"Content-Type": []string{ct}},
		Body:          io.NopCloser(strings.NewReader(body)),
		ContentLength: int64(len(body)),
	}
}

func TestBlockDetector(t *testing.T) {
	bd := newBlockDetector(true, 100)

	if resp := sr(200, "text/html; charset=utf-8", "please solve the captcha"); !bd.shouldCheck(resp) {
		t.Fatal("marker html should be checked")
	}
	if resp := sr(200, "text/plain", "access denied by antibot"); !bd.shouldCheck(resp) {
		t.Fatal("text/plain marker should be checked")
	}
	if resp := sr(200, "image/png", "captcha"); bd.shouldCheck(resp) {
		t.Fatal("non-html content must not be checked")
	}
	if resp := sr(502, "text/html", "captcha"); bd.shouldCheck(resp) {
		t.Fatal("non-200 must not be checked")
	}
	if resp := sr(200, "text/html", strings.Repeat("x", 1000)); bd.shouldCheck(resp) {
		t.Fatal("oversized body must not be checked")
	}

	resp := sr(200, "text/html", "Verify you are human to continue")
	if !bd.readAndMark(resp) {
		t.Fatal("marker not matched")
	}
	if b, _ := io.ReadAll(resp.Body); string(b) != "Verify you are human to continue" {
		t.Fatalf("body lost after sniff-rewind: %q", b)
	}

	empty := sr(200, "text/html", "")
	if !bd.readAndMark(empty) {
		t.Fatal("empty 200 must count as a blocker")
	}
	if b, _ := io.ReadAll(empty.Body); string(b) != "" {
		t.Fatalf("empty body mangled: %q", b)
	}

	clean := sr(200, "text/html", "<html>real page content</html>")
	if bd.readAndMark(clean) {
		t.Fatal("real page misidentified as blocker")
	}
	if b, _ := io.ReadAll(clean.Body); string(b) != "<html>real page content</html>" {
		t.Fatalf("real body mangled: %q", b)
	}

	off := newBlockDetector(false, 100)
	if off.shouldCheck(sr(200, "text/html", "captcha")) {
		t.Fatal("detector disabled but active")
	}

	if !bd.isDeviceJunk(sr(400, "text/plain", "Bad Request")) {
		t.Fatal("tiny 400 must be device junk")
	}
	if !bd.isDeviceJunk(sr(405, "text/plain", "nope")) {
		t.Fatal("tiny 405 must be device junk")
	}
	if !bd.isDeviceJunk(sr(501, "text/html", "not implemented")) {
		t.Fatal("tiny 501 must be device junk")
	}
	if bd.isDeviceJunk(sr(404, "text/html", "not here")) {
		t.Fatal("404 can be a legit origin answer and must not charge")
	}
	if bd.isDeviceJunk(sr(500, "text/html", "oops")) {
		t.Fatal("500 can be a transient origin answer and must not charge")
	}
	if bd.isDeviceJunk(sr(400, "text/plain", strings.Repeat("x", 1000))) {
		t.Fatal("oversized 400 must not be device junk")
	}
	if bd.isDeviceJunk(&http.Response{StatusCode: 400, Header: http.Header{}, ContentLength: -1, Body: io.NopCloser(strings.NewReader("x"))}) {
		t.Fatal("unknown-length 400 must not be charged")
	}
}

// TestPickHealthyPrefersLowestLoad verifies the load-aware term of the picker:
// among equal-health proxies the one with fewer open tunnels wins.
func TestPickHealthyPrefersLowestLoad(t *testing.T) {
	p1 := mustProxy(t, "http://10.1.0.1:3128")
	p2 := mustProxy(t, "http://10.1.0.2:3128")
	b := NewBucket(16)
	b.Add(p1)
	b.Add(p2)
	// identical health, but p1 already carries 3 tunnels
	p1.MarkInFlight()
	p1.MarkInFlight()
	p1.MarkInFlight()

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	for i := 0; i < 20; i++ {
		p, err := b.PickHealthy(ctx, 64, nil)
		if err != nil {
			t.Fatal(err)
		}
		if p != p2 {
			t.Fatalf("pick %d = %q, want p2 (under load)", i, p.Addr())
		}
	}
}

func TestPinPool(t *testing.T) {
	p1 := mustProxy(t, "http://10.1.0.1:3128")
	p2 := mustProxy(t, "http://10.1.0.2:3128")

	pool := NewPinPool(50*time.Millisecond, 4)
	pool.Set("k1", p1)
	pool.Set("k2", p2)
	if pool.Get("k1") != p1 {
		t.Fatal("k1 pin lost")
	}
	if pool.Get("zzz") != nil {
		t.Fatal("missing pin hit")
	}
	pool.Del("k2")
	if pool.Get("k2") != nil {
		t.Fatal("k2 pin not deleted")
	}

	pool.Set("k3", p2)
	pool.Set("k4", p2)
	pool.DropProxy(p2.Key())
	if pool.Get("k3") != nil || pool.Get("k4") != nil {
		t.Fatal("DropProxy did not release p2 pins")
	}

	time.Sleep(60 * time.Millisecond)
	if pool.Get("k1") != nil {
		t.Fatal("pin did not expire")
	}

	pool2 := NewPinPool(time.Minute, 2)
	pool2.Set("a", p1)
	pool2.Set("b", p1)
	pool2.Set("c", p1) // must evict the LRU, "a"
	if pool2.Get("a") != nil {
		t.Fatal("LRU eviction failed")
	}
	if pool2.Get("b") == nil || pool2.Get("c") == nil {
		t.Fatal("live pins evicted")
	}
}
