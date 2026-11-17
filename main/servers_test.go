package main

import (
	"bufio"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"protator/proxy"
)

// The two control-header helpers are the only place where a client-supplied
// header is interpreted and removed: a mistake here either drops stickiness
// (header read but never applied) or fingerprints the tool in the target's
// logs (header forwarded).
func TestStickySessionHeaderAliases(t *testing.T) {
	cases := []struct {
		name string
		h    http.Header
		want string
	}{
		{"legacy", http.Header{"X-Sticky-Session": {"cart-1"}}, "cart-1"},
		{"new", http.Header{"X-Proxy-Session": {"cart-2"}}, "cart-2"},
		{"legacy wins", http.Header{"X-Sticky-Session": {"a"}, "X-Proxy-Session": {"b"}}, "a"},
		{"absent", http.Header{}, ""},
	}
	for _, c := range cases {
		if got := stickySession(c.h); got != c.want {
			t.Errorf("%s: stickySession = %q, want %q", c.name, got, c.want)
		}
	}

	// A session id becomes a PinPool map key; an unbounded one is a memory
	// write primitive handed to any client.
	long := strings.Repeat("x", stickySessionIDMax*2)
	if got := stickySession(http.Header{"X-Proxy-Session": {long}}); len(got) != stickySessionIDMax {
		t.Fatalf("long session id = %d bytes, want %d", len(got), stickySessionIDMax)
	}
}

func TestStripControlHeaders(t *testing.T) {
	h := http.Header{
		"X-Proxy-Session": {"cart-1"},
		"X-Proxy-Country": {"DE"},
		"x-proxy-lower":   {"1"},
		"User-Agent":      {"curl/8"},
		"Cookie":          {"a=b"},
	}
	stripControlHeaders(h)
	for _, name := range []string{"X-Proxy-Session", "X-Proxy-Country", "x-proxy-lower"} {
		if v := h.Get(name); v != "" {
			t.Errorf("%s leaked through: %q", name, v)
		}
	}
	if h.Get("User-Agent") == "" || h.Get("Cookie") == "" {
		t.Fatalf("stripControlHeaders ate unrelated headers: %v", h)
	}
}

// The ACL/waste chain must hold end to end through the real front: a request
// to a waste host is short-circuited without ever dialing, and a CONNECT to a
// blocked host is rejected without a tunnel. Unit tests cover the dial layer;
// only this catches a regression in "browser → front → rule".
//
// Both legs speak raw TCP: goproxy hijacks the connection for CONNECT, which
// httptest.ResponseRecorder cannot do, so a recorder test would measure the
// harness instead of the rule.
func TestFrontWasteAndBlockRules(t *testing.T) {
	cfg := &proxy.Config{}
	cfg.Server.WasteHosts = []string{"tracker.example"}
	cfg.Server.BlockConnect = []string{`evil\.example`}
	bucket := proxy.NewBucket(16)
	fwd := proxy.NewForwardDialer(bucket, cfg)
	gop := buildGoproxy(cfg, fwd, log.New(io.Discard, "", 0))
	srv := httptest.NewServer(gop)
	defer srv.Close()

	dial := func(t *testing.T) net.Conn {
		t.Helper()
		c, err := net.DialTimeout("tcp", strings.TrimPrefix(srv.URL, "http://"), 5*time.Second)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { c.Close() })
		_ = c.SetDeadline(time.Now().Add(10 * time.Second))
		return c
	}
	readStatus := func(t *testing.T, c net.Conn) (int, string) {
		t.Helper()
		br := bufio.NewReader(c)
		line, err := br.ReadString('\n')
		if err != nil {
			t.Fatal(err)
		}
		var proto string
		var code int
		if _, err := fmt.Sscanf(line, "%s %d", &proto, &code); err != nil {
			t.Fatalf("bad status line %q: %v", line, err)
		}
		rest, err := io.ReadAll(br)
		if err != nil {
			t.Fatal(err)
		}
		return code, string(rest)
	}

	// Waste host: short-circuit body, and nothing was dialed (the bucket is
	// empty, so any dial attempt would fail the request instead).
	c := dial(t)
	fmt.Fprintf(c, "GET http://tracker.example/pixel.gif HTTP/1.1\r\nHost: tracker.example\r\nConnection: close\r\n\r\n")
	if code, body := readStatus(t, c); code != http.StatusOK || !strings.Contains(body, "Waste") {
		t.Fatalf("waste host: code=%d body=%q, want 200 Waste", code, body)
	}

	// Blocked CONNECT: rejected, no tunnel follows. goproxy's AlwaysReject
	// carries no response body, so the rejection is a close with no status
	// line — EOF, not a 403. What matters is that nothing is tunneled: no
	// "200 Connection established", no bytes at all.
	c2 := dial(t)
	fmt.Fprintf(c2, "CONNECT evil.example:443 HTTP/1.1\r\nHost: evil.example:443\r\n\r\n")
	br := bufio.NewReader(c2)
	if line, err := br.ReadString('\n'); err != io.EOF {
		t.Fatalf("blocked CONNECT: got %q (err=%v), want EOF (closed, no tunnel)", line, err)
	}
}

// TestFrontTunnelsConnectThroughUpstream walks the whole serving path a client
// actually takes: client → goproxy front → hijack handler → forward dialer →
// upstream CONNECT proxy → target. The rule test above stops at the
// short-circuits and proxy/connect_test.go covers ServeConnect directly, so
// this is the only test that crosses the library's hijack handover.
//
// That seam is exactly what a goproxy upgrade can move: 1.9.3 started replaying
// bytes a client pipelined with its CONNECT into the tunnel, and a regression
// there looks like "the tunnel opens and then hangs" — invisible to every
// handler-level test.
func TestFrontTunnelsConnectThroughUpstream(t *testing.T) {
	echo := startTestEchoTarget(t)
	upstream := startTestConnectUpstream(t)

	p, err := proxy.ParseProxyLine("http://" + upstream)
	if err != nil {
		t.Fatalf("ParseProxyLine(%s): %v", upstream, err)
	}
	bucket := proxy.NewBucket(16)
	if !bucket.Add(p) {
		t.Fatal("bucket rejected the upstream")
	}

	// A literal Config{} leaves ServeRetries at 0, and ForwardDialer.DialContext
	// loops "attempt < serveRetries" — zero attempts, and the tunnel would fail
	// with no upstream ever being tried. IdleConnTimeout is the relay write
	// deadline; at 0 every write gets "deadline now" and the probe kills a
	// tunnel that is working perfectly.
	cfg := &proxy.Config{}
	cfg.Server.DialTimeout = proxy.Duration{Duration: 2 * time.Second}
	cfg.Server.ServeTotalTimeout = proxy.Duration{Duration: 10 * time.Second}
	cfg.Server.ServeConnectProbe = proxy.Duration{Duration: 2 * time.Second}
	cfg.Server.IdleConnTimeout = proxy.Duration{Duration: 5 * time.Second}
	cfg.Server.ServeRetries = 2
	cfg.Server.ServeMaxFails = 3
	cfg.Server.PickProbes = 1

	fwd := proxy.NewForwardDialer(bucket, cfg)
	gop := buildGoproxy(cfg, fwd, log.New(io.Discard, "", 0))
	srv := httptest.NewServer(gop)
	defer srv.Close()

	c, err := net.DialTimeout("tcp", strings.TrimPrefix(srv.URL, "http://"), 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Close() })
	_ = c.SetDeadline(time.Now().Add(10 * time.Second))

	fmt.Fprintf(c, "CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\n", echo, echo)
	br := bufio.NewReader(c)
	status, err := br.ReadString('\n')
	if err != nil {
		t.Fatalf("reading CONNECT status %q: %v", status, err)
	}
	var proto string
	var code int
	if _, err := fmt.Sscanf(status, "%s %d", &proto, &code); err != nil {
		t.Fatalf("bad CONNECT status line %q: %v", status, err)
	}
	if code != http.StatusOK {
		t.Fatalf("CONNECT status = %d (%q), want 200", code, status)
	}
	for {
		line, err := br.ReadString('\n')
		if err != nil {
			t.Fatalf("reading CONNECT headers (%q): %v", line, err)
		}
		if line == "\r\n" || line == "\n" {
			break
		}
	}

	// Once the tunnel is up it must be byte-transparent in both directions.
	payload := []byte("ping-through-the-front")
	if _, err := c.Write(payload); err != nil {
		t.Fatalf("write into tunnel: %v", err)
	}
	got := make([]byte, len(payload))
	if _, err := io.ReadFull(br, got); err != nil {
		t.Fatalf("read from tunnel: %v", err)
	}
	if string(got) != string(payload) {
		t.Fatalf("tunnel echoed %q, want %q", got, payload)
	}
}

// startTestEchoTarget starts a listener that echoes every byte back. The
// returned address is what the CONNECT request names as its target.
func startTestEchoTarget(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				io.Copy(c, c)
			}(conn)
		}
	}()
	return ln.Addr().String()
}

// startTestConnectUpstream starts a deliberately minimal CONNECT proxy: it
// parses one request line, dials the named host and splices the two
// connections. No keep-alive, no auth, no CONNECT probing of its own — the path
// under test is our dialer and our hijack handler, not this half.
func startTestConnectUpstream(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				req, err := http.ReadRequest(bufio.NewReader(c))
				if err != nil {
					return
				}
				target, err := net.DialTimeout("tcp", req.Host, 2*time.Second)
				if err != nil {
					fmt.Fprintf(c, "HTTP/1.1 502 Bad Gateway\r\n\r\n")
					return
				}
				defer target.Close()
				if _, err := io.WriteString(c, "HTTP/1.1 200 Connection established\r\n\r\n"); err != nil {
					return
				}
				done := make(chan struct{})
				go func() {
					io.Copy(target, c)
					close(done)
				}()
				io.Copy(c, target)
				<-done
			}(conn)
		}
	}()
	return ln.Addr().String()
}
