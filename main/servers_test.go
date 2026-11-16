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
