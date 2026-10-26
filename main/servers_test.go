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
