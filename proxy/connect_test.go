package proxy

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"net"
	"strings"
	"testing"
	"time"
)

// startBlackholeConnectProxy runs a CONNECT proxy that dials fine and answers
// 200 but then swallows every tunneled byte and never sends a single byte back:
// the failure class that dial-level accounting cannot see.
func startBlackholeConnectProxy(t *testing.T) string {
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
			go handleTestConnectBlackhole(c)
		}
	}()
	return ln.Addr().String()
}

func handleTestConnectBlackhole(client net.Conn) {
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
	_, _ = io.Copy(io.Discard, br) // swallow forever, never respond
}

// startEchoServer runs a TCP server that echoes everything back.
func startEchoServer(t *testing.T) string {
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
			go func(c net.Conn) {
				defer c.Close()
				_, _ = io.Copy(c, c)
			}(c)
		}
	}()
	return ln.Addr().String()
}

// serveConnectListener accepts client connections and hands each to
// ServeConnect as if goproxy's HijackConnect had fired, reporting every result.
func serveConnectListener(t *testing.T, fwd *ForwardDialer, target string) (addr string, results <-chan error) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	ch := make(chan error, 8)
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
				defer cancel()
				ch <- fwd.ServeConnect(ctx, c, "tcp", target)
			}(c)
		}
	}()
	return ln.Addr().String(), ch
}

// connectAndEcho drives one real client through ServeConnect: wait for the
// 200, send payload, expect the echo, and close.
func connectAndEcho(addr, payload string) error {
	c, err := net.Dial("tcp", addr)
	if err != nil {
		return err
	}
	defer c.Close()
	c.SetReadDeadline(time.Now().Add(10 * time.Second))
	line := make([]byte, len(connectOKLine))
	if _, err := io.ReadFull(c, line); err != nil {
		return fmt.Errorf("read 200: %w", err)
	}
	if string(line) != connectOKLine {
		return fmt.Errorf("expected 200, got %q", line)
	}
	if _, err := c.Write([]byte(payload)); err != nil {
		return err
	}
	got := make([]byte, len(payload))
	if _, err := io.ReadFull(c, got); err != nil {
		return fmt.Errorf("echo: %w", err)
	}
	if string(got) != payload {
		return fmt.Errorf("echo = %q, want %q", got, payload)
	}
	return nil
}

// startTinyReplyServer runs a TCP server that reads part of one request, writes
// a tiny fixed reply, and hangs up: the far side "completed" with almost no
// data — the misrouted/device-endpoint signature that a first-byte-OK verdict
// used to treat as a perfectly healthy tunnel.
func startTinyReplyServer(t *testing.T, reply string) string {
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
			go func(c net.Conn) {
				defer c.Close()
				br := bufio.NewReader(c)
				_, _ = br.ReadByte() // one request byte is enough
				_, _ = c.Write([]byte(reply))
			}(c)
		}
	}()
	return ln.Addr().String()
}

func connectTestConfig(retries, maxFails int, probe time.Duration) *Config {
	cfg := testServerConfig(retries, maxFails)
	cfg.Server.ServeConnectProbe = Duration{probe}
	return cfg
}

// TestServeConnectAlive: a tunnel through a healthy proxy carries a request
// and a response under supervision (no false blackhole verdicts).
func TestServeConnectAlive(t *testing.T) {
	echo := startEchoServer(t)
	p := mustProxy(t, "http://"+startStaticConnectProxy(t, echo))
	b := NewBucket(16)
	b.Add(p)

	cfg := connectTestConfig(2, 3, 2*time.Second)
	fwd := NewForwardDialer(b, cfg)
	addr, results := serveConnectListener(t, fwd, "opencorporates.com:443")

	if err := connectAndEcho(addr, "hello"); err != nil {
		t.Fatal(err)
	}
	if err := <-results; err != nil {
		t.Fatalf("ServeConnect: %v", err)
	}
	if b.Len() != 1 || p.ConsecFails() != 0 {
		t.Fatalf("healthy proxy must be untouched: len=%d fails=%d", b.Len(), p.ConsecFails())
	}
	if p.InFlight() != 0 {
		t.Fatalf("in-flight leaked: %d", p.InFlight())
	}
}

// TestServeConnectBlackholeFailsOver is the reported "second tab does not
// load" scenario: a proxy answers 200 and then blackholes the tunnel. The
// supervised tunnel detects the silence, charges and evicts the proxy, and
// transparently fails over — the browser never notices because its early bytes
// are replayed through the fresh tunnel.
func TestServeConnectBlackholeFailsOver(t *testing.T) {
	bh := mustProxy(t, "http://"+startBlackholeConnectProxy(t))
	echo := startEchoServer(t)
	good := mustProxy(t, "http://"+startStaticConnectProxy(t, echo))

	b := NewBucket(16)
	b.Add(bh) // only the blackhole exists when the tunnel starts

	cfg := connectTestConfig(2, 1, 500*time.Millisecond)
	fwd := NewForwardDialer(b, cfg)
	addr, results := serveConnectListener(t, fwd, "opencorporates.com:443")

	// The client connects immediately: at that moment the blackhole is the
	// only proxy in the bucket, so the first pick is forced. The healthy
	// proxy arrives before the 500ms probe verdict, after which the blackhole
	// is evicted and the replay fails over to it.
	errCh := make(chan error, 1)
	go func() { errCh <- connectAndEcho(addr, "ping") }()
	time.Sleep(200 * time.Millisecond)
	b.Add(good)

	if err := <-errCh; err != nil {
		t.Fatal(err)
	}
	if err := <-results; err != nil {
		t.Fatalf("ServeConnect: %v", err)
	}
	if bh.ConsecFails() != 1 {
		t.Fatalf("blackhole proxy not charged: fails=%d", bh.ConsecFails())
	}
	if b.Len() != 1 {
		t.Fatalf("bucket len = %d, want 1 (blackhole evicted)", b.Len())
	}
	if good.ConsecFails() != 0 {
		t.Fatalf("healthy proxy was marked failed")
	}
	if bh.InFlight() != 0 || good.InFlight() != 0 {
		t.Fatalf("in-flight leaked")
	}
}

// TestServeConnectAllBlackholeFails: no healthy proxy anywhere — the request
// still gets its 200 (the dial succeeded) but every tunnel is charged and
// evicted, and ServeConnect reports the failure.
func TestServeConnectAllBlackholeFails(t *testing.T) {
	bh1 := mustProxy(t, "http://"+startBlackholeConnectProxy(t))
	bh2 := mustProxy(t, "http://"+startBlackholeConnectProxy(t))
	b := NewBucket(16)
	b.Add(bh1)
	b.Add(bh2)

	cfg := connectTestConfig(2, 1, 400*time.Millisecond)
	fwd := NewForwardDialer(b, cfg)
	addr, results := serveConnectListener(t, fwd, "opencorporates.com:443")

	c, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	c.SetReadDeadline(time.Now().Add(10 * time.Second))
	line := make([]byte, len(connectOKLine))
	if _, err := io.ReadFull(c, line); err != nil || string(line) != connectOKLine {
		t.Fatalf("expected 200, got %q err=%v", line, err)
	}
	// Send a byte so each attempt lands a blackhole verdict (instead of the
	// ambiguous "client silent" branch).
	if _, err := c.Write([]byte("x")); err != nil {
		t.Fatal(err)
	}

	if err := <-results; err == nil {
		t.Fatal("ServeConnect must fail when every tunnel blackholes")
	}
	if b.Len() != 0 {
		t.Fatalf("bucket len = %d, want 0 (all evicted)", b.Len())
	}
	if bh1.ConsecFails() != 1 || bh2.ConsecFails() != 1 {
		t.Fatalf("blackholes not charged: %d %d", bh1.ConsecFails(), bh2.ConsecFails())
	}
}

// TestServeConnectConcurrentStreams mirrors the browser opening two tabs at
// once: two tunnels through the same dialer must both serve independently and
// the load accounting must unwind.
// TestServeConnectChargesLowVolumeTunnel: a proxy whose far target completes a
// tiny exchange and hangs up (a Plex/device answering 501-ish over the tunnel)
// is charged as a serving failure — it previously looked perfectly healthy
// because an immediate MarkServeOK fired on the first byte.
func TestServeConnectChargesLowVolumeTunnel(t *testing.T) {
	tiny := startTinyReplyServer(t, "tiny")
	p := mustProxy(t, "http://"+startStaticConnectProxy(t, tiny))
	b := NewBucket(16)
	b.Add(p)

	cfg := connectTestConfig(2, 1, 2*time.Second)
	fwd := NewForwardDialer(b, cfg)
	addr, results := serveConnectListener(t, fwd, "opencorporates.com:443")

	c, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	c.SetReadDeadline(time.Now().Add(10 * time.Second))
	line := make([]byte, len(connectOKLine))
	if _, err := io.ReadFull(c, line); err != nil || string(line) != connectOKLine {
		t.Fatalf("expected 200, got %q err=%v", line, err)
	}
	if _, err := c.Write([]byte("hello")); err != nil {
		t.Fatal(err)
	}
	got := make([]byte, len("tiny"))
	if _, err := io.ReadFull(c, got); err != nil {
		t.Fatalf("tunnel reply: %v", err)
	}
	// The far side replies then hangs up: ServeConnect must relay the end of
	// the tunnel to the client as EOF (a `Connection: close` style finish),
	// and then charge the low-volume exchange.
	if _, err := c.Read(make([]byte, 1)); err != io.EOF {
		t.Fatalf("tunnel did not end upstream-side: %v", err)
	}

	if err := <-results; err != nil {
		t.Fatalf("ServeConnect: %v", err)
	}
	if p.ConsecFails() != 1 {
		t.Fatalf("low-volume tunnel not charged: fails=%d", p.ConsecFails())
	}
	if b.Len() != 0 {
		t.Fatalf("bucket len = %d, want 0 (evicted)", b.Len())
	}
	if p.InFlight() != 0 {
		t.Fatalf("in-flight leaked: %d", p.InFlight())
	}
}

// TestServeConnectBigVolumeNotCharged is the control: a real (large) exchange
// through a healthy proxy must not be charged as a low-volume tunnel.
func TestServeConnectBigVolumeNotCharged(t *testing.T) {
	echo := startEchoServer(t)
	p := mustProxy(t, "http://"+startStaticConnectProxy(t, echo))
	b := NewBucket(16)
	b.Add(p)

	cfg := connectTestConfig(2, 1, 2*time.Second)
	fwd := NewForwardDialer(b, cfg)
	addr, results := serveConnectListener(t, fwd, "opencorporates.com:443")

	if err := connectAndEcho(addr, strings.Repeat("x", 64<<10)); err != nil {
		t.Fatal(err)
	}
	if err := <-results; err != nil {
		t.Fatalf("ServeConnect: %v", err)
	}
	if p.ConsecFails() != 0 {
		t.Fatalf("big exchange charged as low-volume: fails=%d", p.ConsecFails())
	}
	if b.Len() != 1 {
		t.Fatalf("bucket len = %d, want 1", b.Len())
	}
}

func TestServeConnectConcurrentStreams(t *testing.T) {
	echo := startEchoServer(t)
	p := mustProxy(t, "http://"+startStaticConnectProxy(t, echo))
	b := NewBucket(16)
	b.Add(p)

	cfg := connectTestConfig(2, 3, 2*time.Second)
	fwd := NewForwardDialer(b, cfg)
	addr, results := serveConnectListener(t, fwd, "opencorporates.com:443")

	errCh := make(chan error, 2)
	for _, payload := range []string{"tab-a", "tab-b"} {
		go func(p string) { errCh <- connectAndEcho(addr, p) }(payload)
	}
	for i := 0; i < 2; i++ {
		if err := <-errCh; err != nil {
			t.Fatalf("client %d: %v", i, err)
		}
		if err := <-results; err != nil {
			t.Fatalf("ServeConnect %d: %v", i, err)
		}
	}
	if p.InFlight() != 0 {
		t.Fatalf("in-flight leaked: %d", p.InFlight())
	}
}
