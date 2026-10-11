package proxy

import (
	"bytes"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"sync"
	"testing"
	"time"
)

// relayCount must split volume by direction: the SOCKS verdict tells far-side
// silence apart from a session where nobody spoke.
func TestRelayCountSplitsDirections(t *testing.T) {
	c1, c2 := net.Pipe()
	u1, u2 := net.Pipe()
	var wg sync.WaitGroup
	wg.Add(2)
	go func() { // client side: sends 5, receives 10
		defer wg.Done()
		defer c2.Close()
		if _, err := c2.Write([]byte("hello")); err != nil {
			return
		}
		_, _ = io.ReadFull(c2, make([]byte, 10))
	}()
	go func() { // upstream side: receives 5, sends 10
		defer wg.Done()
		defer u2.Close()
		if _, err := io.ReadFull(u2, make([]byte, 5)); err != nil {
			return
		}
		_, _ = u2.Write([]byte("0123456789"))
	}()
	fromA, fromB := relayCount(c1, u1, 5*time.Second)
	wg.Wait()
	// relayCount(conn, up): fromA is client->upstream, fromB upstream->client.
	if fromA != 5 || fromB != 10 {
		t.Fatalf("relayCount = (%d, %d), want (5, 10)", fromA, fromB)
	}
}

// relayCount must propagate a clean half-close: a client that sends its
// request, CloseWrites, and waits for the response would hang until the idle
// timeout if the FIN died at pipe(). Real TCP ends (not net.Pipe) so the
// CloseWrite paths are the production ones.
func TestRelayCountPropagatesHalfClose(t *testing.T) {
	// Far side: reads until the FIN, then answers and hangs up.
	reply := bytes.Repeat([]byte("r"), 64)
	uln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer uln.Close()
	farGot := make(chan []byte, 1)
	go func() {
		c, err := uln.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		req, _ := io.ReadAll(c) // ends on the propagated FIN
		farGot <- req
		_, _ = c.Write(reply)
	}()

	// Client end: send, half-close, then drain the answer.
	cln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer cln.Close()
	clientGot := make(chan []byte, 1)
	go func() {
		c, err := cln.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		if _, err := c.Write([]byte("hello")); err != nil {
			return
		}
		if err := c.(*net.TCPConn).CloseWrite(); err != nil {
			return
		}
		body, _ := io.ReadAll(c)
		clientGot <- body
	}()

	clientConn, err := net.Dial("tcp", cln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	upConn, err := net.Dial("tcp", uln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	toUp, toDown := relayCount(clientConn, upConn, 5*time.Second)

	if got := <-farGot; string(got) != "hello" {
		t.Fatalf("far side read %q, want hello (FIN must propagate)", got)
	}
	if got := <-clientGot; !bytes.Equal(got, reply) {
		t.Fatalf("client read %q, want %q (response must drain past half-close)", got, reply)
	}
	if toUp != 5 || toDown != int64(len(reply)) {
		t.Fatalf("relayCount = (%d, %d), want (5, %d)", toUp, toDown, len(reply))
	}
}

// A SOCKS5 client handshake through the real front: greeting, CONNECT request,
// tunnel relay to a static CONNECT upstream, and a GET over it — plus the
// health feedback the chain must produce. Unit tests cover relayCount and
// settle in isolation; this is the only thing that catches a regression in
// "client bytes → front → upstream → target → verdict".
func TestSocks5HandshakeTunnelEndToEnd(t *testing.T) {
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("target-ok"))
	}))
	defer target.Close()

	upstream := "http://" + startStaticConnectProxy(t, target.Listener.Addr().String())
	p := mustProxy(t, upstream)
	b := NewBucket(16)
	b.Add(p)
	fwd := NewForwardDialer(b, testServerConfig(2, 3))
	s := &Socks5Server{dialer: fwd, dialTO: 5 * time.Second, idleTO: 5 * time.Second}

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	served := make(chan struct{})
	go func() {
		defer close(served)
		c, err := ln.Accept()
		if err != nil {
			return
		}
		s.handle(c)
	}()

	c, err := net.DialTimeout("tcp", ln.Addr().String(), 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(15 * time.Second))

	// Greeting: version + 1 method (no auth).
	if _, err := c.Write([]byte{0x05, 0x01, 0x00}); err != nil {
		t.Fatal(err)
	}
	var greetResp [2]byte
	if _, err := io.ReadFull(c, greetResp[:]); err != nil {
		t.Fatal(err)
	}
	if greetResp != [2]byte{0x05, 0x00} {
		t.Fatalf("greeting reply = %v, want [5 0]", greetResp)
	}

	// CONNECT 127.0.0.1:<targetport>, ATYP IPv4.
	host, portStr, err := net.SplitHostPort(target.Listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	port, err := strconv.Atoi(portStr)
	if err != nil {
		t.Fatal(err)
	}
	ip := net.ParseIP(host).To4()
	if ip == nil {
		t.Fatalf("target is not IPv4: %s", host)
	}
	req := []byte{0x05, 0x01, 0x00, 0x01, ip[0], ip[1], ip[2], ip[3], byte(port >> 8), byte(port)}
	if _, err := c.Write(req); err != nil {
		t.Fatal(err)
	}
	var connResp [10]byte
	if _, err := io.ReadFull(c, connResp[:]); err != nil {
		t.Fatal(err)
	}
	if connResp[0] != 0x05 || connResp[1] != 0x00 {
		t.Fatalf("connect reply = %v, want success", connResp)
	}

	// A real request over the tunnel, answered by the far target.
	if _, err := fmt.Fprintf(c, "GET / HTTP/1.0\r\nHost: %s\r\n\r\n", target.Listener.Addr()); err != nil {
		t.Fatal(err)
	}
	body, err := io.ReadAll(c)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(body, []byte("target-ok")) {
		t.Fatalf("tunnel body = %q, want target-ok", body)
	}
	<-served

	// The chain must have settled health, not just moved bytes.
	if p.OKTotal() < 1 || p.LastServed().IsZero() {
		t.Fatalf("served session left no proof of life: ok=%d served=%v", p.OKTotal(), p.LastServed())
	}
	if b.HotLen() != 1 {
		t.Fatalf("hot tail = %d, want 1 (served session promotes)", b.HotLen())
	}
}

// proof of life, client bytes into silence are charged, and a session where
// nobody spoke (port probe, instant close) settles neutrally — never rewarded.
func TestSocksSettleVerdicts(t *testing.T) {
	b := NewBucket(16)
	cfg := testServerConfig(2, 1)
	fwd := NewForwardDialer(b, cfg)
	s := &Socks5Server{dialer: fwd}

	pOK := mustProxy(t, "http://10.7.7.1:3128")
	b.Add(pOK)
	s.settle(pOK, 3, 10)
	if pOK.OKTotal() != 1 || pOK.LastServed().IsZero() {
		t.Fatalf("healthy session: OK=%d served=%v, want proof of life",
			pOK.OKTotal(), pOK.LastServed())
	}
	if b.HotLen() != 1 {
		t.Fatalf("hot tail = %d, want 1 (served session promotes)", b.HotLen())
	}

	pDead := mustProxy(t, "http://10.7.7.2:3128")
	b.Add(pDead)
	s.settle(pDead, 5, 0)
	if pDead.ConsecFails() != 1 || pDead.OKTotal() != 0 {
		t.Fatalf("blackhole session: fails=%d ok=%d, want charged and unrewarded",
			pDead.ConsecFails(), pDead.OKTotal())
	}
	if b.Len() != 1 {
		t.Fatalf("bucket len = %d, want 1 (blackhole evicted at maxFails=1)", b.Len())
	}

	pIdle := mustProxy(t, "http://10.7.7.3:3128")
	b.Add(pIdle)
	s.settle(pIdle, 0, 0)
	if pIdle.OKTotal() != 0 || pIdle.ConsecFails() != 0 {
		t.Fatalf("silent session: ok=%d fails=%d, want neutral",
			pIdle.OKTotal(), pIdle.ConsecFails())
	}
	if b.HotLen() != 1 {
		t.Fatalf("hot tail = %d, want still 1 (silence promotes nothing)", b.HotLen())
	}
}
