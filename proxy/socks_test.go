package proxy

import (
	"io"
	"net"
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

// The SOCKS verdict must mirror the evidence: bytes from the far side earn
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
