package proxy

import (
	"context"
	"net"
	"sync"
	"testing"
	"time"
)

// blackholeAfterConnect answers the CONNECT handshake and then never sends
// another byte: the tunnel is up, the far side is silent. This is the failure
// class the first-byte probe exists for — the dial succeeded, so dial-level
// accounting sees a healthy proxy, and the client would otherwise wait out the
// whole response_header_timeout before being retried elsewhere.
func blackholeAfterConnect(t *testing.T) (addr string, stop func()) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	done := make(chan struct{})
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			wg.Add(1)
			go func(c net.Conn) {
				defer wg.Done()
				defer c.Close()
				buf := make([]byte, 4096)
				for {
					n, err := c.Read(buf)
					if err != nil {
						return
					}
					if containsCRLFCRLF(buf[:n]) {
						break
					}
				}
				_, _ = c.Write([]byte("HTTP/1.1 200 Connection established\r\n\r\n"))
				<-done // tunnel up, far side silent
			}(c)
		}
	}()
	return ln.Addr().String(), func() { close(done); ln.Close(); wg.Wait() }
}

func newTestDialer(bucket *Bucket, probe time.Duration) *ForwardDialer {
	cfg := &Config{}
	cfg.Server.DialTimeout = Duration{2 * time.Second}
	cfg.Server.ServeResponseProbe = Duration{probe}
	cfg.Server.ServeRetries = 1
	return NewForwardDialer(bucket, cfg)
}

func addProxy(t *testing.T, b *Bucket, addr string) *Proxy {
	t.Helper()
	p, err := ParseProxyLine("http://" + addr)
	if err != nil {
		t.Fatal(err)
	}
	b.Add(p)
	return p
}

// With the probe armed, a blackholed tunnel must be abandoned within the probe
// window — not after the 10s response header timeout.
func TestPlainHTTPFirstByteProbeAbandonsBlackhole(t *testing.T) {
	addr, stop := blackholeAfterConnect(t)
	defer stop()
	b := NewBucket(10)
	addProxy(t, b, addr)
	d := newTestDialer(b, 300*time.Millisecond)

	start := time.Now()
	conn, err := d.dialHTTP(context.Background(), "tcp", "example.com:80")
	if err != nil {
		t.Fatalf("dial through a blackhole proxy should succeed (CONNECT was answered): %v", err)
	}
	defer conn.Close()
	if _, err := conn.Read(make([]byte, 1)); err == nil {
		t.Fatal("a blackholed proxy produced a byte")
	}
	if elapsed := time.Since(start); elapsed > 3*time.Second {
		t.Errorf("blackhole held the request for %s; the probe should have cut it at ~300ms", elapsed)
	}
}

// The probe must not fire on a proxy that answers, however slowly: the
// deadline is cleared by the first byte, so only silence is fatal.
func TestPlainHTTPFirstByteProbeClearsOnFirstByte(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		buf := make([]byte, 4096)
		for {
			n, err := c.Read(buf)
			if err != nil {
				return
			}
			if containsCRLFCRLF(buf[:n]) {
				break
			}
		}
		// The tunnel is up immediately; the far side answers slowly.
		_, _ = c.Write([]byte("HTTP/1.1 200 Connection established\r\n\r\n"))
		time.Sleep(600 * time.Millisecond)
		_, _ = c.Write([]byte("HTTP/1.1 200 OK\r\n\r\n"))
		time.Sleep(time.Second)
	}()

	b := NewBucket(10)
	addProxy(t, b, ln.Addr().String())
	// The probe is wider than the answer delay: slow must survive.
	d := newTestDialer(b, time.Second)

	start := time.Now()
	conn, err := d.dialHTTP(context.Background(), "tcp", "example.com:80")
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if _, err := conn.Read(make([]byte, 1)); err != nil {
		t.Fatalf("a slow-but-answering proxy was cut off: %v", err)
	}
	if elapsed := time.Since(start); elapsed < 500*time.Millisecond {
		t.Errorf("answered after %s, expected the ~600ms delay to be honoured", elapsed)
	}
}

// The SOCKS5 front-end dials DialContext directly and must not get a read
// deadline: its tunnels are long-lived.
func TestSOCKS5DialHasNoFirstByteDeadline(t *testing.T) {
	addr, stop := blackholeAfterConnect(t)
	defer stop()
	b := NewBucket(10)
	addProxy(t, b, addr)
	d := newTestDialer(b, 300*time.Millisecond)

	conn, err := d.DialContext(context.Background(), "tcp", "example.com:80")
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if _, ok := conn.(*firstByteConn); ok {
		t.Error("a direct (SOCKS5-path) dial got the first-byte deadline")
	}
}

// With the probe disabled the old behaviour is kept: no deadline is armed.
func TestPlainHTTPProbeCanBeDisabled(t *testing.T) {
	addr, stop := blackholeAfterConnect(t)
	defer stop()
	b := NewBucket(10)
	addProxy(t, b, addr)
	d := newTestDialer(b, 0)

	conn, err := d.dialHTTP(context.Background(), "tcp", "example.com:80")
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if _, ok := conn.(*firstByteConn); ok {
		t.Error("probe disabled but the deadline was still armed")
	}
}
