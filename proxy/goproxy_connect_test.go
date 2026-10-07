package proxy

import (
	"bufio"
	"crypto/tls"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/elazarl/goproxy"
)

// buildTestGoproxy mirrors main.buildGoproxy: block rules (empty here) then
// the supervised HijackConnect wiring. This guards against the two failing
// the real flow: a CONNECT that never reaches ServeConnect, or a tunnel that
// does not carry a real TLS handshake.
func buildTestGoproxy(cfg *Config, fwd *ForwardDialer) *goproxy.ProxyHttpServer {
	gop := goproxy.NewProxyHttpServer()
	gop.Verbose = false
	gop.Logger = log.New(io.Discard, "", 0)
	gop.OnRequest().HijackConnect(func(req *http.Request, client net.Conn, _ *goproxy.ProxyCtx) {
		host := req.URL.Host
		if host == "" {
			host = req.Host
		}
		if err := fwd.ServeConnect(req.Context(), client, "tcp", host); err != nil {
			gop.Logger.Printf("serveconnect: %v", err)
		}
	})
	return gop
}

// TestGoproxyRealTLSThumbtack drives the complete real-world happy path:
// browser-style CONNECT through the actual goproxy handler with our
// supervised ServeConnect, then a REAL TLS handshake and HTTP GET over the
// tunnel (the far target is a real TLS server reached via a static tiny
// CONNECT proxy).
func TestGoproxyRealTLSThumbtack(t *testing.T) {
	var hits int64
	tlsSrv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits++
		w.Write([]byte("secure-ok"))
	}))
	defer tlsSrv.Close()

	p := mustProxy(t, "http://"+startStaticConnectProxy(t, tlsSrv.Listener.Addr().String()))
	b := NewBucket(16)
	b.Add(p)
	cfg := connectTestConfig(2, 3, 3*time.Second)
	fwd := NewForwardDialer(b, cfg)
	gop := buildTestGoproxy(cfg, fwd)

	proxySrv := httptest.NewServer(gop)
	defer proxySrv.Close()
	proxyAddr := strings.TrimPrefix(proxySrv.URL, "http://")

	targetHost := tlsSrv.Listener.Addr().String()

	conn, err := net.Dial("tcp", proxyAddr)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	br := bufio.NewReader(conn)
	conn.SetDeadline(time.Now().Add(10 * time.Second))

	if _, err := io.WriteString(conn, "CONNECT "+targetHost+" HTTP/1.1\r\nHost: "+targetHost+"\r\n\r\n"); err != nil {
		t.Fatal(err)
	}
	line, err := br.ReadString('\n')
	if err != nil {
		t.Fatalf("read CONNECT response: %v", err)
	}
	if !strings.Contains(line, "200") {
		t.Fatalf("CONNECT rejected: %q", line)
	}
	// Drain the rest of the 200 headers (the blank line) so the bufio reader
	// is positioned exactly at the tunnel stream.
	for {
		h, err := br.ReadString('\n')
		if err != nil {
			t.Fatalf("drain headers: %v", err)
		}
		if h == "\r\n" || h == "\n" {
			break
		}
	}

	// Shrink obstacles: wrap the remaining buffered reader so the TLS client
	// sees every byte (incl. trailing \r\n after the status line).
	rw := struct {
		io.Reader
		io.Writer
	}{br, conn}
	client := tls.Client(tcpSide{rw}, &tls.Config{InsecureSkipVerify: true})
	if err := client.Handshake(); err != nil {
		t.Fatalf("TLS handshake: %v", err)
	}
	defer client.Close()

	if _, err := io.WriteString(client, "GET / HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n"); err != nil {
		t.Fatal(err)
	}
	body, err := io.ReadAll(client)
	if err != nil {
		t.Fatalf("read GET response: %v", err)
	}
	if !strings.Contains(string(body), "secure-ok") {
		t.Fatalf("body = %q", body)
	}
	if hits != 1 {
		t.Fatalf("target hits = %d", hits)
	}
}

// tcpSide adapts an io.Reader/io.Writer pair so tls.Client sees a net.Conn.
type tcpSide struct {
	rw struct {
		io.Reader
		io.Writer
	}
}

func (c tcpSide) Read(p []byte) (int, error)  { return c.rw.Reader.Read(p) }
func (c tcpSide) Write(p []byte) (int, error) { return c.rw.Writer.Write(p) }
func (c tcpSide) Close() error {
	if cc, ok := c.rw.Writer.(net.Conn); ok {
		return cc.Close()
	}
	return nil
}
func (c tcpSide) LocalAddr() net.Addr                { return dummyAddr{} }
func (c tcpSide) RemoteAddr() net.Addr               { return dummyAddr{} }
func (c tcpSide) SetDeadline(t time.Time) error      { return nil }
func (c tcpSide) SetReadDeadline(t time.Time) error  { return nil }
func (c tcpSide) SetWriteDeadline(t time.Time) error { return nil }

type dummyAddr struct{}

func (dummyAddr) Network() string { return "tcp" }
func (dummyAddr) String() string  { return "dummy" }
