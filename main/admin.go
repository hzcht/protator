package main

import (
	"context"
	"crypto/tls"
	"io"
	"log"
	"net"
	"net/http"
	"time"

	"golang.org/x/net/websocket"
	"protator/proxy"
)

// peekConn replays bytes that were read while deciding what a connection was.
// The admin listener uses it to inspect the first byte of every connection
// without consuming it.
type peekConn struct {
	net.Conn
	buf []byte
	off int
}

func (c *peekConn) Read(p []byte) (int, error) {
	if c.off < len(c.buf) {
		n := copy(p, c.buf[c.off:])
		c.off += n
		return n, nil
	}
	return c.Conn.Read(p)
}

// mixedListener answers HTTP and HTTPS on the same port. It reads the first
// byte of every accepted connection: 0x16 is a TLS handshake record, anything
// else is a plaintext HTTP request line.
//
// This exists because a plaintext listener behind an https:// URL fails with
// ERR_SSL_RECORD_TOO_LONG / ERR_SSL_WRONG_VERSION_NUMBER: the browser sends a
// TLS ClientHello, the server answers with HTTP, and the record boundaries no
// longer line up. Handing net/http either the raw connection or a *tls.Conn
// keeps a single http.Server for both, since net/http does the handshake and
// fills in r.TLS whenever the connection it is given is a *tls.Conn.
type mixedListener struct {
	net.Listener
	tlsConfig *tls.Config
}

// sniffTimeout bounds how long a connection may sit without sending its first
// byte. Without it one silent client would stall the whole accept loop.
const sniffTimeout = 5 * time.Second

func (l *mixedListener) Accept() (net.Conn, error) {
	for {
		c, err := l.Listener.Accept()
		if err != nil {
			return nil, err
		}
		pc := &peekConn{Conn: c}
		_ = c.SetReadDeadline(time.Now().Add(sniffTimeout))
		var b [1]byte
		if _, err := io.ReadFull(pc, b[:]); err != nil {
			c.Close()
			continue // vanished or stalled before saying hello: try the next
		}
		_ = c.SetReadDeadline(time.Time{})
		pc.buf = b[:]
		pc.off = 0
		if b[0] == 0x16 { // TLS handshake record
			return tls.Server(pc, l.tlsConfig), nil
		}
		return pc, nil
	}
}

// listenMixed binds addr and, when tlsConfig is non-nil, wraps it so the same
// port answers HTTP and HTTPS.
func listenMixed(addr string, tlsConfig *tls.Config) (net.Listener, error) {
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return nil, err
	}
	if tlsConfig == nil {
		return ln, nil
	}
	return &mixedListener{Listener: ln, tlsConfig: tlsConfig}, nil
}

// newAdminServer builds the admin listener. ErrorLog goes through the shared
// noise dampener — the mixed port takes TLS handshakes (and the failures that
// come with untrusted self-signed certs, scanners, plain-HTTP mistakes), and
// without it every failed handshake lands raw in stderr.
func newAdminServer(a *admin, logNoise *log.Logger) *http.Server {
	return &http.Server{
		Handler:           a.routes(),
		ErrorLog:          logNoise,
		ReadHeaderTimeout: 10 * time.Second,
	}
}

// routes builds the admin HTTP surface. Split out of startAdminServer so tests
// can exercise the exact same handlers.
func (a *admin) routes() *http.ServeMux {
	mux := http.NewServeMux()
	mux.HandleFunc("/", a.handleIndex)
	mux.HandleFunc("/health", a.handleHealth)
	mux.HandleFunc("/ready", a.handleReady)
	mux.HandleFunc("/api/sources", a.handleSources)
	mux.HandleFunc("/api/sites", a.handleSites)
	mux.HandleFunc("/api/proxies", a.handleProxies)
	mux.HandleFunc("/api/proxies/revalidate", a.handleProxiesRevalidate)
	mux.HandleFunc("/api/stats/history", a.handleStatsHistory)
	mux.Handle("/ws", websocket.Handler(a.handleWebSocket)) // WebSocket for live updates
	mux.HandleFunc("/static/admin.css", a.handleCSS)
	mux.HandleFunc("/static/admin.js", a.handleJS)
	return mux
}

// startAdminServer exposes the local admin UI and JSON metrics on
// cfg.Server.AdminListen (empty = disabled). One port answers both HTTP and
// HTTPS: the first byte of each connection decides, so the page can be opened
// with either scheme without a port mismatch.
//
//	GET  /            -> admin UI (source stats, live proxies, site editor)
//	GET  /health      -> current queue/pool/checker state
//	GET  /ready       -> 200 when the queue has live proxies, 503 otherwise
//	GET  /api/sources -> per-source telemetry
//	GET  /api/sites   -> current sites.txt entries
//	POST /api/sites   -> add a source: {"url": "..."}
//	DELETE /api/sites -> remove a source: {"url": "..."}
//	GET  /api/proxies -> live proxies; ?scope=hot|served|checked|all&format=text
//
// It carries no proxy traffic and no auth — bind it to 127.0.0.1 unless the
// machine is firewalled.
func startAdminServer(ctx context.Context, cfg *proxy.Config, bucket *proxy.Bucket, pool *proxy.CandidatePool, collector *proxy.Collector, logNoise *log.Logger) {
	if cfg.Server.AdminListen == "" {
		return
	}
	a := &admin{cfg: cfg, bucket: bucket, pool: pool, collector: collector, started: time.Now(), prevProxies: make(map[string]liveRow), prevHealth: make(map[string]int)}

	cert, err := proxy.LoadOrCreateTLS(cfg.Server.TLSCertFile, cfg.Server.TLSKeyFile)
	var tlsConfig *tls.Config
	if err != nil {
		// A broken cert pair must not cost the operator the metrics endpoint.
		log.Printf("admin: TLS unavailable (%v); serving plain HTTP only", err)
	} else {
		tlsConfig = &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12}
	}

	ln, err := listenMixed(cfg.Server.AdminListen, tlsConfig)
	if err != nil {
		log.Fatalf("admin: %v", err)
	}

	srv := newAdminServer(a, logNoise)
	// Wire bucket changes to WebSocket broadcasts
	bucket.OnChange = func(p *proxy.Proxy, added bool) {
		a.notifyWSChanged()
	}
	a.startStatsRecorder(ctx) // start 24h stats history recorder
	go func() {
		log.Printf("admin: ui + health on %s (http and https)", ln.Addr())
		if err := srv.Serve(ln); err != nil && err != http.ErrServerClosed {
			log.Fatalf("admin: %v", err)
		}
	}()
	go func() {
		<-ctx.Done()
		shutCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		srv.Shutdown(shutCtx)
	}()
}
