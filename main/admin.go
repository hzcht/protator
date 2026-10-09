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
//
// IdleTimeout is set because ReadHeaderTimeout alone leaves an idle keep-alive
// connection (and its goroutine) parked indefinitely. ReadTimeout and
// WriteTimeout are deliberately NOT set: the /ws handler hijacks the
// connection and golang.org/x/net/websocket does not clear the deadline off it,
// so either one would cut a live WebSocket after its timeout. The WebSocket
// manages its own deadline instead (see handleWebSocket).
func newAdminServer(a *admin, logNoise *log.Logger) *http.Server {
	return &http.Server{
		Handler:           a.routes(),
		ErrorLog:          logNoise,
		ReadHeaderTimeout: 10 * time.Second,
		IdleTimeout:       120 * time.Second,
	}
}

// routes builds the admin HTTP surface. Split out of startAdminServer so tests
// can exercise the exact same handlers.
//
// The token gate (requireAdminToken) covers everything except /health and
// /ready: those are supervisor probes that must keep answering when no human
// can authenticate, and they reveal nothing the process does not already treat
// as public by serving traffic.
func (a *admin) routes() *http.ServeMux {
	mux := http.NewServeMux()
	mux.HandleFunc("/", a.handleIndex)
	mux.HandleFunc("/health", a.handleHealth)
	mux.HandleFunc("/ready", a.handleReady)
	mux.HandleFunc("/api/metrics", a.requireAdminToken(a.handleMetrics))
	mux.HandleFunc("/api/logs", a.requireAdminToken(a.handleLogs))
	mux.HandleFunc("/api/config", a.requireAdminToken(a.handleConfig))
	mux.HandleFunc("/api/sources", a.requireAdminToken(a.handleSources))
	mux.HandleFunc("/api/sources/cooldown", a.requireAdminToken(a.handleSourceResetCooldown))
	mux.HandleFunc("/api/collector/wake", a.requireAdminToken(a.handleCollectorWake))
	mux.HandleFunc("/api/sites", a.requireAdminToken(a.handleSites))
	mux.HandleFunc("/api/proxies", a.requireAdminToken(a.handleProxies))
	mux.HandleFunc("/api/proxies/revalidate", a.requireAdminToken(a.handleProxiesRevalidate))
	mux.HandleFunc("/api/stats/history", a.requireAdminToken(a.handleStatsHistory))
	mux.Handle("/ws", websocket.Handler(a.handleWebSocket)) // WebSocket for live updates
	// pprof, behind the same token: profiling the live process is a routine
	// debugging step, and an admin listener that cannot answer it sends the
	// developer back to SSH into a production box.
	for path, handler := range pprofHandlers {
		mux.HandleFunc(path, a.requireAdminToken(handler))
	}
	mux.HandleFunc("/static/admin.css", a.requireAdminToken(a.handleCSS))
	mux.HandleFunc("/static/admin.js", a.requireAdminToken(a.handleJS))
	return mux
}

// startAdminServer exposes the local admin UI and JSON metrics on
// cfg.Server.AdminListen (empty = disabled). One port answers both HTTP and
// HTTPS: the first byte of each connection decides, so the page can be opened
// with either scheme without a port mismatch.
//
//	GET  /              admin UI (live proxies, per-source stats, sites editor)
//	GET  /health        full state: queue counts, heartbeats, metrics, goroutines
//	GET  /ready         200 only while the queue has *proven* proxies, 503 otherwise
//	GET  /api/metrics   counters + per-second rates + gauges (?format=text for Prometheus)
//	GET  /api/logs      in-memory tail of one log category (?category=collector|checker|serve|system)
//	GET  /api/config    effective config (secrets redacted)
//	GET  /api/sources   per-source telemetry
//	GET/POST/DELETE /api/sites  read and edit sites.txt in place (atomic + .bak)
//	GET  /api/proxies   live proxies; ?scope=hot|served|checked|all&format=text|csv|jsonl
//	POST /api/proxies/revalidate  force a re-check of the given proxies
//	POST /api/sources/cooldown     clear a source's failure cooldown
//	POST /api/collector/wake       force a collector cycle now
//
// Everything but /health and /ready requires server.admin_token when that is
// set. It carries no proxy traffic; bind it to 127.0.0.1 unless the machine is
// firewalled.
func startAdminServer(ctx context.Context, cfg *proxy.Config, bucket *proxy.Bucket, pool *proxy.CandidatePool, collector *proxy.Collector, checker *proxy.Checker, debug *proxy.DebugProxies, sink *fileLogSink, beats *beats, workers *checkerWorkers, wake chan<- struct{}, candidates <-chan proxy.Candidate, logNoise *log.Logger) {
	if cfg.Server.AdminListen == "" {
		return
	}
	warnAdminExposure(cfg.Server.AdminListen, cfg.Server.AdminToken)

	cert, err := proxy.LoadOrCreateTLS(cfg.Server.TLSCertFile, cfg.Server.TLSKeyFile)
	var tlsConfig *tls.Config
	if err != nil {
		// A broken cert pair must not cost the operator the metrics endpoint.
		log.Printf("admin: TLS unavailable (%v); serving plain HTTP only", err)
	} else {
		tlsConfig = &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12}
	}

	a := &admin{
		cfg: cfg, bucket: bucket, pool: pool, collector: collector, checker: checker,
		debug: debug, sink: sink, beats: beats, workers: workers, wakeCollector: wake,
		candidates: candidates, ctx: ctx, started: time.Now(), cfgPath: cfg.Path(),
		tlsConfigured: tlsConfig != nil,
		ws:            newWSHub(),
	}

	ln, err := listenMixed(cfg.Server.AdminListen, tlsConfig)
	if err != nil {
		log.Fatalf("admin: %v", err)
	}

	srv := newAdminServer(a, logNoise)
	// Wire bucket changes to WebSocket broadcasts. The subscriber callback
	// only flags a pending change: it runs inline on the mutation path (every
	// checker add, every revalidation drop, every serving-path eviction),
	// where a full delta computation — whole-queue scan + diff + JSON marshal
	// — must not run per mutation. startWSNotifier coalesces the flags into
	// at most one broadcast per tick.
	bucket.Subscribe(func(p *proxy.Proxy, added bool) {
		a.ws.requestNotify()
	})
	go a.startWSNotifier(ctx)
	a.startStatsRecorder(ctx) // start 24h stats history recorder
	go func() {
		log.Printf("admin: ui + health on %s (http and https)", ln.Addr())
		// Runtime accept failure must not exit: log.Fatalf would skip main's
		// defers and lose the unsaved queue. The bind above is already fatal.
		if err := srv.Serve(ln); err != nil && err != http.ErrServerClosed {
			log.Printf("admin: serve stopped on %s: %v", ln.Addr(), err)
		}
	}()
	go func() {
		<-ctx.Done()
		shutCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		srv.Shutdown(shutCtx)
	}()
}
