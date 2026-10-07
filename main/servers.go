package main

import (
	"context"
	"crypto/tls"
	"log"
	"net"
	"net/http"
	"regexp"
	"time"

	"github.com/elazarl/goproxy"
	"protator/proxy"
)

// startServers launches the HTTP, HTTPS and (optionally) SOCKS5 forward
// proxies. A listener that fails to bind is fatal. It returns a shutdown
// function for the graceful drain: SOCKS stops accepting immediately, then
// every http server drains in-flight requests up to the ctx deadline.
func startServers(ctx context.Context, cfg *proxy.Config, bucket *proxy.Bucket, fwd *proxy.ForwardDialer, logNoise *log.Logger) func(context.Context) {
	var servers []*http.Server
	servers = append(servers, startHTTPServer(cfg, fwd, logNoise))
	servers = append(servers, startHTTPSServer(cfg, fwd, logNoise))

	var socks *proxy.Socks5Server
	if cfg.Socks5.Enabled {
		socks = proxy.NewSocks5Server(cfg, fwd)
		go func() {
			log.Printf("socks5: proxy listening on %s", cfg.Socks5.Listen)
			if err := socks.ListenAndServe(ctx); err != nil {
				log.Fatalf("socks5: %v", err)
			}
		}()
	}

	log.Printf("all listeners ready: http=%s https=%s socks5=%s (queue=%d)",
		cfg.Server.Listen, cfg.Server.ListenHTTPS, cfg.Socks5.Listen, bucket.Len())

	return func(cctx context.Context) {
		if socks != nil {
			if err := socks.Close(); err != nil {
				log.Printf("socks5: shutdown: %v", err)
			}
		}
		for _, srv := range servers {
			if err := srv.Shutdown(cctx); err != nil {
				log.Printf("http: shutdown: %v", err)
			}
		}
	}
}

// startHTTPServer launches the plaintext forward proxy (upstream: CONNECT
// tunnels and absolute-URI requests).
func startHTTPServer(cfg *proxy.Config, fwd *proxy.ForwardDialer, logNoise *log.Logger) *http.Server {
	srv := &http.Server{
		Addr:              cfg.Server.Listen,
		Handler:           buildGoproxy(cfg, fwd, logNoise),
		ErrorLog:          logNoise,
		ReadTimeout:       cfg.Server.ReadTimeout.Duration,
		ReadHeaderTimeout: 30 * time.Second,
		WriteTimeout:      cfg.Server.WriteTimeout.Duration,
		IdleTimeout:       cfg.Server.IdleTimeout.Duration,
	}
	srv.SetKeepAlivesEnabled(cfg.Server.KeepAlives)
	go func() {
		log.Printf("http:  proxy listening on %s", cfg.Server.Listen)
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("http:  %v", err)
		}
	}()
	return srv
}

// startHTTPSServer launches the TLS forward proxy with the generated
// long-lived CA-signed cert (proxy.LoadOrCreateTLS).
func startHTTPSServer(cfg *proxy.Config, fwd *proxy.ForwardDialer, logNoise *log.Logger) *http.Server {
	cert, err := proxy.LoadOrCreateTLS(cfg.Server.TLSCertFile, cfg.Server.TLSKeyFile)
	if err != nil {
		log.Fatalf("tls:  %v", err)
	}
	srv := &http.Server{
		Addr:    cfg.Server.ListenHTTPS,
		Handler: buildGoproxy(cfg, fwd, logNoise),
		TLSConfig: &tls.Config{
			Certificates: []tls.Certificate{cert},
			MinVersion:   tls.VersionTLS12,
		},
		ErrorLog:          logNoise,
		ReadTimeout:       cfg.Server.ReadTimeout.Duration,
		ReadHeaderTimeout: 30 * time.Second,
		WriteTimeout:      cfg.Server.WriteTimeout.Duration,
		IdleTimeout:       cfg.Server.IdleTimeout.Duration,
	}
	srv.SetKeepAlivesEnabled(cfg.Server.KeepAlives)
	go func() {
		log.Printf("https: proxy listening on %s", cfg.Server.ListenHTTPS)
		if err := srv.ListenAndServeTLS("", ""); err != nil && err != http.ErrServerClosed {
			log.Fatalf("https: %v", err)
		}
	}()
	return srv
}

func buildGoproxy(cfg *proxy.Config, fwd *proxy.ForwardDialer, noise *log.Logger) *goproxy.ProxyHttpServer {
	gop := goproxy.NewProxyHttpServer()
	gop.Verbose = cfg.Server.Verbose
	gop.Logger = noise

	for _, pat := range cfg.Server.BlockConnect {
		re, err := regexp.Compile(pat)
		if err != nil {
			log.Printf("config: bad block_connect regex %q: %v", pat, err)
			continue
		}
		gop.OnRequest(goproxy.ReqHostMatches(re)).HandleConnect(goproxy.AlwaysReject)
	}

	for _, host := range cfg.Server.WasteHosts {
		gop.OnRequest(goproxy.DstHostIs(host)).DoFunc(wasteResponse)
		gop.OnRequest(goproxy.DstHostIs(host + ":443")).DoFunc(wasteResponse)
	}

	for _, suf := range cfg.Server.BlockURLSuffix {
		re, err := regexp.Compile(regexp.QuoteMeta(suf) + `$`)
		if err != nil {
			continue
		}
		gop.OnRequest(goproxy.UrlMatches(re)).DoFunc(wasteResponse)
	}

	gop.Tr = fwd.NewTransport()
	gop.ConnectDial = fwd.Dial

	// Request-level failover transport (response-time health, interstitial
	// block detection, total per-request deadline) plus session stickiness.
	// goproxy's Tr field is a concrete *http.Transport, so the resilience
	// layer is injected per request through ProxyCtx.RoundTripper.
	rt := &ctxRoundTripper{rt: proxy.NewProxyTransport(cfg, fwd)}
	gop.OnRequest().DoFunc(func(r *http.Request, ctx *goproxy.ProxyCtx) (*http.Request, *http.Response) {
		if r.Method == "CONNECT" {
			return r, nil // tunnels are already sticky per connection
		}
		ctx.RoundTripper = rt
		kctx := r.Context()
		key := r.RemoteAddr
		if key != "" {
			kctx = proxy.WithConnKey(kctx, key)
		}
		if sess := r.Header.Get("X-Sticky-Session"); sess != "" {
			r.Header.Del("X-Sticky-Session")
			kctx = proxy.WithSessionKey(kctx, "s="+sess)
		}
		return r.WithContext(kctx), nil
	})

	// Supervised CONNECT tunnels: request-level failover for HTTPS too. The
	// default ConnectDial path only gets dial-time retries — a proxy that
	// answers CONNECT and then blackholes the tunnel stays invisible to health
	// accounting. Registered after the block_connect rules so blocked hosts are
	// rejected first (handlers are chained first-match-wins).
	gop.OnRequest().HijackConnect(func(req *http.Request, client net.Conn, _ *goproxy.ProxyCtx) {
		host := req.URL.Host
		if host == "" {
			host = req.Host
		}
		_ = fwd.ServeConnect(req.Context(), client, "tcp", host)
	})
	return gop
}

// ctxRoundTripper adapts the http.RoundTripper contract to goproxy's
// ProxyCtx.RoundTripper interface.
type ctxRoundTripper struct{ rt http.RoundTripper }

func (a *ctxRoundTripper) RoundTrip(req *http.Request, _ *goproxy.ProxyCtx) (*http.Response, error) {
	return a.rt.RoundTrip(req)
}

// wasteResponse short-circuits requests to tracking/asset hosts.
func wasteResponse(r *http.Request, ctx *goproxy.ProxyCtx) (*http.Request, *http.Response) {
	return r, goproxy.NewResponse(r, goproxy.ContentTypeText, http.StatusOK, "Waste")
}
