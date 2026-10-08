package proxy

import (
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"
)

// checkerThroughProxy builds a checker whose client routes through the test
// CONNECT proxy, mirroring how fullCheck constructs its sub-request client.
func checkerThroughProxy(t *testing.T, urls []string, selfIP string, p *Proxy) *Checker {
	t.Helper()
	cfg := &Config{}
	cfg.Checker.SelfIPURLs = urls
	cfg.Checker.TCPTimeout = Duration{2 * time.Second}
	cfg.Checker.ConnectT = Duration{3 * time.Second}
	cfg.Checker.TLSHandshake = Duration{3 * time.Second}
	cfg.Checker.ResponseT = Duration{5 * time.Second}
	cfg.Checker.TotalT = Duration{8 * time.Second}
	return &Checker{cfg: cfg, selfIP: net.ParseIP(selfIP), ipRe: reAnyIP}
}

func proxyThrough(t *testing.T) *Proxy {
	t.Helper()
	addr := startTestConnectProxy(t)
	parts := strings.Split(addr, ":")
	port, err := strconv.Atoi(parts[1])
	if err != nil {
		t.Fatal(err)
	}
	return &Proxy{Schema: "http", Host: "127.0.0.1", Port: port}
}

func TestLeakCheckRejectsForwardedIP(t *testing.T) {
	p := proxyThrough(t)
	leaky := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("Remote-Addr: 9.9.9.9 via proxy"))
	}))
	defer leaky.Close()
	clean := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("{}"))
	}))
	defer clean.Close()

	c := checkerThroughProxy(t, nil, "9.9.9.9", p)
	client := &http.Client{Transport: c.transportFor(p), Timeout: 8 * time.Second}
	defer client.Transport.(*http.Transport).CloseIdleConnections()

	c.cfg.Checker.LeakProbeURLs = []string{leaky.URL}
	if err := c.leakCheck(client); err == nil {
		t.Fatal("leaky endpoint accepted")
	}

	c.cfg.Checker.LeakProbeURLs = []string{clean.URL}
	if err := c.leakCheck(client); err != nil {
		t.Fatalf("clean endpoint rejected: %v", err)
	}

	// Disabled config: stage must be skipped entirely.
	c.cfg.Checker.LeakProbeURLs = nil
	if err := c.leakCheck(client); err != nil {
		t.Fatalf("disabled leak stage failed: %v", err)
	}
}

func TestConfirmExitIPStability(t *testing.T) {
	p := proxyThrough(t)
	stable := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("5.6.7.8"))
	}))
	defer stable.Close()
	// Always a different IP: the confirm re-probe must reject the proxy even
	// though the first (simulated) probe saw 5.6.7.8.
	rotating := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("6.7.8.9"))
	}))
	defer rotating.Close()

	c := checkerThroughProxy(t, nil, "9.9.9.9", p)
	client := &http.Client{Transport: c.transportFor(p), Timeout: 8 * time.Second}
	defer client.Transport.(*http.Transport).CloseIdleConnections()

	c.cfg.Checker.RequireStableExit = true
	if err := c.confirmExitIP(client, net.ParseIP("5.6.7.8"), stable.URL); err != nil {
		t.Fatalf("stable endpoint rejected: %v", err)
	}
	if err := c.confirmExitIP(client, net.ParseIP("5.6.7.8"), rotating.URL); err == nil {
		t.Fatal("rotating exit IP accepted")
	}

	// Gated off: must never reject.
	c.cfg.Checker.RequireStableExit = false
	if err := c.confirmExitIP(client, net.ParseIP("5.6.7.8"), rotating.URL); err != nil {
		t.Fatalf("disabled stability stage failed: %v", err)
	}
}

func TestE2EProbe(t *testing.T) {
	svc := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("5.6.7.8"))
	}))
	defer svc.Close()

	good := proxyThrough(t)
	bad := &Proxy{Schema: "http", Host: "127.0.0.1", Port: closedPort(t)}

	c := checkerThroughProxy(t, []string{svc.URL}, "9.9.9.9", good)
	c.cfg.Checker.E2EProbe = true

	if err := c.e2eProbe(good); err != nil {
		t.Fatalf("e2e through working proxy failed: %v", err)
	}
	if err := c.e2eProbe(bad); err == nil {
		t.Fatal("e2e through dead proxy succeeded")
	}

	// Gated off: must never fail even on a dead proxy.
	c.cfg.Checker.E2EProbe = false
	if err := c.e2eProbe(bad); err != nil {
		t.Fatalf("disabled e2e stage failed: %v", err)
	}
}
