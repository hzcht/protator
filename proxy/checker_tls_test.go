package proxy

import (
	"crypto/x509"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// tlsProbeChecker builds a Checker wired for the honesty probe against the
// given target, mirroring what NewChecker parses out of checker.tls_probe_host.
func tlsProbeChecker(t *testing.T, addr, name string, roots *x509.CertPool) *Checker {
	t.Helper()
	cfg := &Config{}
	cfg.Checker.TCPTimeout = Duration{2 * time.Second}
	cfg.Checker.ConnectT = Duration{3 * time.Second}
	cfg.Checker.TLSHandshake = Duration{3 * time.Second}
	cfg.Checker.ResponseT = Duration{5 * time.Second}
	cfg.Checker.TotalT = Duration{8 * time.Second}
	return &Checker{cfg: cfg, tlsProbeAddr: addr, tlsProbeName: name, probeRoots: roots}
}

// tlsProbeServer starts an HTTPS test server; returns its host:port (the
// dialProxy target), the hostname to verify against, and its leaf.
func tlsProbeServer(t *testing.T) (addr, name string, leaf *x509.Certificate) {
	t.Helper()
	srv := httptest.NewTLSServer(http.NotFoundHandler())
	t.Cleanup(srv.Close)
	host, port, _ := net.SplitHostPort(srv.Listener.Addr().String())
	leaf = srv.Certificate()
	if leaf == nil {
		t.Fatal("test server has no certificate")
	}
	return net.JoinHostPort(host, port), host, leaf
}

func TestTLSHonestyProbeSeesHonestChain(t *testing.T) {
	addr, name, leaf := tlsProbeServer(t)
	p := proxyThrough(t)

	// The probe must verify the chain against real roots: trusting the
	// server's own leaf is exactly what an honest exit makes possible and a
	// forging one prevents (the forged chain never validates under any root
	// we hold).
	roots := x509.NewCertPool()
	roots.AddCert(leaf)
	c := tlsProbeChecker(t, addr, name, roots)

	c.tlsHonestyProbe(p, 8*time.Second)
	if got := p.TLSHonestyRank(); got != tlsHonest {
		t.Fatalf("honest exit ranked %d, want %d (tlsHonest)", got, tlsHonest)
	}
	if n := Stats.CheckTLSHonest.Load(); n != 1 {
		t.Fatalf("CheckTLSHonest = %d, want 1", n)
	}
}

func TestTLSHonestyProbeCatchesForge(t *testing.T) {
	addr, name, _ := tlsProbeServer(t)
	p := proxyThrough(t)

	// System roots (nil): the self-signed test leaf has no trusted issuer —
	// the same verdict a forging exit earns for its "None, LLC" chain.
	c := tlsProbeChecker(t, addr, name, nil)

	c.tlsHonestyProbe(p, 8*time.Second)
	if got := p.TLSHonestyRank(); got != tlsForged {
		t.Fatalf("forging exit ranked %d, want %d (tlsForged)", got, tlsForged)
	}
	if n := Stats.CheckTLSForged.Load(); n != 1 {
		t.Fatalf("CheckTLSForged = %d, want 1", n)
	}
}

func TestTLSHonestyProbeInconclusiveLeavesEvidenceAlone(t *testing.T) {
	p := proxyThrough(t)
	p.MarkTLSHonesty(true) // prior evidence must survive an inconclusive probe

	// A closed port: the tunnel fails, which says nothing about honesty.
	c := tlsProbeChecker(t, "127.0.0.1:1", "127.0.0.1", nil)
	c.tlsHonestyProbe(p, 2*time.Second)
	if got := p.TLSHonestyRank(); got != tlsHonest {
		t.Fatalf("dial failure overwrote evidence: rank %d, want %d", got, tlsHonest)
	}
	if n := Stats.CheckTLSInconclusive.Load(); n != 1 {
		t.Fatalf("CheckTLSInconclusive = %d, want 1", n)
	}
}

func TestTLSHonestyProbeDisabled(t *testing.T) {
	p := proxyThrough(t)
	c := tlsProbeChecker(t, "", "", nil) // checker.tls_probe_host = "off"
	// Package-global counters: assert the delta, not the absolute.
	h0, f0, i0 := Stats.CheckTLSHonest.Load(), Stats.CheckTLSForged.Load(), Stats.CheckTLSInconclusive.Load()
	c.tlsHonestyProbe(p, 8*time.Second)
	if got := p.TLSHonestyRank(); got != tlsUnknown {
		t.Fatalf("disabled probe touched the evidence: rank %d, want 0", got)
	}
	if n := Stats.CheckTLSHonest.Load() - h0 + Stats.CheckTLSForged.Load() - f0 + Stats.CheckTLSInconclusive.Load() - i0; n != 0 {
		t.Fatalf("disabled probe counted %d stat increments, want 0", n)
	}
}

func TestTLSHonestyRankValues(t *testing.T) {
	p := &Proxy{}
	if got := p.TLSHonestyRank(); got != tlsUnknown {
		t.Fatalf("fresh proxy ranked %d, want %d (tlsUnknown)", got, tlsUnknown)
	}
	p.MarkTLSHonesty(true)
	if got := p.TLSHonestyRank(); got != tlsHonest {
		t.Fatalf("honest ranked %d, want %d", got, tlsHonest)
	}
	p.MarkTLSHonesty(false)
	if got := p.TLSHonestyRank(); got != tlsForged {
		t.Fatalf("forged ranked %d, want %d", got, tlsForged)
	}
}

// The honesty evidence is a preference between equals in the fresh tier, so
// the tests pin each neighbour of the order and the one place fresh wins.
func TestBetterPickHonestyOrder(t *testing.T) {
	cases := []struct {
		name            string
		fresh, honest   int64 // challenger
		bestF, bestH    int64 // incumbent
		wantBetterPickA bool
	}{
		{"honest beats unknown same tier", freshGreen, int64(tlsHonest), freshGreen, int64(tlsUnknown), true},
		{"unknown beats forged same tier", freshGreen, int64(tlsUnknown), freshGreen, int64(tlsForged), true},
		{"forged loses to honest same tier", freshGreen, int64(tlsForged), freshGreen, int64(tlsHonest), false},
		{"fresh outranks honesty", freshWarm, int64(tlsHonest), freshGreen, int64(tlsForged), false},
		{"full tie falls through", freshGreen, int64(tlsUnknown), freshGreen, int64(tlsUnknown), false},
	}
	for _, tc := range cases {
		if got := betterPick(tc.fresh, tc.honest, 0, 0, 0, tc.bestF, tc.bestH, 0, 0, 0); got != tc.wantBetterPickA {
			t.Errorf("%s: betterPick = %v, want %v", tc.name, got, tc.wantBetterPickA)
		}
	}
}

// rankPick must carry the evidence into the sampling loop: same fresh tier,
// the honest entry has to win against a forged one already stored as best.
func TestRankPickPrefersHonest(t *testing.T) {
	b := NewBucket(0)
	b.SetFreshnessWindows(time.Hour, time.Hour)
	now := nowNanos()

	honest := &Proxy{Schema: "http", Host: "10.1.0.1", Port: 1}
	honest.MarkTLSHonesty(true)
	honest.MarkServeOK(time.Millisecond)
	forged := &Proxy{Schema: "http", Host: "10.1.0.2", Port: 2}
	forged.MarkTLSHonesty(false)
	forged.MarkServeOK(time.Millisecond)

	pool := []*Proxy{forged, honest}
	for i := 0; i < 50; i++ {
		if got := b.rankPick(pool, 256, nil, now, false); got != honest {
			t.Fatalf("pick %d chose a forged proxy over an honest one in the same tier", i)
		}
	}
}

// NewChecker parses checker.tls_probe_host: a bare host gains port 443, an
// explicit host:port passes through, "off" (any case) disables the probe.
func TestNewCheckerParsesTLSProbeHost(t *testing.T) {
	ipSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("9.9.9.9"))
	}))
	defer ipSrv.Close()

	build := func(t *testing.T, probeHost string) *Checker {
		t.Helper()
		cfg := &Config{}
		cfg.Checker.SelfIPURLs = []string{ipSrv.URL}
		cfg.Checker.TLSProbeHost = probeHost
		c, err := NewChecker(cfg)
		if err != nil {
			t.Fatalf("NewChecker: %v", err)
		}
		return c
	}

	if c := build(t, "example.com"); c.tlsProbeAddr != "example.com:443" || c.tlsProbeName != "example.com" {
		t.Errorf("bare host: addr=%q name=%q", c.tlsProbeAddr, c.tlsProbeName)
	}
	if c := build(t, "example.com:8443"); c.tlsProbeAddr != "example.com:8443" || c.tlsProbeName != "example.com" {
		t.Errorf("host:port: addr=%q name=%q", c.tlsProbeAddr, c.tlsProbeName)
	}
	if c := build(t, "off"); c.tlsProbeAddr != "" || c.tlsProbeName != "" {
		t.Errorf("off: addr=%q name=%q, want empty", c.tlsProbeAddr, c.tlsProbeName)
	}
}
