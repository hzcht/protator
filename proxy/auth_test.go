package proxy

import (
	"bufio"
	"context"
	"encoding/base64"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"
)

// Plain-proxy credentials must survive parse → URL → parse unchanged: the
// queue save writes URL() and the next start re-parses it, so a lossy round
// trip would resurrect the proxy without its password and it would fail
// validation as dead.
func TestProxyLineCredentialRoundTrip(t *testing.T) {
	cases := []string{
		"http://user:pass@1.2.3.4:8080",
		"http://u%40er:p%3Ass@1.2.3.4:8080", // URL-significant bytes stay encoded
		"https://user:pass@1.2.3.4:8443",
		"socks5://user:pass@1.2.3.4:1080",
	}
	for _, line := range cases {
		p, err := ParseProxyLine(line)
		if err != nil {
			t.Fatalf("%q: %v", line, err)
		}
		if got := p.URL(); got != line {
			t.Fatalf("round trip changed the line: %q -> %q", line, got)
		}
		if got, want := p.URLLen(), len(p.URL()); got != want {
			t.Fatalf("%q: URLLen = %d, len(URL()) = %d", line, got, want)
		}
		p2, err := ParseProxyLine(p.URL())
		if err != nil {
			t.Fatalf("re-parse %q: %v", p.URL(), err)
		}
		if p2.Key() != p.Key() {
			t.Fatalf("round trip changed the key: %q vs %q", p.Key(), p2.Key())
		}
	}
}

// Credential parsing details: raw storage, schema gating, and identity.
func TestProxyLineCredentialParsing(t *testing.T) {
	p, err := ParseProxyLine("http://user:p%40ss@1.2.3.4:8080")
	if err != nil {
		t.Fatal(err)
	}
	// Raw spelling is preserved (lossless round trip); the dial decodes once.
	if got, want := p.GetProxyAuth(), "user:p%40ss"; got != want {
		t.Fatalf("raw auth = %q, want %q", got, want)
	}
	if _, pass, _ := p.authUserinfo(); pass != "p@ss" {
		t.Fatalf("decoded pass = %q, want %q", pass, "p@ss")
	}

	// The same host:port with different credentials is a different proxy —
	// the identity rule trojan/vless already follow (lists reuse hosts across
	// passwords; extraction dedup must not keep only the first).
	p2, err := ParseProxyLine("http://other:pass@1.2.3.4:8080")
	if err != nil {
		t.Fatal(err)
	}
	if p2.Key() == p.Key() {
		t.Fatal("two credentials on one host:port collapsed into one entry")
	}

	// socks4 has no password auth: a userinfo there is junk, and keeping it
	// would turn a working anonymous dial into a failing authenticated one.
	s4, err := ParseProxyLine("socks4://user:pass@1.2.3.4:4145")
	if err != nil {
		t.Fatal(err)
	}
	if s4.GetProxyAuth() != "" || strings.Contains(s4.URL(), "@") {
		t.Fatalf("socks4 must ignore userinfo, got %q / %q", s4.GetProxyAuth(), s4.URL())
	}

	// No userinfo: URL stays bare (no "@" noise in queue files and exports).
	plain, err := ParseProxyLine("http://1.2.3.4:8080")
	if err != nil {
		t.Fatal(err)
	}
	if plain.GetProxyAuth() != "" || strings.Contains(plain.URL(), "@") {
		t.Fatalf("plain proxy grew credentials: %q", plain.URL())
	}
}

// candidateLine / parsePoolLine persist the pool file; a credential dropped
// there is a proxy that can never validate after a restart.
func TestPoolLinePreservesCredentials(t *testing.T) {
	c := Candidate{Host: "1.2.3.4", Port: 8080, Schema: "http", ProxyAuth: "user:p%40ss"}
	pl, ok := parsePoolLine(candidateLine(c))
	if !ok {
		t.Fatal("credentialed line failed to parse")
	}
	if pl.cand.ProxyAuth != c.ProxyAuth {
		t.Fatalf("pool round trip lost the credential: %+v", pl.cand)
	}
	if pl.cand.key() != c.key() {
		t.Fatalf("pool round trip changed the key: %q vs %q", pl.cand.key(), c.key())
	}

	// The vless/trojan form must survive the same path (Batch re-emits
	// whatever parsePoolLine produced, so this covers the pool re-probe).
	v := Candidate{Host: "5.6.7.8", Port: 443, Schema: "vless", VLESSUUID: "uuid-here"}
	pl, ok = parsePoolLine(candidateLine(v))
	if !ok {
		t.Fatal("vless line failed to parse")
	}
	if pl.cand.VLESSUUID != "uuid-here" {
		t.Fatalf("pool round trip lost the vless uuid: %+v", pl.cand)
	}
}

// startAuthConnectProxy runs a CONNECT proxy that rejects any request without
// exactly this Basic credential: the tunnel only comes up when
// connectHTTPProxy actually sends the Proxy-Authorization header.
func startAuthConnectProxy(t *testing.T, user, pass string) (addr string) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	want := "Basic " + base64.StdEncoding.EncodeToString([]byte(user+":"+pass))
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				br := bufio.NewReader(c)
				line, err := br.ReadString('\n')
				if err != nil {
					return
				}
				if !strings.HasPrefix(line, "CONNECT ") {
					return
				}
				auth := ""
				for {
					h, err := br.ReadString('\n')
					if err != nil {
						return
					}
					if h == "\r\n" || h == "\n" {
						break
					}
					if strings.HasPrefix(strings.ToLower(h), "proxy-authorization:") {
						auth = strings.TrimSpace(h[len("proxy-authorization:"):])
					}
				}
				if auth != want {
					io.WriteString(c, "HTTP/1.1 407 Proxy Authentication Required\r\n\r\n")
					return
				}
				io.WriteString(c, "HTTP/1.1 200 Connection established\r\n\r\n")
				io.Copy(c, c) // echo whatever the client sends over the tunnel
			}(c)
		}
	}()
	return ln.Addr().String()
}

func TestDialProxySendsBasicAuth(t *testing.T) {
	proxy := startAuthConnectProxy(t, "user", "p@ss")
	p, err := ParseProxyLine("http://user:p%40ss@" + proxy)
	if err != nil {
		t.Fatal(err)
	}
	conn, err := dialProxy(p, 5*time.Second, context.Background(), "tcp", "example.com:80")
	if err != nil {
		t.Fatalf("credentialed CONNECT failed: %v", err)
	}
	defer conn.Close()
	// The tunnel is live: the echo proves bytes flow both ways.
	msg := []byte("ping")
	conn.SetDeadline(time.Now().Add(5 * time.Second))
	if _, err := conn.Write(msg); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, len(msg))
	if _, err := io.ReadFull(conn, buf); err != nil {
		t.Fatal(err)
	}
	if string(buf) != string(msg) {
		t.Fatalf("echo mismatch: %q", buf)
	}
}

// A credentialed proxy whose Basic credential does not match must be refused
// (407), not silently accepted.
func TestDialProxyWrongCredentialFails(t *testing.T) {
	proxy := startAuthConnectProxy(t, "user", "p@ss")
	p, err := ParseProxyLine("http://intruder:nope@" + proxy)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := dialProxy(p, 5*time.Second, context.Background(), "tcp", "example.com:80"); err == nil {
		t.Fatal("a wrong proxy credential must fail the dial")
	}
}

// startForwardAuthConnectProxy is startAuthConnectProxy for checker tests: it
// verifies the Basic credential, then forwards the tunnel to target (host:port)
// instead of echoing — the checker's probes speak TLS (or socks) through the
// tunnel, and an echoed tunnel feeds the client its own ClientHello.
func startForwardAuthConnectProxy(t *testing.T, user, pass, target string) (addr string) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	want := "Basic " + base64.StdEncoding.EncodeToString([]byte(user+":"+pass))
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				br := bufio.NewReader(c)
				line, err := br.ReadString('\n')
				if err != nil {
					return
				}
				if !strings.HasPrefix(line, "CONNECT ") {
					return
				}
				auth := ""
				for {
					h, err := br.ReadString('\n')
					if err != nil {
						return
					}
					if h == "\r\n" || h == "\n" {
						break
					}
					if strings.HasPrefix(strings.ToLower(h), "proxy-authorization:") {
						auth = strings.TrimSpace(h[len("proxy-authorization:"):])
					}
				}
				if auth != want {
					io.WriteString(c, "HTTP/1.1 407 Proxy Authentication Required\r\n\r\n")
					return
				}
				up, err := net.DialTimeout("tcp", target, 5*time.Second)
				if err != nil {
					io.WriteString(c, "HTTP/1.1 502 Bad Gateway\r\n\r\n")
					return
				}
				defer up.Close()
				io.WriteString(c, "HTTP/1.1 200 Connection established\r\n\r\n")
				go io.Copy(up, br)
				io.Copy(c, up)
			}(c)
		}
	}()
	return ln.Addr().String()
}

// The probe branch (no explicit schema) must carry the candidate's credential
// through every protocol attempt: a bare `user:pass@host:port` candidate goes
// down this branch, and the branch used to build the Proxy without the
// credential — validated anonymously, so an auth-requiring proxy failed the
// check outright and a lax one entered the queue with the wrong identity.
func TestCheckerProbeBranchCarriesCredentials(t *testing.T) {
	// One TLS server plays both self-IP service and content test: its body
	// contains a foreign IP and the expected template.
	svc := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("your ip is 5.6.7.8, Example Domain"))
	}))
	defer svc.Close()

	// A CONNECT proxy demanding exactly this credential and forwarding the
	// tunnel to svc: every probe protocol must speak through it, so the check
	// only passes when the credential actually rode the tunnel.
	proxy := startForwardAuthConnectProxy(t, "user", "pass", strings.TrimPrefix(svc.URL, "https://"))
	host, portS, err := net.SplitHostPort(proxy)
	if err != nil {
		t.Fatal(err)
	}
	port, err := strconv.Atoi(portS)
	if err != nil {
		t.Fatal(err)
	}

	cfg := &Config{}
	cfg.Checker.SelfIPURLs = []string{svc.URL}
	cfg.Checker.ProbeOrder = []string{"http", "socks5", "socks4", "https"}
	cfg.Checker.TCPTimeout = Duration{3 * time.Second}
	cfg.Checker.ConnectT = Duration{3 * time.Second}
	cfg.Checker.TLSHandshake = Duration{3 * time.Second}
	cfg.Checker.ResponseT = Duration{5 * time.Second}
	cfg.Checker.TotalT = Duration{10 * time.Second}

	checker := &Checker{cfg: cfg, selfIP: net.ParseIP("9.9.9.9"), ipRe: reAnyIP, allowBogon: true}
	checker.tests = []ContentTest{{Name: "svc", URL: svc.URL, MustContain: []string{"Example"}}}

	// Schema == "" sends the candidate down the probe branch. The password is
	// kept URL-significant-byte-free so the raw userinfo and its encoded form
	// coincide and the assertion is not about escaping.
	cand := Candidate{Host: host, Port: port, ProxyAuth: "user:pass"}
	p, err := checker.Check(cand)
	if err != nil {
		t.Fatalf("credentialed probe-branch check failed: %v", err)
	}
	if got := p.GetProxyAuth(); got != "user:pass" {
		t.Fatalf("validated proxy lost the credential: %q", got)
	}
	if !strings.Contains(p.URL(), "user:pass@"+host) {
		t.Fatalf("URL must include the credential: %q", p.URL())
	}
}

// proxyForCandidate is the single construction site for checked proxies: the
// credential must be part of the frozen identity for http/https/socks5, and
// must be dropped for socks4 (the protocol has no auth field) even when a
// hand-built Candidate carries one.
func TestProxyForCandidateCredentialRules(t *testing.T) {
	cand := Candidate{Host: "1.2.3.4", Port: 8080, ProxyAuth: "user:pass"}
	for _, schema := range []string{"http", "https", "socks5"} {
		p := proxyForCandidate(cand, schema)
		if got := p.GetProxyAuth(); got != "user:pass" {
			t.Fatalf("%s: GetProxyAuth = %q, want user:pass", schema, got)
		}
		if !strings.Contains(p.URL(), "user:pass@1.2.3.4:8080") {
			t.Fatalf("%s: URL %q lost the credential", schema, p.URL())
		}
		if !strings.Contains(p.Key(), "user:pass@1.2.3.4:8080") {
			t.Fatalf("%s: frozen key %q must include the credential", schema, p.Key())
		}
	}
	p := proxyForCandidate(cand, "socks4")
	if got := p.GetProxyAuth(); got != "" {
		t.Fatalf("socks4 must drop the credential, got %q", got)
	}
	if strings.Contains(p.URL(), "user:pass@") {
		t.Fatalf("socks4 URL %q still carries the credential", p.URL())
	}
}

// startAuthSocks5Server runs a SOCKS5 server that requires RFC 1929
// username/password auth, exercising the h12.io/socks client path with a
// credentialed socks5 URL (method negotiation, auth reply, then CONNECT).
func startAuthSocks5Server(t *testing.T, user, pass string) (addr string) {
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
				c.SetDeadline(time.Now().Add(5 * time.Second))
				hdr := make([]byte, 2)
				if _, err := io.ReadFull(c, hdr); err != nil || hdr[0] != 5 {
					return
				}
				methods := make([]byte, hdr[1])
				if _, err := io.ReadFull(c, methods); err != nil {
					return
				}
				hasAuth := false
				for _, m := range methods {
					if m == 2 {
						hasAuth = true
					}
				}
				if !hasAuth {
					c.Write([]byte{5, 0xFF})
					return
				}
				c.Write([]byte{5, 2}) // username/password subnegotiation
				aver := make([]byte, 2)
				if _, err := io.ReadFull(c, aver); err != nil || aver[0] != 1 {
					return
				}
				ulen := aver[1]
				uname := make([]byte, ulen)
				if _, err := io.ReadFull(c, uname); err != nil {
					return
				}
				plen := make([]byte, 1)
				if _, err := io.ReadFull(c, plen); err != nil {
					return
				}
				passwd := make([]byte, plen[0])
				if _, err := io.ReadFull(c, passwd); err != nil {
					return
				}
				if string(uname) != user || string(passwd) != pass {
					c.Write([]byte{1, 1}) // auth failure
					return
				}
				c.Write([]byte{1, 0}) // auth ok
				req := make([]byte, 4)
				if _, err := io.ReadFull(c, req); err != nil || req[1] != 1 {
					return
				}
				target, err := readSocks5Target(c, req[3])
				if err != nil {
					return
				}
				_ = target
				c.Write([]byte{5, 0, 0, 1, 0, 0, 0, 0, 0, 0})
				io.Copy(c, c)
			}(c)
		}
	}()
	return ln.Addr().String()
}

// readSocks5Target drains the address part of a SOCKS5 request (the server
// above does not dial out; the tunnel is proven by the echo).
func readSocks5Target(c net.Conn, atyp byte) (string, error) {
	switch atyp {
	case 1: // ipv4
		b := make([]byte, 6)
		_, err := io.ReadFull(c, b)
		return "", err
	case 3: // domain
		l := make([]byte, 1)
		if _, err := io.ReadFull(c, l); err != nil {
			return "", err
		}
		b := make([]byte, l[0]+2)
		_, err := io.ReadFull(c, b)
		return "", err
	default: // ipv6
		b := make([]byte, 18)
		_, err := io.ReadFull(c, b)
		return "", err
	}
}

func TestSocks5UpstreamUsernamePasswordAuth(t *testing.T) {
	addr := startAuthSocks5Server(t, "u", "s3cret")
	p, err := ParseProxyLine("socks5://u:s3cret@" + addr)
	if err != nil {
		t.Fatal(err)
	}
	conn, err := dialProxy(p, 5*time.Second, context.Background(), "tcp", "example.com:80")
	if err != nil {
		t.Fatalf("credentialed socks5 dial failed: %v", err)
	}
	defer conn.Close()
	msg := []byte("pong")
	conn.SetDeadline(time.Now().Add(5 * time.Second))
	if _, err := conn.Write(msg); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, len(msg))
	if _, err := io.ReadFull(conn, buf); err != nil {
		t.Fatal(err)
	}
	if string(buf) != string(msg) {
		t.Fatalf("echo mismatch: %q", buf)
	}
}

// The http.Transport probe path (checker/collector) must attach the userinfo
// so net/http sends Proxy-Authorization; the URL carries it as u.User.
func TestProxyURLOfCarriesUserinfo(t *testing.T) {
	p, err := ParseProxyLine("http://user:p%40ss@1.2.3.4:8080")
	if err != nil {
		t.Fatal(err)
	}
	u := proxyURLOf(p)
	if u.User == nil {
		t.Fatal("proxyURLOf dropped the userinfo")
	}
	if u.User.Username() != "user" {
		t.Fatalf("user = %q", u.User.Username())
	}
	if pw, _ := u.User.Password(); pw != "p@ss" {
		t.Fatalf("password = %q", pw)
	}
	if u.Host != "1.2.3.4:8080" || u.Scheme != "http" {
		t.Fatalf("url = %v", u)
	}

	bare, err := ParseProxyLine("http://1.2.3.4:8080")
	if err != nil {
		t.Fatal(err)
	}
	if proxyURLOf(bare).User != nil {
		t.Fatal("bare proxy grew a userinfo")
	}
}

// RevalidateSeeded feeds queue-loaded proxies back through the checker as
// candidates; credentials dropped there re-killed every alive credentialed
// proxy on every restart.
func TestSeedCandidateCarriesCredentials(t *testing.T) {
	p, err := ParseProxyLine("http://user:pass@10.1.2.3:8080")
	if err != nil {
		t.Fatal(err)
	}
	c := candidateFromProxy(p, "http://src.test")
	if c.ProxyAuth != "user:pass" || c.Host != "10.1.2.3" || c.Port != 8080 {
		t.Fatalf("seed candidate lost data: %+v", c)
	}

	tp, err := ParseProxyLine("trojan://s3cret@10.1.2.4:443")
	if err != nil {
		t.Fatal(err)
	}
	tc := candidateFromProxy(tp, "")
	if tc.TrojanPassword != "s3cret" {
		t.Fatalf("seed candidate lost the trojan password: %+v", tc)
	}
	vp, err := ParseProxyLine("vless://uuid@10.1.2.5:443")
	if err != nil {
		t.Fatal(err)
	}
	if vc := candidateFromProxy(vp, ""); vc.VLESSUUID != "uuid" {
		t.Fatalf("seed candidate lost the vless uuid: %+v", vc)
	}
}

// Port parsing of credentialed lines stays intact (regression guard: the
// userinfo split happens before splitHostPort).
func TestCredentialLinePortParsing(t *testing.T) {
	for _, line := range []string{
		"http://user:pass@[2001:db8::1]:8080",
		"socks5://user:pass@1.2.3.4:" + strconv.Itoa(65535),
	} {
		if _, err := ParseProxyLine(line); err != nil {
			t.Fatalf("%q: %v", line, err)
		}
	}
}

// host:port:user:pass is the column shape spys-style exports publish. It is
// parsed only in that exact, unambiguous form; everything else must still
// fail loudly rather than half-parse.
func TestProxyLineCredentialColumns(t *testing.T) {
	p, err := ParseProxyLine("1.2.3.4:8080:user:p%40ss")
	if err != nil {
		t.Fatal(err)
	}
	if p.Schema != "http" || p.Host != "1.2.3.4" || p.Port != 8080 {
		t.Fatalf("socket parsed wrong: %+v", p)
	}
	if got, want := p.GetProxyAuth(), "user:p%40ss"; got != want {
		t.Fatalf("raw auth = %q, want %q", got, want)
	}
	// The column form normalizes to the URL form, so queue persistence and
	// the dialer share one representation.
	if got, want := p.URL(), "http://user:p%40ss@1.2.3.4:8080"; got != want {
		t.Fatalf("URL = %q, want %q", got, want)
	}

	// SplitN keeps every colon after the user in the password.
	q, err := ParseProxyLine("1.2.3.4:8080:user:pa:ss")
	if err != nil {
		t.Fatal(err)
	}
	if got, want := q.GetProxyAuth(), "user:pa:ss"; got != want {
		t.Fatalf("multi-colon password = %q, want %q", got, want)
	}

	// Domains are acceptable hosts for queue/API input (extraction itself
	// stays IPv4-only); the first two fields decide the socket.
	d, err := ParseProxyLine("proxy.example.com:8080:user:pass")
	if err != nil {
		t.Fatal(err)
	}
	if d.Host != "proxy.example.com" || d.Port != 8080 || d.GetProxyAuth() != "user:pass" {
		t.Fatalf("domain column parse = %+v", d)
	}

	// Too few fields: an error, not a silent host:port read.
	if _, err := ParseProxyLine("1.2.3.4:8080:user"); err == nil {
		t.Fatal("three-field line parsed as a proxy")
	}
	// A bare IPv6 line must not be mistaken for columns (its "port" fails to
	// parse, and splitHostPort requires brackets for more than one colon).
	if _, err := ParseProxyLine("2001:db8::1:8080"); err == nil {
		t.Fatal("bare IPv6 line parsed as a proxy")
	}
	if _, err := ParseProxyLine("[2001:db8::1]:8080"); err != nil {
		t.Fatalf("bracketed IPv6: %v", err)
	}
}

// Extraction must see credentials in both universal forms; otherwise the
// only candidate for a credentialed list is the anonymous host:port, which
// validates as 407/dead and loses the source. The column and clock cases pin
// the conservative suffix rules.
func TestExtractCredentialedForms(t *testing.T) {
	e := &Extractor{}
	cases := []struct {
		name string
		body string
		want []Candidate
	}{
		{
			name: "scheme url",
			body: `<a href="http://user:pass@1.2.3.4:8080">x</a>`,
			want: []Candidate{{Host: "1.2.3.4", Port: 8080, Schema: "http", ProxyAuth: "user:pass"}},
		},
		{
			name: "socks5 raw percent",
			body: "socks5://u:p%40ss@5.6.7.8:1080",
			want: []Candidate{{Host: "5.6.7.8", Port: 1080, Schema: "socks5", ProxyAuth: "u:p%40ss"}},
		},
		{
			name: "socks4 drops auth",
			body: "socks4://user:pass@9.9.9.9:4145",
			want: []Candidate{{Host: "9.9.9.9", Port: 4145, Schema: "socks4"}},
		},
		{
			// Symmetric with the bare form below: "user@ip:port" is a mention
			// far more often than a Basic credential with an empty password.
			// The scheme stays as evidence; the credential is not invented.
			name: "scheme userinfo without colon stays anonymous",
			body: "https://user@8.8.8.8:8443",
			want: []Candidate{{Host: "8.8.8.8", Port: 8443, Schema: "https"}},
		},
		{
			name: "bare userinfo",
			body: "user:pass@2.2.2.2:3128",
			want: []Candidate{{Host: "2.2.2.2", Port: 3128, ProxyAuth: "user:pass"}},
		},
		{
			name: "columns keep both",
			body: "3.3.3.3:8080:user:pass",
			want: []Candidate{
				{Host: "3.3.3.3", Port: 8080},
				{Host: "3.3.3.3", Port: 8080, ProxyAuth: "user:pass"},
			},
		},
		{
			name: "clock is not auth",
			body: "4.4.4.4:8080:10:00:30",
			want: []Candidate{{Host: "4.4.4.4", Port: 8080}},
		},
		{
			name: "port list is not auth",
			body: "4.4.4.5:8080:3128",
			want: []Candidate{{Host: "4.4.4.5", Port: 8080}},
		},
		{
			name: "email is not userinfo",
			body: "admin@6.6.6.6:8080",
			want: []Candidate{{Host: "6.6.6.6", Port: 8080}},
		},
		{
			// ftp:// is not a proxy scheme: its userinfo is guesswork, so only
			// the anonymous socket is kept. Pins the "after ://" guard, which
			// only fires because '/' and '?' are excluded from the userinfo
			// class (otherwise the match would start at "ftp").
			name: "unsupported scheme is not userinfo",
			body: "ftp://user:pass@7.7.7.7:8080",
			want: []Candidate{{Host: "7.7.7.7", Port: 8080}},
		},
	}
	for _, tc := range cases {
		got := e.Extract([]byte(tc.body))
		if len(got) != len(tc.want) {
			t.Fatalf("%s: got %d candidates %v, want %d %v", tc.name, len(got), got, len(tc.want), tc.want)
		}
		want := make(map[string]Candidate, len(tc.want))
		for _, c := range tc.want {
			want[c.key()] = c
		}
		for _, c := range got {
			w, ok := want[c.key()]
			if !ok {
				t.Fatalf("%s: unexpected candidate %+v (key %q)", tc.name, c, c.key())
			}
			if c.Host != w.Host || c.Port != w.Port || c.Schema != w.Schema || c.ProxyAuth != w.ProxyAuth {
				t.Fatalf("%s: candidate %+v, want %+v", tc.name, c, w)
			}
			delete(want, c.key())
		}
		if len(want) != 0 {
			t.Fatalf("%s: missing candidates %v", tc.name, want)
		}
	}
}
