package proxy

import (
	"bufio"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"
)

// readTrojanRequest reads one trojan handshake from br: the hex password
// line, then CMD + SOCKS-style address + CRLF. Returns the claimed hash and
// the requested target. A bare TCP probe (the checker's pre-dial) yields an
// error, not a test failure — the server just hangs up.
//
// br is passed in (not built here) so the caller keeps the same reader for
// the relay: payload bytes already buffered past the handshake belong to
// the tunnel, and a second reader on the conn would strand them.
func readTrojanRequest(br *bufio.Reader) (hash, target string, err error) {
	var line string
	if line, err = br.ReadString('\n'); err != nil {
		return "", "", err
	}
	hash = strings.TrimRight(line, "\r\n")
	var cmd byte
	if cmd, err = br.ReadByte(); err != nil || cmd != 0x01 {
		return "", "", fmt.Errorf("trojan cmd = %x, err = %v; want 0x01", cmd, err)
	}
	atyp, err := br.ReadByte()
	if err != nil {
		return "", "", err
	}
	var host string
	switch atyp {
	case 0x01:
		b := make([]byte, 4)
		if _, err := io.ReadFull(br, b); err != nil {
			return "", "", err
		}
		host = net.IP(b).String()
	case 0x03:
		l, err := br.ReadByte()
		if err != nil {
			return "", "", err
		}
		b := make([]byte, l)
		if _, err := io.ReadFull(br, b); err != nil {
			return "", "", err
		}
		host = string(b)
	case 0x04:
		b := make([]byte, 16)
		if _, err := io.ReadFull(br, b); err != nil {
			return "", "", err
		}
		host = net.IP(b).String()
	default:
		return "", "", fmt.Errorf("trojan atyp = %#x", atyp)
	}
	var portBuf [2]byte
	if _, err := io.ReadFull(br, portBuf[:]); err != nil {
		return "", "", err
	}
	tail := make([]byte, 2)
	if _, err := io.ReadFull(br, tail); err != nil || string(tail) != "\r\n" {
		return "", "", fmt.Errorf("trojan trailing CRLF = %q, err = %v", tail, err)
	}
	port := int(portBuf[0])<<8 | int(portBuf[1])
	return hash, net.JoinHostPort(host, strconv.Itoa(port)), nil
}

// startFakeTrojanServer runs a plaintext (security=none) trojan server that
// checks the password hash and relays to the requested target, like a real
// node does. Anything with a wrong hash is hung up with no reply — trojan
// sends no handshake response.
func startFakeTrojanServer(t *testing.T, password string) (addr string, seen chan string) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	sum := sha256.Sum224([]byte(password))
	want := hex.EncodeToString(sum[:])
	seen = make(chan string, 16)
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				// The handshake reader must stay in the relay path: the
				// client's first payload bytes may already sit in its buffer
				// (one TCP segment), and relaying from the bare conn would
				// drop them — the tunneled request never reaches the target.
				_ = c.SetReadDeadline(time.Now().Add(5 * time.Second))
				br := bufio.NewReader(c)
				hash, target, err := readTrojanRequest(br)
				if err != nil {
					return // bare TCP probe or garbage: hang up
				}
				if hash != want {
					return // wrong password: hang up silently
				}
				select {
				case seen <- hash:
				default:
				}
				up, err := net.DialTimeout("tcp", target, 5*time.Second)
				if err != nil {
					return
				}
				defer up.Close()
				go func() {
					_, _ = io.Copy(up, br)
				}()
				_, _ = io.Copy(c, up)
			}(c)
		}
	}()
	return ln.Addr().String(), seen
}

func TestParseTrojanURL(t *testing.T) {
	cases := []struct {
		token string
		ok    bool
		host  string
		port  int
		pw    string
		sni   string
		noTLS bool
	}{
		{"trojan://XG59623478@game-thrush.rooster465.autos:443?type=tcp", true, "game-thrush.rooster465.autos", 443, "XG59623478", "", false},
		{"trojan://FH72359861@54.180.228.238:443?sni=pure-ram.rooster465.autos&type=tcp#", true, "54.180.228.238", 443, "FH72359861", "pure-ram.rooster465.autos", false},
		{"trojan://pw@host.example:443", true, "host.example", 443, "pw", "", false},
		{"trojan://8r%3C%5B9%27l6hAO%238ZQi@167.71.169.92:443?security=tls", true, "167.71.169.92", 443, "8r%3C%5B9%27l6hAO%238ZQi", "", false},
		{"trojan://Trojan@82164024@92.118.150.146:443?sni=pl.tronsg.com", true, "92.118.150.146", 443, "Trojan@82164024", "pl.tronsg.com", false},
		{"trojan://FNWzI4OwPTNgAFZUUUFjx19m5YfLo3qNXt07tCQ3lZw%3D@65.109.219.124:41393?security=none&type=tcp", true, "65.109.219.124", 41393, "FNWzI4OwPTNgAFZUUUFjx19m5YfLo3qNXt07tCQ3lZw%3D", "", true},
		{"trojan://pw@host.example:443?type=raw", true, "host.example", 443, "pw", "", false},
		{"trojan://pw@host.example:443?type=ws&path=/x", false, "", 0, "", "", false},
		{"trojan://pw@host.example:443?type=grpc", false, "", 0, "", "", false},
		{"trojan://pw@host.example:443?type=xhttp", false, "", 0, "", "", false},
		{"trojan://pw@host.example:443?security=reality&type=tcp", false, "", 0, "", "", false},
		{"trojan://@host.example:443", false, "", 0, "", "", false},
		{"trojan://host.example:443", false, "", 0, "", "", false},
		{"trojan://pw@localhost:443", false, "", 0, "", "", false},
		{"trojan://pw@host.example:0", false, "", 0, "", "", false},
		{"trojan://pw@host.example:70000", false, "", 0, "", "", false},
		{"trojan://pw@[::1]:443", true, "::1", 443, "pw", "", false},
		{"http://pw@host.example:443", false, "", 0, "", "", false},
	}
	for _, tc := range cases {
		c, ok := parseTrojanURL(tc.token)
		if ok != tc.ok {
			t.Errorf("%q: ok = %v, want %v", tc.token, ok, tc.ok)
			continue
		}
		if !tc.ok {
			continue
		}
		if c.Schema != "trojan" || c.Host != tc.host || c.Port != tc.port ||
			c.TrojanPassword != tc.pw || c.TrojanSNI != tc.sni || c.TrojanNoTLS != tc.noTLS {
			t.Errorf("%q: got %+v", tc.token, c)
		}
	}
}

func TestExtractTrojan(t *testing.T) {
	e, _ := NewExtractor(nil)
	body := `
trojan://UX82473651@game-thrush.rooster465.autos:443?type=tcp#one
trojan://OTHERPW@game-thrush.rooster465.autos:443?sni=game-thrush.rooster465.autos#two
trojan://FH72359861@54.180.228.238:443?type=ws&path=/x#ws-skipped
trojan://GRPCPW@10.9.9.9:443?type=grpc#grpc-skipped
trojan://PW1@10.9.9.9:443?type=tcp#tcp-kept
plain 9.9.9.9:8080 still works
`
	cands := e.Extract([]byte(body))
	byKey := map[string]Candidate{}
	for _, c := range cands {
		byKey[c.key()] = c
	}
	// Both passwords on the same host survive: different credentials are
	// different proxies.
	a, ok := byKey["trojan:UX82473651@game-thrush.rooster465.autos:443"]
	if !ok || a.Schema != "trojan" || a.TrojanPassword != "UX82473651" {
		t.Fatalf("first trojan entry missing: %v", byKey)
	}
	b, ok := byKey["trojan:OTHERPW@game-thrush.rooster465.autos:443"]
	if !ok || b.TrojanSNI != "game-thrush.rooster465.autos" {
		t.Fatalf("second trojan entry (other password) missing: %v", byKey)
	}
	if _, ok := byKey["trojan:PW1@10.9.9.9:443"]; !ok {
		t.Fatalf("tcp trojan entry missing: %v", byKey)
	}
	// ws/grpc entries never become candidates…
	for k := range byKey {
		if strings.Contains(k, "FH72359861") || strings.Contains(k, "GRPCPW") {
			t.Fatalf("non-tcp trojan entry leaked: %q", k)
		}
	}
	// …and the trojan socket is not re-emitted as a bare unknown-schema
	// candidate that would burn a multi-protocol check for nothing.
	for k, c := range byKey {
		if (k == "54.180.228.238:443" || k == "10.9.9.9:443") && c.Schema == "" {
			t.Fatalf("trojan socket double-emitted as bare: %q", k)
		}
	}
	if c := byKey["9.9.9.9:8080"]; c.Schema != "" {
		t.Fatalf("plain bare entry lost: %+v", c)
	}
}

// A password with URL-significant bytes must survive the whole persistence
// chain byte-identical: queue save, proxy.lst reload, pool file, admin view.
func TestTrojanModelRoundTrip(t *testing.T) {
	for _, line := range []string{
		"trojan://XG59623478@game-thrush.rooster465.autos:443?type=tcp",
		"trojan://8r%3C%5B9%27l6hAO%238ZQi@167.71.169.92:443?sni=Koma-YT.PAGeS.Dev",
		"trojan://FNWzI4OwPTNgAFZUUUFjx19m5YfLo3qNXt07tCQ3lZw%3D@65.109.219.124:41393?security=none&type=tcp",
		"trojan://Trojan@82164024@92.118.150.146:443?sni=pl.tronsg.com",
	} {
		p, err := ParseProxyLine(line)
		if err != nil {
			t.Fatalf("%q: %v", line, err)
		}
		if !p.IsTrojan() || p.GetTrojanPassword() == "" {
			t.Fatalf("%q: not parsed as credentialed trojan: %+v", line, p)
		}
		if got := string(p.AppendURL(nil)); got != p.URL() {
			t.Errorf("AppendURL(%q) = %q, URL() = %q", line, got, p.URL())
		}
		if p.URLLen() != len(p.URL()) {
			t.Errorf("URLLen(%q) = %d, len(URL()) = %d", line, p.URLLen(), len(p.URL()))
		}
		q, err := ParseProxyLine(p.URL())
		if err != nil {
			t.Fatalf("reload %q (from %q): %v", p.URL(), line, err)
		}
		if q.Schema != "trojan" || q.Host != p.Host || q.Port != p.Port ||
			q.GetTrojanPassword() != p.GetTrojanPassword() ||
			q.GetTrojanSNI() != p.GetTrojanSNI() ||
			q.GetTrojanNoTLS() != p.GetTrojanNoTLS() {
			t.Errorf("round-trip %q: got pw=%q sni=%q noTLS=%v; want pw=%q sni=%q noTLS=%v",
				line, q.GetTrojanPassword(), q.GetTrojanSNI(), q.GetTrojanNoTLS(),
				p.GetTrojanPassword(), p.GetTrojanSNI(), p.GetTrojanNoTLS())
		}
		if q.Key() != p.Key() {
			t.Errorf("round-trip %q: key changed %q -> %q", line, p.Key(), q.Key())
		}
	}
}

// Pool persistence must keep the credentials: a re-probed pool line without
// them is a candidate that can never validate again.
func TestTrojanPoolLineKeepsCredentials(t *testing.T) {
	c := Candidate{Schema: "trojan", Host: "game-thrush.rooster465.autos", Port: 443,
		TrojanPassword: "pw#1", TrojanSNI: "sni.example", Source: "http://s/list.txt"}
	line := poolPersistLine(c)
	if !strings.Contains(line, "trojan://pw#1@") || !strings.Contains(line, "sni=sni.example") {
		t.Fatalf("pool line dropped credentials: %q", line)
	}
	pl, ok := parsePoolLine(line + "\t" + c.Source)
	if !ok {
		t.Fatalf("pool line does not re-parse: %q", line)
	}
	back, err := ParseProxyLine(strings.SplitN(line, "\t", 2)[0])
	if err != nil {
		t.Fatalf("pool line reload: %v", err)
	}
	_ = back
	if pl.schema != "trojan" || pl.host != c.Host || pl.port != c.Port {
		t.Fatalf("pool line parsed as %+v", pl)
	}
	if pl.source != c.Source {
		t.Fatalf("pool line source = %q, want %q", pl.source, c.Source)
	}
}

func TestDialTrojanPlaintext(t *testing.T) {
	const password = "8r<[9'l6hAO#8ZQi" // decoded form of an observed encoded password
	addr, seen := startFakeTrojanServer(t, password)
	_, portStr, _ := net.SplitHostPort(addr)
	port, err := strconv.Atoi(portStr)
	if err != nil {
		t.Fatal(err)
	}
	// Local echo target: the tunnel must carry bytes both ways past the
	// handshake, like a real relayed session.
	echoLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer echoLn.Close()
	go func() {
		for {
			c, err := echoLn.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				_, _ = io.Copy(c, c)
			}(c)
		}
	}()
	p := &Proxy{Schema: "trojan", Host: "127.0.0.1", Port: port, meta: &ProxyMeta{}}
	// Stored URL-form (encoded): the handshake must hash the decoded bytes —
	// the server below checks against sha224("8r<[9'l6hAO#8ZQi").
	p.SetTrojan("8r%3C%5B9%27l6hAO%238ZQi", "", true)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	conn, err := dialTrojan(p, 5*time.Second, ctx, "tcp", echoLn.Addr().String())
	if err != nil {
		t.Fatalf("dialTrojan plaintext: %v", err)
	}
	defer conn.Close()
	select {
	case <-seen:
	case <-time.After(5 * time.Second):
		t.Fatal("server never saw the handshake")
	}
	if _, err := conn.Write([]byte("ping")); err != nil {
		t.Fatalf("tunnel write: %v", err)
	}
	_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	got := make([]byte, 4)
	if _, err := io.ReadFull(conn, got); err != nil || string(got) != "ping" {
		t.Fatalf("tunnel echo = %q, err = %v", got, err)
	}
}

func TestDialTrojanTLS(t *testing.T) {
	cert, err := LoadOrCreateTLS("", "")
	if err != nil {
		t.Fatalf("test cert: %v", err)
	}
	sniSeen := make(chan string, 1)
	tlsCfg := &tls.Config{
		Certificates: []tls.Certificate{cert},
		GetConfigForClient: func(hello *tls.ClientHelloInfo) (*tls.Config, error) {
			select {
			case sniSeen <- hello.ServerName:
			default:
			}
			return nil, nil
		},
	}
	ln, err := tls.Listen("tcp", "127.0.0.1:0", tlsCfg)
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	type req struct{ hash, target string }
	got := make(chan req, 1)
	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		_ = c.SetReadDeadline(time.Now().Add(5 * time.Second))
		hash, target, err := readTrojanRequest(bufio.NewReader(c))
		if err != nil {
			t.Errorf("server read: %v", err)
			return
		}
		got <- req{hash, target}
	}()
	_, portStr, _ := net.SplitHostPort(ln.Addr().String())
	port, err := strconv.Atoi(portStr)
	if err != nil {
		t.Fatal(err)
	}
	p := &Proxy{Schema: "trojan", Host: "127.0.0.1", Port: port, meta: &ProxyMeta{}}
	p.SetTrojan("s3cret", "trojan-sni.example", false)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	conn, err := dialTrojan(p, 5*time.Second, ctx, "tcp", "93.184.216.34:80")
	if err != nil {
		t.Fatalf("dialTrojan TLS: %v", err)
	}
	defer conn.Close()
	select {
	case r := <-got:
		sum := sha256.Sum224([]byte("s3cret"))
		if r.hash != hex.EncodeToString(sum[:]) {
			t.Fatalf("server hash = %q, want sha224(password)", r.hash)
		}
		if r.target != "93.184.216.34:80" {
			t.Fatalf("server target = %q", r.target)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("server never saw the handshake")
	}
	select {
	case sni := <-sniSeen:
		if sni != "trojan-sni.example" {
			t.Fatalf("TLS SNI = %q, want the trojan sni (not the tunneled target)", sni)
		}
	case <-time.After(time.Second):
		t.Fatal("no ClientHello observed")
	}
}

func TestDialTrojanNeedsPassword(t *testing.T) {
	p := &Proxy{Schema: "trojan", Host: "127.0.0.1", Port: 443, meta: &ProxyMeta{}}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if _, err := dialTrojan(p, 2*time.Second, ctx, "tcp", "93.184.216.34:80"); err == nil {
		t.Fatal("passwordless trojan dial succeeded")
	}
}

// Full validation through a fake trojan node: exit-IP proof, field wiring,
// and the serving dial path (e2eProbe) in one go.
func TestCheckTrojanEndToEnd(t *testing.T) {
	const password = "UX82473651"
	trojanAddr, _ := startFakeTrojanServer(t, password)
	_, tPortStr, _ := net.SplitHostPort(trojanAddr)
	tPort, err := strconv.Atoi(tPortStr)
	if err != nil {
		t.Fatal(err)
	}
	selfIP := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("your ip is 1.2.3.4"))
	}))
	defer selfIP.Close()

	cfg := &Config{}
	cfg.Checker.SelfIPURLs = []string{selfIP.URL}
	cfg.Checker.TCPTimeout = Duration{2 * time.Second}
	cfg.Checker.ConnectT = Duration{3 * time.Second}
	cfg.Checker.TLSHandshake = Duration{3 * time.Second}
	cfg.Checker.ResponseT = Duration{5 * time.Second}
	cfg.Checker.TotalT = Duration{15 * time.Second}
	cfg.Checker.E2EProbe = true
	c := &Checker{cfg: cfg, selfIP: net.ParseIP("9.9.9.9"), ipRe: reAnyIP, allowBogon: true}

	cand := Candidate{Schema: "trojan", Host: "127.0.0.1", Port: tPort,
		TrojanPassword: password, TrojanSNI: "", TrojanNoTLS: true}
	p, err := c.Check(cand)
	if err != nil {
		t.Fatalf("trojan check: %v", err)
	}
	if !p.IsTrojan() || p.GetTrojanPassword() != password {
		t.Fatalf("validated proxy lost its credentials: %+v", p)
	}
	if p.Host != "127.0.0.1" || p.Port != tPort {
		t.Fatalf("validated proxy = %s:%d", p.Host, p.Port)
	}
}
