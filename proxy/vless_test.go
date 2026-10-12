package proxy

import (
	"bufio"
	"context"
	"encoding/binary"
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

const testVLESSUUID = "d342d11e-d424-4583-b36e-524ab1f0afa4"

// readVLESSRequest reads one VLESS handshake from the server side: version,
// UUID, command, addon, SOCKS-style address (VLESS numbering: 1=v4, 2=domain,
// 3=v6). Returns the UUID bytes and the requested target.
func readVLESSRequest(br *bufio.Reader) (uuid []byte, target string, err error) {
	fail := func(format string, args ...interface{}) ([]byte, string, error) {
		return nil, "", fmt.Errorf(format, args...)
	}
	ver, err := br.ReadByte()
	if err != nil || ver != 0 {
		return fail("vless version = %x, err = %v", ver, err)
	}
	uuid = make([]byte, 16)
	if _, err := io.ReadFull(br, uuid); err != nil {
		return fail("vless uuid: %v", err)
	}
	cmd, err := br.ReadByte()
	if err != nil || cmd != 1 {
		return fail("vless cmd = %x, err = %v", cmd, err)
	}
	var addonLen [2]byte
	if _, err := io.ReadFull(br, addonLen[:]); err != nil {
		return fail("vless addon len: %v", err)
	}
	if n := int(binary.BigEndian.Uint16(addonLen[:])); n > 0 {
		if _, err := io.CopyN(io.Discard, br, int64(n)); err != nil {
			return fail("vless addon: %v", err)
		}
	}
	atyp, err := br.ReadByte()
	if err != nil {
		return fail("vless atyp: %v", err)
	}
	var host string
	switch atyp {
	case 1:
		b := make([]byte, 4)
		if _, err := io.ReadFull(br, b); err != nil {
			return fail("vless ipv4: %v", err)
		}
		host = net.IP(b).String()
	case 2:
		l, err := br.ReadByte()
		if err != nil {
			return fail("vless domain len: %v", err)
		}
		b := make([]byte, l)
		if _, err := io.ReadFull(br, b); err != nil {
			return fail("vless domain: %v", err)
		}
		host = string(b)
	case 3:
		b := make([]byte, 16)
		if _, err := io.ReadFull(br, b); err != nil {
			return fail("vless ipv6: %v", err)
		}
		host = net.IP(b).String()
	default:
		return fail("vless atyp = %#x", atyp)
	}
	var portBuf [2]byte
	if _, err := io.ReadFull(br, portBuf[:]); err != nil {
		return fail("vless port: %v", err)
	}
	return uuid, net.JoinHostPort(host, strconv.Itoa(int(portBuf[0])<<8|int(portBuf[1]))), nil
}

func TestParseVLESSURL(t *testing.T) {
	cases := []struct {
		token string
		ok    bool
		host  string
		port  int
		uuid  string
		sni   string
		noTLS bool
	}{
		{"vless://d342d11e-d424-4583-b36e-524ab1f0afa4@1.2.3.4:443?encryption=none&security=tls&sni=example.com&type=tcp", true, "1.2.3.4", 443, testVLESSUUID, "example.com", false},
		{"vless://uuid@host.example:443", true, "host.example", 443, "uuid", "", false},
		{"vless://uuid@host.example:443?security=none&type=tcp", true, "host.example", 443, "uuid", "", true},
		{"vless://uuid@host.example:443?security=reality&pbk=abc&sid=1&sni=x.com", true, "host.example", 443, "uuid", "x.com", false},
		{"vless://uuid@host.example:443?type=ws&path=/x", false, "", 0, "", "", false},
		{"vless://uuid@host.example:443?type=grpc", false, "", 0, "", "", false},
		{"vless://uuid@host.example:443?security=xtls", false, "", 0, "", "", false},
		{"vless://@host.example:443", false, "", 0, "", "", false},
		{"vless://host.example:443", false, "", 0, "", "", false},
		{"vless://uuid@localhost:443", false, "", 0, "", "", false},
		{"vless://uuid@host.example:0", false, "", 0, "", "", false},
		{"trojan://pw@host.example:443", false, "", 0, "", "", false},
	}
	for _, tc := range cases {
		c, ok := parseVLESSURL(tc.token)
		if ok != tc.ok {
			t.Errorf("%q: ok = %v, want %v", tc.token, ok, tc.ok)
			continue
		}
		if !tc.ok {
			continue
		}
		if c.Schema != "vless" || c.Host != tc.host || c.Port != tc.port ||
			c.VLESSUUID != tc.uuid || c.VLESSSNI != tc.sni || c.VLESSNoTLS != tc.noTLS {
			t.Errorf("%q: got %+v", tc.token, c)
		}
	}
}

func TestExtractVLESS(t *testing.T) {
	e, _ := NewExtractor(nil)
	body := `
vless://d342d11e-d424-4583-b36e-524ab1f0afa4@node.example:443?encryption=none&security=tls&sni=node.example&type=tcp#one
vless://other-uuid@node.example:443?security=tls#two
vless://ws-uuid@node.example:443?type=ws#ws-skipped
plain 9.9.9.9:8080 still works
`
	cands := e.Extract([]byte(body))
	byKey := map[string]Candidate{}
	for _, c := range cands {
		byKey[c.key()] = c
	}
	if a, ok := byKey["vless:"+testVLESSUUID+"@node.example:443"]; !ok || a.TrojanPassword != "" || a.VLESSSNI != "node.example" {
		t.Fatalf("first vless entry missing: %v", byKey)
	}
	if _, ok := byKey["vless:other-uuid@node.example:443"]; !ok {
		t.Fatalf("second vless entry (other uuid) missing: %v", byKey)
	}
	for k := range byKey {
		if strings.Contains(k, "ws-uuid") {
			t.Fatalf("ws vless entry leaked: %q", k)
		}
		if k == "node.example:443" {
			t.Fatalf("vless socket double-emitted as bare: %q", k)
		}
	}
	if _, ok := byKey["9.9.9.9:8080"]; !ok {
		t.Fatalf("plain bare entry lost: %v", byKey)
	}
}

// security=none must survive the persistence chain like every other field.
func TestVLESSModelRoundTripNoTLS(t *testing.T) {
	line := "vless://d342d11e-d424-4583-b36e-524ab1f0afa4@node.example:443?security=none&type=tcp"
	p, err := ParseProxyLine(line)
	if err != nil {
		t.Fatalf("%q: %v", line, err)
	}
	if !p.IsVLESS() || !p.GetVLESSNoTLS() {
		t.Fatalf("%q: noTLS not parsed: %+v", line, p)
	}
	if got := string(p.AppendURL(nil)); got != p.URL() {
		t.Errorf("AppendURL = %q, URL() = %q", got, p.URL())
	}
	if p.URLLen() != len(p.URL()) {
		t.Errorf("URLLen = %d, len(URL()) = %d", p.URLLen(), len(p.URL()))
	}
	q, err := ParseProxyLine(p.URL())
	if err != nil {
		t.Fatalf("reload %q: %v", p.URL(), err)
	}
	if !q.GetVLESSNoTLS() || q.GetVLESSUUID() != testVLESSUUID {
		t.Errorf("round-trip lost fields: %+v", q)
	}
}

// startFakeVLESSServer runs a plaintext VLESS server that checks the UUID
// and relays to the requested target.
func startFakeVLESSServer(t *testing.T, uuidHex string) (addr string, seen chan string) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	want, err := parseUUID(uuidHex)
	if err != nil {
		t.Fatal(err)
	}
	seen = make(chan string, 16)
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				_ = c.SetReadDeadline(time.Now().Add(5 * time.Second))
				br := bufio.NewReader(c)
				uuid, target, err := readVLESSRequest(br)
				if err != nil {
					return // bare TCP probe or garbage: hang up
				}
				if string(uuid) != string(want) {
					return // wrong UUID: hang up silently
				}
				select {
				case seen <- target:
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

func TestDialVLESSPlaintext(t *testing.T) {
	addr, seen := startFakeVLESSServer(t, testVLESSUUID)
	_, portStr, _ := net.SplitHostPort(addr)
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
	host, portStr2, _ := net.SplitHostPort(addr)
	_ = host
	port, err := strconv.Atoi(portStr2)
	if err != nil {
		t.Fatal(err)
	}
	_ = portStr
	p := &Proxy{Schema: "vless", Host: "127.0.0.1", Port: port, meta: &ProxyMeta{}}
	p.SetVLESS(testVLESSUUID, "", "", "", "", "", true)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	conn, err := dialVLESS(p, 5*time.Second, ctx, "tcp", echoLn.Addr().String())
	if err != nil {
		t.Fatalf("dialVLESS plaintext: %v", err)
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

// The fixed credential copy, proven end to end: a fresh vless candidate
// with a UUID must validate — before the fix the UUID never left the
// Candidate and every such check failed.
func TestCheckVLESSEndToEnd(t *testing.T) {
	vlessAddr, _ := startFakeVLESSServer(t, testVLESSUUID)
	_, tPortStr, _ := net.SplitHostPort(vlessAddr)
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

	cand := Candidate{Schema: "vless", Host: "127.0.0.1", Port: tPort,
		VLESSUUID: testVLESSUUID, VLESSNoTLS: true}
	p, err := c.Check(cand)
	if err != nil {
		t.Fatalf("vless check: %v", err)
	}
	if !p.IsVLESS() || p.GetVLESSUUID() != testVLESSUUID {
		t.Fatalf("validated proxy lost its UUID: %+v", p)
	}
}
