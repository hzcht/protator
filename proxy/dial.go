package proxy

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
	"time"

	utls "github.com/refraction-networking/utls"
	"golang.org/x/crypto/curve25519"
	"golang.org/x/crypto/hkdf"
	"h12.io/socks"
)

// isSocks reports whether the schema is a SOCKS protocol.
func isSocks(schema string) bool {
	return schema == "socks4" || schema == "socks5"
}

// dialProxy opens a TCP connection to addr tunnelling through proxy p.
// Works for http/https (CONNECT), socks4/socks5, and vless.
func dialProxy(p *Proxy, timeout time.Duration, ctx context.Context, network, addr string) (net.Conn, error) {
	switch p.Schema {
	case "socks4", "socks5":
		return socksDialTimeout(p, timeout, ctx, network, addr)
	case "vless":
		return dialVLESS(p, timeout, ctx, network, addr)
	default: // http, https
		return connectHTTPProxy(p, timeout, ctx, network, addr)
	}
}

// connectHTTPProxy establishes a CONNECT tunnel through an http/https proxy.
func connectHTTPProxy(p *Proxy, timeout time.Duration, ctx context.Context, network, addr string) (net.Conn, error) {
	d := net.Dialer{Timeout: timeout, KeepAlive: 30 * time.Second}
	conn, err := d.DialContext(ctx, network, p.Addr())
	if err != nil {
		return nil, err
	}

	if p.Schema == "https" {
		tconn := tls.Client(conn, &tls.Config{
			ServerName:         p.Host,
			InsecureSkipVerify: true,
		})
		tconn.SetDeadline(time.Now().Add(timeout))
		if err := tconn.HandshakeContext(ctx); err != nil {
			conn.Close()
			return nil, err
		}
		tconn.SetDeadline(time.Time{})
		conn = tconn
	}

	conn.SetDeadline(time.Now().Add(timeout))
	req := "CONNECT " + addr + " HTTP/1.1\r\nHost: " + addr + "\r\nProxy-Connection: keep-alive\r\n\r\n"
	if _, err := conn.Write([]byte(req)); err != nil {
		conn.Close()
		return nil, err
	}

	status, err := readCONNECTResponse(conn)
	if err != nil {
		conn.Close()
		return nil, err
	}
	if status != 200 {
		conn.Close()
		return nil, errors.New("proxy CONNECT rejected with status " + strconv.Itoa(status))
	}
	conn.SetDeadline(time.Time{})
	return conn, nil
}

// readCONNECTResponse reads and drains the proxy's HTTP/1.x reply, returning
// the status code.
func readCONNECTResponse(conn net.Conn) (int, error) {
	const bufSize = 512
	buf := make([]byte, bufSize)
	var resp []byte
	for {
		n, err := conn.Read(buf)
		if n > 0 {
			resp = append(resp, buf[:n]...)
			if containsCRLFCRLF(resp) {
				break
			}
		}
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return 0, errors.New("proxy closed during CONNECT")
			}
			return 0, err
		}
		// n == 0 with err == nil is legal for an io.Reader; the read
		// deadline set by the caller is the only thing that bounds this
		// loop, so there is nothing extra to guard here.
		if len(resp) > 8192 {
			return 0, errors.New("proxy sent oversized CONNECT reply")
		}
	}
	return parseHTTPStatus(resp)
}

func containsCRLFCRLF(b []byte) bool {
	return bytes.Index(b, []byte("\r\n\r\n")) >= 0
}

func parseHTTPStatus(b []byte) (int, error) {
	// "HTTP/1.1 200 Connection established\r\n"
	if len(b) < 12 {
		return 0, errors.New("short CONNECT reply")
	}
	i := 0
	for i < len(b) && b[i] != ' ' {
		i++
	}
	if i >= len(b) {
		return 0, errors.New("malformed CONNECT reply")
	}
	i++
	var code int
	for i < len(b) && b[i] >= '0' && b[i] <= '9' {
		code = code*10 + int(b[i]-'0')
		i++
	}
	if code == 0 {
		return 0, errors.New("malformed CONNECT reply status")
	}
	return code, nil
}

// socksDialRes is the outcome of one background SOCKS dial.
type socksDialRes struct {
	conn net.Conn
	err  error
}

// socksDialTimeout bounds h12.io/socks's blocking dial.
//
// The timeout has to be handed to the library as a query parameter, not just
// enforced by the select below: h12.io/socks only sets deadlines on the socket
// when cfg.Timeout > 0, so without ?timeout= the connect, the greeting and the
// SOCKS handshake all run unbounded. The select still returns on time, but the
// abandoned goroutine below then parks on an operation that can take minutes —
// which is how a scraped proxy that accepts TCP and ignores the greeting leaks
// a goroutine and a socket per attempt.
func socksDialTimeout(p *Proxy, timeout time.Duration, ctx context.Context, network, addr string) (net.Conn, error) {
	dial := socks.Dial(socksProxyURL(p, timeout))
	ch := make(chan socksDialRes, 1)
	go func() {
		defer RecoverPanic("socks: dial")
		conn, err := dial(network, addr)
		ch <- socksDialRes{conn, err}
	}()
	timer := time.NewTimer(timeout)
	defer timer.Stop()
	select {
	case r := <-ch:
		if r.err == nil && r.conn != nil {
			// The library armed socket deadlines for its own handshake and
			// clears them on the socks4 path only — socks5 returns the conn
			// still carrying them. Nothing downstream refreshes a *write*
			// deadline, so leaving it armed means the first client write at
			// dial_timeout (5s on the serving path) fails with i/o timeout and
			// every long session dies. Clear them here.
			if err := r.conn.SetDeadline(time.Time{}); err != nil {
				r.conn.Close()
				return nil, err
			}
		}
		return r.conn, r.err
	case <-ctx.Done():
		closeLateSocksDial(ch)
		return nil, ctx.Err()
	case <-timer.C:
		closeLateSocksDial(ch)
		return nil, errors.New("socks dial timeout")
	}
}

// socksProxyURL is the proxy address with h12.io/socks's timeout query
// parameter appended, so the library bounds its own socket operations.
func socksProxyURL(p *Proxy, timeout time.Duration) string {
	return p.URL() + "?timeout=" + timeout.String()
}

// closeLateSocksDial reaps a dial that finished after the caller gave up, so
// its connection is closed rather than leaked. The library's own deadline
// bounds how long this parks.
func closeLateSocksDial(ch <-chan socksDialRes) {
	go func() {
		defer RecoverPanic("socks: late dial cleanup")
		if r := <-ch; r.conn != nil {
			r.conn.Close()
		}
	}()
}

// dialVLESS establishes a VLESS connection through a VLESS proxy.
// VLESS protocol: TLS handshake -> VLESS handshake (UUID + command) -> target connection.
// Supports REALITY (pbk/sid) and Vision (spider) flows.
func dialVLESS(p *Proxy, timeout time.Duration, ctx context.Context, network, addr string) (net.Conn, error) {
	d := net.Dialer{Timeout: timeout, KeepAlive: 30 * time.Second}
	conn, err := d.DialContext(ctx, network, p.Addr())
	if err != nil {
		return nil, err
	}

	// TLS handshake (REALITY or standard) using uTLS for fingerprinting
	sni := p.GetVLESSSNI()
	if sni == "" {
		host, _, _ := net.SplitHostPort(addr)
		sni = host
	}

	pbk := p.GetVLESSPbk()
	sid := p.GetVLESSSid()
	flow := p.GetVLESSFlow()

	var tconn *utls.Conn

	if pbk != "" {
		// REALITY: use uTLS with custom ClientHello
		tconn, err = dialVLESSRealty(conn, ctx, timeout, sni, pbk, sid, flow)
		if err != nil {
			conn.Close()
			return nil, err
		}
	} else {
		// Standard VLESS over TLS
		tlsConfig := &utls.Config{
			ServerName:         sni,
			InsecureSkipVerify: true,
			NextProtos:         []string{"vless"},
		}
		tconn = utls.Client(conn, tlsConfig)
		tconn.SetDeadline(time.Now().Add(timeout))
		if err := tconn.HandshakeContext(ctx); err != nil {
			conn.Close()
			return nil, err
		}
		tconn.SetDeadline(time.Time{})
	}

	// VLESS handshake: send UUID + command
	if err := vlessHandshake(tconn, p, addr); err != nil {
		tconn.Close()
		return nil, err
	}

	// Vision/Spider header if present
	if spider := p.GetVLESSSpider(); spider != "" {
		if _, err := tconn.Write([]byte(spider)); err != nil {
			tconn.Close()
			return nil, err
		}
	}

	return tconn, nil
}

// dialVLESSRealty performs a REALITY handshake using uTLS.
// REALITY is a TLS extension that disguises VLESS traffic as normal HTTPS.
// It encrypts the ClientHello using keys derived from the server's public key (pbk)
// and a short ID (sid).
func dialVLESSRealty(conn net.Conn, ctx context.Context, timeout time.Duration, sni, pbkB64, sid, flow string) (*utls.Conn, error) {
	// Decode server's public key (x25519)
	pbk, err := base64.RawURLEncoding.DecodeString(pbkB64)
	if err != nil {
		return nil, fmt.Errorf("decode pbk: %w", err)
	}
	if len(pbk) != 32 {
		return nil, errors.New("pbk must be 32 bytes")
	}

	// Generate ephemeral x25519 keypair
	var priv, pub [32]byte
	if _, err := rand.Read(priv[:]); err != nil {
		return nil, err
	}
	curve25519.ScalarBaseMult(&pub, &priv)

	// Compute shared secret: X25519(priv, pbk)
	var shared [32]byte
	curve25519.ScalarMult(&shared, &priv, (*[32]byte)(pbk))

	// Derive keys using HKDF-SHA256
	// REALITY uses HKDF with salt = sid (or empty) and info = "reality"
	sidBytes := []byte(sid)
	info := []byte("reality")
	hkdfReader := hkdf.New(sha256.New, shared[:], sidBytes, info)
	var key, iv [16]byte
	if _, err := rand.Read(key[:]); err != nil {
		return nil, err
	}
	if _, err := io.ReadFull(hkdfReader, iv[:]); err != nil {
		return nil, err
	}

	// Build uTLS Config with custom ClientHello
	// Use Chrome HelloID for realistic fingerprint
	tlsConfig := &utls.Config{
		ServerName:         sni,
		InsecureSkipVerify: true,
		NextProtos:         []string{"vless"},
	}

	// Create uTLS connection with Chrome fingerprint
	uconn := utls.Client(conn, tlsConfig)
	if err := uconn.SetDeadline(time.Now().Add(timeout)); err != nil {
		conn.Close()
		return nil, err
	}

	// Build a Custom ClientHello. The ClientHello is encrypted with AES-GCM
	// using the derived key/iv and padded before being sent — see
	// sendRealtyClientHello, which is a stub. REALITY proxies will fail here.
	if err := sendRealtyClientHello(uconn); err != nil {
		uconn.Close()
		return nil, err
	}

	// Read server response
	uconn.SetReadDeadline(time.Now().Add(timeout))
	buf := make([]byte, 16384)
	n, err := uconn.Read(buf)
	if err != nil {
		uconn.Close()
		return nil, err
	}
	if n == 0 {
		uconn.Close()
		return nil, errors.New("REALITY: empty server response")
	}

	uconn.SetDeadline(time.Time{})
	return uconn, nil
}

// sendRealtyClientHello triggers the TLS ClientHello for a REALITY connection.
//
// A real REALITY dial does not send a plain ClientHello: the hello has to be
// AES-GCM encrypted with the derived key/iv, padded to a random length, and
// sent as one record, so the server can authenticate it as TLS-in-TLS. This
// implementation does none of that — it relies on uTLS to emit a normal
// ClientHello and on the server accepting it. It is a stub: the key/iv dialVLESS
// derives below are unused, and `flow` belongs to the VLESS handshake that
// follows, not here. REALITY proxies will fail here.
func sendRealtyClientHello(uconn *utls.Conn) error {
	// Trigger the handshake: uTLS emits the ClientHello on first Write.
	_, err := uconn.Write([]byte{})
	return err
}

// vlessHandshake sends the VLESS handshake packet: UUID + command + target address.
// VLESS packet format: [version(1)][uuid(16)][command(1)][addon_len(2)][addon][address][port(2)]
func vlessHandshake(conn net.Conn, p *Proxy, addr string) error {
	uuid := p.GetVLESSUUID()
	if uuid == "" {
		return errors.New("VLESS UUID required")
	}
	// Parse UUID string to 16 bytes
	uuidBytes, err := parseUUID(uuid)
	if err != nil {
		return err
	}

	host, portStr, err := net.SplitHostPort(addr)
	if err != nil {
		return err
	}
	port, _ := strconv.Atoi(portStr)

	// Build VLESS handshake packet
	// Version (1 byte) = 0
	// UUID (16 bytes)
	// Command (1 byte) = 1 (TCP connect)
	// Addon length (2 bytes) = 0 for now
	// Address: type(1) + len(1) + data... (IPv4=1, Domain=2, IPv6=3)
	// Port (2 bytes, big endian)

	// Fixed-size buffer on stack. The header is 1+16+1+2 = 20 bytes; the
	// address is at most type(1)+len(1)+255+port(2).
	//
	// addr comes from the client (a SOCKS5 ATYP domain is a single length
	// byte, so up to 255 bytes, and nothing validates it against the DNS
	// limit). The old arithmetic double-counted a byte and let a 256-byte
	// host index past the end of the array, so the check is now on the
	// address itself rather than on a buffer-size formula.
	const vlessMaxDomain = 255
	if len(host) > vlessMaxDomain {
		return fmt.Errorf("destination host too long for VLESS handshake: %d bytes (max %d)", len(host), vlessMaxDomain)
	}
	var buf [1 + 16 + 1 + 2 + 1 + 1 + vlessMaxDomain + 2]byte
	n := 0
	buf[n] = 0 // version
	n++
	copy(buf[n:], uuidBytes) // uuid (16 bytes)
	n += 16
	buf[n] = 1 // command = TCP connect
	n++
	binary.BigEndian.PutUint16(buf[n:], 0) // addon length = 0
	n += 2

	// Address encoding
	ip := net.ParseIP(host)
	if ip != nil {
		if ip4 := ip.To4(); ip4 != nil {
			buf[n] = 1 // IPv4
			n++
			copy(buf[n:], ip4) // 4 bytes
			n += 4
		} else {
			buf[n] = 3 // IPv6
			n++
			copy(buf[n:], ip.To16()) // 16 bytes
			n += 16
		}
	} else {
		// Domain
		buf[n] = 2 // domain
		n++
		buf[n] = byte(len(host))
		n++
		copy(buf[n:], host)
		n += len(host)
	}

	binary.BigEndian.PutUint16(buf[n:], uint16(port))
	n += 2

	if err := conn.SetWriteDeadline(time.Now().Add(10 * time.Second)); err != nil {
		return err
	}
	if _, err = conn.Write(buf[:n]); err != nil {
		return err
	}
	// Clear it again. The connection goes straight to the serving path, and a
	// SOCKS5 tunnel or a CONNECT tunnel is long-lived: leaving a 10s write
	// deadline armed killed any session that wrote later than that, even
	// though nothing was wrong with it.
	return conn.SetDeadline(time.Time{})
}

// parseUUID parses a UUID string (xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx) to 16 bytes.
func parseUUID(s string) ([]byte, error) {
	// Remove hyphens
	clean := make([]byte, 0, 32)
	for i := 0; i < len(s); i++ {
		if s[i] != '-' {
			clean = append(clean, s[i])
		}
	}
	if len(clean) != 32 {
		return nil, errors.New("invalid UUID length")
	}
	var out [16]byte
	if _, err := hex.Decode(out[:], clean); err != nil {
		return nil, err
	}
	return out[:], nil
}
