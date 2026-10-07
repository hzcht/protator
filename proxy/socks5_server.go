package proxy

import (
	"context"
	"encoding/binary"
	"errors"
	"io"
	"log"
	"net"
	"strconv"
	"sync"
	"time"
)

// Socks5Server is a minimal SOCKS5 (RFC 1928) front-end. Accepted CONNECT
// sessions are tunnelled through a random live upstream proxy, so SOCKS5
// clients get the same rotating-anonymity behaviour as HTTP clients.
type Socks5Server struct {
	dialer     *ForwardDialer
	dialTO     time.Duration
	idleTO     time.Duration
	listenAddr string

	mu sync.Mutex
	ln net.Listener
}

// NewSocks5Server builds the front-end from config.
func NewSocks5Server(cfg *Config, dialer *ForwardDialer) *Socks5Server {
	return &Socks5Server{
		dialer:     dialer,
		dialTO:     cfg.Socks5.DialTimeout.Duration,
		idleTO:     cfg.Socks5.IdleTimeout.Duration,
		listenAddr: cfg.Socks5.Listen,
	}
}

// ListenAndServe runs the accept loop until ctx is cancelled.
func (s *Socks5Server) ListenAndServe(ctx context.Context) error {
	ln, err := net.Listen("tcp", s.listenAddr)
	if err != nil {
		return err
	}
	s.mu.Lock()
	s.ln = ln
	s.mu.Unlock()
	defer func() {
		ln.Close()
		s.mu.Lock()
		s.ln = nil
		s.mu.Unlock()
	}()
	log.Printf("socks5: listening on %s", s.listenAddr)

	var wg sync.WaitGroup
	defer wg.Wait()
	for {
		conn, err := ln.Accept()
		if err != nil {
			if ctx.Err() != nil || s.closed() {
				return nil
			}
			continue
		}
		wg.Add(1)
		go func(c net.Conn) {
			defer wg.Done()
			s.handle(c)
		}(conn)
	}
}

// Close stops the accept loop immediately; active sessions keep running until
// they finish or idle out. Safe to call multiple times / from another goroutine.
func (s *Socks5Server) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.ln != nil {
		err := s.ln.Close()
		s.ln = nil
		return err
	}
	return nil
}

func (s *Socks5Server) closed() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.ln == nil
}

func (s *Socks5Server) handle(conn net.Conn) {
	defer conn.Close()
	if err := conn.SetDeadline(time.Now().Add(s.dialTO)); err != nil {
		return
	}

	// ---- greeting: version + methods ----
	var hdr [2]byte
	if _, err := io.ReadFull(conn, hdr[:]); err != nil {
		return
	}
	if hdr[0] != 5 {
		return
	}
	methods := make([]byte, int(hdr[1]))
	if _, err := io.ReadFull(conn, methods); err != nil {
		return
	}
	if !containsByte(methods, 0x00) {
		conn.Write([]byte{0x05, 0xFF}) // no acceptable methods
		return
	}
	if _, err := conn.Write([]byte{0x05, 0x00}); err != nil { // no auth
		return
	}

	// ---- request ----
	var req [4]byte
	if _, err := io.ReadFull(conn, req[:]); err != nil {
		return
	}
	if req[0] != 5 {
		return
	}
	if req[1] != 1 { // only CONNECT
		s.reply(conn, 0x07) // command not supported
		return
	}

	target, err := readTarget(conn, req[3])
	if err != nil {
		s.reply(conn, 0x08)
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), s.dialTO)
	up, err := s.dialer.DialContext(ctx, "tcp", target)
	cancel()
	if err != nil {
		s.reply(conn, 0x05) // connection refused
		return
	}

	// bnd.addr 0.0.0.0:0 is acceptable to most clients
	reply := []byte{0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0}
	if _, err := conn.Write(reply); err != nil {
		up.Close()
		return
	}
	conn.SetDeadline(time.Time{})

	toUp, toDown := relayCount(conn, up, s.idleTO)
	// The session ran to completion: settle the proxy's health (the dial only
	// sampled latency; a served session is what clears any failure streak).
	if pc, ok := up.(*proxyConn); ok {
		s.settle(pc.p, toUp, toDown)
	}
}

// settle turns a finished SOCKS session into proxy health. Only a session
// that actually moved far-side bytes is proof of life: crediting silent
// tunnels with MarkServeOK is how blackholes entrenched themselves in the hot
// tail. A session where the client spoke but the far side never answered is
// charged like a blackhole; a session where nobody spoke (port probe, instant
// close) is neutral — no proof either way.
func (s *Socks5Server) settle(p *Proxy, toUp, toDown int64) {
	switch {
	case toDown > 0:
		p.MarkServeOK(0)
		s.dialer.bucket.Promote(p)
	case toUp > 0:
		if fails := p.MarkServeFail(); fails >= int64(s.dialer.serveMaxFails) {
			s.dialer.bucket.Remove(p)
		}
	}
}

func readTarget(conn net.Conn, atyp byte) (string, error) {
	var host string
	switch atyp {
	case 0x01: // IPv4
		b := make([]byte, 4)
		if _, err := io.ReadFull(conn, b); err != nil {
			return "", err
		}
		host = net.IP(b).String()
	case 0x03: // domain
		var l [1]byte
		if _, err := io.ReadFull(conn, l[:]); err != nil {
			return "", err
		}
		b := make([]byte, int(l[0]))
		if _, err := io.ReadFull(conn, b); err != nil {
			return "", err
		}
		host = string(b)
	case 0x04: // IPv6
		b := make([]byte, 16)
		if _, err := io.ReadFull(conn, b); err != nil {
			return "", err
		}
		host = net.IP(b).String()
	default:
		return "", errors.New("unknown ATYP")
	}
	var port [2]byte
	if _, err := io.ReadFull(conn, port[:]); err != nil {
		return "", err
	}
	p := binary.BigEndian.Uint16(port[:])
	if p == 0 {
		return "", errors.New("zero port")
	}
	return net.JoinHostPort(host, strconv.Itoa(int(p))), nil
}

func (s *Socks5Server) reply(conn net.Conn, code byte) {
	conn.Write([]byte{0x05, code, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
}

func containsByte(b []byte, v byte) bool {
	for _, x := range b {
		if x == v {
			return true
		}
	}
	return false
}

// relay pipes bidirectional traffic, resetting the idle deadline on every
// byte so that long-lived tunnels stay open while active.
func relay(a, b net.Conn, idle time.Duration) {
	relayCount(a, b, idle)
}

// relayCount is relay plus per-leg volume: fromA counts bytes a->b, fromB
// bytes b->a. The SOCKS verdict needs the split (far-side silence vs a session
// where nobody spoke); the CONNECT path only needs the pipe.
func relayCount(a, b net.Conn, idle time.Duration) (fromA, fromB int64) {
	var wg sync.WaitGroup
	wg.Add(2)
	// pipe(dst, src) counts src->dst, so pipe(a, b) is the b->a leg.
	go func() { defer wg.Done(); fromB = pipe(a, b, idle) }()
	go func() { defer wg.Done(); fromA = pipe(b, a, idle) }()
	wg.Wait()
	return fromA, fromB
}

func pipe(dst, src net.Conn, idle time.Duration) int64 {
	var total int64
	buf := getSocksBuf()
	defer putSocksBuf(buf)
	for {
		if err := src.SetReadDeadline(time.Now().Add(idle)); err != nil {
			return total
		}
		n, err := src.Read(buf)
		if n > 0 {
			total += int64(n)
			if _, werr := dst.Write(buf[:n]); werr != nil {
				return total
			}
		}
		if err != nil {
			return total
		}
	}
}

var socksBufPool = sync.Pool{
	New: func() interface{} {
		return make([]byte, 32<<10)
	},
}

func getSocksBuf() []byte {
	return socksBufPool.Get().([]byte)
}

func putSocksBuf(buf []byte) {
	socksBufPool.Put(buf)
}
