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
	totalTO    time.Duration
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
		// The HTTP front bounds a whole request by serve_total_timeout; the
		// SOCKS5 handshake has no equivalent, so one slow upstream per retry
		// could hold a client for dial_timeout × serve_retries with no cap.
		totalTO: cfg.Server.ServeTotalTimeout.Duration,
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
	// Accept errors are not rare: fd exhaustion (EMFILE), hitting the
	// default somaxconn backlog and per-connection nonce exhaustion all show
	// up here. Looping straight back into Accept on a persistent error spins
	// the CPU at 100% while the process is already out of descriptors, so
	// every consecutive failure idles briefly and the backoff caps at 1s.
	backoff := time.Millisecond
	for {
		conn, err := ln.Accept()
		if err != nil {
			if ctx.Err() != nil || s.closed() {
				return nil
			}
			time.Sleep(backoff)
			backoff *= 2
			if backoff > time.Second {
				backoff = time.Second
			}
			continue
		}
		backoff = time.Millisecond
		wg.Add(1)
		go func(c net.Conn) {
			defer wg.Done()
			// One malformed SOCKS5 request must not take down every listener
			// and the unsaved queue with it; net/http recovers its own
			// goroutines, this one has no such net.
			defer RecoverPanic("socks5: session")
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

	// One unit per completed handshake (P47): a SOCKS5 session is what this
	// front serves, and counting it here (not in DialContext) keeps the
	// per-front counters disjoint — a failed greeting never reaches here.
	Stats.SOCKS5Sessions.Add(1)

	// The upstream dial below may legitimately consume the whole dialTO
	// budget (socks5.dial_timeout, default 12s). Clear the handshake deadline
	// before it: the greeting's SetDeadline armed *both* halves, so the
	// success reply written afterwards would fail its own write deadline on a
	// slow-but-working upstream, tearing down a tunnel that was just
	// established. The reply write gets its own bounded deadline instead.
	_ = conn.SetDeadline(time.Time{})

	ctx, cancel := context.WithTimeout(context.Background(), s.dialTO)
	// One client TCP connection = one upstream, same contract as the HTTP
	// front's ConnKey pin: without it every SOCKS session picked afresh and
	// the config's stickiness promise did not cover this front.
	if key := conn.RemoteAddr().String(); key != "" {
		ctx = WithConnKey(ctx, key)
	}
	// Bound the whole handshake by the same total the HTTP front enforces:
	// DialContext retries internally up to serve_retries, so the per-dial
	// budget alone lets one client wait dial_timeout × retries.
	if s.totalTO > 0 {
		var totalCancel context.CancelFunc
		ctx, totalCancel = context.WithTimeout(ctx, s.totalTO)
		defer totalCancel()
	}
	up, err := s.dialer.DialContext(ctx, "tcp", target)
	cancel()
	if err != nil {
		_ = conn.SetWriteDeadline(time.Now().Add(s.dialTO))
		s.reply(conn, 0x05) // connection refused
		return
	}
	// The upstream must be closed on every exit path: proxyConn.Close is the
	// only caller of MarkInFlightDone, so skipping it ratchets p.inFlight +1
	// per session forever (the picker reads it as load) and leaves the socket
	// to the finalizer. The CONNECT front closes its upstream for exactly this
	// reason; the SOCKS path used to forget.
	defer up.Close()

	// bnd.addr 0.0.0.0:0 is acceptable to most clients
	reply := []byte{0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0}
	_ = conn.SetWriteDeadline(time.Now().Add(s.dialTO))
	if _, err := conn.Write(reply); err != nil {
		up.Close()
		return
	}
	// The tunnel owns its own deadlines now: relayCount sets the idle read
	// deadline per leg.
	_ = conn.SetDeadline(time.Time{})

	toUp, toDown := relayCount(conn, up, s.idleTO)
	// Bytes belong to the registry, not just the verdict below: without them a
	// SOCKS5-dominant workload reads bytes_in/out = 0 while serving flat out.
	// (Requests/Attempts/Failures are already counted: the dial above goes
	// through the shared ForwardDialer.DialContext.)
	Stats.BytesOut.Add(toUp)
	Stats.BytesIn.Add(toDown)
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
//
// The verdict is counted in the registry like every other serving path: the
// dial-time counters live in DialContext, but only settle knows whether the
// tunnel delivered anything.
func (s *Socks5Server) settle(p *Proxy, toUp, toDown int64) {
	switch {
	case toDown > 0:
		p.MarkServeOK(0)
		Stats.ServedOK.Add(1)
		s.dialer.bucket.Promote(p)
	case toUp > 0:
		Stats.ServeFailures.Add(1)
		if fails := p.MarkServeFail(); fails >= int64(s.dialer.serveMaxFails) {
			s.dialer.bucket.Remove(p)
			Stats.Evictions.Add(1)
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
// relayCount pipes both directions and returns per-leg volume: fromA counts
// bytes a->b, fromB bytes b->a. The SOCKS verdict needs the split (far-side
// silence vs a session where nobody spoke); the CONNECT path uses it too for
// its probe-off byte accounting.
func relayCount(a, b net.Conn, idle time.Duration) (fromA, fromB int64) {
	var wg sync.WaitGroup
	wg.Add(2)
	// pipe(dst, src) counts src->dst, so pipe(a, b) is the b->a leg.
	// A panic on one leg must still let wg.Wait return, or the session
	// goroutine hangs forever on a WaitGroup that never completes.
	go func() {
		defer wg.Done()
		defer RecoverPanic("socks5: pipe b->a")
		fromB = pipe(a, b, idle)
	}()
	go func() {
		defer wg.Done()
		defer RecoverPanic("socks5: pipe a->b")
		fromA = pipe(b, a, idle)
	}()
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
			// A write deadline is not optional: a peer that stops reading
			// (closed TCP window) blocks dst.Write forever, wg.Wait in
			// relayCount waits for this leg, and the session goroutine plus
			// both sockets stay pinned past idle_timeout. Read deadlines do
			// not cover the write half.
			_ = dst.SetWriteDeadline(time.Now().Add(idle))
			if _, werr := dst.Write(buf[:n]); werr != nil {
				return total
			}
		}
		if err != nil {
			// A clean EOF from src is a half-close, not session death:
			// propagate the FIN via CloseWrite so the peer's read side
			// unblocks (SOCKS/CONNECT clients that request, half-close,
			// then wait for the full response would otherwise hang until
			// idle_timeout rips the whole session). Error/reset paths
			// keep the old behavior — the session is already broken.
			if errors.Is(err, io.EOF) {
				if cw, ok := dst.(interface{ CloseWrite() error }); ok {
					_ = cw.CloseWrite()
				}
			}
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
