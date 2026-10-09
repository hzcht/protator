package proxy

import (
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"log"
	"net"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// ForwardDialer opens outbound connections through a random live proxy from
// the bucket. Destinations that are themselves known upstream proxies are
// dialed directly to avoid self-loops.
type ForwardDialer struct {
	bucket      *Bucket
	dialTimeout time.Duration
	tlsTimeout  time.Duration
	responseT   time.Duration
	maxIdle     int
	idleTimeout time.Duration

	serveRetries  int // dial attempts with distinct proxies per request
	serveMaxFails int // consecutive serving failures before eviction
	pickProbes    int // rejection-sampling probes per pick
	serveTotal    time.Duration
	connectProbe  time.Duration // CONNECT-tunnel blackhole supervision window
	responseProbe time.Duration // plain-HTTP first-response-byte supervision window

	// pins bind connection/session stickiness keys to a stable upstream so
	// a client session keeps one source IP across requests/connections.
	pins *PinPool

	loop networkSet
}

// networkSet tracks which host:port addresses are currently served by a proxy
// in the queue, so the dialer can bypass them instead of looping back into one
// of its own upstreams.
//
// Addresses are reference counted because the bucket's identity is the full URL:
// the same host:port is a distinct entry under http and socks5, and removing
// one must not unblock the other. Unblocking early here is the unsafe
// direction — it hands the dialer a proxy that may dial itself.
type networkSet struct {
	mu sync.RWMutex
	m  map[string]int
}

func newNetworkSet() networkSet {
	return networkSet{m: make(map[string]int, 1024)}
}

func (s *networkSet) contains(addr string) bool {
	s.mu.RLock()
	n := s.m[addr]
	s.mu.RUnlock()
	return n > 0
}

func (s *networkSet) put(addr string) {
	s.mu.Lock()
	s.m[addr]++
	s.mu.Unlock()
}

func (s *networkSet) drop(addr string) {
	s.mu.Lock()
	if n := s.m[addr]; n <= 1 {
		delete(s.m, addr)
	} else {
		s.m[addr] = n - 1
	}
	s.mu.Unlock()
}

// NewForwardDialer wires a dialer to the bucket and registers it for loop-set
// updates.
func NewForwardDialer(bucket *Bucket, cfg *Config) *ForwardDialer {
	d := &ForwardDialer{
		bucket:        bucket,
		dialTimeout:   cfg.Server.DialTimeout.Duration,
		tlsTimeout:    cfg.Server.TLSHandshake.Duration,
		responseT:     cfg.Server.ResponseHeader.Duration,
		maxIdle:       cfg.Server.MaxIdleConns,
		idleTimeout:   cfg.Server.IdleConnTimeout.Duration,
		serveRetries:  cfg.Server.ServeRetries,
		serveMaxFails: cfg.Server.ServeMaxFails,
		pickProbes:    cfg.Server.PickProbes,
		serveTotal:    cfg.Server.ServeTotalTimeout.Duration,
		connectProbe:  cfg.Server.ServeConnectProbe.Duration,
		responseProbe: cfg.Server.ServeResponseProbe.Duration,
		pins:          NewPinPool(cfg.Server.ServePinTTL.Duration, cfg.Server.ServePinMax),
		loop:          newNetworkSet(),
	}
	// Subscribe rather than assign: the admin page subscribes too, and a
	// single-slot callback field lets the later registration silently replace
	// this one (that is exactly how the loop set and pin release stopped
	// being notified in production).
	bucket.Subscribe(d.onChange)
	for _, p := range bucket.Snapshot() {
		d.loop.put(p.Addr())
	}
	return d
}

func (d *ForwardDialer) onChange(p *Proxy, added bool) {
	if added {
		d.loop.put(p.Addr())
	} else {
		d.loop.drop(p.Addr())
		d.pins.DropProxy(p.Key())
	}
}

// DialContext implements the net DialContext contract used by http.Transport.
//
// Every call builds a fresh upstream selection ("new chain per request"): it
// picks a healthy proxy (preferring a sticky pin when the request belongs to a
// pinned connection/session), and on dial failure retries with a distinct one.
// Failures feed back into proxy health; a proxy that fails serveMaxFails
// times in a row is evicted immediately instead of waiting for the next
// revalidation cycle. Retrying the dial is safe: no request bytes have been
// sent yet at this point.
func (d *ForwardDialer) DialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	if network != "tcp" && network != "tcp4" && network != "tcp6" {
		return nil, errors.New("unsupported network " + network)
	}
	if d.loop.contains(addr) {
		var nd net.Dialer
		return nd.DialContext(ctx, network, addr)
	}
	st := attemptStateFrom(ctx)
	skip := d.triedFrom(st)
	pinKey := pinKeyFrom(ctx)

	Stats.Requests.Add(1)
	var lastErr error
	for attempt := 0; attempt < d.serveRetries; attempt++ {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		p, err := d.pickProxy(ctx, skip, pinKey)
		if err != nil {
			return nil, err
		}
		skip[p.Key()] = struct{}{}
		st.dial(p)
		start := time.Now()
		Stats.DialAttempts.Add(1)
		conn, err := dialProxy(p, d.dialTimeout, ctx, network, addr)
		if err != nil {
			lastErr = err
			Stats.DialFailures.Add(1)
			if fails := p.MarkServeFail(); fails >= int64(d.serveMaxFails) {
				d.bucket.Remove(p)
				Stats.Evictions.Add(1)
			}
			if pinKey != "" {
				d.pins.Del(pinKey) // remap next request to a fresh pick
			}
			continue
		}
		st.setConnOK()
		if pinKey != "" {
			d.pins.Set(pinKey, p)
		}
		p.MarkDialOK(time.Since(start))
		p.MarkInFlight()
		if d.responseProbe > 0 {
			if _, probe := ctx.Value(keyProbe).(bool); probe {
				conn = &firstByteConn{Conn: conn, window: d.responseProbe}
			}
		}
		return &proxyConn{Conn: conn, p: p}, nil
	}
	if lastErr == nil {
		lastErr = errors.New("no live proxy available")
	}
	return nil, lastErr
}

// pickProxy honours the stickiness pin for the request when set and still
// usable, otherwise falls back to the health- and load-aware bucket pick.
func (d *ForwardDialer) pickProxy(ctx context.Context, skip map[string]struct{}, pinKey string) (*Proxy, error) {
	if pinKey != "" {
		if p := d.pins.Get(pinKey); p != nil {
			if _, used := skip[p.Key()]; !used {
				return p, nil
			}
		}
	}
	return d.bucket.PickHealthy(ctx, d.pickProbes, skip)
}

func attemptStateFrom(ctx context.Context) *attemptState {
	st, _ := ctx.Value(keyAttempt).(*attemptState)
	return st
}

// triedFrom builds the already-tried set for a dial. The result is freshly
// allocated and writable: DialContext records each proxy it burns for the
// current attempt into it.
func (d *ForwardDialer) triedFrom(st *attemptState) map[string]struct{} {
	return st.snapshot()
}

// probeKeyT marks a dial as a plain-HTTP upstream selection, so the
// first-byte supervision applies to it. The SOCKS5 front-end dials through
// DialContext directly and must not get a read deadline: its tunnels are
// long-lived and a deadline would cut them off mid-session.
type probeKeyT struct{}

var keyProbe = probeKeyT{}

// firstByteConn enforces a first-response-byte deadline on a plain-HTTP
// upstream. A proxy that accepts the connection and then never answers is a
// blackhole: without this, the client waits out the whole
// response_header_timeout (10s by default) on one dead proxy, which is most of
// the failover budget gone. The deadline is cleared by the first byte that
// arrives, so a slow-but-working proxy is unaffected — only silence is fatal.
type firstByteConn struct {
	net.Conn
	window  time.Duration
	armed   sync.Once
	cleared sync.Once
}

func (c *firstByteConn) Read(p []byte) (int, error) {
	c.armed.Do(func() { _ = c.Conn.SetReadDeadline(time.Now().Add(c.window)) })
	n, err := c.Conn.Read(p)
	if n > 0 {
		c.cleared.Do(func() { _ = c.Conn.SetReadDeadline(time.Time{}) })
	}
	return n, err
}

// proxyConn wraps a live tunnel so closing it releases the proxy's in-flight
// counter, keeping the load-aware picker honest.
type proxyConn struct {
	net.Conn
	p    *Proxy
	once sync.Once
}

func (c *proxyConn) Close() error {
	c.once.Do(func() {
		if c.p != nil {
			c.p.MarkInFlightDone()
		}
	})
	return c.Conn.Close()
}

// Dial implements goproxy's ConnectDial func(network, addr).
func (d *ForwardDialer) Dial(network, addr string) (net.Conn, error) {
	ctx, cancel := context.WithTimeout(context.Background(), d.dialTimeout)
	defer cancel()
	return d.DialContext(ctx, network, addr)
}

const (
	connectOKLine      = "HTTP/1.1 200 Connection established\r\n\r\n"
	connectFailureLine = "HTTP/1.1 502 Bad Gateway\r\n\r\n"
	connectReplayMax   = 64 << 10 // bytes of early client traffic to buffer for replay
	connectForwardBuf  = 32 << 10
	connectFirstBuf    = 4 << 10  // first-byte read buffer (was 128KB, only needs ~100 bytes)
	connectBufSize     = 32 << 10 // reverse relay buffer (was 128KB, 32KB is plenty)

	// A CONNECT tunnel that the far side completes with less than this volume
	// (and within this window) carried no real content: the "proxy" is really
	// a misrouted/device endpoint that answered and hung up. Charged as a
	// serving failure so the pool stops picking it.
	connectMinOKBytes = 8 << 10
	connectMinOKTime  = 5 * time.Second
)

// ServeConnect establishes a CONNECT tunnel with request-level failover on top
// of the dialing path. Unlike the plain pass-through (gop.ConnectDial), the
// tunnel is supervised after the upstream answers "200": while the client is
// sending bytes (ClientHello and friends) the far target must produce the
// first byte within the probe window. A proxy that dials fine but then
// blackholes the tunnel — a failure class invisible to dial-level accounting —
// is charged as a serving failure, evicted after serve_max_fails, and the
// client's early bytes are transparently replayed through a fresh tunnel.
//
// The 200 is written exactly once, before any tunnel attempt, matching what
// the browser's TLS handshake expects. client is always closed on return;
// host may omit the port, in which case 443 is assumed.
func (d *ForwardDialer) ServeConnect(ctx context.Context, client net.Conn, network, addr string) error {
	defer client.Close()
	_ = client.SetDeadline(time.Time{}) // shed any http.Server read/write deadlines

	if _, _, err := net.SplitHostPort(addr); err != nil {
		addr = net.JoinHostPort(addr, "443")
	}
	total := ctx
	if d.serveTotal > 0 {
		var cancel context.CancelFunc
		total, cancel = context.WithTimeout(ctx, d.serveTotal)
		defer cancel()
	}

	skip := make(map[string]struct{}, d.serveRetries)
	replay := bytes.NewBuffer(nil)
	sent200 := false

	markFailed := func(p *Proxy) {
		if fails := p.MarkServeFail(); fails >= int64(d.serveMaxFails) {
			d.bucket.Remove(p)
		}
	}

	for attempt := 0; attempt < d.serveRetries; attempt++ {
		if err := total.Err(); err != nil {
			return err
		}
		p, err := d.pickProxy(total, skip, "")
		if err != nil {
			return err
		}
		skip[p.Key()] = struct{}{}
		start := time.Now()
		conn, err := dialProxy(p, d.dialTimeout, total, network, addr)
		if err != nil {
			log.Printf("serve: CONNECT %s via %s dial failed: %v", addr, p.URL(), err)
			markFailed(p)
			continue
		}
		_ = conn.SetDeadline(time.Time{})
		if !sent200 {
			if _, werr := client.Write([]byte(connectOKLine)); werr != nil {
				_ = conn.Close()
				return werr
			}
			sent200 = true
		}

		if d.connectProbe > 0 {
			if d.serveConnectStream(client, conn, p, start, replay) {
				markFailed(p) // blackholed / died early: charge and evict
				continue
			}
			return nil
		}
		// Supervision disabled: plain pass-through relay, the old behavior.
		p.MarkServeOK(time.Since(start))
		d.bucket.Promote(p)
		p.MarkInFlight()
		pc := &proxyConn{Conn: conn, p: p}
		relay(client, pc, d.idleTimeout)
		_ = pc.Close()
		return nil
	}

	if !sent200 {
		_, _ = client.Write([]byte(connectFailureLine))
	}
	return errors.New("connect: all upstream tunnels failed")
}

// serveConnectStream supervises a single CONNECT tunnel until it proves healthy
// (first byte from the far target) or fails, then streams in both directions.
// It returns true when the tunnel must be re-established through a different
// proxy (early death while the client was sending and the replay buffer is
// intact), false when the tunnel ran its natural course or cannot be repaired.
func (d *ForwardDialer) serveConnectStream(client, conn net.Conn, p *Proxy, start time.Time, replay *bytes.Buffer) (retryable bool) {
	probeTO := d.connectProbe
	stop := make(chan struct{})
	overflowed := make(chan struct{}, 1)
	fwdDone := make(chan struct{})

	// volume = bytes relayed both ways; upstreamEnded = the far side (through
	// the proxy) closed the tunnel first. Together they drive the post-relay
	// verdict: "the exit delivered content" vs "a device answered and hung up".
	volume := new(int64)
	var upstreamEnded bool

	// client -> tunnel. Early client bytes are buffered up to the replay cap,
	// so a proven-dead tunnel can be retried — but only while the whole hand
	// shape still fits in the buffer; an overflowing client is never replayed
	// (TLS would be silently corrupted).
	go func() {
		defer close(fwdDone)
		defer RecoverPanic("connect: client->tunnel")
		if replay.Len() > 0 {
			// A retry: replay the early client bytes into the fresh tunnel
			// before anything new (the previous tunnel ate them).
			if _, werr := conn.Write(replay.Bytes()); werr != nil {
				return
			}
		}
		buf := make([]byte, connectForwardBuf)
		for {
			select {
			case <-stop:
				return
			default:
			}
			_ = client.SetReadDeadline(time.Now().Add(probeTO))
			n, rerr := client.Read(buf)
			if n > 0 {
				if replay.Len()+n > connectReplayMax {
					select {
					case overflowed <- struct{}{}:
					default:
					}
				} else {
					_, _ = replay.Write(buf[:n])
				}
				if _, werr := conn.Write(buf[:n]); werr != nil {
					return
				}
				atomic.AddInt64(volume, int64(n))
				Stats.BytesOut.Add(int64(n))
			}
			if rerr != nil {
				if isTimeoutErr(rerr) {
					continue
				}
				return // client closed or errored
			}
		}
	}()

	// Wait for the far target's first byte (or silence up to the probe window).
	_ = conn.SetReadDeadline(time.Now().Add(probeTO))
	first := make([]byte, connectFirstBuf)
	n, rerr := conn.Read(first)
	_ = conn.SetReadDeadline(time.Time{})

	// abort tears the tunnel down and stops the forwarder. The client read
	// deadline is pushed to "now" so a forwarder blocked in client.Read wakes
	// immediately instead of at its next probe deadline.
	abort := func() {
		_ = client.SetReadDeadline(time.Now())
		close(stop)
		_ = conn.Close()
		<-fwdDone
	}

	overflow := false
	select {
	case <-overflowed:
		overflow = true
	default:
	}
	// The replay buffer carries every previous attempt's bytes, and that is
	// exactly right: they are written into THIS tunnel before the forwarder
	// starts, so a silent tunnel that received them is a genuine blackhole —
	// not an ambiguous quiet client. Only a tunnel that got nothing at all
	// streams on best-effort.
	forwarded := replay.Len() > 0

	switch {
	case n > 0:
		// Far target answered: the tunnel is alive. Write the first bytes
		// through and keep the forwarder as the permanent client->tunnel leg.
		if _, werr := client.Write(first[:n]); werr != nil {
			abort()
			return false // client gone; nothing left to repair
		}
	case !isTimeoutErr(rerr):
		// Tunnel died before speaking. If the client's early bytes are fully
		// buffered this is a clean, safe retry — otherwise abandon the stream.
		abort()
		return !overflow
	case overflow:
		// Client flooded past the replay cap; a retry cannot repair a partial
		// TLS handshake, so treat the tunnel as undetermined and stream on.
	case forwarded:
		// Client sent bytes, far target stayed silent for probeTO: blackhole.
		abort()
		return true
	default:
		// Client silent too: nothing to conclude, stream on (best effort).
	}

	// Tunnel proven alive (or undetermined): relay, and only after it ends
	// decide the proxy's verdict. An immediate MarkServeOK on the first byte
	// made misrouted/device "proxies" (a Plex box answering 501 over TLS, a
	// wrong-SNI endpoint) look perfectly healthy forever. Now the far side
	// completing the tunnel with almost no data is charged as a failure.
	p.MarkInFlight()
	pc := &proxyConn{Conn: conn, p: p}
	revDone := make(chan struct{})
	go func() {
		defer close(revDone)
		defer RecoverPanic("connect: tunnel->client")
		buf := make([]byte, connectBufSize)
		for {
			_ = conn.SetReadDeadline(time.Now().Add(d.idleTimeout))
			m, rerr := conn.Read(buf)
			if m > 0 {
				atomic.AddInt64(volume, int64(m))
				Stats.BytesIn.Add(int64(m))
				if _, werr := client.Write(buf[:m]); werr != nil {
					_ = pc.Close()
					return
				}
			}
			if rerr != nil {
				if !isTimeoutErr(rerr) && !isSelfClosedErr(rerr) {
					// The far side ended the tunnel (EOF / reset): relay that
					// to the client instead of leaving it hanging — clients
					// delimit `Connection: close` responses by the EOF. This
					// is also the trigger for the low-volume verdict below.
					upstreamEnded = true
					_ = client.SetReadDeadline(time.Now())
					_ = client.Close()
				}
				_ = pc.Close()
				return
			}
		}
	}()
	<-fwdDone // forwarder exits when the client closes or the tunnel dies
	_ = pc.Close()
	<-revDone
	if upstreamEnded && atomic.LoadInt64(volume) < connectMinOKBytes && time.Since(start) < connectMinOKTime {
		Stats.ServeFailures.Add(1)
		if fails := p.MarkServeFail(); fails >= int64(d.serveMaxFails) {
			d.bucket.Remove(p)
			Stats.Evictions.Add(1)
		}
	} else {
		Stats.ServedOK.Add(1)
		p.MarkServeOK(time.Since(start))
		d.bucket.Promote(p)
	}
	return false
}

// isSelfClosedErr reports whether err came from our own conn.Close(), i.e. the
// tunnel ended because we tore it down — not because the far side gave up.
func isSelfClosedErr(err error) bool {
	if errors.Is(err, net.ErrClosed) {
		return true
	}
	return strings.Contains(err.Error(), "use of closed network connection")
}

func isTimeoutErr(err error) bool {
	if ne, ok := err.(net.Error); ok {
		return ne.Timeout()
	}
	return false
}

// dialHTTP marks the dial as a plain-HTTP upstream selection so the first-byte
// supervision applies. Only the HTTP front-end goes through here; the SOCKS5
// front-end dials DialContext directly and must not get a read deadline.
func (d *ForwardDialer) dialHTTP(ctx context.Context, network, addr string) (net.Conn, error) {
	return d.DialContext(context.WithValue(ctx, keyProbe, true), network, addr)
}

// NewTransport builds the upstream transport used to forward HTTP traffic.
//
// DisableKeepAlives is deliberate, not a leftover: every request must open its
// own upstream connection so DialContext runs again and picks a fresh proxy.
// With keep-alives on, a retry reuses the pooled connection to the *same*
// upstream and a block page / dead tunnel is served again through the very
// proxy the failover was supposed to move away from.
//
// The consequence, which the config comments must make plain, is that
// server.max_idle_conns and server.idle_conn_timeout have no effect here: with
// keep-alives disabled the idle pool is never populated. They still govern the
// checker's and collector's own clients.
func (d *ForwardDialer) NewTransport() *http.Transport {
	return &http.Transport{
		DialContext:           d.dialHTTP,
		DisableKeepAlives:     true,
		MaxIdleConns:          d.maxIdle,
		MaxIdleConnsPerHost:   4,
		IdleConnTimeout:       d.idleTimeout,
		TLSHandshakeTimeout:   d.tlsTimeout,
		ResponseHeaderTimeout: d.responseT,
		ExpectContinueTimeout: time.Second,
		TLSClientConfig:       &tls.Config{InsecureSkipVerify: true},
	}
}
