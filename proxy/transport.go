package proxy

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net/http"
	"strings"
	"sync/atomic"
	"time"
)

// attemptState threads per-request state between ProxyTransport.RoundTrip and
// ForwardDialer.DialContext: the set of proxies already tried and the proxy
// picked for the *current* dial attempt (needed to attribute response-level
// failures — a proxy that dials fine but never answers).
//
// cur/connOK are written from the transport's dial goroutine, not from the
// RoundTrip goroutine, and net/http deliberately detaches an in-flight dial
// from the request context on cancel (WithoutCancel) — so a client abort or a
// serve_total_timeout fire races the RoundTrip error path's read of these
// fields unless they are atomic. Only tried (a slice) is single-writer:
// RoundTrip appends, and the next attempt's snapshot is sequenced after it.
//
// The tried set is a slice, not a fixed [4]string: serve_retries is
// configurable and unbounded above, so a fixed array silently dropped every
// entry past index 3 — the failover sequence then re-picked a proxy it had
// already burned. Only tried, triedN and the snapshot are per request, and a
// fresh slice is one allocation instead of a 64-byte array copy.
type attemptState struct {
	tried  []string
	cur    atomic.Pointer[Proxy]
	connOK atomic.Bool
}

func newAttemptState() *attemptState {
	return &attemptState{}
}

// dial records the proxy chosen for the current attempt, before dialing.
func (s *attemptState) dial(p *Proxy) {
	if s == nil {
		return
	}
	s.cur.Store(p)
	s.connOK.Store(false)
}

// setConnOK marks that the tunnel through the current proxy was established.
func (s *attemptState) setConnOK() {
	if s == nil {
		return
	}
	s.connOK.Store(true)
}

func (s *attemptState) proxyUsed() (*Proxy, bool) {
	if s == nil {
		return nil, false
	}
	return s.cur.Load(), s.connOK.Load()
}

func (s *attemptState) mark(p *Proxy) {
	if s == nil || p == nil {
		return
	}
	s.tried = append(s.tried, p.Key())
}

// snapshot returns the tried set as a lookup map, rebuilt per dial attempt.
// The previous version built the map, copied it into a second map, and handed
// back two allocations on the hottest path in the process.
//
// The map is always non-nil and never the caller's: ForwardDialer.DialContext
// writes into it as it burns proxies for the current attempt, and an attempt
// state must not accumulate those writes across attempts.
func (s *attemptState) snapshot() map[string]struct{} {
	if s == nil || len(s.tried) == 0 {
		return map[string]struct{}{}
	}
	out := make(map[string]struct{}, len(s.tried))
	for _, k := range s.tried {
		out[k] = struct{}{}
	}
	return out
}

// ProxyTransport wraps the upstream http.Transport with the serving-path
// resilience layer:
//   - request-level failover: when an attempt yields no response at all
//     (header timeout, reset, deadline), the failure is charged to the proxy
//     and the request is retried through a distinct one, up to serve_retries
//     attempts inside a total wall-clock budget;
//   - interstitial/block-page detection: a 200 text/html response with a small
//     body matching known blocker markers counts as "no content" and is also
//     retried once through another proxy.
type ProxyTransport struct {
	fwd     *ForwardDialer
	base    http.RoundTripper
	retries int // additional attempts after the first
	totalT  time.Duration
	sniffT  time.Duration
	block   *blockDetector
}

// NewProxyTransport builds the serving transport. It must be used as
// goproxy.Tr (equivalent of ForwardDialer.NewTransport, plus resilience).
func NewProxyTransport(cfg *Config, fwd *ForwardDialer) *ProxyTransport {
	// Exactly N extra attempts for serve_retries = N (dial path does the
	// same). The old clamp forced at least one retry even for
	// serve_retries = 1, i.e. two attempts on plain HTTP — the knob lied.
	retries := cfg.Server.ServeRetries - 1
	if retries < 0 {
		retries = 0
	}
	return &ProxyTransport{
		fwd:     fwd,
		base:    fwd.NewTransport(),
		retries: retries,
		totalT:  cfg.Server.ServeTotalTimeout.Duration,
		sniffT:  cfg.Server.ServeSniffTimeout.Duration,
		block:   newBlockDetector(cfg.Server.ServeBlockDetect, cfg.Server.ServeBlockMaxBytes),
	}
}

// RoundTrip implements http.RoundTripper.
func (t *ProxyTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	// One unit per client request (P47), not per transport dial call: the
	// retry loop below may re-dial, but the operator-facing "requests" is
	// what the client asked for. requests_total in Snapshot sums this with
	// the CONNECT and SOCKS5 units.
	Stats.HTTPRequests.Add(1)
	ctx := req.Context()
	if t.totalT > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, t.totalT)
		defer cancel()
	}
	st := newAttemptState()
	req = req.WithContext(context.WithValue(ctx, keyAttempt, st))
	pinKey := pinKeyFrom(ctx)
	dropPin := func() {
		if pinKey != "" {
			t.fwd.pins.Del(pinKey) // remap next request to a fresh pick
		}
	}

	var lastErr error
	for attempt := 0; attempt <= t.retries; attempt++ {
		if attempt > 0 {
			// Replaying a body is only safe when the caller supplied GetBody
			// (a front-end HTTP/1.1 server request never has one, and the
			// previous RoundTrip already closed Body). Re-arming the consumed
			// reader makes the retry die on the *new* proxy's watch and
			// strangles an innocent exit with ServeFailures. A dial-level
			// failure (connOK false) never touched the body, so that retry is
			// still safe with the original reader.
			if _, connOK := st.proxyUsed(); connOK {
				if req.GetBody == nil {
					if req.Body != nil {
						break
					}
				} else {
					b, gerr := req.GetBody()
					if gerr != nil {
						lastErr = gerr
						break
					}
					req.Body = b
				}
			}
		}
		resp, err := t.base.RoundTrip(req)
		if err == nil && resp != nil {
			// servedBlock tracks a block page on the response being returned:
			// handing a captcha back to the client is honest, but it is not
			// proof the proxy works — crediting it with MarkServeOK would
			// promote burned IPs into the hot tail, and the picker would
			// sample them first.
			servedBlock := false
			if t.block.shouldCheck(resp) {
				blocked, stalled := t.block.readAndMarkBudget(resp, t.sniffT)
				if stalled {
					// Headers arrived but the body stalled inside the sniff;
					// the sniff already closed it. Same failure class as a
					// response that never answered: charge the proxy and fail
					// over. Returning this response would hand the client a
					// closed body, and waiting out the stall would hold its
					// headers hostage until serve_total_timeout kills the
					// whole request instead of this one attempt.
					lastErr = errors.New("upstream stalled during block-page sniff")
					resp.Body.Close()
					if p, ok := st.proxyUsed(); p != nil {
						if ok {
							Stats.ServeFailures.Add(1)
							if fails := p.MarkServeFail(); fails >= int64(t.fwd.serveMaxFails) {
								t.fwd.bucket.Remove(p)
								Stats.Evictions.Add(1)
							}
							dropPin()
						}
						st.mark(p)
					} else {
						break
					}
					if attempt < t.retries && ctx.Err() == nil {
						continue
					}
					break
				}
				if blocked {
					servedBlock = true
					Stats.BlockPages.Add(1)
					if attempt < t.retries {
						// Block page instead of content: attribute to the proxy
						// and re-request through another one.
						resp.Body.Close()
						if p, ok := st.proxyUsed(); p != nil && ok {
							st.mark(p)
							dropPin()
						}
						lastErr = errors.New("upstream served interstitial block page")
						if ctx.Err() != nil {
							break
						}
						continue
					}
					// Last attempt: the page goes back as-is below, with the
					// positive feedback withheld.
				}
			}
			if t.block.isDeviceJunk(resp) {
				// The "proxy" answered like a plain internet device (Plex,
				// UPnP, printer, ...), not like a forwarding proxy: a tiny
				// 400/405/501/505 to a plain request. That is a proxy-side
				// failure, not a target-side block: charge the device (it
				// still looks perfectly "healthy" otherwise — this was the
				// hole that kept the pool polluted). Whenever attempts remain,
				// re-request through another proxy; on the last attempt the
				// junk page is handed back as-is but the charge stands.
				if p, ok := st.proxyUsed(); p != nil && ok {
					Stats.ServeFailures.Add(1)
					st.mark(p)
					dropPin()
					if fails := p.MarkServeFail(); fails >= int64(t.fwd.serveMaxFails) {
						t.fwd.bucket.Remove(p)
						Stats.Evictions.Add(1)
					}
				}
				if attempt < t.retries && ctx.Err() == nil {
					resp.Body.Close()
					lastErr = errors.New("upstream answered like a device, not a proxy")
					continue
				}
				return resp, nil
			}
			if p, ok := st.proxyUsed(); p != nil && ok {
				if !servedBlock {
					Stats.ServedOK.Add(1)
					p.MarkServeOK(0) // a genuine response: the proxy served it
					t.fwd.bucket.Promote(p)
				}
			}
			return resp, nil
		}
		if err == nil {
			err = errors.New("upstream returned nil response")
		}
		lastErr = err
		if resp != nil {
			resp.Body.Close()
		}
		if p, ok := st.proxyUsed(); p != nil {
			if ok {
				// Tunnel was up but never answered — a distinct failure class
				// from a dead dial: response-level health.
				Stats.ServeFailures.Add(1)
				if fails := p.MarkServeFail(); fails >= int64(t.fwd.serveMaxFails) {
					t.fwd.bucket.Remove(p)
					Stats.Evictions.Add(1)
				}
				dropPin()
			}
			st.mark(p)
		} else {
			break // no proxy attribution; retrying cannot help
		}
		if ctx.Err() != nil {
			break
		}
	}
	return nil, lastErr
}

// blockDetector recognizes proxy/gateway interstitial pages served instead of
// the requested content. It only examines responses that *could* be a blocker:
// status 200, html-or-text body, and a small on-disk size (real pages are big).
type blockDetector struct {
	active  bool
	max     int
	markers []string
}

func newBlockDetector(active bool, maxBytes int) *blockDetector {
	if maxBytes <= 0 {
		maxBytes = 16384
	}
	return &blockDetector{
		active: active,
		max:    maxBytes,
		markers: []string{
			"captcha", "recaptcha", "human verification", "verify you are human",
			"access denied", "access forbidden", "forbidden 403", "request blocked",
			"access has been blocked", "blocked for security", "unusual traffic",
			"attention required", "automated access", "enable javascript",
			"please turn javascript", "antibot", "abuse report", "pagina de verificação",
			"https://colomaker.info 正在加载", "checking your browser",
		},
	}
}

func (bd *blockDetector) shouldCheck(resp *http.Response) bool {
	if resp == nil || !bd.active {
		return false
	}
	if resp.StatusCode != http.StatusOK {
		return false
	}
	ct := resp.Header.Get("Content-Type")
	if !strings.Contains(ct, "html") && !strings.Contains(ct, "text/plain") {
		return false
	}
	if resp.ContentLength > int64(bd.max) {
		return false
	}
	return true
}

// isDeviceJunk reports whether resp looks like it came from a plain internet
// device that is *not* a forwarding proxy: a tiny 400/405/501/505 to a plain
// client request. Real origins and proper proxies never produce those for a
// normal page request, but UPnP/Plex/printer/router classes do — then the
// "proxy" is garbage and the pick must be charged as a failure (it behaves
// identically to a healthy proxy otherwise, exactly how the pool got swamped).
// Requires a known small Content-Length: a chunked/unknown body is left alone.
func (bd *blockDetector) isDeviceJunk(resp *http.Response) bool {
	if resp == nil || !bd.active {
		return false
	}
	switch resp.StatusCode {
	case 400, 405, 501, 505:
	default:
		return false
	}
	if resp.ContentLength <= 0 || resp.ContentLength > int64(bd.max) {
		return false
	}
	return true
}

// readAndMark reads up to max+1 bytes, rewraps the body so the buffered bytes
// are still consumable downstream, and reports whether the payload matches
// blocker markers. Returns false for oversized bodies (a real page).
func (bd *blockDetector) readAndMark(resp *http.Response) bool {
	r := io.LimitReader(resp.Body, int64(bd.max)+1)
	buf, err := io.ReadAll(r)
	// A read error here (stall until serve_total_timeout killed the upstream)
	// used to be discarded: the partial buffer was rewound and handed to the
	// client as a complete response — silent truncation. Replay the error
	// after the buffered prefix so the client's next read fails honestly.
	var tail io.Reader
	if err != nil {
		tail = io.MultiReader(bytes.NewReader(buf), stickyErr{err}, resp.Body)
	} else {
		tail = io.MultiReader(bytes.NewReader(buf), resp.Body)
	}
	resp.Body = &rewoundBody{
		Reader: tail,
		closer: resp.Body,
	}
	if len(buf) > bd.max {
		return false
	}
	return bd.matches(buf)
}

// stickyErr replays a mid-sniff read error after the buffered prefix.
type stickyErr struct{ err error }

func (e stickyErr) Read([]byte) (int, error) { return 0, e.err }

// readAndMarkBudget is readAndMark under a wall-clock bound. A chunked
// interstitial check reads up to max+1 body bytes inside RoundTrip, before
// any of it reaches the client; an upstream that answers headers and then
// stalls mid-body would otherwise hold the client's headers hostage for the
// rest of serve_total_timeout (25s) — on every retry attempt. On expiry the
// body is closed (unblocking the in-flight read), the sniff's verdict is
// discarded, and stalled=true tells the caller to charge the proxy and fail
// over like any other response-level failure. A budget <= 0 keeps the old
// unbounded behavior (there is no legitimate "hang the client" mode in
// production — fillDefaults always provides a budget).
func (bd *blockDetector) readAndMarkBudget(resp *http.Response, budget time.Duration) (blocked, stalled bool) {
	if budget <= 0 {
		return bd.readAndMark(resp), false
	}
	// Capture the body before the goroutine starts: on the stalled path it
	// replaces resp.Body with a rewound wrapper, and closing must target the
	// original to actually abort the transport read.
	orig := resp.Body
	done := make(chan bool, 1)
	go func() {
		blocked := false
		defer func() {
			// The send must happen exactly once, even on panic: the caller
			// waits on done after closing the body, and a missing send would
			// hang the request goroutine forever.
			defer RecoverPanic("serve: sniff")
			done <- blocked
		}()
		blocked = bd.readAndMark(resp)
	}()
	timer := time.NewTimer(budget)
	defer timer.Stop()
	select {
	case blocked = <-done:
		return blocked, false
	case <-timer.C:
	}
	// The timer may have fired after the sniff already finished (both cases
	// ready: select picks randomly). Prefer the real verdict over a false
	// stall that would burn a healthy proxy.
	select {
	case blocked = <-done:
		return blocked, false
	default:
	}
	// Stuck mid-body. Closing the original aborts the read; the sniff
	// goroutine then finishes (its rewound wrapper is dead either way — the
	// response is discarded). The buffered channel means it cannot leak.
	_ = orig.Close()
	<-done
	return false, true
}

func (bd *blockDetector) matches(body []byte) bool {
	s := strings.ToLower(string(body))
	if strings.TrimSpace(s) == "" {
		return true // fully empty 200 is never real content
	}
	for _, m := range bd.markers {
		if strings.Contains(s, m) {
			return true
		}
	}
	return false
}

// rewoundBody re-serves buffered sniff bytes before the remainder of the body.
type rewoundBody struct {
	io.Reader
	closer io.Closer
}

func (b *rewoundBody) Close() error { return b.closer.Close() }
