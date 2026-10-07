package proxy

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net/http"
	"strings"
	"time"
)

// attemptState threads per-request state between ProxyTransport.RoundTrip and
// ForwardDialer.DialContext: the set of proxies already tried and the proxy
// picked for the *current* dial attempt (needed to attribute response-level
// failures — a proxy that dials fine but never answers).
// Uses a fixed-size array instead of a map to avoid allocation on the hot path.
type attemptState struct {
	tried  [4]string // fixed-size array (retries typically ≤ 4)
	triedN int
	cur    *Proxy
	connOK bool
}

func newAttemptState() *attemptState {
	return &attemptState{}
}

// dial records the proxy chosen for the current attempt, before dialing.
func (s *attemptState) dial(p *Proxy) {
	if s == nil {
		return
	}
	s.cur = p
	s.connOK = false
}

// setConnOK marks that the tunnel through the current proxy was established.
func (s *attemptState) setConnOK() {
	if s == nil {
		return
	}
	s.connOK = true
}

func (s *attemptState) proxyUsed() (*Proxy, bool) {
	if s == nil {
		return nil, false
	}
	return s.cur, s.connOK
}

func (s *attemptState) mark(p *Proxy) {
	if s == nil || p == nil {
		return
	}
	if s.triedN < len(s.tried) {
		s.tried[s.triedN] = p.Key()
		s.triedN++
	}
}

func (s *attemptState) snapshot() map[string]struct{} {
	if s == nil {
		return map[string]struct{}{}
	}
	out := make(map[string]struct{}, s.triedN)
	for i := 0; i < s.triedN; i++ {
		out[s.tried[i]] = struct{}{}
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
	block   *blockDetector
}

// NewProxyTransport builds the serving transport. It must be used as
// goproxy.Tr (equivalent of ForwardDialer.NewTransport, plus resilience).
func NewProxyTransport(cfg *Config, fwd *ForwardDialer) *ProxyTransport {
	retries := cfg.Server.ServeRetries - 1
	if retries < 1 {
		retries = 1
	}
	return &ProxyTransport{
		fwd:     fwd,
		base:    fwd.NewTransport(),
		retries: retries,
		totalT:  cfg.Server.ServeTotalTimeout.Duration,
		block:   newBlockDetector(cfg.Server.ServeBlockDetect, cfg.Server.ServeBlockMaxBytes),
	}
}

// RoundTrip implements http.RoundTripper.
func (t *ProxyTransport) RoundTrip(req *http.Request) (*http.Response, error) {
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
		req.Body = requestBodyForRetry(req)
		resp, err := t.base.RoundTrip(req)
		if err == nil && resp != nil {
			// servedBlock tracks a block page on the response being returned:
			// handing a captcha back to the client is honest, but it is not
			// proof the proxy works — crediting it with MarkServeOK would
			// promote burned IPs into the hot tail, and the picker would
			// sample them first.
			servedBlock := false
			if t.block.shouldCheck(resp) && t.block.readAndMark(resp) {
				servedBlock = true
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
					st.mark(p)
					dropPin()
					if fails := p.MarkServeFail(); fails >= int64(t.fwd.serveMaxFails) {
						t.fwd.bucket.Remove(p)
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
				if fails := p.MarkServeFail(); fails >= int64(t.fwd.serveMaxFails) {
					t.fwd.bucket.Remove(p)
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
	buf, _ := io.ReadAll(r)
	resp.Body = &rewoundBody{
		Reader: io.MultiReader(bytes.NewReader(buf), resp.Body),
		closer: resp.Body,
	}
	if len(buf) > bd.max {
		return false
	}
	return bd.matches(buf)
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

// requestBodyForRetry restores a replayable request body between failover
// attempts. The first RoundTrip consumes/closes the original body; with a
// GetBody producer the next attempt gets a fresh reader. Streams without a
// GetBody fall back to an empty body (documented retry limitation).
func requestBodyForRetry(req *http.Request) io.ReadCloser {
	if req.Body == nil || req.GetBody == nil {
		return req.Body
	}
	b, err := req.GetBody()
	if err != nil {
		return req.Body
	}
	return b
}
