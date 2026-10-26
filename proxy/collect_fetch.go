package proxy

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync/atomic"
	"time"
)

// One HTTP fetch of one site: how a response is requested, whether it counts
// as a usable page (content type, captcha, block page, retry hints), and the
// per-proxy transport cache it goes through. The collector loop, the site
// rotation and the candidate dedup stay in collector.go.

// fetchResult is the outcome of one fetch attempt with a one-line diagnosis.
type fetchResult struct {
	cands []Candidate
	note  string
	// proxyFault reports that the failure points at the upstream proxy itself
	// (transport error / EOF / device-junk status), as opposed to a
	// target-side block or a page that simply yielded nothing. Only proxy
	// faults feed back into the pool health.
	proxyFault bool
	// notModified reports a 304: the source is healthy and simply has no new
	// content. Treating it as a failure (the old behavior, since the empty
	// candidate list was indistinguishable from a dead fetch) made every
	// ETag'd source fail every cycle, burn via-proxy retries and a browser
	// render, and cool down after site_max_fails — then keep failing from
	// the cooldown branch until the remote content happened to change.
	notModified bool
}

// collectViaAttemptTimeout caps a single via-proxy fetch. Dead/blackholed
// proxies otherwise eat the full collector http_timeout (45s) per attempt.
const collectViaAttemptTimeout = 20 * time.Second

// setBrowserHeaders makes a plain GET look like a browser navigation.
func setBrowserHeaders(req *http.Request) {
	req.Header.Set("User-Agent", defaultUAs[uaIndex()])
	req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8")
	req.Header.Set("Accept-Language", "en-US,en;q=0.9")
	req.Header.Set("Upgrade-Insecure-Requests", "1")
	req.Header.Set("Sec-Fetch-Site", "none")
	req.Header.Set("Sec-Fetch-Mode", "navigate")
	req.Header.Set("Sec-Fetch-User", "?1")
	req.Header.Set("Sec-Fetch-Dest", "document")
}

// skipContentType reports whether a body is certainly not a proxy list
// (images, fonts, archives, ...).
var skipContentTypes = []string{"image/", "audio/", "video/", "font/", "application/pdf", "application/zip"}

func skipContentType(ct string) bool {
	ct = strings.ToLower(strings.TrimSpace(ct))
	for _, p := range skipContentTypes {
		if strings.HasPrefix(ct, p) {
			return true
		}
	}
	return false
}

// retryAfterSecs parses a Retry-After header, bounded by maxWait.
func retryAfterSecs(h string, maxWait time.Duration) time.Duration {
	h = strings.TrimSpace(h)
	if h == "" {
		return 0
	}
	var d time.Duration
	if n, err := strconv.Atoi(h); err == nil {
		d = time.Duration(n) * time.Second
	} else if t, err := http.ParseTime(h); err == nil {
		d = time.Until(t)
		if d < 0 {
			return 0
		}
	} else {
		return 0
	}
	if d > maxWait {
		d = maxWait
	}
	return d
}

// lowerBody returns the first 128 KB of body lowercased. jsHint and
// isCaptchaBody used to lowercase the same body independently, so every
// fetched page paid the copy and the ASCII folding twice; sharing one copy
// halves it. The signature list lives here too, because the two functions
// also allocated their string slices per call.
var bodySigs = []string{
	"captcha", "recaptcha", "cf-browser-verification", "challenge-platform",
	"hcaptcha", "are you a human", "please verify you are human",
	"access denied", "403 forbidden", "just a moment...",
}

const bodyScanLimit = 128 << 10

func lowerBody(body []byte) string {
	if len(body) > bodyScanLimit {
		body = body[:bodyScanLimit]
	}
	return strings.ToLower(string(body))
}

// jsHint guesses why a sizable body yielded nothing (for operator logs).
func jsHint(body []byte) string {
	if len(body) < 2000 {
		return ""
	}
	lower := lowerBody(body)
	switch {
	case strings.Contains(lower, "document.write"):
		return "js-obfuscated?"
	case strings.Contains(lower, "__next_data__") || strings.Contains(lower, "__nuxt") ||
		strings.Contains(lower, `id="root"`) || strings.Contains(lower, `id="app"`):
		return "js-rendered?"
	case strings.Contains(lower, "enable javascript"):
		return "js-required?"
	case strings.Contains(lower, "challenge-platform") || strings.Contains(lower, "just a moment"):
		return "cf-challenge?"
	}
	return ""
}

// extractHTTP GETs the site without a proxy.
// Uses conditional GET (If-None-Match / If-Modified-Since) based on SiteStat.
func (c *Collector) extractHTTP(ctx context.Context, site string) fetchResult {
	// Check for cached validators
	var etag, lastMod string
	if s := c.stats.Site(site); s != nil {
		etag = s.ETag
		lastMod = s.LastModified
	}

	req, err := http.NewRequestWithContext(ctx, "GET", site, nil)
	if err != nil {
		return fetchResult{note: "bad url: " + err.Error()}
	}
	setBrowserHeaders(req)
	// Conditional GET headers
	if etag != "" {
		req.Header.Set("If-None-Match", etag)
	}
	if lastMod != "" {
		req.Header.Set("If-Modified-Since", lastMod)
	}

	resp, err := c.client.Do(req)
	if err != nil {
		return fetchResult{note: "get: " + shortErr(err)}
	}
	// 304 Not Modified: healthy source, no new content.
	if resp.StatusCode == http.StatusNotModified {
		resp.Body.Close()
		return fetchResult{note: "304 not modified", notModified: true}
	}
	// One immediate retry on rate-limit/challenge with server-guided wait.
	if resp.StatusCode == http.StatusTooManyRequests || resp.StatusCode == http.StatusServiceUnavailable {
		wait := retryAfterSecs(resp.Header.Get("Retry-After"), 30*time.Second)
		io.Copy(io.Discard, io.LimitReader(resp.Body, 4<<10))
		resp.Body.Close()
		if wait > 0 {
			// Bounded by the cycle context: a bare sleep outlived SIGTERM by
			// up to 30s and held a fetch_workers slot the whole time.
			timer := time.NewTimer(wait)
			select {
			case <-ctx.Done():
				timer.Stop()
				return fetchResult{note: "rate-limited, shutdown"}
			case <-timer.C:
			}
			if resp2, err2 := c.client.Do(req); err2 == nil {
				resp = resp2
			} else {
				return fetchResult{note: fmt.Sprintf("status %d, retry: %s", resp.StatusCode, shortErr(err2))}
			}
		} else {
			return fetchResult{note: fmt.Sprintf("status %d (rate-limited)", resp.StatusCode)}
		}
	}
	defer resp.Body.Close()
	if !isHealthyResponse(resp) {
		io.Copy(io.Discard, io.LimitReader(resp.Body, 4<<10))
		return fetchResult{note: fmt.Sprintf("status %d", resp.StatusCode)}
	}
	if ct := resp.Header.Get("Content-Type"); skipContentType(ct) {
		io.Copy(io.Discard, io.LimitReader(resp.Body, 4<<10))
		return fetchResult{note: "content-type " + ct}
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 8<<20))
	if err != nil {
		return fetchResult{note: "read: " + shortErr(err)}
	}
	if isCaptchaBody(body) {
		return fetchResult{note: fmt.Sprintf("captcha (%d bytes)", len(body))}
	}
	cands := c.ext.Extract(body)

	// Update cached validators on successful fetch (200)
	newETag := resp.Header.Get("ETag")
	newLastMod := resp.Header.Get("Last-Modified")
	if newETag != "" || newLastMod != "" {
		c.stats.UpdateValidators(site, newETag, newLastMod)
	}

	note := fmt.Sprintf("200 %d bytes %d cands", len(body), len(cands))
	if len(cands) == 0 {
		if h := jsHint(body); h != "" {
			note += " " + h
		}
	}
	return fetchResult{cands: cands, note: note}
}

// extractViaProxy GETs the site through a specific upstream proxy. Failures
// are classified: transport-level errors and device-junk statuses mark the
// proxy as at fault (proxyFault), while target-side blocks *(a tiny 200
// lander, a 403/404/429, a 5xx) leave the proxy's health untouched.
func (c *Collector) extractViaProxy(ctx context.Context, site string, p *Proxy) fetchResult {
	// net/http's Transport.ProxyURL only understands http/https/socks5/socks5h.
	// A socks4/vless proxy (both valid pipeline schemas; the checker swaps
	// dialers for them) fails instantly with "unsupported protocol scheme" —
	// and that used to be charged as a proxy fault, so the collector silently
	// evicted healthy non-http proxies on every via-proxy attempt.
	switch p.Schema {
	case "http", "https", "socks5", "socks5h":
	default:
		return fetchResult{note: "via-proxy unsupported for schema " + p.Schema}
	}
	proxyURL, err := url.Parse(p.URL())
	if err != nil {
		return fetchResult{note: "bad proxy url", proxyFault: true}
	}
	to := c.cfg.Collector.HTTPTimeout.Duration
	if to > collectViaAttemptTimeout {
		to = collectViaAttemptTimeout
	}

	// Use cached transport per proxy address to enable connection reuse.
	tr := c.getTransport(p, proxyURL)

	client := &http.Client{
		Timeout:   to,
		Transport: tr,
	}
	if c.jar != nil {
		client.Jar = c.jar
	}

	// Check for cached validators
	var etag, lastMod string
	if s := c.stats.Site(site); s != nil {
		etag = s.ETag
		lastMod = s.LastModified
	}

	req, err := http.NewRequestWithContext(ctx, "GET", site, nil)
	if err != nil {
		return fetchResult{note: "bad url", proxyFault: true}
	}
	setBrowserHeaders(req)
	// Conditional GET headers
	if etag != "" {
		req.Header.Set("If-None-Match", etag)
	}
	if lastMod != "" {
		req.Header.Set("If-Modified-Since", lastMod)
	}

	resp, err := client.Do(req)
	if err != nil {
		return fetchResult{note: "via " + p.Addr() + ": " + shortErr(err), proxyFault: true}
	}
	// 304 Not Modified: healthy source, no new content.
	if resp.StatusCode == http.StatusNotModified {
		resp.Body.Close()
		return fetchResult{note: "304 not modified", notModified: true}
	}
	defer resp.Body.Close()
	if !isHealthyResponse(resp) {
		io.Copy(io.Discard, io.LimitReader(resp.Body, 4<<10))
		// A tiny 400/405/501/505 to a plain GET means a device answered, not a
		// forwarding proxy (mirrors the serving-path device-junk detector).
		fault := resp.StatusCode == 400 || resp.StatusCode == 405 ||
			resp.StatusCode == 501 || resp.StatusCode == 505
		return fetchResult{note: fmt.Sprintf("via %s: status %d", p.Addr(), resp.StatusCode), proxyFault: fault}
	}
	if ct := resp.Header.Get("Content-Type"); skipContentType(ct) {
		io.Copy(io.Discard, io.LimitReader(resp.Body, 4<<10))
		return fetchResult{note: "content-type " + ct}
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 8<<20))
	if err != nil {
		return fetchResult{note: "read: " + shortErr(err), proxyFault: true}
	}
	if isCaptchaBody(body) {
		return fetchResult{note: fmt.Sprintf("via %s: captcha", p.Addr())}
	}
	cands := c.ext.Extract(body)

	// Update cached validators on successful fetch (200)
	newETag := resp.Header.Get("ETag")
	newLastMod := resp.Header.Get("Last-Modified")
	if newETag != "" || newLastMod != "" {
		c.stats.UpdateValidators(site, newETag, newLastMod)
	}

	return fetchResult{cands: cands, note: fmt.Sprintf("via %s: 200 %d bytes %d cands", p.Addr(), len(body), len(cands))}
}

// getTransport returns a cached http.Transport for the given proxy.
// Transports are cached per proxy address to enable connection reuse.
//
// The transport has real idle limits: keep-alives are on here (unlike the
// serving transport), so without them each cached transport holds its sockets
// to a dead upstream forever. The cache is bounded and eviction closes the
// idle connections it drops.
func (c *Collector) getTransport(p *Proxy, proxyURL *url.URL) *http.Transport {
	key := p.Key()
	if tr, ok := c.transportCache.Load(key); ok {
		return tr.(*http.Transport)
	}
	tr := &http.Transport{
		Proxy: http.ProxyURL(proxyURL),
		// https-schema proxies routinely present IP-SAN-less certs; the pool
		// self-validates them elsewhere, this fetch must not fail on that.
		TLSClientConfig:       &tls.Config{InsecureSkipVerify: true},
		MaxIdleConns:          4,
		MaxIdleConnsPerHost:   2,
		IdleConnTimeout:       30 * time.Second,
		TLSHandshakeTimeout:   15 * time.Second,
		ResponseHeaderTimeout: 30 * time.Second,
	}
	actual, loaded := c.transportCache.LoadOrStore(key, tr)
	if loaded {
		tr.CloseIdleConnections() // lost the race; do not leak this handle
		return actual.(*http.Transport)
	}
	if atomic.AddInt64(&c.transportCacheSize, 1) > collectorTransportCacheMax {
		// Evict one entry, and never the one just inserted: sync.Map.Range
		// order is undefined, so it can hand back `key` itself, and the
		// transport would then be uncached despite having been stored.
		c.transportCache.Range(func(k, v interface{}) bool {
			if kk, _ := k.(string); kk == key {
				return true // keep looking
			}
			if old, ok := v.(*http.Transport); ok {
				old.CloseIdleConnections()
			}
			c.transportCache.Delete(k)
			atomic.AddInt64(&c.transportCacheSize, -1)
			return false
		})
	}
	return tr
}

// CloseTransportCache drops every cached via-proxy transport and its idle
// connections. Called on shutdown so the fetcher does not hold sockets open
// past exit.
func (c *Collector) CloseTransportCache() {
	c.transportCache.Range(func(k, v interface{}) bool {
		if tr, ok := v.(*http.Transport); ok {
			tr.CloseIdleConnections()
		}
		c.transportCache.Delete(k)
		atomic.AddInt64(&c.transportCacheSize, -1)
		return true
	})
}

// shortErr trims verbose network errors for one-line logs.
func shortErr(err error) string {
	s := err.Error()
	if i := strings.Index(s, ": "); i >= 0 {
		if j := strings.LastIndex(s, ": "); j > i {
			return s[j+2:]
		}
	}
	if len(s) > 120 {
		return s[:120]
	}
	return s
}

// isHealthyResponse checks whether a response is a real page (not an error
// page, captcha, or Cloudflare challenge).
func isHealthyResponse(resp *http.Response) bool {
	if resp.StatusCode < 200 || resp.StatusCode >= 400 {
		return false
	}
	ct := resp.Header.Get("Content-Type")
	// If it says it's HTML but the body is tiny — likely a captcha/challenge
	// redirect page. We'll read and check further below.
	if strings.Contains(ct, "text/html") || ct == "" {
		// We can't peek the body without consuming it, so rely on status + size
		// heuristic: a <500 byte HTML page is almost never a real proxy list.
		if resp.ContentLength >= 0 && resp.ContentLength < 500 {
			return false
		}
	}
	return true
}

// isCaptchaBody inspects a fetched HTML body for known captcha/challenge signatures.
func isCaptchaBody(body []byte) bool {
	lower := lowerBody(body)
	for _, s := range bodySigs {
		if strings.Contains(lower, s) {
			return true
		}
	}
	return false
}
