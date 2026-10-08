package proxy

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// Collector scrapes proxy-list pages (HTTP first, browser as fallback) and
// pushes extracted candidates into the validation pipeline.
type Collector struct {
	cfg     *Config
	ext     *Extractor
	client  *http.Client
	jar     http.CookieJar
	browser *browserPool
	bucket  *Bucket
	stats   *SiteRegistry
	seen    map[string]time.Time
	seenMu  sync.Mutex

	// transportCache caches http.Transport per proxy address for via-proxy fetches.
	// Key: "schema://host:port", Value: *http.Transport
	transportCache sync.Map
}

var defaultUAs = []string{
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0 Safari/537.36",
	"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Safari/605.1.15",
	"Mozilla/5.0 (X11; Linux x86_64; rv:121.0) Gecko/20100101 Firefox/121.0",
}

// NewCollector builds the collector, compiling the site-specific regexes.
func NewCollector(cfg *Config, bucket *Bucket) (*Collector, error) {
	ext, err := NewExtractor(mustLoadRegexes(cfg.Collector.RegexFile))
	if err != nil {
		return nil, err
	}
	c := &Collector{
		cfg:    cfg,
		ext:    ext,
		bucket: bucket,
		stats:  NewSiteRegistry(cfg.Collector.SiteMaxFails, cfg.Collector.SiteCooldown.Duration),
		seen:   make(map[string]time.Time),
		client: &http.Client{
			Timeout: cfg.Collector.HTTPTimeout.Duration,
			Transport: &http.Transport{
				Proxy:               nil,
				MaxIdleConns:        cfg.Collector.FetchWorkers * 2,
				MaxIdleConnsPerHost: 4,
				IdleConnTimeout:     90 * time.Second,
			},
		},
	}
	if jar, err := cookiejar.New(nil); err == nil {
		c.jar = jar
		c.client.Jar = jar
	}
	if cfg.Collector.UseBrowser {
		c.browser = newBrowserPool(cfg.Collector.BrowserHead, cfg.Collector.PageTimeout.Duration)
	}
	return c, nil
}

// Stats exposes the per-source telemetry registry (admin page / diagnostics).
func (c *Collector) Stats() *SiteRegistry { return c.stats }

// aliveBySource returns the bucket's per-source live counts, tolerating a nil
// bucket (tests build a collector without one to exercise fetching only).
func (c *Collector) aliveBySource() map[string]int {
	if c.bucket == nil {
		return nil
	}
	return c.bucket.SourceCounts()
}

// Run runs collection cycles forever until ctx is cancelled. A non-nil wake
// channel lets an external watchdog (e.g. empty-queue alert) kick an
// immediate cycle instead of waiting out CycleSleep.
func (c *Collector) Run(ctx context.Context, out chan<- Candidate, wake <-chan struct{}) {
	for {
		sites, err := LoadSites(c.cfg.Collector.SitesFile)
		if err != nil {
			log.Printf("collector: %v", err)
		} else {
			c.stats.Track(sites)
			c.stats.SetAlive(c.aliveBySource())
			c.cycle(ctx, c.stats.Order(sites), out)
		}
		select {
		case <-ctx.Done():
			return
		case <-wake:
			log.Printf("collector: wake (emergency cycle)")
		case <-time.After(c.cfg.Collector.CycleSleep.Duration):
		}
	}
}

// cycle fetches all sites concurrently (limited by fetch_workers). The site
// list arrives pre-ordered by the registry (best source first); max_sites_per_cycle
// caps how many are attempted so a long list stays on a predictable rotation
// instead of one cycle running for days.
func (c *Collector) cycle(ctx context.Context, sites []string, out chan<- Candidate) {
	if n := c.cfg.Collector.MaxSitesPerCycle; n > 0 && len(sites) > n {
		log.Printf("collector: %d sources queued, fetching the top %d this cycle", len(sites), n)
		sites = sites[:n]
	}
	var wg sync.WaitGroup
	var okSites, failSites int64
	var totalCands int64
	sem := make(chan struct{}, c.cfg.Collector.FetchWorkers)
	for _, site := range sites {
		select {
		case <-ctx.Done():
			return
		case sem <- struct{}{}:
		}
		wg.Add(1)
		go func(url string) {
			defer wg.Done()
			defer func() { <-sem }()
			if n := c.fetch(ctx, url, out); n >= 0 {
				atomic.AddInt64(&okSites, 1)
				atomic.AddInt64(&totalCands, int64(n))
			} else {
				atomic.AddInt64(&failSites, 1)
			}
		}(site)
	}
	wg.Wait()
	c.stats.SetAlive(c.aliveBySource())
	log.Printf("collector: cycle done (%d sites: %d ok, %d failed, %d candidates)",
		len(sites), okSites, failSites, totalCands)
}

// fetch processes a single site: try a plain GET, then retry through random
// live proxies on failure, and finally fall back to the browser.
// Returns the number of candidates emitted, or -1 when all attempts failed.
func (c *Collector) fetch(ctx context.Context, site string, out chan<- Candidate) int {
	// Cooling sites get a cheap direct attempt only (no proxy retries,
	// no browser) until the cooldown expires.
	if c.stats.Failed(site) {
		r := c.extractHTTP(site)
		if len(r.cands) > 0 {
			n := c.emit(ctx, site, r.cands, out)
			c.record(site, true, len(r.cands), n, r.note)
			return n
		}
		c.record(site, false, 0, 0, r.note)
		log.Printf("collector: %s -> cooling [%s]", site, r.note)
		return -1
	}

	r := c.extractHTTP(site)
	if len(r.cands) > 0 {
		n := c.emit(ctx, site, r.cands, out)
		c.record(site, true, len(r.cands), n, r.note)
		return n
	}
	directNote := r.note

	// Retry through random live proxies from the queue. Each attempt feeds
	// back into the proxy's health: collection is real traffic and must help
	// the pool converge, otherwise dead devices keep looking fresh forever
	// and the via-proxy fallback never recovers.
	retries := c.cfg.Collector.FetchRetries
	if retries > 0 && c.bucket != nil && c.bucket.Len() > 0 {
		var viaNotes []string
		// Probe count comes from the same config knob the serving path uses:
		// a hardcoded 8 here meant pick_probes had no effect on via-proxy
		// collection, no matter how it was tuned.
		probes := c.cfg.Server.PickProbes
		if probes < 1 {
			probes = 1
		}
		for attempt := 0; attempt < retries; attempt++ {
			p, err := c.bucket.PickHealthy(ctx, probes, nil)
			if err != nil {
				break
			}
			r = c.extractViaProxy(site, p)
			if len(r.cands) > 0 {
				p.MarkServeOK(0)
				c.bucket.Promote(p) // served a genuine fetch: earn the hot tail
				log.Printf("collector: %s ok via %s attempt %d", site, p.URL(), attempt+1)
				n := c.emit(ctx, site, r.cands, out)
				c.record(site, true, len(r.cands), n, r.note)
				return n
			}
			switch {
			case r.proxyFault:
				// The attempt died on the proxy (EOF / timeout / device-junk
				// status / proxy TLS): charge it like every other serving path.
				if fails := p.MarkServeFail(); fails >= int64(c.cfg.Server.ServeMaxFails) {
					c.bucket.Remove(p)
				}
			default:
				// Target-side block or an unreachable-but-answering page: the
				// proxy itself is healthy, leave its counters alone.
			}
			viaNotes = append(viaNotes, r.note)
		}
		if len(viaNotes) > 0 {
			log.Printf("collector: %s -> direct [%s]; via-proxy [%s]", site, directNote, strings.Join(viaNotes, " | "))
		}
	}

	// Last resort: browser.
	if c.browser != nil {
		if body, err := c.browser.text(ctx, site); err == nil && len(body) > 0 {
			cands := c.ext.Extract([]byte(body))
			if len(cands) > 0 {
				n := c.emit(ctx, site, cands, out)
				c.record(site, true, len(cands), n, "browser")
				return n
			}
		} else if err != nil {
			log.Printf("collector: browser %s: %v", site, err)
		}
	}
	c.record(site, false, 0, 0, directNote)
	log.Printf("collector: %s -> 0 candidates (all attempts failed)", site)
	return -1
}

// record files one fetch attempt in the per-source registry and logs the
// transition into failure cooldown.
func (c *Collector) record(site string, ok bool, found, emitted int, note string) {
	if c.stats.Record(site, ok, found, emitted, note) {
		if s := c.stats.Site(site); s != nil {
			log.Printf("collector: %s cooling down until %s after %d failures",
				site, s.CoolUntil.Format(time.RFC3339), s.Fails)
		}
	}
}

func (c *Collector) emit(ctx context.Context, site string, cands []Candidate, out chan<- Candidate) int {
	if n := c.cfg.Collector.MaxCandidatesPerSite; n > 0 && len(cands) > n {
		// Uniform stride instead of a plain head-slice: huge generated lists
		// are often grouped by region/protocol, and a head-slice would re-test
		// the same cluster on every cycle while the tail stays cold forever.
		// The persisted pool re-probes the rest, so nothing is permanently lost.
		step := len(cands) / n
		sampled := make([]Candidate, 0, n)
		for i := 0; i < len(cands) && len(sampled) < n; i += step {
			sampled = append(sampled, cands[i])
		}
		log.Printf("collector: %s capped %d -> sampled %d candidates", site, len(cands), len(sampled))
		cands = sampled
	}
	log.Printf("collector: %s -> %d candidates", site, len(cands))
	// Protocol-tagged list URLs (socks5.txt, http.txt, protocol=..., type=...)
	// hint the probe order so the common case checks one protocol instead of
	// four. The hint is advisory only — Check falls back to the rest.
	prefer := schemaFromURL(site)
	emitted := 0
	for i := range cands {
		cands[i].Source = site
		if cands[i].Schema == "" && prefer != "" {
			cands[i].Prefer = prefer
		}
		if c.seenRecently(cands[i]) {
			continue
		}
		// Blocking send: dropping candidates here directly hurts list
		// completeness under load.
		select {
		case out <- cands[i]:
			emitted++
		case <-ctx.Done():
			return emitted
		}
	}
	return emitted
}

// fetchResult is the outcome of one fetch attempt with a one-line diagnosis.
type fetchResult struct {
	cands []Candidate
	note  string
	// proxyFault reports that the failure points at the upstream proxy itself
	// (transport error / EOF / device-junk status), as opposed to a
	// target-side block or a page that simply yielded nothing. Only proxy
	// faults feed back into the pool health.
	proxyFault bool
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
func (c *Collector) extractHTTP(site string) fetchResult {
	// Check for cached validators
	var etag, lastMod string
	if s := c.stats.Site(site); s != nil {
		etag = s.ETag
		lastMod = s.LastModified
	}

	req, err := http.NewRequest("GET", site, nil)
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
	// 304 Not Modified: no new content, return empty candidates
	if resp.StatusCode == http.StatusNotModified {
		resp.Body.Close()
		return fetchResult{cands: nil, note: "304 not modified"}
	}
	// One immediate retry on rate-limit/challenge with server-guided wait.
	if resp.StatusCode == http.StatusTooManyRequests || resp.StatusCode == http.StatusServiceUnavailable {
		wait := retryAfterSecs(resp.Header.Get("Retry-After"), 30*time.Second)
		io.Copy(io.Discard, io.LimitReader(resp.Body, 4<<10))
		resp.Body.Close()
		if wait > 0 {
			time.Sleep(wait)
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
func (c *Collector) extractViaProxy(site string, p *Proxy) fetchResult {
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

	req, err := http.NewRequest("GET", site, nil)
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
	// 304 Not Modified: no new content
	if resp.StatusCode == http.StatusNotModified {
		resp.Body.Close()
		return fetchResult{cands: nil, note: "304 not modified"}
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
// timeout is not used: the client that owns this transport sets the whole
// request budget, and a transport DialContext timeout would double it. Keeping
// the parameter would leave the impression that it bounds the dial here.
func (c *Collector) getTransport(p *Proxy, proxyURL *url.URL) *http.Transport {
	key := p.URL()
	if tr, ok := c.transportCache.Load(key); ok {
		return tr.(*http.Transport)
	}
	tr := &http.Transport{
		Proxy: http.ProxyURL(proxyURL),
		// https-schema proxies routinely present IP-SAN-less certs; the pool
		// self-validates them elsewhere, this fetch must not fail on that.
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	actual, _ := c.transportCache.LoadOrStore(key, tr)
	return actual.(*http.Transport)
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

// seenRecently skips candidates already pushed within the last 10 minutes.
// The key is built without fmt.Sprintf: the collector emits thousands of
// candidates per cycle and the format call dominated the dedup path.
func (c *Collector) seenRecently(cand Candidate) bool {
	key := cand.Schema + "://" + cand.Host + ":" + strconv.Itoa(cand.Port)
	now := time.Now()
	c.seenMu.Lock()
	defer c.seenMu.Unlock()
	if t, ok := c.seen[key]; ok && now.Sub(t) < 10*time.Minute {
		return true
	}
	if len(c.seen) > 100000 {
		for k, t := range c.seen {
			if now.Sub(t) > 10*time.Minute {
				delete(c.seen, k)
			}
		}
	}
	c.seen[key] = now
	return false
}

// uaIndex picks a rotating user agent index.
func uaIndex() int {
	return int(time.Now().UnixNano()/1e6) % len(defaultUAs)
}

// schemaFromURL infers a probe-protocol hint from the source URL. Many
// aggregated lists tag the protocol in the roster path or query (socks5.txt,
// http.txt, protocol=socks4, type=https, ...,/data.txt), which the plain
// bare host:port extraction loses. Returns "" when the URL does not clearly
// name one protocol (all.txt, proxydb, spys …), leaving full probe order.
func schemaFromURL(raw string) string {
	l := strings.ToLower(raw)
	i := strings.Index(l, "://")
	if i >= 0 {
		l = l[i+3:]
	}
	switch {
	case strings.Contains(l, "socks5"), strings.Contains(l, "socks_5"), strings.Contains(l, "socks%5"):
		return "socks5"
	case strings.Contains(l, "socks4"), strings.Contains(l, "socks_4"):
		return "socks4"
	case strings.Contains(l, "https"):
		return "https"
	case strings.Contains(l, "http"):
		return "http"
	}
	return ""
}

func mustLoadRegexes(path string) []string {
	lines, err := LoadRegexLines(path)
	if err != nil {
		log.Printf("collector: regex file %s: %v (continuing with universal patterns)", path, err)
		return nil
	}
	return lines
}
