package proxy

import (
	"context"
	"log"
	"net/http"
	"net/http/cookiejar"
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
	// seenSwept is when the last expiry sweep of seen ran, so the sweep is
	// amortized over time instead of running on every candidate once the map
	// is over its cap (see seenRecently).
	seenSwept time.Time
	// windowOff is the rotation offset for rotateWindow: how many ordered
	// sources past the head the current cycle starts at. Atomic: cycle runs
	// on one goroutine, but tests drive rotateWindow concurrently.
	windowOff int64

	// transportCache caches http.Transport per proxy address for via-proxy
	// fetches. Key: "schema://host:port", Value: *http.Transport
	transportCache sync.Map
	// transportCacheSize tracks the entries above so the cache can be bounded.
	// The via-proxy fallback tries a different upstream on every failure, so
	// this grew with the number of distinct upstreams ever used — with no
	// limit on idle connections per transport, each one pinned its sockets to
	// a dead proxy for the life of the process.
	transportCacheSize int64
}

// collectorTransportCacheMax bounds the via-proxy transport cache. Matches the
// checker's own cap.
const collectorTransportCacheMax = 1000

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
		// Per cycle, not per run: a panic in one cycle (a malformed sites.txt
		// line, a registry edge) must cost that cycle, not the collector —
		// without it the only producer of fresh candidates dies silently and
		// the queue starves over days.
		func() {
			defer RecoverPanic("collector: cycle")
			sites, err := LoadSites(c.cfg.Collector.SitesFile)
			if err != nil {
				log.Printf("collector: %v", err)
			} else {
				c.stats.Track(sites)
				c.stats.SetAlive(c.aliveBySource())
				c.cycle(ctx, c.stats.Order(sites), out)
			}
		}()
		select {
		case <-ctx.Done():
			return
		case <-wake:
			log.Printf("collector: wake (emergency cycle)")
		case <-time.After(c.cfg.Collector.CycleSleep.Duration):
		}
	}
}

// rotateWindow walks the ordered source list in slices of MaxSitesPerCycle so
// the tail is fetched every ceil(len/n) cycles instead of never. Always taking
// the head starves everything past the cap: the head sources keep their yield
// (and their cooldowns keep everyone else out), so the tail is effectively
// dead configuration. The window advances by n per cycle and wraps, so the
// first cycle still starts at the head and every source is reached regularly.
func (c *Collector) rotateWindow(sites []string) []string {
	n := c.cfg.Collector.MaxSitesPerCycle
	if n <= 0 || len(sites) <= n {
		return sites
	}
	start := int((atomic.AddInt64(&c.windowOff, int64(n)) - int64(n)) % int64(len(sites)))
	if start == 0 {
		log.Printf("collector: %d sources queued, fetching the top %d this cycle", len(sites), n)
		return sites[:n]
	}
	out := make([]string, 0, n)
	out = append(out, sites[start:]...)
	if len(out) < n {
		out = append(out, sites[:n-len(out)]...)
	}
	log.Printf("collector: %d sources queued, fetching %d at offset %d this cycle", len(sites), len(out), start)
	return out
}

// cycle fetches all sites concurrently (limited by fetch_workers). The site
// list arrives pre-ordered by the registry (best source first); max_sites_per_cycle
// caps how many are attempted so a long list stays on a predictable rotation
// instead of one cycle running for days.
func (c *Collector) cycle(ctx context.Context, sites []string, out chan<- Candidate) {
	sites = c.rotateWindow(sites)
	var wg sync.WaitGroup
	var okSites, failSites int64
	var totalCands int64
	sem := make(chan struct{}, c.cfg.Collector.FetchWorkers)
sitesLoop:
	for _, site := range sites {
		select {
		case <-ctx.Done():
			// Stop scheduling, but still wait for the in-flight fetches: they
			// are (now) ctx-bound and call MarkServeOK/Promote/Remove on the
			// bucket, which must not race the deferred shutdown saves.
			break sitesLoop
		case sem <- struct{}{}:
		}
		wg.Add(1)
		go func(url string) {
			defer wg.Done()
			defer func() { <-sem }()
			// Per site: this parses arbitrary scraped HTML and browser output.
			// A panic here would otherwise exit the process, and wg.Wait below
			// would never return, so the recovery has to come after wg.Done.
			defer RecoverPanic("collector: site " + url)
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
	Stats.CollectorCycles.Add(1)
	Stats.CollectorSitesOK.Add(okSites)
	Stats.CollectorSitesFailed.Add(failSites)
	Stats.CandidatesEmitted.Add(totalCands)
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
		r := c.extractHTTP(ctx, site)
		if len(r.cands) > 0 {
			n := c.emit(ctx, site, r.cands, out)
			c.record(site, true, len(r.cands), n, r.note)
			return n
		}
		if r.notModified {
			// Healthy, nothing new — this is what a cooling ETag'd source
			// answers every cycle; recording it as a failure kept it in
			// cooldown forever.
			c.record(site, true, 0, 0, r.note)
			return 0
		}
		c.record(site, false, 0, 0, r.note)
		log.Printf("collector: %s -> cooling [%s]", site, r.note)
		return -1
	}

	r := c.extractHTTP(ctx, site)
	if len(r.cands) > 0 {
		n := c.emit(ctx, site, r.cands, out)
		c.record(site, true, len(r.cands), n, r.note)
		return n
	}
	if r.notModified {
		c.record(site, true, 0, 0, r.note)
		return 0
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
			r = c.extractViaProxy(ctx, site, p)
			if len(r.cands) > 0 {
				p.MarkServeOK(0)
				c.bucket.Promote(p) // served a genuine fetch: earn the hot tail
				log.Printf("collector: %s ok via %s attempt %d", site, p.URL(), attempt+1)
				n := c.emit(ctx, site, r.cands, out)
				c.record(site, true, len(r.cands), n, r.note)
				return n
			}
			if r.notModified {
				c.record(site, true, 0, 0, r.note)
				return 0
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
			// Mark seen only after the send lands: recording first made a
			// send abandoned on ctx.Done() hide the candidate for the whole
			// window without it ever reaching the pipeline.
			c.markSeen(cands[i])
			emitted++
		case <-ctx.Done():
			return emitted
		}
	}
	return emitted
}

// seenCap bounds the dedup map, and seenSweepInterval is how often expiry is
// actually run once it is full.
const (
	seenCap           = 100000
	seenWindow        = 10 * time.Minute
	seenSweepInterval = 1 * time.Minute
)

// seenRecently skips candidates already pushed inside seenWindow.
// The key is built without fmt.Sprintf: the collector emits thousands of
// candidates per cycle and the format call dominated the dedup path.
//
// The expiry sweep is rate-limited by seenSwept. Gating it on len(seen) alone
// made it run on *every* candidate once the map was over the cap — which is
// this collector's normal operating rate, since more than a hundred thousand
// candidates inside ten minutes is the rule, not the exception. Every emit
// then walked the whole map under seenMu.
func (c *Collector) seenRecently(cand Candidate) bool {
	key := cand.Schema + "://" + cand.Host + ":" + strconv.Itoa(cand.Port)
	now := time.Now()
	c.seenMu.Lock()
	defer c.seenMu.Unlock()
	if t, ok := c.seen[key]; ok && now.Sub(t) < seenWindow {
		return true
	}
	if len(c.seen) > seenCap && now.Sub(c.seenSwept) > seenSweepInterval {
		c.seenSwept = now
		for k, t := range c.seen {
			if now.Sub(t) > seenWindow {
				delete(c.seen, k)
			}
		}
	}
	return false
}

// markSeen records a successfully emitted candidate. Recording is separate
// from the check so a send abandoned on shutdown does not blacklist a
// candidate that never reached the pipeline.
func (c *Collector) markSeen(cand Candidate) {
	key := cand.Schema + "://" + cand.Host + ":" + strconv.Itoa(cand.Port)
	c.seenMu.Lock()
	c.seen[key] = time.Now()
	c.seenMu.Unlock()
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
