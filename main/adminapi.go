package main

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/pprof"
	"strconv"
	"sync"
	"time"

	"protator/proxy"
)

// admin holds the live handles the HTTP surface reads from. Everything here
// is read-only except the sites editor and the two action endpoints (forced
// revalidation, source cooldown reset), and nothing holds a lock while
// rendering: the bucket, pool and registry each hand out copies.
//
// The three mutex-protected concerns are deliberately narrow:
//   - sitesMu serializes the editor's read-modify-write of sites.txt;
//   - statsMu guards the 24h history ring;
//   - metricsMu guards the two metrics samples a rate is computed from.
//
// WebSocket state is not here: it lives in wsHub (adminws.go), because four
// mutexes on one struct is how a connection set ends up guarded by the lock
// that also protects the stats history.
type admin struct {
	cfg       *proxy.Config
	cfgPath   string
	bucket    *proxy.Bucket
	pool      *proxy.CandidatePool
	collector *proxy.Collector
	checker   *proxy.Checker
	debug     *proxy.DebugProxies
	sink      *fileLogSink
	beats     *beats
	workers   *checkerWorkers
	// candidates is the validation channel; only its depth is read, for the
	// health view. nil in tests.
	candidates <-chan proxy.Candidate

	// tlsConfigured records whether the mixed listener has a certificate. The
	// WebSocket frame carries no TLS state, so the live updates report the
	// listener's.
	tlsConfigured bool
	// ctx is the process lifetime context: the forced-revalidation action
	// spawns work that must outlive the HTTP request that asked for it.
	ctx     context.Context
	started time.Time

	// wakeCollector is the emergency-cycle kick: the same channel the
	// empty-queue watchdog uses. Set by startAdminServer; nil in tests.
	wakeCollector chan<- struct{}

	// sitesMu serializes the editor's read-modify-write. Two POSTs racing on
	// the same file would both read the old list and the second save would
	// drop the first one's entry. Only the write path takes it; GET does not
	// need to, because the save is an atomic rename.
	sitesMu sync.Mutex

	// statsMu guards the 24h history ring (1 sample per minute = 1440 entries).
	statsMu   sync.Mutex
	statsHist []statsSample

	ws *wsHub

	// metricsMu guards lastMetrics/lastMetricsAt: the pair the rate window is
	// computed from, so two concurrent /api/metrics calls must not interleave.
	metricsMu        sync.Mutex
	lastMetrics      map[string]int64
	lastMetricsAt    time.Time
	hasMetricsSample bool
}

type statsSample struct {
	Time           time.Time `json:"time"`
	QueueLive      int       `json:"queue_live"`
	QueueHot       int       `json:"queue_hot"`
	PoolCandidates int       `json:"pool_candidates"`
	// Serving and validation rates in the minute that produced the sample:
	// the queue lengths say how big the pool is, these say whether it is
	// getting better or worse.
	RequestsPerMin float64 `json:"requests_per_min"`
	ChecksPerMin   float64 `json:"checks_per_min"`
	DialFailPerMin float64 `json:"dial_fail_per_min"`
}

// recordStatsSample adds a sample to the 24h ring buffer (1440 minutes max).
func (a *admin) recordStatsSample() {
	a.statsMu.Lock()
	defer a.statsMu.Unlock()
	now := time.Now()
	rpm, cpm, dpm := 0.0, 0.0, 0.0
	if a.hasMetricsSample && !a.lastMetricsAt.IsZero() {
		mins := now.Sub(a.lastMetricsAt).Minutes()
		if mins > 0 {
			c := proxy.Stats.Snapshot()
			rpm = deltaPerMin(c["requests_total"], a.lastMetrics["requests_total"], mins)
			cpm = deltaPerMin(c["checks_total"], a.lastMetrics["checks_total"], mins)
			dpm = deltaPerMin(c["dial_failures_total"], a.lastMetrics["dial_failures_total"], mins)
		}
	}
	a.statsHist = append(a.statsHist, statsSample{
		Time:           now,
		QueueLive:      a.bucket.Len(),
		QueueHot:       a.bucket.HotLen(),
		PoolCandidates: a.pool.Len(),
		RequestsPerMin: rpm,
		ChecksPerMin:   cpm,
		DialFailPerMin: dpm,
	})
	if len(a.statsHist) > 1440 {
		// Keep only the last 24h (1440 minutes).
		copy(a.statsHist, a.statsHist[len(a.statsHist)-1440:])
		a.statsHist = a.statsHist[:1440]
	}
}

// deltaPerMin turns a counter delta over minutes into a per-minute rate.
func deltaPerMin(now, prev int64, mins float64) float64 {
	if now <= prev {
		return 0
	}
	return float64(now-prev) / mins
}

// startStatsRecorder begins recording stats every minute. It re-arms itself
// with AfterFunc so a slow sample cannot pile up ticks behind it, and it stops
// when the process context is done.
func (a *admin) startStatsRecorder(ctx context.Context) {
	var arm func()
	arm = func() {
		time.AfterFunc(time.Minute, func() {
			select {
			case <-ctx.Done():
				return
			default:
				a.recordStatsSample()
				arm()
			}
		})
	}
	arm()
}

// statsHistory returns a copy of the 24h ring.
func (a *admin) statsHistory() []statsSample {
	a.statsMu.Lock()
	defer a.statsMu.Unlock()
	out := make([]statsSample, len(a.statsHist))
	copy(out, a.statsHist)
	return out
}

func (a *admin) handleStatsHistory(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, map[string]interface{}{"samples": a.statsHistory()})
}

// sourceRow is the JSON shape of one sites.txt entry plus its telemetry.
type sourceRow struct {
	URL       string    `json:"url"`
	Alive     int       `json:"alive"`
	Total     int64     `json:"total"`
	Emitted   int       `json:"emitted"`
	Found     int       `json:"found"`
	Cycles    int64     `json:"cycles"`
	Fails     int       `json:"fails"`
	OK        bool      `json:"ok"`
	Cooling   bool      `json:"cooling"`
	CoolUntil time.Time `json:"cool_until,omitempty"`
	LastFetch time.Time `json:"last_fetch,omitempty"`
	LastNote  string    `json:"last_note,omitempty"`
	// Yield is the share of emitted candidates that are still alive, as a
	// percentage. It is the single number that says whether a source earns
	// its place in the list.
	Yield float64 `json:"yield_pct"`
	// Unproven marks sources the collector has never fetched yet, so the UI can
	// show them apart from the ones that already have a verdict.
	Unproven bool `json:"unproven"`
}

func (a *admin) sources() []sourceRow {
	var stats []proxy.SiteStat
	if a.collector != nil {
		stats = a.collector.Stats().Snapshot()
	}
	// SiteStat.Alive is only refreshed once per collector cycle (25 min), so it
	// says "0 alive" for a source whose proxies the checker has been adding
	// for the last few minutes. The bucket's per-source counter is updated on
	// every add/remove, so it is the fresher number — including zero, which
	// means "nothing of this source's output is in the queue right now" and
	// must not be papered over with a stale per-cycle value.
	live := a.bucket.SourceCounts()
	out := make([]sourceRow, 0, len(stats))
	for _, s := range stats {
		alive := live[s.URL]
		row := sourceRow{
			URL:       s.URL,
			Alive:     alive,
			Total:     s.Total,
			Emitted:   s.Emitted,
			Found:     s.Found,
			Cycles:    s.Cycles,
			Fails:     s.Fails,
			OK:        s.OK,
			Cooling:   !s.CoolUntil.IsZero() && time.Now().Before(s.CoolUntil),
			CoolUntil: s.CoolUntil,
			LastFetch: s.LastFetch,
			LastNote:  s.LastNote,
			Unproven:  s.Cycles == 0,
		}
		if s.Total > 0 {
			row.Yield = float64(alive) * 100 / float64(s.Total)
		}
		out = append(out, row)
	}
	return out
}

func (a *admin) handleSources(w http.ResponseWriter, r *http.Request) {
	rows := a.sources()
	total := 0
	productive := 0
	for _, s := range rows {
		if s.Cycles == 0 {
			continue
		}
		total++
		if s.Alive > 0 {
			productive++
		}
	}
	writeJSON(w, map[string]interface{}{
		"sources":          rows,
		"tracked":          len(rows),
		"measured":         total,
		"with_live_output": productive,
		"live_proxies":     a.bucket.Len(),
		"generated_at":     time.Now().Format(time.RFC3339),
	})
}

// handleSourceResetCooldown clears a source's failure cooldown so the next
// cycle fetches it in full. The operator's "I fixed the thing, retry now"
// button: waiting out site_cooldown is half an hour per fix otherwise.
func (a *admin) handleSourceResetCooldown(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", "POST")
		writeError(w, http.StatusMethodNotAllowed, "use POST")
		return
	}
	var body struct {
		URL  string   `json:"url"`
		URLs []string `json:"urls"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<16)).Decode(&body); err != nil {
		writeError(w, http.StatusBadRequest, "bad json: "+err.Error())
		return
	}
	urls := body.URLs
	if body.URL != "" {
		urls = append(urls, body.URL)
	}
	if len(urls) == 0 {
		writeError(w, http.StatusBadRequest, "url or urls[] required")
		return
	}
	if a.collector == nil {
		writeError(w, http.StatusServiceUnavailable, "collector is not wired up")
		return
	}
	reg := a.collector.Stats()
	reset := make([]string, 0, len(urls))
	for _, u := range urls {
		if reg.ResetCooldown(u) {
			reset = append(reset, u)
		}
	}
	writeJSON(w, map[string]interface{}{
		"ok": true, "reset": reset, "requested": len(urls),
		"note": "the next collector cycle fetches these in full",
	})
}

// handleCollectorWake forces an immediate collector cycle. It uses the same
// channel the empty-queue watchdog uses, so a cycle started this way obeys
// every existing rule (the site list is re-read, the priority order still
// applies) — it is a nudge, not a second collection mode.
func (a *admin) handleCollectorWake(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", "POST")
		writeError(w, http.StatusMethodNotAllowed, "use POST")
		return
	}
	if a.wakeCollector == nil {
		writeError(w, http.StatusServiceUnavailable, "collector is not wired up")
		return
	}
	select {
	case a.wakeCollector <- struct{}{}:
		writeJSON(w, map[string]interface{}{
			"ok": true, "note": "emergency collector cycle started",
		})
	default:
		writeJSON(w, map[string]interface{}{
			"ok": true, "note": "a cycle is already pending",
		})
	}
}
func (a *admin) handleSites(w http.ResponseWriter, r *http.Request) {
	path := a.cfg.Collector.SitesFile
	switch r.Method {
	case http.MethodGet:
		list, err := proxy.LoadSiteList(path)
		if err != nil {
			writeError(w, http.StatusInternalServerError, err.Error())
			return
		}
		writeJSON(w, map[string]interface{}{
			"path":     path,
			"comments": countComments(list),
			"entries":  list.URLs(),
		})
	case http.MethodPost:
		var body struct {
			URL string `json:"url"`
		}
		if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<16)).Decode(&body); err != nil {
			writeError(w, http.StatusBadRequest, "bad json: "+err.Error())
			return
		}
		a.sitesMu.Lock()
		defer a.sitesMu.Unlock()
		list, err := proxy.LoadSiteList(path)
		if err != nil {
			writeError(w, http.StatusInternalServerError, err.Error())
			return
		}
		added, err := list.Add(body.URL)
		if err != nil {
			writeError(w, http.StatusBadRequest, err.Error())
			return
		}
		if !added {
			writeJSON(w, map[string]interface{}{
				"ok": true, "changed": false, "added": false,
				"entries": len(list.URLs()), "reason": "already in the list",
			})
			return
		}
		if err := proxy.SaveSiteList(list); err != nil {
			writeError(w, http.StatusInternalServerError, err.Error())
			return
		}
		writeJSON(w, map[string]interface{}{
			"ok": true, "changed": true, "added": true,
			"entries": len(list.URLs()), "note": "picked up on the next collector cycle",
		})
	case http.MethodDelete:
		// Support both single URL and bulk delete (array of URLs).
		var body struct {
			URL  string   `json:"url"`
			URLs []string `json:"urls"`
		}
		if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<16)).Decode(&body); err != nil {
			writeError(w, http.StatusBadRequest, "bad json: "+err.Error())
			return
		}
		a.sitesMu.Lock()
		defer a.sitesMu.Unlock()
		list, err := proxy.LoadSiteList(path)
		if err != nil {
			writeError(w, http.StatusInternalServerError, err.Error())
			return
		}
		var removed int
		if len(body.URLs) > 0 {
			for _, u := range body.URLs {
				if list.Remove(u) {
					removed++
				}
			}
		} else if body.URL != "" {
			if list.Remove(body.URL) {
				removed = 1
			}
		} else {
			writeError(w, http.StatusBadRequest, "url or urls[] required")
			return
		}
		if removed == 0 {
			writeJSON(w, map[string]interface{}{"ok": true, "changed": false, "reason": "not in the list"})
			return
		}
		if len(list.URLs()) == 0 {
			writeError(w, http.StatusBadRequest,
				"refusing to empty "+path+"; the collector would have no sources")
			return
		}
		if err := proxy.SaveSiteList(list); err != nil {
			writeError(w, http.StatusInternalServerError, err.Error())
			return
		}
		writeJSON(w, map[string]interface{}{
			"ok": true, "changed": true, "removed": removed,
			"entries": len(list.URLs()), "note": "picked up on the next collector cycle",
		})
	default:
		w.Header().Set("Allow", "GET, POST, DELETE")
		writeError(w, http.StatusMethodNotAllowed, "use GET, POST or DELETE")
	}
}

func (a *admin) handleProxies(w http.ResponseWriter, r *http.Request) {
	scope := r.URL.Query().Get("scope")
	switch scope {
	case proxy.AliveHot, proxy.AliveServed, proxy.AliveChecked, proxy.AliveAll:
	default:
		scope = proxy.AliveChecked
	}
	format := r.URL.Query().Get("format")
	text := format == "text"
	csv := format == "csv"
	jsonl := format == "jsonl"
	countryFilter := r.URL.Query().Get("country")
	asnFilter := r.URL.Query().Get("asn")
	limit := 0
	if v := r.URL.Query().Get("limit"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n < 0 {
			writeError(w, http.StatusBadRequest, "bad limit: "+v)
			return
		}
		limit = n
	} else if !text && !csv && !jsonl {
		limit = jsonRowCap
	}
	rows, total := a.live(scope, limit, countryFilter, asnFilter)
	switch {
	case text:
		// Plain scheme://host:port per line: paste straight into curl, a
		// config file, or another tool.
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.Header().Set("Content-Disposition", `attachment; filename="live-proxies.txt"`)
		_, _ = w.Write(exportText(rows))
	case csv:
		w.Header().Set("Content-Type", "text/csv; charset=utf-8")
		w.Header().Set("Content-Disposition", `attachment; filename="live-proxies.csv"`)
		_, _ = w.Write(exportCSV(rows))
	case jsonl:
		w.Header().Set("Content-Type", "application/jsonl; charset=utf-8")
		w.Header().Set("Content-Disposition", `attachment; filename="live-proxies.jsonl"`)
		enc := json.NewEncoder(w)
		for _, row := range rows {
			_ = enc.Encode(row)
		}
	default:
		writeJSON(w, map[string]interface{}{
			"scope": scope, "window_seconds": int(liveWindow.Seconds()),
			"count": len(rows), "total": total, "proxies": rows,
		})
	}
}

// handleProxiesRevalidate forces revalidation of selected proxies.
// POST body: {"urls": ["scheme://host:port", ...]} or {"keys": ["scheme://host:port", ...]}.
// The proxies are re-checked through the checker off the periodic schedule and
// are dropped only if the re-check fails; live ones stay in the queue with a
// refreshed stamp.
func (a *admin) handleProxiesRevalidate(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", "POST")
		writeError(w, http.StatusMethodNotAllowed, "use POST")
		return
	}
	var body struct {
		URLs []string `json:"urls"`
		Keys []string `json:"keys"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<16)).Decode(&body); err != nil {
		writeError(w, http.StatusBadRequest, "bad json: "+err.Error())
		return
	}
	if len(body.URLs) == 0 && len(body.Keys) == 0 {
		writeError(w, http.StatusBadRequest, "urls[] or keys[] required")
		return
	}
	if a.checker == nil || a.debug == nil {
		writeError(w, http.StatusServiceUnavailable, "revalidation is not wired up")
		return
	}

	// One scan to resolve the requested identities. A checker pass costs
	// seconds per proxy, so the handler must not wait for it: the work runs
	// under the process context and the page sees progress via the live view.
	targets := make(map[string]*proxy.Proxy)
	for _, p := range a.bucket.Snapshot() {
		if _, dup := targets[p.Key()]; !dup {
			targets[p.Key()] = p
		}
	}

	var revalidated int
	var notFound []string
	checkList := append(append([]string{}, body.URLs...), body.Keys...)
	picked := make([]*proxy.Proxy, 0, len(checkList))
	for _, key := range checkList {
		if p, ok := targets[key]; ok {
			revalidated++
			picked = append(picked, p)
			continue
		}
		notFound = append(notFound, key)
	}
	if revalidated > 0 {
		workers := a.cfg.Storage.RevalidateWorkers
		if workers < 1 {
			workers = 1
		}
		if workers > revalidated {
			workers = revalidated
		}
		go proxy.RevalidateNow(a.ctx, a.checker, a.bucket, picked, workers, a.debug)
	}

	writeJSON(w, map[string]interface{}{
		"ok":          true,
		"revalidated": revalidated,
		"not_found":   notFound,
		"resolved":    len(targets),
		"note":        "re-checking now; dead entries are dropped, live ones stay",
	})
}

func (a *admin) handleIndex(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	_, _ = w.Write([]byte(indexHTML))
}

func (a *admin) handleCSS(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/css; charset=utf-8")
	w.Header().Set("Cache-Control", "max-age=60")
	_, _ = w.Write([]byte(adminCSS))
}

func (a *admin) handleJS(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/javascript; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	_, _ = w.Write([]byte(adminJS))
}

func countComments(l *proxy.SiteList) int {
	n := 0
	for _, e := range l.Entries {
		if e.Comment != "" {
			n++
		}
	}
	return n
}

func writeJSON(w http.ResponseWriter, v interface{}) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	// Compact JSON: API consumers don't need indented output.
	enc := json.NewEncoder(w)
	_ = enc.Encode(v)
}

// writeError keeps every response on the API JSON, including failures: the UI
// shows the message directly, so a text/plain 400 would be unreadable there.
func writeError(w http.ResponseWriter, code int, msg string) {
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(code)
	writeJSON(w, map[string]interface{}{"ok": false, "error": msg, "code": code})
}

// pprofPaths are the profiling endpoints served on the admin listener, behind
// the same token as everything else. Profiling a process that also serves
// client traffic is a routine debugging step ("the proxy is slow" is a flame
// chart question long before it is anything else), and an admin listener that
// cannot answer it sends the developer back to SSH-ing into a production box.
var pprofHandlers = map[string]http.HandlerFunc{
	"/debug/pprof/":        pprof.Index,
	"/debug/pprof/cmdline": pprof.Cmdline,
	"/debug/pprof/profile": pprof.Profile,
	"/debug/pprof/symbol":  pprof.Symbol,
	"/debug/pprof/trace":   pprof.Trace,
}
