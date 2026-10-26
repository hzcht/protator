package main

import (
	"context"
	"encoding/json"
	"log"
	"net/http"
	"net/http/pprof"
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

	// procCancel triggers the process-wide graceful shutdown (the same
	// context SIGTERM cancels). It backs POST /api/shutdown, which is how
	// stop.ps1 stops the daemon on Windows: Stop-Process is TerminateProcess
	// and would skip every defer in main. nil in tests.
	procCancel func()

	// sitesMu serializes the editor's read-modify-write. Two POSTs racing on
	// the same file would both read the old list and the second save would
	// drop the first one's entry. Only the write path takes it; GET does not
	// need to, because the save is an atomic rename.
	sitesMu sync.Mutex

	// statsMu guards the 24h history ring (1 sample per minute = 1440 entries)
	// and the recorder's own previous snapshot below.
	statsMu   sync.Mutex
	statsHist []statsSample
	// histPrev/histPrevAt are the previous recorder sample. Rates are computed
	// sample-to-sample on the recorder's own minute cadence — not against the
	// /api/metrics scrape window, which the page never scrapes (so the rates
	// used to read zero forever) and which concurrent scrapers would shorten
	// under each other.
	histPrev   map[string]int64
	histPrevAt time.Time

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
	c := proxy.Stats.Snapshot()
	rpm, cpm, dpm := 0.0, 0.0, 0.0
	if a.histPrev != nil && !a.histPrevAt.IsZero() {
		if mins := now.Sub(a.histPrevAt).Minutes(); mins > 0 {
			rpm = deltaPerMin(c["requests_total"], a.histPrev["requests_total"], mins)
			cpm = deltaPerMin(c["checks_total"], a.histPrev["checks_total"], mins)
			dpm = deltaPerMin(c["dial_failures_total"], a.histPrev["dial_failures_total"], mins)
		}
	}
	a.histPrev, a.histPrevAt = c, now
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
		proxy.Stats.CollectorWakes.Add(1)
		writeJSON(w, map[string]interface{}{
			"ok": true, "note": "emergency collector cycle started",
		})
	default:
		writeJSON(w, map[string]interface{}{
			"ok": true, "note": "a cycle is already pending",
		})
	}
}

// handleShutdown cancels the process lifetime context, which runs main's own
// graceful sequence: stop accepting, drain in-flight requests within
// shutdown_timeout, save the queue, flush the pool. It exists because Windows
// has no SIGTERM — Stop-Process is TerminateProcess and would lose the queue
// tail on every scheduled stop.
func (a *admin) handleShutdown(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", "POST")
		writeError(w, http.StatusMethodNotAllowed, "use POST")
		return
	}
	if a.procCancel == nil {
		writeError(w, http.StatusServiceUnavailable, "shutdown is not wired up")
		return
	}
	log.Printf("admin: graceful shutdown requested via /api/shutdown")
	writeJSON(w, map[string]interface{}{"ok": true, "note": "shutting down"})
	// Cancel after the response is on the wire: cancelling first tears the
	// listener down and the client would see a connection reset instead.
	go func() {
		defer proxy.RecoverPanic("admin: delayed shutdown")
		time.Sleep(50 * time.Millisecond)
		a.procCancel()
	}()
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
//
// writeJSON sets the Content-Type, so it must run before WriteHeader: headers
// set after the status is written never reach the wire (the response ships as
// sniffed text/plain instead). Same trap handleReady documents.
func writeError(w http.ResponseWriter, code int, msg string) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(code)
	enc := json.NewEncoder(w)
	_ = enc.Encode(map[string]interface{}{"ok": false, "error": msg, "code": code})
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
