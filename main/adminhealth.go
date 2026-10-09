package main

import (
	"fmt"
	"net/http"
	"reflect"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"time"

	"protator/proxy"
)

// healthView builds the payload that /health, /ready and the WebSocket share.
//
// It answers "is this thing working", which the four queue counts on their own
// cannot: a collector that crashed, a revalidation pass that never runs and a
// queue that is empty of *proven* proxies are all invisible in a length.
func (a *admin) healthView(tls bool) map[string]interface{} {
	m := map[string]interface{}{
		"uptime_seconds":  int(time.Since(a.started).Seconds()),
		"queue_live":      a.bucket.Len(),
		"queue_hot":       a.bucket.HotLen(),
		"queue_proven":    a.bucket.ProvenCount(),
		"pool_candidates": a.pool.Len(),
		"tls":             tls,
		"ws_clients":      a.ws.count(),
		"goroutines":      runtime.NumGoroutine(),
	}
	if a.candidates != nil {
		m["candidate_channel"] = map[string]interface{}{
			"len": len(a.candidates), "cap": cap(a.candidates),
		}
	}
	if a.workers != nil {
		m["worker_restarts"] = a.workers.Restarts()
	}
	if a.beats != nil {
		m["beats"] = a.beats.view(a.cfg.Storage.RevalidateInterval.Duration, a.cfg.Collector.CycleSleep.Duration)
	}
	counters := proxy.Stats.Snapshot()
	for _, k := range []string{
		"requests_total", "dial_attempts_total", "dial_failures_total", "evictions_total",
		"served_ok_total", "serve_failures_total", "block_pages_total",
		"checks_total", "checks_passed_total", "checks_failed_total",
		"collector_cycles_total", "reval_passes_total", "reval_dropped_total",
		"recovered_panics_total",
	} {
		m[k] = counters[k]
	}
	return m
}

func (a *admin) handleHealth(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, a.healthView(r.TLS != nil))
}

// handleReady is the probe a supervisor watches: 200 only while the queue can
// actually serve a client. JSON in both cases so the reason is machine-readable.
//
// The test is the proven tier, not the queue length: a queue of two million
// seeded-but-unverified addresses answers "is anything in the queue" with yes
// while every dial fails, and a supervisor told that is healthy keeps routing
// clients into a dead proxy. JSON in both cases so the reason is
// machine-readable.
func (a *admin) handleReady(w http.ResponseWriter, r *http.Request) {
	live, hot := a.bucket.Len(), a.bucket.ProvenCount()
	code := http.StatusOK
	body := map[string]interface{}{
		"ok": true, "queue_live": live, "queue_proven": hot,
	}
	if hot == 0 {
		code = http.StatusServiceUnavailable
		reason := "no proven proxies: the queue has entries, but none has served traffic or passed a check inside the pick windows"
		if live == 0 {
			reason = "the queue is empty: nothing to serve yet"
		}
		body = map[string]interface{}{
			"ok": false, "error": reason, "queue_live": live, "queue_proven": hot,
		}
	}
	// Content-Type before WriteHeader, not after: once the status is written
	// the header is already on the wire, so setting it afterwards is a no-op
	// and the response ships as whatever Go sniffed.
	// httptest.ResponseRecorder does not reproduce that, which is why the test
	// could pass while production did not.
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(code)
	writeJSON(w, body)
}

// handleMetrics serves the counters, their per-second rates since the previous
// request, and the live gauges. ?format=text emits Prometheus-style lines.
func (a *admin) handleMetrics(w http.ResponseWriter, r *http.Request) {
	counters, rates, elapsed := a.countersAndRates()
	gauges := map[string]int64{
		"queue_live":      int64(a.bucket.Len()),
		"queue_hot":       int64(a.bucket.HotLen()),
		"queue_proven":    int64(a.bucket.ProvenCount()),
		"pool_candidates": int64(a.pool.Len()),
		"goroutines":      int64(runtime.NumGoroutine()),
	}
	if a.candidates != nil {
		gauges["candidate_channel_len"] = int64(len(a.candidates))
		gauges["candidate_channel_cap"] = int64(cap(a.candidates))
	}

	if r.URL.Query().Get("format") == "text" {
		w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
		writeMetricsText(w, counters, rates, gauges)
		return
	}
	writeJSON(w, map[string]interface{}{
		"counters":       counters,
		"rates_per_sec":  rates,
		"sample_seconds": elapsed.Seconds(),
		"gauges":         gauges,
	})
}

// countersAndRates returns the current counters, the per-second rates since
// the previous call, and how long that window was. Two calls are needed for a
// rate, so the first response after startup reports zero rates.
func (a *admin) countersAndRates() (map[string]int64, map[string]float64, time.Duration) {
	a.metricsMu.Lock()
	defer a.metricsMu.Unlock()
	current := proxy.Stats.Snapshot()
	if !a.hasMetricsSample {
		a.lastMetrics = current
		a.lastMetricsAt = time.Now()
		a.hasMetricsSample = true
		return current, map[string]float64{}, 0
	}
	elapsed := time.Since(a.lastMetricsAt)
	secs := elapsed.Seconds()
	rates := make(map[string]float64, len(current))
	if secs > 0 {
		for k, v := range current {
			if prev, ok := a.lastMetrics[k]; ok && v > prev {
				rates[k] = float64(v-prev) / secs
			}
		}
	}
	a.lastMetrics = current
	a.lastMetricsAt = time.Now()
	return current, rates, elapsed
}

// writeMetricsText renders Prometheus text format. Labels are deliberately
// absent: everything here is process-wide.
func writeMetricsText(w http.ResponseWriter, counters map[string]int64, rates map[string]float64, gauges map[string]int64) {
	write := func(name string, v interface{}) {
		fmt.Fprintf(w, "%s %v\n", name, v)
	}
	keys := make([]string, 0, len(counters))
	for k := range counters {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		write(k, counters[k])
	}
	for _, k := range keys {
		if v, ok := rates[k]; ok {
			write(k[:len(k)-len("_total")]+"_per_sec", strconv.FormatFloat(v, 'f', 4, 64))
		}
	}
	gkeys := make([]string, 0, len(gauges))
	for k := range gauges {
		gkeys = append(gkeys, k)
	}
	sort.Strings(gkeys)
	for _, k := range gkeys {
		write(k, gauges[k])
	}
}

// logCategory describes one log category for the /api/logs endpoint.
type logCategory struct {
	Name  string `json:"name"`
	Count int    `json:"count"`
}

// log categories routed by fileLogSink.
var logCategories = []string{"collector", "checker", "serve", "system"}

// handleLogs serves the in-memory tail of one log category. Reading a rotated
// file over SSH is the first thing an operator does during an incident; this
// makes it one page refresh.
func (a *admin) handleLogs(w http.ResponseWriter, r *http.Request) {
	if a.sink == nil {
		writeError(w, http.StatusNotImplemented, "file logging is not enabled (logging.dir is empty)")
		return
	}
	cat := r.URL.Query().Get("category")
	if cat == "" {
		cats := make([]logCategory, 0, len(logCategories))
		for _, c := range logCategories {
			cats = append(cats, logCategory{Name: c, Count: len(a.sink.Tail(c, logTailLines))})
		}
		writeJSON(w, map[string]interface{}{"categories": cats})
		return
	}
	limit := 200
	if v := r.URL.Query().Get("limit"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n >= 0 {
			limit = n
		}
	}
	if limit > logTailLines {
		limit = logTailLines
	}
	writeJSON(w, map[string]interface{}{
		"category": cat, "lines": a.sink.Tail(cat, limit),
	})
}

// redactedConfig renders the effective config as JSON, hiding anything that
// looks like a credential. It is reflection-driven on purpose: the config gains
// fields constantly, and a hand-maintained copy on the admin page would drift
// within a release.
func redactedConfig(cfg *proxy.Config) map[string]interface{} {
	out := map[string]interface{}{}
	v := reflect.ValueOf(cfg).Elem()
	t := v.Type()
	for i := 0; i < t.NumField(); i++ {
		sv := v.Field(i)
		// Skip anything that is not a config section: the struct also carries
		// unexported bookkeeping (the load path), and reflect cannot render it.
		if sv.Kind() != reflect.Struct {
			continue
		}
		name := t.Field(i).Tag.Get("toml")
		if name == "" {
			continue
		}
		section := map[string]interface{}{}
		st := sv.Type()
		for j := 0; j < st.NumField(); j++ {
			key := st.Field(j).Tag.Get("toml")
			if key == "" {
				continue
			}
			fv := sv.Field(j)
			if isSecretField(key) {
				section[key] = "<set>"
				if fmt.Sprint(fv.Interface()) == "" {
					section[key] = ""
				}
				continue
			}
			section[key] = fv.Interface()
		}
		out[name] = section
	}
	return out
}

// isSecretField names the fields whose values must never be rendered. Matched
// by substring so a future token/password field is redacted by default.
func isSecretField(name string) bool {
	for _, needle := range []string{"token", "password", "secret", "key_file"} {
		if strings.Contains(name, needle) {
			return true
		}
	}
	return false
}

func (a *admin) handleConfig(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, map[string]interface{}{
		"effective_config": redactedConfig(a.cfg),
		"config_path":      a.cfgPath,
	})
}

// requireAdminToken gates the mutating and telemetry endpoints when
// server.admin_token is set. The health probes stay open: a supervisor that
// cannot authenticate would report a broken service instead of an unready one.
func (a *admin) requireAdminToken(next http.HandlerFunc) http.HandlerFunc {
	token := a.cfg.Server.AdminToken
	if token == "" {
		return next
	}
	return func(w http.ResponseWriter, r *http.Request) {
		given := r.Header.Get("Authorization")
		if v := strings.TrimPrefix(given, "Bearer "); v != given && v != "" {
			given = v
		} else if v := r.URL.Query().Get("token"); v != "" {
			given = v
		} else {
			given = ""
		}
		if !constantTimeEqual(given, token) {
			writeError(w, http.StatusUnauthorized, "invalid or missing admin token")
			return
		}
		next(w, r)
	}
}

// constantTimeEqual compares two tokens without leaking their common prefix
// length through timing.
func constantTimeEqual(a, b string) bool {
	if len(a) != len(b) {
		return false
	}
	var v byte
	for i := 0; i < len(a); i++ {
		v |= a[i] ^ b[i]
	}
	return v == 0
}
