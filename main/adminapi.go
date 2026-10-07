package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/net/websocket"
	"protator/proxy"
)

// admin holds the live handles the HTTP surface reads from. Everything here
// is read-only except the sites editor, and nothing holds a lock while
// rendering: the bucket, pool and registry each hand out copies.
type admin struct {
	cfg       *proxy.Config
	bucket    *proxy.Bucket
	pool      *proxy.CandidatePool
	collector *proxy.Collector
	started   time.Time

	// sitesMu serializes the editor's read-modify-write. Two POSTs racing on
	// the same file would both read the old list and the second save would
	// drop the first one's entry. Only the write path takes it; GET does not
	// need to, because the save is an atomic rename.
	sitesMu sync.Mutex

	// stats history ring buffer for 24h graph (1 sample per minute = 1440 entries)
	statsMu    sync.Mutex
	statsHist  []statsSample
	statsTimer *time.Timer

	// WebSocket connections for live updates
	wsMu    sync.Mutex
	wsConns map[*wsConn]struct{}

	// Delta WS updates: track previous proxy state to send incremental updates.
	wsMuPrev    sync.Mutex
	prevProxies map[string]liveRow // key = proxy URL
	prevHealth  map[string]int
}

type wsConn struct {
	conn   *websocket.Conn
	send   chan []byte
	closed bool
}

type statsSample struct {
	Time           time.Time `json:"time"`
	QueueLive      int       `json:"queue_live"`
	QueueHot       int       `json:"queue_hot"`
	PoolCandidates int       `json:"pool_candidates"`
}

// recordStatsSample adds a sample to the 24h ring buffer (1440 minutes max).
func (a *admin) recordStatsSample() {
	a.statsMu.Lock()
	defer a.statsMu.Unlock()
	s := statsSample{
		Time:           time.Now(),
		QueueLive:      a.bucket.Len(),
		QueueHot:       a.bucket.HotLen(),
		PoolCandidates: a.pool.Len(),
	}
	a.statsHist = append(a.statsHist, s)
	if len(a.statsHist) > 1440 {
		// Keep only last 24h (1440 minutes)
		copy(a.statsHist, a.statsHist[len(a.statsHist)-1440:])
		a.statsHist = a.statsHist[:1440]
	}
}

// startStatsRecorder begins recording stats every minute.
func (a *admin) startStatsRecorder(ctx context.Context) {
	a.statsTimer = time.AfterFunc(time.Minute, func() {
		select {
		case <-ctx.Done():
			return
		default:
			a.recordStatsSample()
			a.startStatsRecorder(ctx)
		}
	})
}

// handleStatsHistory returns the 24h stats history for graphing.
func (a *admin) handleStatsHistory(w http.ResponseWriter, r *http.Request) {
	a.statsMu.Lock()
	defer a.statsMu.Unlock()
	writeJSON(w, map[string]interface{}{
		"samples": a.statsHist,
	})
}

// handleWebSocket upgrades the connection to a WebSocket for live updates.
func (a *admin) handleWebSocket(ws *websocket.Conn) {
	c := &wsConn{conn: ws, send: make(chan []byte, 256)}
	a.wsMu.Lock()
	if a.wsConns == nil {
		a.wsConns = make(map[*wsConn]struct{})
	}
	a.wsConns[c] = struct{}{}
	a.wsMu.Unlock()

	// Send initial state
	a.sendWSState(c)

	// Writer goroutine
	go func() {
		for msg := range c.send {
			if c.closed {
				return
			}
			if err := websocket.Message.Send(ws, string(msg)); err != nil {
				a.closeWS(c)
				return
			}
		}
	}()

	// Reader: keep alive, ignore messages
	var msg string
	for {
		if err := websocket.Message.Receive(ws, &msg); err != nil {
			a.closeWS(c)
			return
		}
	}
}

func (a *admin) closeWS(c *wsConn) {
	a.wsMu.Lock()
	if !c.closed {
		c.closed = true
		close(c.send)
		delete(a.wsConns, c)
	}
	a.wsMu.Unlock()
}

// broadcastWS sends a message to all connected WebSocket clients.
func (a *admin) broadcastWS(msg []byte) {
	a.wsMu.Lock()
	for c := range a.wsConns {
		select {
		case c.send <- msg:
		default:
			// Client buffer full, drop
		}
	}
	a.wsMu.Unlock()
}

// sendWSState sends the current state to a newly connected client.
func (a *admin) sendWSState(c *wsConn) {
	a.statsMu.Lock()
	hist := make([]statsSample, len(a.statsHist))
	copy(hist, a.statsHist)
	a.statsMu.Unlock()

	live, _ := a.live(proxy.AliveChecked, 0, "", "")
	sources := a.sources()

	msg := map[string]interface{}{
		"type":    "state",
		"health":  map[string]interface{}{"queue_live": a.bucket.Len(), "queue_hot": a.bucket.HotLen(), "pool_candidates": a.pool.Len()},
		"proxies": live,
		"sources": sources,
		"history": hist,
	}
	data, _ := json.Marshal(msg)
	select {
	case c.send <- data:
	default:
	}
}

// notifyWSChanged is called by bucket.OnChange to broadcast updates.
// Sends delta updates: only changed proxies (added/removed/updated) plus health.
func (a *admin) notifyWSChanged() {
	a.statsMu.Lock()
	hist := make([]statsSample, len(a.statsHist))
	copy(hist, a.statsHist)
	a.statsMu.Unlock()

	live, _ := a.live(proxy.AliveChecked, 0, "", "")
	currentProxies := make(map[string]liveRow, len(live))
	for _, p := range live {
		currentProxies[p.URL] = p
	}

	// Compute delta
	a.wsMuPrev.Lock()
	added := make([]liveRow, 0)
	removed := make([]string, 0)
	updated := make([]liveRow, 0)

	for url, p := range currentProxies {
		if prev, ok := a.prevProxies[url]; !ok {
			added = append(added, p)
		} else if prev.Latency != p.Latency || prev.Consec != p.Consec || prev.InFlight != p.InFlight || prev.Served != p.Served || prev.Checked != p.Checked {
			updated = append(updated, p)
		}
	}
	for url := range a.prevProxies {
		if _, ok := currentProxies[url]; !ok {
			removed = append(removed, url)
		}
	}

	// Update previous state
	a.prevProxies = currentProxies
	prevHealth := map[string]int{"queue_live": a.bucket.Len(), "queue_hot": a.bucket.HotLen(), "pool_candidates": a.pool.Len()}
	a.prevHealth = prevHealth
	a.wsMuPrev.Unlock()

	// Build delta message
	msg := map[string]interface{}{
		"type":    "delta",
		"health":  prevHealth,
		"added":   added,
		"removed": removed,
		"updated": updated,
		"history": hist,
	}
	data, _ := json.Marshal(msg)
	a.broadcastWS(data)
}

// liveWindow is how recent a proof of life must be for a proxy to be listed as
// alive. It is deliberately short: the point of the page is "right now", not
// "once worked".
const liveWindow = 15 * time.Minute

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

// liveRow is one entry of the "really alive" proxy table.
type liveRow struct {
	URL      string  `json:"url"`
	Schema   string  `json:"schema"`
	Host     string  `json:"host"`
	Port     int     `json:"port"`
	Source   string  `json:"source,omitempty"`
	Country  string  `json:"country,omitempty"`
	ASN      string  `json:"asn,omitempty"`
	Latency  int64   `json:"latency_ms"`
	OK       int64   `json:"ok_total"`
	Fails    int64   `json:"fail_total"`
	Consec   int64   `json:"consec_fails"`
	Age      float64 `json:"proof_age_s"`
	Served   bool    `json:"served"`
	Checked  bool    `json:"checked"`
	InFlight int64   `json:"in_flight"`
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

// live renders the page of proxy rows plus the size of the scope itself, so the
// UI can say "1000 of 41234" instead of implying the page is the whole truth.
// Returns (filteredRows, unfilteredTotal).
func (a *admin) live(scope string, limit int, countryFilter, asnFilter string) ([]liveRow, int) {
	if a.bucket == nil {
		return nil, 0
	}
	proxies, unfilteredTotal := a.bucket.LiveListPage(scope, liveWindow, 0) // get all for filtering
	now := time.Now()
	out := make([]liveRow, 0, len(proxies))
	for _, p := range proxies {
		if countryFilter != "" && !strings.EqualFold(p.GetCountry(), countryFilter) {
			continue
		}
		if asnFilter != "" && !strings.Contains(strings.ToLower(p.GetASN()), strings.ToLower(asnFilter)) {
			continue
		}
		served, checked := p.LastServed(), p.LastCheck()
		age := now.Sub(served)
		if served.IsZero() || (!checked.IsZero() && checked.After(served)) {
			age = now.Sub(checked)
		}
		out = append(out, liveRow{
			URL:      p.URL(),
			Schema:   p.Schema,
			Host:     p.Host,
			Port:     p.Port,
			Source:   p.Source(),
			Country:  p.GetCountry(),
			ASN:      p.GetASN(),
			Latency:  p.Latency().Milliseconds(),
			OK:       p.OKTotal(),
			Fails:    p.FailTotal(),
			Consec:   p.ConsecFails(),
			Age:      age.Seconds(),
			Served:   !served.IsZero() && now.Sub(served) <= liveWindow,
			Checked:  !checked.IsZero() && now.Sub(checked) <= liveWindow,
			InFlight: p.InFlight(),
		})
	}
	if limit > 0 && len(out) > limit {
		out = out[:limit]
	}
	return out, unfilteredTotal
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

func (a *admin) handleHealth(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, map[string]interface{}{
		"uptime_seconds":  int(time.Since(a.started).Seconds()),
		"queue_live":      a.bucket.Len(),
		"queue_hot":       a.bucket.HotLen(),
		"pool_candidates": a.pool.Len(),
		"tls":             r.TLS != nil,
	})
}

// handleReady is the probe a supervisor watches: 200 only while the queue can
// actually serve a client. JSON in both cases so the reason is machine-readable.
func (a *admin) handleReady(w http.ResponseWriter, r *http.Request) {
	if n := a.bucket.Len(); n > 0 {
		w.WriteHeader(http.StatusOK)
		writeJSON(w, map[string]interface{}{"ok": true, "queue_live": n})
		return
	}
	w.WriteHeader(http.StatusServiceUnavailable)
	writeJSON(w, map[string]interface{}{
		"ok": false, "error": "no live proxies in the queue", "queue_live": 0,
	})
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
		// Support both single URL and bulk delete (array of URLs)
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

// jsonRowCap bounds a single JSON response. The queue can hold two million
// entries and the page only ever shows the first pageful, so an unbounded
// "scope=all" would build a multi-hundred-megabyte response out of a stray
// click. The text download is left uncapped on purpose: exporting the list is
// the one thing an operator asks for a lot of rows.
const jsonRowCap = 1000

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
	if text {
		// Plain scheme://host:port per line: paste straight into curl, a
		// config file, or another tool.
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.Header().Set("Content-Disposition", `attachment; filename="live-proxies.txt"`)
		var sb strings.Builder
		for _, row := range rows {
			sb.WriteString(row.URL)
			sb.WriteByte('\n')
		}
		_, _ = w.Write([]byte(sb.String()))
		return
	}
	if csv {
		w.Header().Set("Content-Type", "text/csv; charset=utf-8")
		w.Header().Set("Content-Disposition", `attachment; filename="live-proxies.csv"`)
		var sb strings.Builder
		sb.WriteString("url,schema,host,port,source,country,asn,latency_ms,ok_total,fail_total,consec_fails,proof_age_s,served,checked,in_flight\n")
		for _, row := range rows {
			fmt.Fprintf(&sb, "%s,%s,%s,%d,%s,%s,%s,%d,%d,%d,%d,%.3f,%v,%v,%d\n",
				row.URL, row.Schema, row.Host, row.Port, row.Source, row.Country, row.ASN,
				row.Latency, row.OK, row.Fails, row.Consec, row.Age, row.Served, row.Checked, row.InFlight)
		}
		_, _ = w.Write([]byte(sb.String()))
		return
	}
	if jsonl {
		w.Header().Set("Content-Type", "application/jsonl; charset=utf-8")
		w.Header().Set("Content-Disposition", `attachment; filename="live-proxies.jsonl"`)
		enc := json.NewEncoder(w)
		for _, row := range rows {
			_ = enc.Encode(row)
		}
		return
	}
	writeJSON(w, map[string]interface{}{
		"scope": scope, "window_seconds": int(liveWindow.Seconds()),
		"count": len(rows), "total": total, "proxies": rows,
	})
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

// handleProxiesRevalidate forces revalidation of selected proxies.
// POST body: {"urls": ["scheme://host:port", ...]} or {"keys": ["scheme://host:port", ...]}.
// The proxies are looked up in the bucket and queued for immediate revalidation
// through the checker (bypassing the normal revalidate interval).
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

	// Collect proxies from bucket
	targets := make(map[string]*proxy.Proxy)
	if a.bucket != nil {
		for _, p := range a.bucket.Snapshot() {
			targets[p.URL()] = p
			targets[p.Key()] = p
		}
	}

	var revalidated int
	var notFound []string
	checkList := append(body.URLs, body.Keys...)
	for _, key := range checkList {
		p, ok := targets[key]
		if !ok {
			notFound = append(notFound, key)
			continue
		}
		// Mark proxy for revalidation by removing it - it will be re-added if valid
		// or the collector will re-discover it. The revalidateLoop will also pick it up.
		a.bucket.Remove(p)
		revalidated++
	}

	writeJSON(w, map[string]interface{}{
		"ok":          true,
		"revalidated": revalidated,
		"not_found":   notFound,
		"note":        "proxies removed from queue; will be revalidated on next cycle",
	})
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
