package main

import (
	"encoding/json"
	"net/http"
	"strings"
	"time"

	"protator/proxy"
)

// The site list and its telemetry: the /api/sources rows (entry + per-source
// counters + cooldown), the cooldown-reset button, and the sites.txt editor.
// The registry behind the numbers is proxy/sitestats.go; nothing here holds a
// lock while rendering — the editor serializes its own read-modify-write via
// admin.sitesMu.

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
		// Single URL or a bulk paste from the multiline box: {url} or
		// {urls: [...]}. Every line goes through SiteList.Add (validated,
		// normalized, deduped); the file is rewritten once per request, not
		// per line, so a 50-line paste is one atomic save with one .bak.
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
		if len(body.URLs) == 0 && body.URL == "" {
			writeError(w, http.StatusBadRequest, "url or urls[] required")
			return
		}
		if len(body.URLs) == 0 {
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
			return
		}
		raws := body.URLs
		if body.URL != "" {
			raws = append([]string{body.URL}, raws...)
		}
		var added, dups int
		invalid := []map[string]string{}
		for _, raw := range raws {
			if strings.TrimSpace(raw) == "" {
				continue // pasted blank lines are not errors
			}
			ok, err := list.Add(raw)
			if err != nil {
				invalid = append(invalid, map[string]string{"line": raw, "reason": err.Error()})
				continue
			}
			if !ok {
				dups++
				continue
			}
			added++
		}
		if added == 0 && dups == 0 && len(invalid) == 0 {
			writeError(w, http.StatusBadRequest, "url or urls[] required")
			return
		}
		if added > 0 {
			if err := proxy.SaveSiteList(list); err != nil {
				writeError(w, http.StatusInternalServerError, err.Error())
				return
			}
		}
		writeJSON(w, map[string]interface{}{
			"ok": true, "changed": added > 0,
			"added": added, "duplicates": dups, "invalid": invalid,
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
