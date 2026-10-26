package main

import (
	"encoding/json"
	"net/http"
	"strconv"

	"protator/proxy"
)

// The proxy-facing admin endpoints: the paged list with its text/csv/jsonl
// exports, forced revalidation of selected entries, and the operator override
// that drops one from the queue outright.

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
		// An explicit limit is still a limit: without the clamp a scripted
		// loop with ?limit=0 (or =2000000) re-ranks the whole queue per
		// request. Downloads get the export cap, pages the row cap.
		if text || csv || jsonl {
			if limit == 0 || limit > maxExportRows {
				limit = maxExportRows
			}
		} else if limit == 0 || limit > maxExportRows {
			limit = jsonRowCap
		}
	} else if !text && !csv && !jsonl {
		limit = jsonRowCap
	} else {
		limit = maxExportRows
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

	// Resolve the requested identities one lookup each. A checker pass costs
	// seconds per proxy, so the handler must not wait for it: the work runs
	// under the process context and the page sees progress via the live view.
	//
	// Resolving by lookup, not by indexing a snapshot: the snapshot built a map
	// with an entry per live proxy (two million entries, a million Key() calls)
	// to answer at most a few hundred lookups - one click that cost hundreds of
	// megabytes and seconds of CPU on the largest queue.
	var revalidated int
	var notFound []string
	picked := make([]*proxy.Proxy, 0, len(body.URLs)+len(body.Keys))
	for _, key := range append(append([]string{}, body.URLs...), body.Keys...) {
		if p := a.bucket.Get(key); p != nil {
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
		"note":        "re-checking now; dead entries are dropped, live ones stay",
	})
}

// handleProxiesDrop removes selected proxies from the live queue immediately.
// POST body: {"urls": ["scheme://host:port", ...]}.
// Unlike revalidation (which re-checks and drops only the dead), this is an
// operator override: a burned exit IP, a proxy that must not serve even
// though it validates, a poisoned entry. Resolution is one bucket lookup per
// URL (Get, not a snapshot index — same shape as the revalidate handler).
func (a *admin) handleProxiesDrop(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", "POST")
		writeError(w, http.StatusMethodNotAllowed, "use POST")
		return
	}
	var body struct {
		URLs []string `json:"urls"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<16)).Decode(&body); err != nil {
		writeError(w, http.StatusBadRequest, "bad json: "+err.Error())
		return
	}
	if len(body.URLs) == 0 {
		writeError(w, http.StatusBadRequest, "urls[] required")
		return
	}
	var dropped int
	var notFound []string
	for _, key := range body.URLs {
		p := a.bucket.Get(key)
		if p == nil {
			notFound = append(notFound, key)
			continue
		}
		if a.bucket.Remove(p) {
			dropped++
		} else {
			notFound = append(notFound, key)
		}
	}
	writeJSON(w, map[string]interface{}{
		"ok":        true,
		"dropped":   dropped,
		"not_found": notFound,
		"note":      "removed from the live queue now; the checker may re-add an address if a source still lists it",
	})
}
