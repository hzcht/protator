package main

import (
	"encoding/csv"
	"strconv"
	"strings"
	"time"

	"protator/proxy"
)

// liveWindow is how recent a proof of life must be for a proxy to be listed as
// alive. It is deliberately short: the point of the page is "right now", not
// "once worked".
const liveWindow = 15 * time.Minute

// filterScanFactor / filterScanMax bound the over-fetch a country or ASN filter
// needs: rows are dropped after the ranked scan, so the scan has to look at more
// than the caller asked for or a filtered page comes back short.
const filterScanFactor = 100
const filterScanMax = 200_000

// jsonRowCap bounds a single JSON response. The queue can hold two million
// entries and the page only ever shows the first pageful, so an unbounded
// "scope=all" would build a multi-hundred-megabyte response out of a stray
// click.
const jsonRowCap = 1000

// maxExportRows bounds the text/csv/jsonl downloads and any explicit limit.
// Exporting the list is the one thing an operator asks for a lot of rows, so
// the downloads are allowed two orders of magnitude more than a page — but not
// infinity: an uncapped scope=all on a multi-million queue materializes the
// whole ranked set, and a scripted loop against it is a self-DoS behind the
// token. limit=0 still means "everything up to this".
const maxExportRows = 100_000

// liveRow is one entry of the "really alive" proxy table. It is the single
// rendering of a proxy for every admin surface — the HTTP list, the CSV/JSONL
// exports and the WebSocket delta — so a field added here shows up everywhere.
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

// newLiveRow renders one proxy. Callers hold no lock: every field is read
// through its atomic accessor, so this is safe to run while the checker and
// the serving path mutate the same proxy.
func newLiveRow(p *proxy.Proxy, now time.Time) liveRow {
	served, checked := p.LastServed(), p.LastCheck()
	age := now.Sub(served)
	if served.IsZero() || (!checked.IsZero() && checked.After(served)) {
		age = now.Sub(checked)
	}
	return liveRow{
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
	}
}

// live renders the page of proxy rows plus the size of the scope itself, so the
// UI can say "1000 of 41234" instead of implying the page is the whole truth.
// Returns (filteredRows, unfilteredTotal).
//
// limit is handed to LiveListPage (limit <= 0 means "everything"). That is the
// difference between ranking a bounded page and ranking the whole queue to then
// throw most of it away. With a country/ASN filter the drop happens after the
// scan, so the scan is over-fetched by filterScanFactor — the only way a
// filtered request can fill the page at all.
func (a *admin) live(scope string, limit int, countryFilter, asnFilter string) ([]liveRow, int) {
	if a.bucket == nil {
		return nil, 0
	}
	scan := limit
	if (countryFilter != "" || asnFilter != "") && scan > 0 {
		scan *= filterScanFactor
		if scan > filterScanMax {
			scan = filterScanMax
		}
	}
	proxies, unfilteredTotal := a.bucket.LiveListPage(scope, liveWindow, scan)
	now := time.Now()
	out := make([]liveRow, 0, len(proxies))
	for _, p := range proxies {
		if countryFilter != "" && !strings.EqualFold(p.GetCountry(), countryFilter) {
			continue
		}
		if asnFilter != "" && !strings.Contains(strings.ToLower(p.GetASN()), strings.ToLower(asnFilter)) {
			continue
		}
		out = append(out, newLiveRow(p, now))
	}
	if limit > 0 && len(out) > limit {
		out = out[:limit]
	}
	return out, unfilteredTotal
}

// liveDelta renders the full set the WebSocket diff needs, without ranking it.
// The diff is a membership test: it ran once per second over a ranked scan of
// the whole queue, which for a two million entry queue is most of a second of
// CPU per broadcast. The unranked scan is the same set at a fraction of the
// cost.
//
// The result is capped at jsonRowCap: every proxy checked inside the window
// used to go out whole in the initial state and every broadcast (~100k rows
// is ~20-30 MB of JSON per tick, per client). The page only renders the first
// pageful, so the rows past the cap are simply not shown; truncated tells it
// (and the operator) that the view is partial rather than silently short.
func (a *admin) liveDelta() (rows []liveRow, truncated bool) {
	if a.bucket == nil {
		return nil, false
	}
	proxies := a.bucket.LiveListUnranked(proxy.AliveChecked, liveWindow)
	now := time.Now()
	out := make([]liveRow, 0, len(proxies))
	for _, p := range proxies {
		if len(out) >= jsonRowCap {
			truncated = true
			break
		}
		out = append(out, newLiveRow(p, now))
	}
	return out, truncated
}

// exportText renders rows as one proxy URL per line: paste straight into curl,
// a config file, or another tool.
func exportText(rows []liveRow) []byte {
	var b strings.Builder
	for _, row := range rows {
		b.WriteString(row.URL)
		b.WriteByte('\n')
	}
	return []byte(b.String())
}

// exportCSV renders rows as CSV through encoding/csv: a source URL with a
// comma in it (many list URLs carry query strings) used to shift every
// following column when fields were concatenated raw. The column order lives
// with the writer; the old csvHeader const drifted from the row struct.
func exportCSV(rows []liveRow) []byte {
	var b strings.Builder
	w := csv.NewWriter(&b)
	w.Write([]string{"url", "schema", "host", "port", "source", "country", "asn",
		"latency_ms", "ok_total", "fail_total", "consec_fails", "proof_age_s",
		"served", "checked", "in_flight"})
	for _, row := range rows {
		w.Write([]string{
			row.URL,
			row.Schema,
			row.Host,
			strconv.Itoa(row.Port),
			row.Source,
			row.Country,
			row.ASN,
			strconv.FormatInt(row.Latency, 10),
			strconv.FormatInt(row.OK, 10),
			strconv.FormatInt(row.Fails, 10),
			strconv.FormatInt(row.Consec, 10),
			strconv.FormatFloat(row.Age, 'f', 3, 64),
			strconv.FormatBool(row.Served),
			strconv.FormatBool(row.Checked),
			strconv.FormatInt(row.InFlight, 10),
		})
	}
	w.Flush()
	return []byte(b.String())
}
