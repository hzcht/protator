package main

import (
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
// click. The text download is left uncapped on purpose: exporting the list is
// the one thing an operator asks for a lot of rows.
const jsonRowCap = 1000

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
func (a *admin) liveDelta() []liveRow {
	if a.bucket == nil {
		return nil
	}
	proxies := a.bucket.LiveListUnranked(proxy.AliveChecked, liveWindow)
	now := time.Now()
	out := make([]liveRow, 0, len(proxies))
	for _, p := range proxies {
		out = append(out, newLiveRow(p, now))
	}
	return out
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

// csvHeader is the CSV column order. Keeping it next to the row struct is what
// keeps the two from drifting: the header and the writer read the same fields.
const csvHeader = "url,schema,host,port,source,country,asn,latency_ms,ok_total,fail_total,consec_fails,proof_age_s,served,checked,in_flight\n"

// exportCSV renders rows as CSV.
func exportCSV(rows []liveRow) []byte {
	var b strings.Builder
	b.WriteString(csvHeader)
	for _, row := range rows {
		b.WriteString(row.URL)
		b.WriteByte(',')
		b.WriteString(row.Schema)
		b.WriteByte(',')
		b.WriteString(row.Host)
		b.WriteByte(',')
		b.WriteString(strconv.Itoa(row.Port))
		b.WriteByte(',')
		b.WriteString(row.Source)
		b.WriteByte(',')
		b.WriteString(row.Country)
		b.WriteByte(',')
		b.WriteString(row.ASN)
		b.WriteByte(',')
		b.WriteString(strconv.FormatInt(row.Latency, 10))
		b.WriteByte(',')
		b.WriteString(strconv.FormatInt(row.OK, 10))
		b.WriteByte(',')
		b.WriteString(strconv.FormatInt(row.Fails, 10))
		b.WriteByte(',')
		b.WriteString(strconv.FormatInt(row.Consec, 10))
		b.WriteByte(',')
		b.WriteString(strconv.FormatFloat(row.Age, 'f', 3, 64))
		b.WriteByte(',')
		b.WriteString(strconv.FormatBool(row.Served))
		b.WriteByte(',')
		b.WriteString(strconv.FormatBool(row.Checked))
		b.WriteByte(',')
		b.WriteString(strconv.FormatInt(row.InFlight, 10))
		b.WriteByte('\n')
	}
	return []byte(b.String())
}
