package proxy

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
	"time"
)

// provenidx.go is the restart memory of the warm tier.
//
// proxy.lst carries URLs only: SaveBucketAtomic renders exactly p.URLLen()
// bytes per entry and AppendGood writes p.URL(), so a restart used to produce a
// queue where nothing carried proof of life. /ready (ProvenCount) reported
// zero, the picker fell back to the unverified bulk, and the pool only
// recovered as fast as the revalidation loop could churn — the longest, least
// predictable outage the process could have. This sidecar stores the proof per
// entry, keyed by the same Key() the bucket indexes on (URL plus credentials),
// so it survives queue rewrites and hand edits of proxy.lst.
//
// It is deliberately a cache, never a source of truth: an unreadable, empty or
// stale index costs a slow start, nothing else. No code path may turn a read
// failure here into a fatal error.

const (
	provenHeader = "#protator proven index v1"
	// provenFieldCount is key, last_check_ns, last_ok_ns, latency_ns, source,
	// country, asn.
	provenFieldCount = 7
)

// provenRecord is one persisted proof of life.
type provenRecord struct {
	Key       string
	LastCheck int64 // unix nanos of the last successful validation
	LastOK    int64 // unix nanos of the last successful serving dial
	Latency   int64 // dial/check latency EMA in ns
	Source    string
	Country   string
	ASN       string
}

// SaveProvenIndex writes every entry whose last validation is younger than
// maxAge. Older proofs cannot pass freshnessRank anyway, so they are left out
// of the file instead of being carried around forever.
func SaveProvenIndex(path string, proxies []*Proxy, now time.Time, maxAge time.Duration) error {
	if path == "" {
		return nil
	}
	if maxAge <= 0 {
		maxAge = defaultPickFreshWindow
	}
	nowNs := now.UnixNano()
	return writeFileAtomicTo(path, tmpPatternProven, func(w io.Writer) error {
		bw := bufio.NewWriterSize(w, 64<<10)
		if _, err := bw.WriteString(provenHeader + "\n"); err != nil {
			return err
		}
		for _, p := range proxies {
			lc := p.lastCheckNanos()
			if lc == 0 || nowNs-lc > int64(maxAge) {
				continue
			}
			var country, asn string
			if p.meta != nil {
				country, asn = p.meta.Country(), p.meta.ASN()
			}
			line := strings.Join([]string{
				p.Key(),
				strconv.FormatInt(lc, 10),
				strconv.FormatInt(p.lastOKNanos(), 10),
				strconv.FormatInt(p.latencyEMAValue(), 10),
				p.Source(),
				country,
				asn,
			}, "\t")
			if _, err := bw.WriteString(line + "\n"); err != nil {
				return err
			}
		}
		return bw.Flush()
	})
}

// LoadProvenIndex reads the index into a key -> record map. A missing file is
// not an error (first run, or an operator deleted it): it means "nothing to
// restore". Malformed lines are skipped and counted, never fatal — a truncated
// tail from a hard kill must not cost the whole warm tier.
func LoadProvenIndex(path string) (map[string]provenRecord, int, error) {
	if path == "" {
		return nil, 0, nil
	}
	f, err := os.Open(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, 0, nil
		}
		return nil, 0, err
	}
	defer f.Close()

	out := make(map[string]provenRecord)
	bad := 0
	sc := bufio.NewScanner(f)
	// A key is a URL plus credentials; the rest is numbers and two short
	// codes. 64 KB per line is generous, and the buffer must not be the
	// thing that silently truncates a valid entry.
	sc.Buffer(make([]byte, 0, 64<<10), 1<<20)
	for sc.Scan() {
		line := sc.Text()
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		parts := strings.Split(line, "\t")
		if len(parts) != provenFieldCount || parts[0] == "" {
			bad++
			continue
		}
		lc, err1 := strconv.ParseInt(parts[1], 10, 64)
		lo, err2 := strconv.ParseInt(parts[2], 10, 64)
		lat, err3 := strconv.ParseInt(parts[3], 10, 64)
		if err1 != nil || err2 != nil || err3 != nil || lc == 0 {
			bad++
			continue
		}
		out[parts[0]] = provenRecord{
			Key: parts[0], LastCheck: lc, LastOK: lo, Latency: lat,
			Source: parts[4], Country: parts[5], ASN: parts[6],
		}
	}
	if err := sc.Err(); err != nil {
		return out, bad, fmt.Errorf("reading %s: %w", path, err)
	}
	return out, bad, nil
}

// ApplyProvenIndex re-applies the restored proofs to the freshly seeded queue.
// Entries absent from the queue (removed since the save, or a hand-edited
// proxy.lst) are ignored.
//
// Records older than the freshness window are still applied — but only up to
// twice that age. They cannot make the pool look healthy: proven-ness is
// graded from the stamp by freshnessRank, so an old stamp reads as unproven by
// definition. What the old stamp does buy is ordering and attribution:
// RevalidateMany sorts the pass oldest-first, so these entries are re-checked
// in the first pass after a restart instead of queueing behind fifty thousand
// entries with no stamp at all, and their source/country/latency survive the
// restart. Beyond twice the window the record is evidence of nothing and is
// discarded.
//
// It returns how many entries were warmed as proven, how many were applied
// but left unproven (aging), and how many records were too old to use.
func ApplyProvenIndex(b *Bucket, idx map[string]provenRecord, now time.Time, freshWindow time.Duration) (restored, aging, discarded int) {
	if len(idx) == 0 || b == nil {
		return 0, 0, 0
	}
	if freshWindow <= 0 {
		freshWindow = defaultPickFreshWindow
	}
	nowNs := now.UnixNano()
	agingLimit := int64(2 * freshWindow)
	for _, p := range b.Snapshot() {
		rec, ok := idx[p.Key()]
		if !ok {
			continue
		}
		age := nowNs - rec.LastCheck
		if age > agingLimit {
			discarded++
			continue
		}
		p.RestoreProof(rec.LastCheck, rec.LastOK, rec.Latency)
		if rec.Source != "" {
			p.SetSource(rec.Source)
		}
		if rec.Country != "" || rec.ASN != "" {
			p.SetGeoIP(rec.Country, rec.ASN)
		}
		if age > int64(freshWindow) {
			aging++
			continue
		}
		restored++
	}
	return restored, aging, discarded
}
