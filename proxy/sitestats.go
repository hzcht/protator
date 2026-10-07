package proxy

import (
	"math/rand"
	"sort"
	"strings"
	"sync"
	"time"
)

// maxTrackedSites bounds the registry. sites.txt is operator-editable and a
// runaway list must not be able to grow this map without limit; once full, new
// URLs are still collected, just not scored.
const maxTrackedSites = 200000

// SiteStat is per-source collection telemetry for one sites.txt entry: what the
// last fetch produced, how it has been behaving, and how much of what it
// produced is still alive in the live queue.
type SiteStat struct {
	URL       string    `json:"url"`
	OK        bool      `json:"ok"`
	Fails     int       `json:"fails"`
	Found     int       `json:"found"`   // candidates extracted, last cycle
	Emitted   int       `json:"emitted"` // candidates pushed downstream, last cycle
	Alive     int       `json:"alive"`   // of its candidates, live in the queue now
	Cycles    int64     `json:"cycles"`  // fetches attempted
	Total     int64     `json:"total"`   // candidates emitted, lifetime
	Priority  int64     `json:"priority"`
	LastFetch time.Time `json:"last_fetch"`
	LastOK    time.Time `json:"last_ok"`
	CoolUntil time.Time `json:"cool_until"`
	LastNote  string    `json:"last_note"`

	// Conditional GET support: store ETag and Last-Modified from last successful fetch
	// to send If-None-Match / If-Modified-Since on next fetch (304 = no changes).
	ETag         string `json:"etag,omitempty"`
	LastModified string `json:"last_modified,omitempty"`
}

// Cooling reports whether the site is in failure cooldown.
func (s *SiteStat) Cooling(now time.Time) bool {
	return !s.CoolUntil.IsZero() && now.Before(s.CoolUntil)
}

// SiteRegistry tracks per-source statistics and the cooldown state that used to
// live in the collector's private maps. It is the single source of truth behind
// both the collector's failure cooldown and the admin page's source table.
type SiteRegistry struct {
	mu    sync.Mutex
	stats map[string]*SiteStat
	alive map[string]int // source -> live proxies in the bucket (refreshed on demand)
	rng   *rand.Rand
	cycle int64
	// Cooldown policy, copied from collector.site_max_fails / site_cooldown.
	failLimit int
	cooldown  time.Duration
}

// NewSiteRegistry returns an empty registry using the given cooldown policy.
func NewSiteRegistry(failLimit int, cooldown time.Duration) *SiteRegistry {
	if failLimit <= 0 {
		failLimit = 3
	}
	if cooldown <= 0 {
		cooldown = 30 * time.Minute
	}
	return &SiteRegistry{
		stats:     make(map[string]*SiteStat),
		alive:     make(map[string]int),
		rng:       rand.New(rand.NewSource(time.Now().UnixNano())),
		failLimit: failLimit,
		cooldown:  cooldown,
	}
}

// Track makes sure every URL of the current source list has a stat entry, so
// the admin page can show sources that have not been fetched yet.
func (r *SiteRegistry) Track(urls []string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, u := range urls {
		if strings.TrimSpace(u) == "" {
			continue
		}
		if _, ok := r.stats[u]; ok {
			continue
		}
		if len(r.stats) >= maxTrackedSites {
			return
		}
		r.stats[u] = &SiteStat{URL: u}
	}
}

// Failed reports whether the site is in failure cooldown and re-arms it once it
// expires. Returns true when the caller should use the cheap direct attempt.
func (r *SiteRegistry) Failed(url string) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	s := r.statLocked(url)
	if s.CoolUntil.IsZero() || !time.Now().Before(s.CoolUntil) {
		s.CoolUntil = time.Time{}
		return false
	}
	return true
}

// Record files the outcome of one fetch attempt and maintains the cooldown. It
// returns true when this failure armed (or re-armed) the cooldown, so the
// caller can log the transition.
func (r *SiteRegistry) Record(url string, ok bool, found, emitted int, note string) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	s := r.statLocked(url)
	now := time.Now()
	s.Cycles++
	s.Found = found
	s.Emitted = emitted
	s.Total += int64(emitted)
	s.LastFetch = now
	s.LastNote = note
	if ok {
		s.OK = true
		s.Fails = 0
		s.CoolUntil = time.Time{}
		s.LastOK = now
		return false
	}
	s.OK = false
	s.Fails++
	if s.Fails < r.failLimit {
		return false
	}
	armed := !s.CoolUntil.After(now)
	s.CoolUntil = now.Add(r.cooldown)
	return armed
}

// UpdateValidators updates the ETag and Last-Modified for a site after a successful fetch.
func (r *SiteRegistry) UpdateValidators(url, etag, lastMod string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	s := r.statLocked(url)
	if etag != "" {
		s.ETag = etag
	}
	if lastMod != "" {
		s.LastModified = lastMod
	}
}

// Site returns a copy of one source's stats (nil when unknown).
func (r *SiteRegistry) Site(url string) *SiteStat {
	r.mu.Lock()
	defer r.mu.Unlock()
	s, ok := r.stats[url]
	if !ok {
		return nil
	}
	cp := *s
	cp.Alive = r.alive[url]
	return &cp
}

// Snapshot returns a copy of every tracked site, ordered by priority.
func (r *SiteRegistry) Snapshot() []SiteStat {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]SiteStat, 0, len(r.stats))
	for _, s := range r.stats {
		cp := *s
		cp.Alive = r.alive[s.URL]
		out = append(out, cp)
	}
	r.sortLocked(out)
	return out
}

// SetAlive replaces the per-source live counts (from the bucket) and recomputes
// priorities.
func (r *SiteRegistry) SetAlive(counts map[string]int) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.alive = counts
}

// sortLocked orders sites best-first. Known-good, high-yield sources lead; sites
// that have never been fetched get a rotating jitter so each cycle explores a
// different slice of them instead of starving the same head of the alphabet.
func (r *SiteRegistry) sortLocked(out []SiteStat) {
	for i := range out {
		out[i].Priority = r.scoreLocked(&out[i])
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Priority != out[j].Priority {
			return out[i].Priority > out[j].Priority
		}
		return out[i].URL < out[j].URL
	})
}

// Priority bands. The gaps are far wider than any realistic yield score, so a
// source can never be promoted out of its band by a single lucky cycle.
const (
	bandProven     int64 = 1 << 50 // fetched successfully, may still be cooling
	bandUnproven   int64 = 1 << 40 // never fetched: explore, but after the proven
	bandFailing    int64 = 0       // fetched and failed: lowest
	priorityJitter       = 1000    // width of the rotating slice within a band
)

// scoreLocked is the fetch-order score. Sources that have proven they produce
// live proxies lead, sources nobody has tried come next, and sources that keep
// failing sink to the bottom. Within a band, live output dominates (it is the
// only number that reflects the checker's verdict), then the last yield, then
// a penalty for repeated failures.
func (r *SiteRegistry) scoreLocked(s *SiteStat) int64 {
	if s.Cycles == 0 {
		return bandUnproven + int64(r.rng.Intn(priorityJitter))
	}
	yield := int64(8)*int64(r.alive[s.URL]) + int64(s.Emitted) - 4*int64(s.Fails)
	if s.OK {
		return bandProven + yield
	}
	return bandFailing + yield
}

// unprovenScore is the deterministic-per-cycle variant used by Order, so the
// whole list is sorted against one stable jitter instead of a re-rolled one.
func unprovenScore(url string, epoch int64) int64 {
	return bandUnproven + int64((hashStr(url)+uint64(epoch)*2654435761)%priorityJitter)
}

// Order returns the current fetch order for the given source list: every URL of
// the list, best source first. URLs without a stat entry score as unproven.
func (r *SiteRegistry) Order(urls []string) []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.cycle++
	epoch := r.cycle
	out := make([]*SiteStat, 0, len(urls))
	for _, u := range urls {
		s := r.statLocked(u)
		out = append(out, s)
	}
	// The unproven jitter must not re-roll on every sort of the same cycle.
	for _, s := range out {
		if s.Cycles == 0 {
			s.Priority = unprovenScore(s.URL, epoch)
		} else {
			s.Priority = r.scoreLocked(s)
		}
	}
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].Priority != out[j].Priority {
			return out[i].Priority > out[j].Priority
		}
		return out[i].URL < out[j].URL
	})
	res := make([]string, len(out))
	for i, s := range out {
		res[i] = s.URL
	}
	return res
}

func (r *SiteRegistry) statLocked(url string) *SiteStat {
	if s, ok := r.stats[url]; ok {
		return s
	}
	if len(r.stats) >= maxTrackedSites {
		// Tracking is capped: fall back to a scratch entry that is not stored.
		return &SiteStat{URL: url}
	}
	s := &SiteStat{URL: url}
	r.stats[url] = s
	return s
}

func hashStr(s string) uint64 {
	var h uint64 = 1469598103934665603
	for i := 0; i < len(s); i++ {
		h ^= uint64(s[i])
		h *= 1099511628211
	}
	return h
}
