package proxy

import (
	"errors"
	"math/bits"
	"math/rand/v2"
	"time"
)

// pick.go holds the serving-path selection policy: how a proxy's proof of life
// is graded, and how the picker samples a queue to land on the best one.
//
// It is separate from bucket.go (the data structure) because the two change
// for different reasons and at different rates: the queue's job is membership,
// ordering and notifications, while everything here is a policy decision that
// exists to keep the serving path away from the dead bulk of a heavily polluted
// pool.

// Proof tiers, deliberately ordered:
//  1. serving proof (lastOK): MarkServeOK stamps a proxy after it actually
//     delivered a genuine response. Real traffic is self-reinforcing — proxies
//     that work get picked, serve bytes, stay in the green tier; the 99% that
//     merely "valided once" cannot keep up. This is what separates the live
//     tail of a heavily-polluted pool from the rest.
//  2. validation proof (lastCheck): freshly full-checked proxies are warm, one
//     step above everything stale, so new finds get a chance to prove
//     themselves by serving (and thus promote themselves to green).
const (
	freshGreen = int64(2) // served real traffic within the serve window
	freshWarm  = int64(1) // validated within the fresh window
	freshStale = int64(0) // older, or never proven (boot seeds)
)

// Defaults for the two proof windows. They live on the Bucket (not as constants)
// because they must be tunable: see SetFreshnessWindows.
const (
	defaultPickServeWindow = 90 * time.Second
	// The fresh window has to outlast the revalidation interval, otherwise the
	// warm tier empties between two revalidation passes and the picker has
	// nothing better to offer than the unproven bulk. That mistake is silent:
	// the pool looks full and every pick lands on a proxy nobody ever checked.
	defaultPickFreshWindow = 20 * time.Minute

	// freshRebuildInterval bounds how stale the proven-pool cache may be. The
	// rebuild is an O(queue) scan, so it is amortized: a queue of 20k costs a
	// few hundred microseconds, twice a second, instead of once per pick. The
	// cache itself lives on the Bucket (bucket.go); the interval is policy, so
	// it is here.
	freshRebuildInterval = 2 * time.Second
)

// SetFreshnessWindows configures how recent a proof of life must be for an
// entry to count as proven. freshWindow must outlast the revalidation interval:
// the picker prefers proven entries, so a window shorter than the gap between
// two revalidation passes leaves it with nothing but unproven seeds to serve
// from, which is worse than having no preference at all.
func (b *Bucket) SetFreshnessWindows(serve, fresh time.Duration) {
	if serve <= 0 {
		serve = defaultPickServeWindow
	}
	if fresh <= 0 {
		fresh = defaultPickFreshWindow
	}
	b.mu.Lock()
	b.serveWindow, b.freshWindow = serve, fresh
	b.mu.Unlock()
}

// freshnessRank grades one entry's proof of life at time now (unix nanos).
func (b *Bucket) freshnessRank(now int64, p *Proxy) int64 {
	serve, fresh := b.serveWindow, b.freshWindow
	if serve <= 0 {
		serve = defaultPickServeWindow
	}
	if fresh <= 0 {
		fresh = defaultPickFreshWindow
	}
	if lo := p.lastOKNanos(); lo != 0 && now-lo <= int64(serve) {
		return freshGreen
	}
	if lc := p.lastCheckNanos(); lc != 0 && now-lc <= int64(fresh) {
		return freshWarm
	}
	return freshStale
}

// SetRequireProven switches the picker to fail-closed mode: when no entry
// carries proof of life inside the pick windows, PickHealthy returns
// ErrNoProven instead of falling back to the unverified bulk of the queue.
// Off by default; an operator who would rather see a failed request than a
// request served through an unvalidated proxy turns it on.
func (b *Bucket) SetRequireProven(on bool) {
	b.mu.Lock()
	b.requireProven = on
	b.mu.Unlock()
}

// ErrNoProven is the fail-closed verdict: the queue is non-empty, but nothing
// in it carries proof of life inside the pick windows, and requireProven is
// on. Callers fail the request (the HTTP front turns this into a 502) instead
// of serving it through an entry nobody ever checked.
var ErrNoProven = errors.New("no proven proxy in the queue")

// pickProvenLocked serves only from entries with proof of life inside the
// windows: the fresh slice of the hot tail first, then the proven pool. It
// never samples the unverified bulk — that is the whole point of the flag.
// The proven pool itself is taken as evidence (it was fresh at most
// freshRebuildInterval ago, and betterPick still ranks by actual freshness),
// while the hot tail is filtered strictly: without that, sampling could miss
// its few fresh entries and return a stale one. Callers hold at least a read
// lock.
func (b *Bucket) pickProvenLocked(proven []*Proxy, probes int, skip map[string]struct{}, now int64) (*Proxy, error) {
	if fresh := b.freshHotLocked(now); len(fresh) > 0 {
		if best := b.rankPick(fresh, probes, skip, now, false); best != nil {
			return best, nil
		}
	}
	// verified: proven is a cached snapshot, not the live queue, so every
	// sample still has to be checked against the index (see rankPick).
	if best := b.rankPick(proven, probes, skip, now, true); best != nil {
		return best, nil
	}
	return nil, ErrNoProven
}

// IsProven reports whether p carries proof of life inside the pick windows
// right now. Used by the fail-closed path to validate a pinned proxy before
// serving through it: stickiness is a routing preference, not proof of life,
// and a pin outlives the proof that created it.
func (b *Bucket) IsProven(p *Proxy) bool {
	if p == nil {
		return false
	}
	b.mu.RLock()
	defer b.mu.RUnlock()
	return b.freshnessRank(nowNanos(), p) != freshStale
}

// hotHasFreshLocked reports whether the curated tail holds at least one entry
// whose proof of life is still inside the pick windows. Callers hold at least
// a read lock.
//
// Membership alone says nothing: entries are promoted once and age in place
// (revalidation deliberately does NOT re-promote), so after any lull the tail
// can be full of entries no fresher than boot seeds. Picking the tier by
// non-emptiness then serves exclusively from a dead tail while thousands of
// freshly verified entries sit in the proven pool, ignored — and /ready keeps
// answering 200 for a queue where every dial fails. The scan is O(hotMax) and
// usually exits on the first entry: index 0 is the most recently proven.
func (b *Bucket) hotHasFreshLocked(now int64) bool {
	for _, p := range b.hot {
		if b.freshnessRank(now, p) != freshStale {
			return true
		}
	}
	return false
}

// freshHotLocked returns the hot-tail entries whose proof of life is still
// inside the pick windows, or nil. Callers hold at least a read lock.
//
// This is the strict version of hotHasFreshLocked, for the fail-closed path:
// returning the tier is not enough there, because rejection sampling can miss
// its few fresh entries and hand back a stale one — serving through an entry
// with no live proof, which is exactly what the flag forbids.
func (b *Bucket) freshHotLocked(now int64) []*Proxy {
	var out []*Proxy
	for _, p := range b.hot {
		if b.freshnessRank(now, p) != freshStale {
			out = append(out, p)
		}
	}
	return out
}

// rankPick samples pool up to probes times and returns the best entry by
// (proof freshness, consecutive failures, latency, in-flight load), or nil if
// every sample was in skip or no longer in the queue. Callers hold at least a
// read lock.
//
// verifyLive says whether a sample must be re-checked against b.index. That
// lookup is not cheap: it hashes the proxy's whole URL string, once per probe
// (profiled at 50% of PickHealthy at 70k entries), so it is only worth paying
// for a pool that can be stale. The live slices (b.proxies, b.hot) are mutated
// exclusively under the write lock, so while this read lock is held every one
// of their elements IS in the index — pass false for them. A cached snapshot
// that may lag freshRebuildInterval behind (freshPool's proven cache) can
// still hold an entry removed since; it must never win a pick, because
// dropping the sample costs one wasted attempt and serving it costs a failed
// dial — pass true there.
func (b *Bucket) rankPick(pool []*Proxy, probes int, skip map[string]struct{}, nowNanos int64, verifyLive bool) *Proxy {
	n := len(pool)
	if n == 0 {
		return nil
	}
	// Rejection sampling must reach the better entries of a large pool, which
	// shrink as a share of it: scale probes with log2(size). The 1.5%-proven
	// case this exists for needs ~200 samples for a 95% hit rate, so the cap
	// has to be well above the old 64.
	if scaled := 8*(bits.Len(uint(n))-1) + 1; scaled > probes {
		if scaled > 256 {
			scaled = 256
		}
		probes = scaled
	}
	var best *Proxy
	var bestFresh, bestFails, bestLat, bestLoad int64
	for i := 0; i < probes; i++ {
		p := pool[rand.IntN(n)]
		// Both guards are folded behind their own precondition: an empty skip
		// map is the common case (the first pick of a request has no failover
		// history yet), and hashing p.Key() for a lookup that cannot reject
		// anything was costing a Key() call per probe on its own.
		if verifyLive || len(skip) > 0 {
			key := p.Key()
			if verifyLive {
				if _, live := b.index[key]; !live {
					continue
				}
			}
			if _, bad := skip[key]; bad {
				continue
			}
		}
		f := p.ConsecFails()
		l := p.latencyEMAValue()
		load := p.InFlight()
		fresh := b.freshnessRank(nowNanos, p)
		if best == nil || betterPick(fresh, f, l, load, bestFresh, bestFails, bestLat, bestLoad) {
			best, bestFresh, bestFails, bestLat, bestLoad = p, fresh, f, l, load
			if fresh == freshGreen && f == 0 && l == 0 && load == 0 {
				break // unmeasured, freshly proven proxy: good enough
			}
		}
	}
	return best
}

// betterPick orders two candidates for the serving path. Lower is better at
// every step: newer proof first, then fewer consecutive failures, then lower
// latency, then fewer open tunnels.
//
// Latency needs care: 0 means "never measured", not "infinitely fast", so an
// unmeasured entry must lose to any measured one. Comparing the raw values
// with a plain `<` gets that backwards for the very first candidate, which is
// how an unproven entry with no samples at all could win a whole pick.
func betterPick(fresh, fails, lat, load, bestFresh, bestFails, bestLat, bestLoad int64) bool {
	if fresh != bestFresh {
		return fresh > bestFresh
	}
	if fails != bestFails {
		return fails < bestFails
	}
	switch {
	case lat == 0 && bestLat == 0:
		// both unmeasured: nothing to compare but load
	case lat == 0:
		return false // challenger unmeasured, incumbent measured
	case bestLat == 0:
		return true // challenger measured, incumbent unmeasured
	case lat != bestLat:
		return lat < bestLat
	}
	return load < bestLoad
}

func nowNanos() int64 { return time.Now().UnixNano() }
