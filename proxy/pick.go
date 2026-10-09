package proxy

import (
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

// rankPick samples pool up to probes times and returns the best entry by
// (proof freshness, consecutive failures, latency, in-flight load), or nil if
// every sample was in skip or no longer in the queue. Callers hold at least a
// read lock.
func (b *Bucket) rankPick(pool []*Proxy, probes int, skip map[string]struct{}, nowNanos int64) *Proxy {
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
		// The proven pool and the hot tail are snapshots: freshPool may lag up
		// to freshRebuildInterval behind, so a removed proxy can still sit in
		// `pool` here. It must never win a pick — dropping it costs one wasted
		// sample, serving it costs a failed dial.
		key := p.Key()
		if _, live := b.index[key]; !live {
			continue
		}
		if _, bad := skip[key]; bad {
			continue
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
