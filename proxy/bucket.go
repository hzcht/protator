package proxy

import (
	"context"
	"math/bits"
	"math/rand"
	"sort"
	"sync"
	"time"
)

// Freshness tiers for the picker. A proxy proven alive recently is strongly
// preferred over one that merely "never failed": left unchecked, a
// stale-but-silent queue looks identical to a freshly-warmed one and the
// pool's working tail gets no more requests than the dead bulk.
//
// Two proof kinds, deliberately ordered:
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
	// few hundred microseconds, twice a second, instead of once per pick.
	freshRebuildInterval = 2 * time.Second
)

// Bucket is a concurrency-safe queue of live upstream proxies. All methods are
// goroutine safe: it may be mutated by collection workers while the forwarding
// servers pick proxies from it.
type Bucket struct {
	mu      sync.RWMutex
	proxies []*Proxy
	index   map[string]int // key -> position in proxies
	// bySource counts live entries per discovery site (sites.txt URL). It is
	// what makes "how much of what this source produced is still alive"
	// answerable without walking the whole queue on every admin request.
	bySource map[string]int
	// hot is the curated tail of the pool: proxies with recent proof of life
	// (just validated, just revalidated, just served real traffic). It is
	// bounded and always much smaller than the main queue (which is dominated
	// by long-dead entries in a pooled list), so PickHealthy can concentrate
	// serving capacity on the handful that demonstrably work. Members only
	// leave through eviction or when the proxy is removed from the bucket.
	hot    []*Proxy
	hotIdx map[*Proxy]int
	rng    *rand.Rand
	max    int
	signal chan struct{} // edge-triggered wakeup when queue becomes non-empty
	dirty  bool          // true when queue changed since last save

	// fresh caches the entries that carry proof of life, so PickHealthy can
	// aim at the working tail instead of rejection-sampling a queue whose
	// living fraction is a fraction of a percent. Guarded by its own mutex:
	// never hold it while taking mu (see freshPool).
	freshMu sync.Mutex
	fresh   []*Proxy
	freshAt time.Time

	// Proof-of-life windows used by freshnessRank. Set once at startup from
	// the config; see SetFreshnessWindows.
	serveWindow time.Duration
	freshWindow time.Duration

	// OnChange, if set, is invoked after every successful add/remove.
	OnChange func(p *Proxy, added bool)
}

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

// freshPool returns the proven entries, rebuilding the cache at most once per
// freshRebuildInterval. The snapshot is allowed to lag reality by that much: an
// entry that was removed underneath it costs one failed dial and a retry, and
// invalidating on every add would turn each pick into an O(queue) scan.
func (b *Bucket) freshPool(now time.Time) []*Proxy {
	b.freshMu.Lock()
	if !b.freshAt.IsZero() && now.Sub(b.freshAt) < freshRebuildInterval {
		out := b.fresh
		b.freshMu.Unlock()
		return out
	}
	b.freshMu.Unlock()

	b.mu.RLock()
	// Reuse the existing slice to avoid allocation on every rebuild.
	if b.fresh == nil {
		b.fresh = make([]*Proxy, 0, 256)
	} else {
		b.fresh = b.fresh[:0]
	}
	nowNanos := now.UnixNano()
	for _, p := range b.proxies {
		if b.freshnessRank(nowNanos, p) != freshStale {
			b.fresh = append(b.fresh, p)
		}
	}
	b.mu.RUnlock()

	b.freshMu.Lock()
	b.freshAt = now
	b.freshMu.Unlock()
	return b.fresh
}

// hotMax caps the curated proving tail. A few hundred recently-proven proxies
// is plenty of diversity for serving; anything larger dilutes back toward the
// dead bulk.
const hotMax = 512

// NewBucket creates an empty bucket bounded at max entries.
func NewBucket(max int) *Bucket {
	if max <= 0 {
		max = 2000000
	}
	return &Bucket{
		index:       make(map[string]int, 1024),
		bySource:    make(map[string]int, 64),
		hotIdx:      make(map[*Proxy]int, 1024),
		rng:         rand.New(rand.NewSource(time.Now().UnixNano())),
		max:         max,
		signal:      make(chan struct{}, 1),
		serveWindow: defaultPickServeWindow,
		freshWindow: defaultPickFreshWindow,
	}
}

// Seed inserts pre-validated proxies (e.g. loaded from disk) without rechecking.
func (b *Bucket) Seed(proxies []*Proxy) int {
	b.mu.Lock()
	var evicted []*Proxy
	added := 0
	for _, p := range proxies {
		ok, ev := b.addLocked(p)
		if ok {
			added++
		}
		if ev != nil {
			evicted = append(evicted, ev)
		}
	}
	b.mu.Unlock()
	b.poke()
	for _, ev := range evicted {
		b.notify(ev, false)
	}
	return added
}

// Add inserts a proxy if it is not already present. Returns true if inserted.
func (b *Bucket) Add(p *Proxy) bool {
	b.mu.Lock()
	added, evicted := b.addLocked(p)
	b.mu.Unlock()
	if added {
		b.notify(p, true)
		if evicted != nil {
			b.notify(evicted, false)
		}
		b.poke()
	}
	return added
}

func (b *Bucket) notify(p *Proxy, added bool) {
	if b.OnChange != nil {
		b.OnChange(p, added)
	}
}

func (b *Bucket) addLocked(p *Proxy) (added bool, evicted *Proxy) {
	if p == nil || p.Port < 1 || p.Port > 65535 {
		return false, nil
	}
	key := p.Key()
	if idx, ok := b.index[key]; ok {
		// Dedup hit: the caller just re-validated an existing member. Refresh
		// its validation stamp so it holds the warm tier, but do NOT promote
		// it into the hot tail: bulk revalidation of a huge queue must not
		// flood the curated tail with merely-"validated once" proxies — hot
		// stays reserved for genuine serving proof (MarkServeOK on a real
		// response) and for newly discovered candidates, which earned their
		// shot the moment they entered the queue.
		if lc := p.lastCheckNanos(); lc != 0 {
			b.proxies[idx].stampCheck(lc)
		}
		return false, nil
	}
	if len(b.proxies) >= b.max {
		// drop an arbitrary (oldest-ish) entry to make room
		evicted = b.proxies[0]
		delete(b.index, evicted.Key())
		b.demoteLocked(evicted)
		b.countSourceLocked(evicted, -1)
		b.proxies[0] = p
		b.index[key] = 0
	} else {
		b.index[key] = len(b.proxies)
		b.proxies = append(b.proxies, p)
	}
	b.countSourceLocked(p, 1)
	// A freshly validated candidate (lastCheck just stamped by the checker)
	// is the strongest possible new proof of life: put it in the serving tail.
	if b.freshnessRank(time.Now().UnixNano(), p) != freshStale {
		b.promoteLocked(p)
	}
	return true, evicted
}

// Promote marks p as recently proven (served a genuine response, passed a
// revalidation, or was just validated), so pickers concentrate capacity on the
// working tail of the pool instead of the dead bulk. Cheap and lock-free to
// call from the serving path; a no-op for entries already out of the bucket.
func (b *Bucket) Promote(p *Proxy) {
	if p == nil {
		return
	}
	b.mu.Lock()
	b.promoteLocked(p)
	b.mu.Unlock()
}

// promoteLocked moves p to the front of the hot tail (or adds it) if it is
// still in the bucket. Callers hold mu.
func (b *Bucket) promoteLocked(p *Proxy) {
	if _, inMain := b.index[p.Key()]; !inMain {
		return
	}
	if idx, ok := b.hotIdx[p]; ok {
		if idx == 0 {
			return
		}
		// Move p to front: shift elements [0:idx] right by 1, then set [0]=p.
		// Only update indices for the affected range, not the entire map.
		copy(b.hot[1:idx+1], b.hot[0:idx])
		b.hot[0] = p
		for i := 0; i <= idx; i++ {
			b.hotIdx[b.hot[i]] = i
		}
		return
	}
	if len(b.hot) >= hotMax {
		tail := b.hot[len(b.hot)-1]
		delete(b.hotIdx, tail)
		b.hot = b.hot[:len(b.hot)-1]
	}
	// New entry: prepend to hot tail.
	b.hot = append([]*Proxy{p}, b.hot...)
	b.hotIdx[p] = 0
	for i := 1; i < len(b.hot); i++ {
		b.hotIdx[b.hot[i]] = i
	}
}

func (b *Bucket) demoteLocked(p *Proxy) {
	idx, ok := b.hotIdx[p]
	if !ok {
		return
	}
	delete(b.hotIdx, p)
	b.hot = append(b.hot[:idx], b.hot[idx+1:]...)
	for i := idx; i < len(b.hot); i++ {
		b.hotIdx[b.hot[i]] = i
	}
}

// Remove deletes a proxy from the queue. Returns true if it was present.
func (b *Bucket) Remove(p *Proxy) bool {
	b.mu.Lock()
	if b.removeLocked(p) {
		b.mu.Unlock()
		b.notify(p, false)
		return true
	}
	b.mu.Unlock()
	return false
}

func (b *Bucket) removeLocked(p *Proxy) bool {
	key := p.Key()
	i, ok := b.index[key]
	if !ok {
		return false
	}
	last := len(b.proxies) - 1
	if i != last {
		b.proxies[i] = b.proxies[last]
		b.index[b.proxies[i].Key()] = i
	}
	b.proxies = b.proxies[:last]
	delete(b.index, key)
	b.countSourceLocked(p, -1)
	b.demoteLocked(p)
	return true
}

// countSourceLocked adjusts the per-source live counter. Unattributed proxies
// (loaded from disk, re-probed from a legacy pool line without a source,
// added by hand) are skipped: with no site to credit, counting them would only
// feed a phantom row in the source table.
func (b *Bucket) countSourceLocked(p *Proxy, delta int) {
	if p == nil {
		return
	}
	src := p.source
	if src == "" {
		return
	}
	if n := b.bySource[src] + delta; n > 0 {
		b.bySource[src] = n
	} else {
		delete(b.bySource, src)
	}
}

// SourceCounts returns how many live proxies each discovery source owns.
func (b *Bucket) SourceCounts() map[string]int {
	b.mu.RLock()
	defer b.mu.RUnlock()
	out := make(map[string]int, len(b.bySource))
	for k, v := range b.bySource {
		out[k] = v
	}
	return out
}

// Len returns the number of live proxies.
func (b *Bucket) Len() int {
	b.mu.RLock()
	defer b.mu.RUnlock()
	return len(b.proxies)
}

// IsDirty reports whether the queue has changed since the last save.
func (b *Bucket) IsDirty() bool {
	b.mu.RLock()
	defer b.mu.RUnlock()
	return b.dirty
}

// MarkClean clears the dirty flag after a successful save.
func (b *Bucket) MarkClean() {
	b.mu.Lock()
	b.dirty = false
	b.mu.Unlock()
}

// markDirty sets the dirty flag when the queue is mutated.
func (b *Bucket) markDirty() {
	b.dirty = true
}

// HotLen returns the number of entries in the curated proving tail.
func (b *Bucket) HotLen() int {
	b.mu.RLock()
	defer b.mu.RUnlock()
	return len(b.hot)
}

// Random returns a uniformly random live proxy, waiting if the queue is empty.
func (b *Bucket) Random(ctx context.Context) (*Proxy, error) {
	for {
		b.mu.RLock()
		n := len(b.proxies)
		if n > 0 {
			p := b.proxies[b.rng.Intn(n)]
			b.mu.RUnlock()
			return p, nil
		}
		b.mu.RUnlock()

		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-b.signal:
		case <-time.After(500 * time.Millisecond): // safety poll
		}
	}
}

// PickHealthy returns a live proxy biased toward healthy, fast, lightly
// loaded and recently-proven entries, waiting if the queue is empty. It probes
// up to `probes` uniform picks (scaled with population size so the tiny
// proven tail of a huge queue is still reachable) and returns the one with the
// lowest (staleness, consecFails, latency, inFlight) penalty, skipping keys in
// `skip` (used to avoid re-picking within one failover sequence).
//
// The sampling source is chosen by strength of evidence: the curated hot tail
// first, then the proven pool, then the raw queue. Falling back to the raw queue
// while proven entries exist is the failure mode this avoids — in a queue that
// is mostly boot seeds, uniform sampling lands on an unvalidated proxy almost
// every time, and no amount of rejection sampling fixes a 1% minority. Never
// fails while the bucket is non-empty: in the worst case the least-bad proxy
// is returned.
func (b *Bucket) PickHealthy(ctx context.Context, probes int, skip map[string]struct{}) (*Proxy, error) {
	if probes < 1 {
		probes = 1
	}
	for {
		b.mu.RLock()
		source := b.proxies
		switch {
		case len(b.hot) > 0:
			source = b.hot
		default:
			if proven := b.freshPool(time.Now()); len(proven) > 0 {
				source = proven
			}
		}
		n := len(source)
		if n == 0 {
			b.mu.RUnlock()
			select {
			case <-ctx.Done():
				return nil, ctx.Err()
			case <-b.signal:
				continue
			case <-time.After(500 * time.Millisecond): // safety poll
				continue
			}
		}
		// Sample the preferred tier first: the proven entries are a small
		// minority of a big queue, so searching everything and ranking would
		// find them only by luck (at 1.5% proven, ~1 pick in 6 misses). The
		// tiers are disjoint in rank, so a proven entry always outranks a
		// stale one; the wide search is only for when the tier has nothing
		// usable, which is what the skip-aware fallback below is for.
		now := nowNanos()
		best := b.rankPick(source, probes, skip, now)
		if best == nil {
			// Everything in the preferred tier was already tried by this
			// failover sequence, or the tier is empty. Widen to the whole
			// queue: a stale proxy is a far better outcome for the client than
			// re-picking the one that just failed.
			best = b.rankPick(b.proxies, probes, skip, now)
		}
		if best == nil {
			// The entire queue is already tried. Reuse an entry anyway:
			// returning nothing fails the client's request outright, which is
			// strictly worse than one more attempt at a known proxy.
			best = source[b.rng.Intn(n)]
		}
		b.mu.RUnlock()
		return best, nil
	}
}

// rankPick samples pool up to probes times and returns the best entry by
// (proof freshness, consecutive failures, latency, in-flight load), or nil if
// every sample was in skip. Callers hold at least a read lock.
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
		p := pool[b.rng.Intn(n)]
		if _, bad := skip[p.Key()]; bad {
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

// Snapshot returns a defensive copy of the current queue.
func (b *Bucket) Snapshot() []*Proxy {
	b.mu.RLock()
	defer b.mu.RUnlock()
	out := make([]*Proxy, len(b.proxies))
	copy(out, b.proxies)
	return out
}

// Liveness scopes for LiveList.
const (
	// AliveServed keeps only proxies that delivered real client traffic
	// inside the window — the strictest, most trustworthy definition.
	AliveServed = "served"
	// AliveChecked also keeps proxies that passed a full validation inside
	// the window, even if they have not been picked for serving yet.
	AliveChecked = "checked"
	// AliveAll is the whole queue, unproven entries included.
	AliveAll = "all"
	// AliveHot is the curated tail the picker actually samples: proxies that
	// proved themselves and are still in hotMax. It is a subset of the queue
	// that survives a liveness window better than AliveAll, and the set worth
	// exporting when the goal is "give me the ones that work right now".
	AliveHot = "hot"
)

// LiveList returns the queue entries that carry recent proof of life, best
// first: served traffic outranks a validation stamp, and inside a tier the most
// recent proof and then the lowest latency come first. scope is one of
// AliveHot / AliveServed / AliveChecked / AliveAll; window bounds how old a proof
// may be. limit <= 0 returns everything that qualifies.
func (b *Bucket) LiveList(scope string, window time.Duration, limit int) []*Proxy {
	rows, _ := b.LiveListPage(scope, window, limit)
	return rows
}

// LiveListPage is LiveList plus the number of entries that qualify before
// limit is applied. Callers that page through the queue need both: a response
// that silently stops at the limit reads as "this is all of them", which is how
// a proxy list ends up lying about how much is alive.
func (b *Bucket) LiveListPage(scope string, window time.Duration, limit int) (rows []*Proxy, total int) {
	now := time.Now()
	type row struct {
		p     *Proxy
		rank  int
		stamp time.Time
	}
	var found []row
	b.mu.RLock()
	if scope == AliveHot {
		// The hot tail is the smallest set with the best evidence, so it is
		// already ranked; only the window still has to be applied.
		for _, p := range b.hot {
			served, checked := p.LastServed(), p.LastCheck()
			switch {
			case !served.IsZero() && now.Sub(served) <= window:
				found = append(found, row{p: p, rank: 3, stamp: served})
			case !checked.IsZero() && now.Sub(checked) <= window:
				found = append(found, row{p: p, rank: 2, stamp: checked})
			}
		}
		b.mu.RUnlock()
		total = len(found)
		if limit > 0 && len(found) > limit {
			found = found[:limit]
		}
		out := make([]*Proxy, len(found))
		for i := range found {
			out[i] = found[i].p
		}
		return out, total
	}
	for _, p := range b.proxies {
		served := p.LastServed()
		checked := p.LastCheck()
		var rank int
		var stamp time.Time
		switch {
		case !served.IsZero() && now.Sub(served) <= window:
			rank, stamp = 2, served
		case !checked.IsZero() && now.Sub(checked) <= window:
			rank, stamp = 1, checked
		default:
			if scope == AliveAll {
				rank, stamp = 0, time.Time{}
			} else {
				continue
			}
		}
		if scope == AliveServed && rank < 2 {
			continue
		}
		found = append(found, row{p: p, rank: rank, stamp: stamp})
	}
	b.mu.RUnlock()
	total = len(found)

	sort.Slice(found, func(i, j int) bool {
		if found[i].rank != found[j].rank {
			return found[i].rank > found[j].rank
		}
		if !found[i].stamp.Equal(found[j].stamp) {
			return found[i].stamp.After(found[j].stamp)
		}
		li, lj := found[i].p.Latency(), found[j].p.Latency()
		if li != lj {
			if li == 0 {
				return false // unmeasured sorts last
			}
			if lj == 0 {
				return true
			}
			return li < lj
		}
		return found[i].p.Key() < found[j].p.Key()
	})
	if limit > 0 && len(found) > limit {
		found = found[:limit]
	}
	out := make([]*Proxy, len(found))
	for i := range found {
		out[i] = found[i].p
	}
	return out, total
}

// poke wakes up goroutines waiting in Random (buffer 1 -> no multi-wake storms).
func (b *Bucket) poke() {
	select {
	case b.signal <- struct{}{}:
	default:
	}
}
