package proxy

import (
	"context"
	"math/rand/v2" // package-level IntN: lock-free and safe to call while holding the read lock (a shared *rand.Rand was not)
	"sort"
	"sync"
	"time"
)

// Freshness tiers for the picker. A proxy proven alive recently is strongly
// preferred over one that merely "never failed": left unchecked, a
// stale-but-silent queue looks identical to a freshly-warmed one and the
// pool's working tail gets no more requests than the dead bulk.
//
// Both proof kinds and the windows that bound them are defined in pick.go,
// together with the sampling policy that uses them: this file is the queue
// itself, not the policy layered on top of it.

// Bucket is a concurrency-safe queue of live upstream proxies. All methods are
// goroutine safe: it may be mutated by collection workers while the forwarding
// servers pick proxies from it.
//
// The serving-path selection policy — the proof tiers, their windows and the
// sampling that picks between them — lives in pick.go. This file is the data
// structure: membership, ordering, persistence hooks and change notifications.
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
	max    int
	signal chan struct{} // edge-triggered wakeup when queue becomes non-empty
	dirty  bool          // true when queue changed since last save

	// fresh caches the entries that carry proof of life, so PickHealthy can
	// aim at the working tail instead of rejection-sampling a queue whose
	// living fraction is a fraction of a percent. Guarded by its own mutex
	// with lock order freshMu -> mu: never take freshMu while holding mu, and
	// never call freshPool without releasing mu first (see freshPool).
	freshMu sync.Mutex
	fresh   []*Proxy
	freshAt time.Time

	// Proof-of-life windows used by freshnessRank. Set once at startup from
	// the config; see SetFreshnessWindows.
	serveWindow time.Duration
	freshWindow time.Duration

	// changeMu guards subs. Subscribers are a list, not a single slot: the
	// forward dialer (loop set, pin release) and the admin page (WebSocket
	// deltas) both need the notification, and a one-slot field silently loses
	// whichever subscriber was registered first.
	changeMu  sync.Mutex
	subs      []bucketSub
	nextSubID uint64
}

// bucketSub is one registered change listener. The id (not the func value) is
// the identity: Go function values are only comparable to nil, and
// reflect.Value.Pointer on a closure yields its code pointer, which is shared
// by every closure written at the same source location.
type bucketSub struct {
	id uint64
	fn func(p *Proxy, added bool)
}

// Subscribe registers a listener invoked after every successful add/remove
// (including evictions) and returns a function that unregisters it. Listeners
// run outside the bucket's lock, in registration order.
func (b *Bucket) Subscribe(fn func(p *Proxy, added bool)) func() {
	if fn == nil {
		return func() {}
	}
	b.changeMu.Lock()
	b.nextSubID++
	id := b.nextSubID
	b.subs = append(b.subs, bucketSub{id: id, fn: fn})
	b.changeMu.Unlock()
	return func() {
		b.changeMu.Lock()
		defer b.changeMu.Unlock()
		for i, s := range b.subs {
			if s.id == id {
				out := make([]bucketSub, 0, len(b.subs)-1)
				out = append(out, b.subs[:i]...)
				b.subs = append(out, b.subs[i+1:]...)
				return
			}
		}
	}
}

// freshPool returns the proven entries, rebuilding the cache at most once per
// freshRebuildInterval. The snapshot is allowed to lag reality by that much: an
// entry that was removed underneath it costs one failed dial and a retry, and
// invalidating on every add would turn each pick into an O(queue) scan.
//
// Lock order is freshMu -> mu, and no caller may hold mu when calling this:
// PickHealthy used to take b.mu.RLock and then land here, where the rebuild
// takes b.mu.RLock again — a recursive read lock, which deadlocks the moment
// a writer (Add/Remove) queues between the two acquisitions.
//
// freshMu is held across the whole rebuild so two goroutines cannot build
// into b.fresh at the same time (it used to be released before the scan), and
// every rebuild allocates a NEW slice: previously it recycled the storage
// under a read lock, writing into a slice that pickers were iterating.
func (b *Bucket) freshPool(now time.Time) []*Proxy {
	b.freshMu.Lock()
	defer b.freshMu.Unlock()
	if !b.freshAt.IsZero() && now.Sub(b.freshAt) < freshRebuildInterval {
		return b.fresh
	}
	b.mu.RLock()
	nowNanos := now.UnixNano()
	out := make([]*Proxy, 0, 256)
	for _, p := range b.proxies {
		if b.freshnessRank(nowNanos, p) != freshStale {
			out = append(out, p)
		}
	}
	b.fresh, b.freshAt = out, now
	b.mu.RUnlock()
	return out
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
	b.changeMu.Lock()
	subs := b.subs
	b.changeMu.Unlock()
	for _, s := range subs {
		s.fn(p, added)
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
	b.markDirty()
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
//
// Ordering is exact: the front is the most recently proven entry, and pushing
// a new one in shifts the rest back. Only the allocation was wasted here —
// `append([]*Proxy{p}, b.hot...)` built a fresh 512-element slice on every
// promotion, so hundreds of 4 KB allocations per minute of serving traffic.
// Shifting in place keeps the same order at amortized O(1) for the slice; the
// hotIdx rebuild is O(len(hot)) either way and only the promotion of a new
// entry pays it.
func (b *Bucket) promoteLocked(p *Proxy) {
	if _, inMain := b.index[p.Key()]; !inMain {
		return
	}
	if idx, ok := b.hotIdx[p]; ok {
		if idx == 0 {
			return
		}
		// Move p to front: shift elements [0:idx] right by 1, then set [0]=p.
		copy(b.hot[1:idx+1], b.hot[0:idx])
		b.hot[0] = p
		for i := 0; i <= idx; i++ {
			b.hotIdx[b.hot[i]] = i
		}
		return
	}
	if len(b.hot) >= hotMax {
		// Full: the last entry is the least recently proven, drop it.
		delete(b.hotIdx, b.hot[len(b.hot)-1])
	} else {
		b.hot = append(b.hot, nil)
	}
	copy(b.hot[1:], b.hot[:len(b.hot)-1])
	b.hot[0] = p
	for i := 0; i < len(b.hot); i++ {
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
	b.markDirty()
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

// markDirty flags the queue as changed so saveLoop persists it on the next
// tick. Only the persisted member set matters (the file holds plain URLs), so
// stamp-only updates like the dedup path in addLocked deliberately leave the
// flag alone. Callers must hold mu.
func (b *Bucket) markDirty() {
	b.dirty = true
}

// HotLen returns the number of entries in the curated proving tail.
func (b *Bucket) HotLen() int {
	b.mu.RLock()
	defer b.mu.RUnlock()
	return len(b.hot)
}

// ProvenCount returns how many proxies can be served with evidence, i.e. how
// many are in the proven tier: they either carried a real client response or
// passed a full validation inside the pick_windows the picker uses.
//
// This is what a readiness probe must look at, not Len(). A queue of two
// million seeded-but-unverified addresses answers "is anything in the queue"
// with yes while every single dial fails, which is the one state a supervisor
// must not be told is healthy.
func (b *Bucket) ProvenCount() int {
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
			p := b.proxies[rand.IntN(n)]
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
		// Read the proven pool BEFORE taking mu: freshPool takes mu.RLock
		// itself while rebuilding, and a nested RLock is how a serving pick
		// could wedge against a concurrent Add/Remove. The snapshot is a
		// pointer, and reheating it is a freshMu fast path, so this is cheap;
		// the caller below only pays for the scan once per rebuild interval.
		proven := b.freshPool(time.Now())
		b.mu.RLock()
		// The real queue decides whether there is anything to serve: a stale
		// proven/hot snapshot must not keep serving entries that are already
		// gone (both are read before/outside the rebuild interval).
		if len(b.proxies) == 0 {
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
		// Pick the preferred tier under the lock. proven is immutable once
		// handed out (freshPool builds a new slice per rebuild) and only
		// admits entries that were live at rebuild time; rankPick re-checks
		// each sample against b.index and skips the ones removed since.
		now := nowNanos()
		source := b.proxies
		switch {
		case len(b.hot) > 0:
			source = b.hot
		case len(proven) > 0:
			source = proven
		}
		// Sample the preferred tier first: the proven entries are a small
		// minority of a big queue, so searching everything and ranking would
		// find them only by luck (at 1.5% proven, ~1 pick in 6 misses). The
		// tiers are disjoint in rank, so a proven entry always outranks a
		// stale one; the wide search is only for when the tier has nothing
		// usable, which is what the skip-aware fallback below is for.
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
			best = b.proxies[rand.IntN(len(b.proxies))]
		}
		b.mu.RUnlock()
		return best, nil
	}
}

// rankPick samples pool up to probes times and returns the best entry by
// (proof freshness, consecutive failures, latency, in-flight load), or nil if
// every sample was in skip or no longer in the queue. Callers hold at least a
// read lock.
// rankPick, betterPick, nowNanos and the freshness policy they use live in
// pick.go: this file ends at the queue itself.

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

// LiveListUnranked returns every entry in the scope that sits inside the
// window, in queue order. It exists for callers that only need the set — the
// admin WebSocket delta diffs two of these a second, and ranking a two million
// entry queue to compute a set difference is almost the entire cost of the
// broadcast. Order here is meaningless by design.
func (b *Bucket) LiveListUnranked(scope string, window time.Duration) []*Proxy {
	now := time.Now()
	var out []*Proxy
	b.mu.RLock()
	defer b.mu.RUnlock()
	src := b.proxies
	if scope == AliveHot {
		src = b.hot
	}
	for _, p := range src {
		served := p.LastServed()
		checked := p.LastCheck()
		switch {
		case !served.IsZero() && now.Sub(served) <= window:
		case !checked.IsZero() && now.Sub(checked) <= window:
		default:
			if scope != AliveAll {
				continue
			}
		}
		if scope == AliveServed && (served.IsZero() || now.Sub(served) > window) {
			continue
		}
		out = append(out, p)
	}
	return out
}

// LiveListPage is LiveList plus the number of entries that qualify before
// limit is applied. Callers that page through the queue need both: a response
// that silently stops at the limit reads as "this is all of them", which is how
// a proxy list ends up lying about how much is alive.
//
// Every scope ranks on the same three-level scale — serving proof first, then
// a validation stamp, then unproven — so the hot tail and the queue scan order
// identically. (The hot branch used to double the scale, 3 and 2, making a
// "hot" rank incomparable to a "served" one.)
//
// limit <= 0 returns everything that qualifies. A caller with a cap should
// pass it: ranking a whole huge queue and slicing afterwards is the same work
// with no bound to stop it.
func (b *Bucket) LiveListPage(scope string, window time.Duration, limit int) (rows []*Proxy, total int) {
	now := time.Now()
	type row struct {
		p     *Proxy
		rank  int
		stamp time.Time
	}
	var found []row
	b.mu.RLock()
	src := b.proxies
	if scope == AliveHot {
		// The hot tail is the smallest set with the best evidence, so only the
		// window still has to be applied. Same rank scale as the queue scan
		// below: serving proof first, then a validation stamp.
		src = b.hot
	}
	for _, p := range src {
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

	// SliceStable, and no key comparison for ties: a tie keeps queue order,
	// which is all the determinism the page needs. The old tie-break called
	// p.Key() inside the comparator, and Key() falls back to building the URL
	// for any proxy that has not been through a pick yet — so ranking a page
	// of a 70k queue made a million fmt.Sprintf calls and 146k allocations,
	// ~15ms of every admin request.
	sort.SliceStable(found, func(i, j int) bool {
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
		return false // equal evidence: insertion order decides (stable)
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
