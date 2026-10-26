package proxy

import (
	"slices"
	"time"
)

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
//
// Only the pointer copy runs under the read lock; the window filter runs
// outside it. Every field the filter reads is atomic, so holding RLock across
// the whole scan would only stall Add/Remove (checker, revalidation, serving
// evictions) for no correctness gain. Membership can shift mid-scan on a huge
// queue — an entry added between copy and filter may be missed, one removed
// may be included — but the delta recomputes every second, so the view
// self-heals faster than an operator can read it.
func (b *Bucket) LiveListUnranked(scope string, window time.Duration) []*Proxy {
	b.mu.RLock()
	src := b.proxies
	if scope == AliveHot {
		src = b.hot
	}
	cp := make([]*Proxy, len(src))
	copy(cp, src)
	b.mu.RUnlock()
	// Nano compares, same as LiveListPage: time.Unix + Time.Sub per queue
	// entry was the dominant cost of the one-second delta scan once the
	// copy moved out of the lock.
	nowNS := time.Now().UnixNano()
	windowNS := int64(window)
	var out []*Proxy
	for _, p := range cp {
		served := p.lastOKNanos()
		checked := p.lastCheckNanos()
		switch {
		case served != 0 && nowNS-served <= windowNS:
		case checked != 0 && nowNS-checked <= windowNS:
		default:
			if scope != AliveAll {
				continue
			}
		}
		if scope == AliveServed && (served == 0 || nowNS-served > windowNS) {
			continue
		}
		out = append(out, p)
	}
	return out
}

// liveRankRow carries the ranking evidence for one qualifying queue entry.
// It is package-level, not a closure-local type, for two measurable reasons:
// the comparators can then be plain functions the compiler inlines (as
// closures they were indirect calls made inside every heap sift — 40% of a
// LiveListPage request in the profile), and the row fits in 32 bytes instead
// of 40, which is what the top-k heap moves around on every better candidate.
//
// idx is the scan position and breaks every remaining tie: that is what
// SliceStable's "equal elements keep insertion order" used to provide, and
// with a total order the selection needs no stability. int32 is enough because
// max_proxies is 2,000,000.
//
// stamp is the raw unix-nano proof time, not a time.Time: the scan runs this
// over every queue entry, and time.Unix+Time.Sub per row was the dominant cost
// of the whole request once the sort was bounded (the picker already compares
// nanos this way — see lastOKNanos in pick.go). 0 means "no proof"; comparisons
// are plain int64.
type liveRankRow struct {
	p     *Proxy
	stamp int64
	lat   time.Duration
	rank  int32
	idx   int32
}

// liveRankBetter orders a row before another: higher proof first, then newer
// proof, then lower latency (0 = never measured, so it sorts last), then scan
// position. Lower is therefore "worse" everywhere and liveRankWorse is its
// mirror for the max-heap below.
func liveRankBetter(a, b liveRankRow) bool {
	if a.rank != b.rank {
		return a.rank > b.rank
	}
	if a.stamp != b.stamp {
		return a.stamp > b.stamp
	}
	if a.lat != b.lat {
		if a.lat == 0 {
			return false // unmeasured sorts last
		}
		if b.lat == 0 {
			return true
		}
		return a.lat < b.lat
	}
	return a.idx < b.idx
}

func liveRankWorse(a, b liveRankRow) bool { return liveRankBetter(b, a) }

// liveRankSort is liveRankBetter in the form slices.SortFunc wants. The order
// itself stays defined once, in liveRankBetter (the tie-break on idx makes it
// total, so the equal case is unreachable).
func liveRankSort(a, b liveRankRow) int {
	switch {
	case liveRankBetter(a, b):
		return -1
	case liveRankBetter(b, a):
		return 1
	}
	return 0
}

// liveRankSiftDown restores the max-heap property (root = worst kept row)
// after slot i was overwritten.
func liveRankSiftDown(h []liveRankRow, i int) {
	for {
		l := 2*i + 1
		if l >= len(h) {
			return
		}
		j := l
		if r := l + 1; r < len(h) && liveRankWorse(h[r], h[l]) {
			j = r
		}
		if !liveRankWorse(h[j], h[i]) {
			return
		}
		h[i], h[j] = h[j], h[i]
		i = j
	}
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
	// Copy pointers under the lock, filter and rank outside it (same shape as
	// LiveListUnranked, P49): the scan used to run with b.mu.RLock held, so
	// one default admin page blocked checker commits and serving evictions
	// for the duration of a full-queue walk. The lock now covers a copy.
	b.mu.RLock()
	src := b.proxies
	if scope == AliveHot {
		// The hot tail is the smallest set with the best evidence, so only the
		// window still has to be applied. Same rank scale as the queue scan
		// below: serving proof first, then a validation stamp.
		src = b.hot
	}
	cp := make([]*Proxy, len(src))
	copy(cp, src)
	b.mu.RUnlock()

	// Ranking itself (row type, comparators, sift) is package-level above:
	// liveRankRow, liveRankBetter, liveRankSiftDown.

	// The old shape collected every qualifier, sorted the whole set
	// (O(n log n) of the queue) and truncated — a two-million entry queue
	// spent most of an admin request ranking rows the page would never
	// show, and the comparator re-read Latency() (an atomic load) inside
	// every comparison. Selection keeps only the best `limit` rows in a
	// bounded max-heap: O(n log k) with k = limit, one Latency() load per
	// qualifier, and O(k) memory instead of O(n). limit <= 0 still means
	// "everything" — no bound to stop at, so that path never evicts from
	// the heap and the final sort ranks everything it saw.
	//
	// Latency is snapshotted into the row once per qualifier, never read
	// inside better(): the old comparator paid two atomic loads per
	// comparison.
	keep := limit
	nowNS := now.UnixNano()
	windowNS := int64(window)
	var heap []liveRankRow
	for i, p := range cp {
		served := p.lastOKNanos()
		checked := p.lastCheckNanos()
		var rank int32
		var stamp int64
		switch {
		case served != 0 && nowNS-served <= windowNS:
			rank, stamp = 2, served
		case checked != 0 && nowNS-checked <= windowNS:
			rank, stamp = 1, checked
		default:
			if scope == AliveAll {
				rank, stamp = 0, 0
			} else {
				continue
			}
		}
		if scope == AliveServed && rank < 2 {
			continue
		}
		total++
		row := liveRankRow{p: p, rank: rank, stamp: stamp, lat: p.Latency(), idx: int32(i)}
		if keep > 0 && len(heap) == keep {
			if !liveRankBetter(row, heap[0]) {
				continue // loses to the worst row already kept
			}
			heap[0] = row
			liveRankSiftDown(heap, 0)
			continue
		}
		heap = append(heap, row)
		for j := len(heap) - 1; j > 0; {
			parent := (j - 1) / 2
			if !liveRankWorse(heap[j], heap[parent]) {
				break
			}
			heap[j], heap[parent] = heap[parent], heap[j]
			j = parent
		}
	}
	// slices.SortFunc, not sort.Slice: the reflection-based swap of sort.Slice
	// costs an indirect call per swap and a reflect-visible closure; on a
	// 1000-row page that was a measurable share of the request.
	slices.SortFunc(heap, liveRankSort)
	out := make([]*Proxy, len(heap))
	for i := range heap {
		out[i] = heap[i].p
	}
	return out, total
}
