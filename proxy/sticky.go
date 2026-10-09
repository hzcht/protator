package proxy

import (
	"container/list"
	"context"
	"sync"
	"time"
)

// Context keys carry session stickiness and per-request attempt state from
// the goproxy front-end down to ForwardDialer.DialContext. Each key uses its
// own private type so string values stored under different keys can never
// collide with each other or with user contexts.
type (
	connKeyT    struct{}
	sessionKeyT struct{}
	attemptKeyT struct{}
)

var (
	keyConn    = connKeyT{}
	keySession = sessionKeyT{}
	keyAttempt = attemptKeyT{}
)

// WithConnKey attaches a client-connection identity to the context. Pin the
// upstream per client TCP connection (RemoteAddr based).
func WithConnKey(ctx context.Context, key string) context.Context {
	return context.WithValue(ctx, keyConn, key)
}

// WithSessionKey attaches a session identity to the context, pinning the
// upstream for the client-supplied "X-Sticky-Session" header (stripped before
// forwarding), which survives connection churn.
func WithSessionKey(ctx context.Context, key string) context.Context {
	return context.WithValue(ctx, keySession, key)
}

// pinKeyFrom extracts the stickiness key (connection or session) from the
// context, connection identity taking precedence.
func pinKeyFrom(ctx context.Context) string {
	if k, _ := ctx.Value(keyConn).(string); k != "" {
		return k
	}
	if k, _ := ctx.Value(keySession).(string); k != "" {
		return k
	}
	return ""
}

// PinPool maps a stickiness key (client connection or session) to the upstream
// proxy that served it, so a browser session keeps one source IP. Entries
// expire after ttl of idleness; the pool is bounded by max with LRU eviction.
//
// The reverse index matters: DropProxy runs on every bucket removal, and a
// revalidation pass removes tens of thousands of proxies at once. Scanning the
// whole map for each of them — while holding the same lock Get needs on every
// dial — serializes minutes of scanning into the serving path.
//
// LRU is a doubly linked list, not a scan: at serve_pin_max (100k by default)
// the old eviction walked the entire map under the write lock on every Set that
// found the table full, stalling every dial on the serving path for the length
// of that scan. Now eviction is O(1) (drop the tail) and expiry is O(expired),
// because the list is kept in recency order.
type PinPool struct {
	mu    sync.RWMutex
	m     map[string]*list.Element       // pin key -> LRU element
	byPrx map[string]map[string]struct{} // proxy key -> pin keys pointing at it
	lru   *list.List                     // front = most recently used
	max   int
	ttl   time.Duration
	// ops counts every mutation, not just Set: a Get/Del-only workload would
	// otherwise never trigger a sweep and let expired pins accumulate.
	ops int64
}

// pinSweepEvery is how many operations may pass between expiry sweeps. It
// bounds how long a dead pin can outlive its TTL: without it only the key being
// Get is ever checked, so pins from disconnected clients are never released
// until LRU pressure evicts them.
const pinSweepEvery = 512

type pinEntry struct {
	key      string // pin key, so the list element can be removed by value
	p        *Proxy
	lastUsed int64 // unix nanos
}

// NewPinPool builds an empty pin pool with the given TTL and size cap.
func NewPinPool(ttl time.Duration, max int) *PinPool {
	if max <= 0 {
		max = 100000
	}
	if ttl <= 0 {
		ttl = 10 * time.Minute
	}
	return &PinPool{
		m:     make(map[string]*list.Element, 1024),
		byPrx: make(map[string]map[string]struct{}, 1024),
		lru:   list.New(),
		max:   max,
		ttl:   ttl,
	}
}

// Get returns the pinned proxy for key, refreshing its idle timestamp, or nil
// when absent/expired.
func (s *PinPool) Get(key string) *Proxy {
	if key == "" {
		return nil
	}
	now := time.Now().UnixNano()
	s.mu.Lock()
	defer s.mu.Unlock()
	e, ok := s.m[key]
	if !ok {
		return nil
	}
	if now-e.Value.(*pinEntry).lastUsed > int64(s.ttl) {
		s.removeLocked(key)
		return nil
	}
	s.touchLocked(e, now)
	// A hit is the common case on the serving path, and sweeping here keeps
	// the amortized counter honest for a Get/Del-heavy workload.
	s.maybeSweepLocked(now)
	return e.Value.(*pinEntry).p
}

// Set pins key to proxy. If full, the least-recently-used entry is evicted.
func (s *PinPool) Set(key string, p *Proxy) {
	if key == "" || p == nil {
		return
	}
	now := time.Now().UnixNano()
	s.mu.Lock()
	defer s.mu.Unlock()
	if e, ok := s.m[key]; ok {
		entry := e.Value.(*pinEntry)
		if entry.p.Key() != p.Key() {
			s.unindexLocked(key, entry.p.Key())
			entry.p = p
			s.indexLocked(key, p.Key())
		}
		s.touchLocked(e, now)
		return
	}
	if s.lru.Len() >= s.max {
		s.evictLRULocked()
	}
	e := s.lru.PushFront(&pinEntry{key: key, p: p, lastUsed: now})
	s.m[key] = e
	s.indexLocked(key, p.Key())
}

// Del removes the pin for key (called when a pinned proxy fails, so the next
// request remaps to a fresh pick).
func (s *PinPool) Del(key string) {
	if key == "" {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.removeLocked(key)
	s.maybeSweepLocked(time.Now().UnixNano())
}

// DropProxy removes every pin that points at the given proxy key. Wired to
// bucket.Subscribe so evicted/revalidated-dead proxies release their pins.
//
// O(pins on that proxy), not O(all pins): the reverse index makes a bulk
// revalidation pass cheap instead of quadratic.
func (s *PinPool) DropProxy(proxyKey string) {
	if proxyKey == "" {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	keys, ok := s.byPrx[proxyKey]
	if !ok {
		return
	}
	for k := range keys {
		s.removeLocked(k)
	}
	delete(s.byPrx, proxyKey)
}

// Len returns the number of active pins (tests/logging).
func (s *PinPool) Len() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.m)
}

// touchLocked moves an entry to the front of the LRU and refreshes its idle
// stamp. Callers hold mu.
func (s *PinPool) touchLocked(e *list.Element, now int64) {
	s.lru.MoveToFront(e)
	e.Value.(*pinEntry).lastUsed = now
}

// indexLocked records that pinKey points at proxyKey.
func (s *PinPool) indexLocked(pinKey, proxyKey string) {
	set := s.byPrx[proxyKey]
	if set == nil {
		set = make(map[string]struct{}, 1)
		s.byPrx[proxyKey] = set
	}
	set[pinKey] = struct{}{}
}

// unindexLocked drops one pin from the reverse index.
func (s *PinPool) unindexLocked(pinKey, proxyKey string) {
	set := s.byPrx[proxyKey]
	delete(set, pinKey)
	if len(set) == 0 {
		delete(s.byPrx, proxyKey)
	}
}

// removeLocked deletes a pin by key and keeps the reverse index and the LRU
// consistent. Callers hold mu.
func (s *PinPool) removeLocked(key string) {
	e, ok := s.m[key]
	if !ok {
		return
	}
	entry := e.Value.(*pinEntry)
	s.unindexLocked(key, entry.p.Key())
	delete(s.m, key)
	s.lru.Remove(e)
}

// evictLRULocked drops the least recently used entry. Callers hold mu.
func (s *PinPool) evictLRULocked() {
	if e := s.lru.Back(); e != nil {
		s.removeLocked(e.Value.(*pinEntry).key)
	}
}

// maybeSweepLocked drops expired entries once enough operations have passed.
// The LRU is in recency order, so expired entries sit at the tail: the sweep
// walks backwards and stops at the first live one, costing O(expired) instead
// of O(all pins).
func (s *PinPool) maybeSweepLocked(now int64) {
	s.ops++
	if s.ops < pinSweepEvery {
		return
	}
	s.ops = 0
	floor := now - int64(s.ttl)
	for e := s.lru.Back(); e != nil; {
		prev := e.Prev()
		if e.Value.(*pinEntry).lastUsed < floor {
			s.removeLocked(e.Value.(*pinEntry).key)
		} else {
			return // everything in front is more recent
		}
		e = prev
	}
}
