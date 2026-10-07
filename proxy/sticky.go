package proxy

import (
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
// expire after ttl of idleness; the pool is bounded by max with LRU eviction
// (ties broken by insert order, because clocks can be coarse).
type PinPool struct {
	mu   sync.Mutex
	m    map[string]pinEntry
	max  int
	ttl  time.Duration
	seq  int64 // insert counter for LRU tie-breaking
	ops  int64 // counter to amortize expiry sweeps
	last time.Time
}

type pinEntry struct {
	p        *Proxy
	lastUsed int64 // unix nanos
	seq      int64 // insert sequence
}

// NewPinPool builds an empty pin pool with the given TTL and size cap.
func NewPinPool(ttl time.Duration, max int) *PinPool {
	if max <= 0 {
		max = 100000
	}
	if ttl <= 0 {
		ttl = 10 * time.Minute
	}
	return &PinPool{m: make(map[string]pinEntry, 1024), max: max, ttl: ttl}
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
	if now-e.lastUsed > int64(s.ttl) {
		delete(s.m, key)
		return nil
	}
	e.lastUsed = now
	s.m[key] = e
	return e.p
}

// Set pins key to proxy. If full, the least-recently-used entry is evicted.
func (s *PinPool) Set(key string, p *Proxy) {
	if key == "" || p == nil {
		return
	}
	now := time.Now().UnixNano()
	s.mu.Lock()
	if _, ok := s.m[key]; !ok && len(s.m) >= s.max {
		s.evictLocked(now - int64(s.ttl))
	}
	s.seq++
	s.m[key] = pinEntry{p: p, lastUsed: now, seq: s.seq}
	s.mu.Unlock()
}

// Del removes the pin for key (called when a pinned proxy fails, so the next
// request remaps to a fresh pick).
func (s *PinPool) Del(key string) {
	if key == "" {
		return
	}
	s.mu.Lock()
	delete(s.m, key)
	s.mu.Unlock()
}

// DropProxy removes every pin that points at the given proxy key. Wired to
// bucket.OnChange so evicted/revalidated-dead proxies release their pins.
func (s *PinPool) DropProxy(proxyKey string) {
	s.mu.Lock()
	for k, e := range s.m {
		if e.p.Key() == proxyKey {
			delete(s.m, k)
		}
	}
	s.mu.Unlock()
}

// Len returns the number of active pins (tests/logging).
func (s *PinPool) Len() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.m)
}

func (s *PinPool) evictLocked(floor int64) {
	var oldestKey string
	var oldestUsed, oldestSeq int64
	for k, e := range s.m {
		if e.lastUsed < floor {
			delete(s.m, k) // expired entries go first
			continue
		}
		if oldestKey == "" || e.lastUsed < oldestUsed ||
			(e.lastUsed == oldestUsed && e.seq < oldestSeq) {
			oldestKey, oldestUsed, oldestSeq = k, e.lastUsed, e.seq
		}
	}
	if oldestKey != "" {
		delete(s.m, oldestKey)
	}
}
