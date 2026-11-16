package proxy

import (
	"context"
	"testing"
	"time"
)

// A named session has to outrank the connection key: every front sets a
// connection key on every request, so with the old precedence the header could
// never reach the pin table and session stickiness was dead code.
func TestPinKeyFromPrefersSession(t *testing.T) {
	ctx := WithConnKey(context.Background(), "10.0.0.5:4321")
	ctx = WithSessionKey(ctx, "s=cart-1")
	if got := pinKeyFrom(ctx); got != "s=cart-1" {
		t.Fatalf("session must outrank the connection key: got %q, want %q", got, "s=cart-1")
	}

	ctx = WithConnKey(context.Background(), "10.0.0.5:4321")
	if got := pinKeyFrom(ctx); got != "10.0.0.5:4321" {
		t.Fatalf("connection key without a session: got %q", got)
	}
	if got := pinKeyFrom(context.Background()); got != "" {
		t.Fatalf("empty context must yield no key, got %q", got)
	}
}

func TestServerConfigPinKey(t *testing.T) {
	cases := []struct{ pinBy, addr, want string }{
		{PinByConn, "10.0.0.5:4321", "10.0.0.5:4321"},
		{PinByClient, "10.0.0.5:4321", "10.0.0.5"},
		{PinByClient, "[::1]:4321", "::1"},
		{PinByClient, "garbage", "garbage"},
		{PinByClient, "", ""},
		// An unset value behaves like the default instead of keying by "".
		{"", "10.0.0.5:4321", "10.0.0.5:4321"},
	}
	for _, c := range cases {
		got := ServerConfig{ServePinBy: c.pinBy}.PinKey(c.addr)
		if got != c.want {
			t.Errorf("PinKey(%q, %q) = %q, want %q", c.pinBy, c.addr, got, c.want)
		}
	}
}

func TestServePinByDefaultsAndNormalizes(t *testing.T) {
	unset := &Config{}
	_ = unset.fillDefaults()
	if unset.Server.ServePinBy != PinByConn {
		t.Fatalf("unset serve_pin_by = %q, want %q", unset.Server.ServePinBy, PinByConn)
	}

	typo := &Config{}
	typo.Server.ServePinBy = "clinet"
	_ = typo.fillDefaults()
	if typo.Server.ServePinBy != PinByConn {
		t.Fatalf("typo must fall back to %q, got %q", PinByConn, typo.Server.ServePinBy)
	}

	set := &Config{}
	set.Server.ServePinBy = PinByClient
	_ = set.fillDefaults()
	if set.Server.ServePinBy != PinByClient {
		t.Fatalf("explicit %q was overwritten with %q", PinByClient, set.Server.ServePinBy)
	}
}

// The pin counters are the only way to see stickiness from outside: a client
// complaining about a changing exit IP looks identical to a healthy pool
// without them. Each lifecycle event has to move its own counter, and only
// that one.
func TestPinCountersFollowLifecycle(t *testing.T) {
	p := mustProxy(t, "http://1.2.3.4:8080")
	p2 := mustProxy(t, "http://1.2.3.5:8080")
	p3 := mustProxy(t, "http://1.2.3.6:8080")

	hits, remaps, expired, evicted := Stats.PinHits.Load(), Stats.PinRemaps.Load(),
		Stats.PinExpired.Load(), Stats.PinEvicts.Load()

	pool := NewPinPool(time.Minute, 2)
	pool.Set("k", p)
	if got := pool.Get("k"); got == nil {
		t.Fatal("Get after Set returned nil")
	}
	if d := Stats.PinHits.Load() - hits; d != 1 {
		t.Fatalf("pin_hits delta = %d, want 1", d)
	}

	// A Del on a key that was never pinned is not a remap: every failed dial
	// on an unpinned request calls Del, and counting those would make the
	// remap rate read as a session churn that never happened.
	pool.Del("never-pinned")
	if d := Stats.PinRemaps.Load() - remaps; d != 0 {
		t.Fatalf("unpinned Del counted as a remap: delta = %d", d)
	}
	pool.Del("k")
	if d := Stats.PinRemaps.Load() - remaps; d != 1 {
		t.Fatalf("pin_remaps delta = %d, want 1", d)
	}

	// Cap pressure evicts the LRU tail (cap 2, three distinct keys).
	pool.Set("a", p)
	pool.Set("b", p2)
	pool.Set("c", p3)
	if d := Stats.PinEvicts.Load() - evicted; d != 1 {
		t.Fatalf("pin_evictions delta = %d, want 1", d)
	}

	// TTL expiry on the Get path.
	short := NewPinPool(5*time.Millisecond, 4)
	short.Set("old", p)
	time.Sleep(20 * time.Millisecond)
	if got := short.Get("old"); got != nil {
		t.Fatalf("expired pin survived TTL: %v", got)
	}
	if d := Stats.PinExpired.Load() - expired; d != 1 {
		t.Fatalf("pin_expired delta = %d, want 1", d)
	}
}
