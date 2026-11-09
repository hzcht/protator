package main

// The WebSocket delta pipeline (P3) without a real socket: deltas are read
// off the send channel of a registered hub client.
//
// Two delta shapes run side by side — the full heal (whole-queue render,
// authoritative, O(queue)) and the incremental apply (per-row lookups of the
// tracked set, O(tracked)). The tests pin the contract between them: what
// each may report, when each runs, and the state that decides it. The row
// comparison itself is rowChanged, shared by both paths and exercised here
// through field changes.

import (
	"encoding/json"
	"fmt"
	"testing"
	"time"

	"golang.org/x/net/websocket"
	"protator/proxy"
)

// wsDeltaMsg decodes a broadcast off the send channel.
type wsDeltaMsg struct {
	Type      string                 `json:"type"`
	Health    map[string]interface{} `json:"health"`
	Added     []liveRow              `json:"added"`
	Removed   []string               `json:"removed"`
	Updated   []liveRow              `json:"updated"`
	Truncated bool                   `json:"truncated"`
}

// wsClient registers a fake hub client. The conn is never touched outside the
// hub's bookkeeping (no writer goroutine runs in tests), so a zero value does.
func wsClient(t *testing.T, a *admin) *wsConn {
	t.Helper()
	c := &wsConn{conn: &websocket.Conn{}, send: make(chan []byte, 8)}
	if !a.ws.add(c) {
		t.Fatal("hub refused the test client")
	}
	t.Cleanup(func() { a.ws.remove(c) })
	return c
}

func drainDelta(t *testing.T, c *wsConn) wsDeltaMsg {
	t.Helper()
	select {
	case raw := <-c.send:
		var m wsDeltaMsg
		if err := json.Unmarshal(raw, &m); err != nil {
			t.Fatalf("bad delta json: %v\n%s", err, raw)
		}
		return m
	case <-time.After(2 * time.Second):
		t.Fatal("no delta broadcast arrived")
		return wsDeltaMsg{}
	}
}

// checkedProxy builds a bucket entry that passes the live window.
func checkedProxy(t *testing.T, host string, port int, latency time.Duration) *proxy.Proxy {
	t.Helper()
	p, err := proxy.ParseProxyLine(fmt.Sprintf("http://%s:%d", host, port))
	if err != nil {
		t.Fatal(err)
	}
	p.MarkAlive(latency)
	return p
}

// backdateHeal forces the next eligible tick down the heal path.
func backdateHeal(t *testing.T, a *admin) {
	t.Helper()
	a.ws.dirtyMu.Lock()
	a.ws.lastFull = time.Now().Add(-2 * wsFullHealInterval)
	a.ws.dirtyMu.Unlock()
}

// The first run performs the heal (the tracked set starts empty, lastFull is
// zero), so freshly added rows are reported as added; a run inside the heal
// interval is incremental and must not re-arm the heal timestamp.
func TestWSDeltaHealThenIncremental(t *testing.T) {
	a, bucket, _ := newTestAdmin(t)
	c := wsClient(t, a)
	a.subscribeBucket(bucket)

	p1 := checkedProxy(t, "1.2.3.4", 8080, 30*time.Millisecond)
	p2 := checkedProxy(t, "2.2.2.2", 80, 50*time.Millisecond)
	bucket.Add(p1)
	bucket.Add(p2)

	a.notifyWSChanged()
	m := drainDelta(t, c)
	if m.Type != "delta" {
		t.Fatalf("type = %q", m.Type)
	}
	if len(m.Added) != 2 {
		t.Fatalf("heal added = %v", m.Added)
	}
	if len(m.Updated) != 0 || len(m.Removed) != 0 {
		t.Fatalf("heal reported changes on a fresh set: updated %v removed %v", m.Updated, m.Removed)
	}
	if m.Health == nil {
		t.Fatal("delta carried no health view")
	}

	// Incremental tick: a field change on a tracked row reaches the page
	// without a queue re-render. MarkAlive again shifts the latency EMA and
	// bumps the OK counter.
	healedAt, _ := a.ws.healState()
	p1.MarkAlive(120 * time.Millisecond)
	a.notifyWSChanged()
	m = drainDelta(t, c)
	if len(m.Updated) != 1 || m.Updated[0].URL != p1.URL() {
		t.Fatalf("field change: updated = %v, want %s", m.Updated, p1.URL())
	}
	if h, _ := a.ws.healState(); !h.Equal(healedAt) {
		t.Fatal("an incremental tick must not advance the heal timestamp")
	}
}

// The incremental tick must catch every class of change the full heal does:
// a row whose proof has gone stale, membership removals, and a re-broken
// replacement must all be reported without waiting for the heal.
func TestWSDeltaIncrementalCoversChanges(t *testing.T) {
	a, bucket, _ := newTestAdmin(t)
	c := wsClient(t, a)
	a.subscribeBucket(bucket)

	p1 := checkedProxy(t, "1.2.3.4", 8080, 30*time.Millisecond)
	p2 := checkedProxy(t, "2.2.2.2", 80, 50*time.Millisecond)
	bucket.Add(p1)
	bucket.Add(p2)
	a.notifyWSChanged()
	drainDelta(t, c) // discard the heal

	// Proof gone stale while the proxy stays queued: the object is replaced
	// with an unproven one under the same key (Remove + re-Add, no tick in
	// between, so the tracker still holds the row). The tracked re-render
	// finds the lookup, the replacement carries no proof of life, and the
	// verdict matches what the full render's window filter would reach.
	bucket.Remove(p2)
	reshaped := &proxy.Proxy{Schema: p2.Schema, Host: p2.Host, Port: p2.Port}
	bucket.Add(reshaped)
	a.notifyWSChanged()
	m := drainDelta(t, c)
	if len(m.Removed) != 1 || m.Removed[0] != p2.URL() {
		t.Fatalf("stale verdict: removed = %v, want %q", m.Removed, p2.URL())
	}
	if _, ok := a.ws.prevProxies[p2.URL()]; ok {
		t.Fatal("the stale row is still tracked")
	}
	// The add side must not re-insert it either: an unproven row sits
	// outside the checked scope, in the incremental shape just as in the
	// render's window filter.
	a.notifyWSChanged()
	m = drainDelta(t, c)
	if len(m.Added) != 0 && m.Added[0].URL == p2.URL() {
		t.Fatalf("unproven row was re-tracked: %v", m.Added)
	}
	if _, ok := a.ws.prevProxies[p2.URL()]; ok {
		t.Fatal("the unproven row is tracked")
	}

	// Membership removal while the proxy is gone entirely.
	bucket.Remove(p1)
	a.notifyWSChanged()
	m = drainDelta(t, c)
	if len(m.Removed) != 1 || m.Removed[0] != p1.URL() {
		t.Fatalf("removal = %v, want %q", m.Removed, p1.URL())
	}
}

// Between heals a newly added qualifying row joins the set when the universe
// is complete, and is left to the next heal when the universe is a
// cap-truncated sample.
func TestWSDeltaAddGating(t *testing.T) {
	a, bucket, _ := newTestAdmin(t)
	c := wsClient(t, a)
	a.subscribeBucket(bucket)

	seed := checkedProxy(t, "3.3.3.3", 80, 10*time.Millisecond)
	bucket.Add(seed)
	a.notifyWSChanged()
	drainDelta(t, c) // heal with the seed tracked

	// Complete universe: the add is applied at once.
	pNew := checkedProxy(t, "4.4.4.4", 8080, 70*time.Millisecond)
	bucket.Add(pNew)
	a.notifyWSChanged()
	m := drainDelta(t, c)
	if len(m.Added) != 1 || m.Added[0].URL != pNew.URL() {
		t.Fatalf("universe complete: added = %v, want %s", m.Added, pNew.URL())
	}

	// Truncated universe: the add is deferred. The full render stops at the
	// cap, so inserting here would have the next heal report the row
	// removed again (visible-then-vanished churn).
	a.ws.markHealed(true)
	pTail := checkedProxy(t, "5.5.5.5", 8080, 70*time.Millisecond)
	bucket.Add(pTail)
	a.notifyWSChanged()
	m = drainDelta(t, c)
	if len(m.Added) != 0 {
		t.Fatalf("truncated universe took the add: %v", m.Added)
	}

	// The heal is authoritative on both counts: it re-renders the set from
	// a whole-queue walk, picks up the deferred row, and re-arms truncation
	// from what that walk actually saw. The test bucket is small, so the
	// render is uncapped.
	backdateHeal(t, a)
	a.notifyWSChanged()
	m = drainDelta(t, c)
	if len(m.Added) != 1 || m.Added[0].URL != pTail.URL() {
		t.Fatalf("heal did not pick up the deferred add: %v", m.Added)
	}
	if a.ws.truncated {
		t.Fatal("heal recorded truncated=true on an uncapped render")
	}
}

// An add burst bigger than one render cannot go out as one message of adds:
// the tick resyncs through the heal, and the burst set is drained.
func TestWSDeltaBurstFallsBackToHeal(t *testing.T) {
	a, _, _ := newTestAdmin(t)
	c := wsClient(t, a)

	a.notifyWSChanged()
	drainDelta(t, c)

	healedAt, _ := a.ws.healState()
	for j := 0; j <= jsonRowCap; j++ {
		a.ws.markDirty(fmt.Sprintf("http://10.%d.%d.%d:1", j>>8, j>>4&15, j&15))
	}
	// The Windows timer's monotonic resolution can make the heal timestamp
	// equal the one already recorded, which would read the fallback as
	// "never happened": advance the clock past that resolution.
	time.Sleep(2 * time.Millisecond)
	a.notifyWSChanged()
	drainDelta(t, c)
	if h, _ := a.ws.healState(); h.Equal(healedAt) {
		t.Fatal("an add burst must fall back to a full heal")
	}
	if n := a.ws.dirtyLen(); n != 0 {
		t.Fatalf("heal left %d dirty urls behind", n)
	}
}

// With no client listening the delta work is skipped, and the add-side set
// does not pool up in the background: it is dropped with the audience. A
// client that connects later gets a full state render and a fresh heal.
func TestWSDeltaNoAudienceDropsDirty(t *testing.T) {
	a, _, _ := newTestAdmin(t)
	a.ws.markDirty("http://1.2.3.4:8080")
	a.notifyWSChanged()
	if n := a.ws.dirtyLen(); n != 0 {
		t.Fatalf("no-audience tick kept %d dirty urls", n)
	}
}

// The full heal on a capped queue records truncation and stops the tracked
// set at the cap; a still-tracked-tick add is deferred, not reverted by the
// next tick.
func TestWSDeltaFullRenderCapped(t *testing.T) {
	// The default test bucket caps at 100 rows: a render of that can never
	// reach the render cap, so this brings one it can.
	a, bucket, _ := newTestAdminBucket(t, jsonRowCap+100)
	c := wsClient(t, a)
	a.subscribeBucket(bucket)

	// One more qualifying row than the render cap.
	for j := 0; j <= jsonRowCap; j++ {
		p := checkedProxy(t, fmt.Sprintf("10.%d.%d.%d", j>>8, j>>4&15, j&15), 80, 10*time.Millisecond)
		bucket.Add(p)
	}
	a.notifyWSChanged()
	m := drainDelta(t, c)
	if !m.Truncated {
		t.Fatal("capped render did not flag truncation")
	}
	if len(m.Added) != jsonRowCap {
		t.Fatalf("capped heal added %d rows, want %d", len(m.Added), jsonRowCap)
	}
	if len(a.ws.prevProxies) != jsonRowCap {
		t.Fatalf("tracked set = %d, want the cap", len(a.ws.prevProxies))
	}
	// A still-tracked-tick add arrives while the universe is truncated: it
	// must be deferred rather than re-rendered as removed by the next heal.
	pMore := checkedProxy(t, "11.11.11.11", 80, 10*time.Millisecond)
	bucket.Add(pMore)
	a.notifyWSChanged()
	m = drainDelta(t, c)
	if len(m.Added) != 0 {
		t.Fatalf("capped universe took the add: %v", m.Added)
	}
	if _, ok := a.ws.prevProxies[pMore.URL()]; ok {
		t.Fatal("the deferred add is tracked despite truncation")
	}
}
