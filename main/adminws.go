package main

import (
	"context"
	"encoding/json"
	"sync"
	"time"

	"golang.org/x/net/websocket"
	"protator/proxy"
)

// wsConn is one connected admin page's writer half. The send channel is the
// only way anything reaches the socket: it decouples the broadcast (which
// holds wsMu) from a slow or dead peer.
type wsConn struct {
	conn   *websocket.Conn
	send   chan []byte
	closed bool
}

// The WebSocket deadlines. golang.org/x/net/websocket has no ping frame and
// does not clear server deadlines off the connection it hijacks, so an
// abandoned client — one that went away without a FIN, or simply opened the
// page and left it — would hold a goroutine and a socket for the life of the
// process. Instead: every server write refreshes the deadline, a write that
// cannot complete in wsWriteTimeout reaps a half-dead peer, and a connection
// the server has had nothing to say to for wsIdleTimeout is dropped. The page
// reconnects on its own (ws.onclose) and re-polls over HTTP every 30s, so a
// periodic close is invisible to the operator.
const (
	wsIdleTimeout  = 5 * time.Minute
	wsWriteTimeout = 30 * time.Second
	// wsMaxFrameBytes bounds one inbound frame. The admin page never sends
	// data; the only inbound traffic is the implicit close/ping path, so
	// 64 KB is orders of magnitude above anything legitimate.
	wsMaxFrameBytes = 64 << 10
	// wsMaxClients bounds simultaneous admin pages. Each costs two
	// goroutines, a 256-slot buffer and a socket.
	wsMaxClients = 32
	// wsFullHealInterval bounds how long the delta may run without a
	// whole-queue rescan (P3). Between heals the delta is incremental: it
	// re-renders only the rows it already tracks (jsonRowCap lookups, not a
	// queue walk) plus the URLs the bucket reported as added. The heal is
	// what still catches what no bucket event ever reports — a row ageing
	// out of the live window, queue-order churn inside the capped render —
	// so it runs on this interval whenever a delta is due at all.
	wsFullHealInterval = time.Minute
)

// wsHub owns every connected admin page. It is a type of its own because the
// admin struct used to carry four mutexes for this one concern, and the
// connection set, the previous-state diff and the broadcast path are only
// meaningful together.
type wsHub struct {
	mu    sync.Mutex
	conns map[*wsConn]struct{}

	// delta bookkeeping: the previous render of the live set, so each
	// broadcast sends only what changed.
	prevProxies map[string]liveRow
	// Coalesced change flags from bucket.Subscribe (cap 1: a pending flag is
	// all the notifier needs).
	notify chan struct{}

	// Incremental-delta bookkeeping (P3). dirtyMu guards the add-side set
	// plus the heal bookkeeping: markDirty runs inline on the bucket's
	// mutation path (it has to stay a map insert of a cached key), while the
	// notifier goroutine is the only writer of lastFull/truncated. Separate
	// from mu so a checker add never contends with broadcast and connection
	// set traffic.
	dirtyMu  sync.Mutex
	dirty    map[string]struct{}
	lastFull time.Time
	// truncated mirrors the previous full render: when the checked scope was
	// cut at jsonRowCap, the tracked set is a queue-order sample, not the
	// whole alive set, and a newly added row outside that sample must not be
	// inserted incrementally — the next heal would not have it in its render
	// and would report the row removed again (visible-then-vanished churn).
	truncated bool
}

func newWSHub() *wsHub {
	return &wsHub{
		conns:       make(map[*wsConn]struct{}),
		prevProxies: make(map[string]liveRow),
		notify:      make(chan struct{}, 1),
		dirty:       make(map[string]struct{}),
	}
}

// requestNotify flags the live view as dirty. It is the only work done on the
// mutation path, so it must stay cheap: no queue scan, no allocation, no
// blocking (the channel is cap 1, a pending flag is idempotent).
func (h *wsHub) requestNotify() {
	select {
	case h.notify <- struct{}{}:
	default:
	}
}

// markDirty records the URL of a proxy the bucket just added, so the next
// incremental tick can consider it for insertion. Key() is the cached URL
// string — no formatting, no allocation, nothing else the mutation path would
// feel. Runs only for adds: removals need no marker, a re-render of the
// tracked set finds them through the failed lookup. evictions (an add at
// capacity) surface the same way.
func (h *wsHub) markDirty(key string) {
	h.dirtyMu.Lock()
	h.dirty[key] = struct{}{}
	h.dirtyMu.Unlock()
}

// takeDirty swaps in a fresh set and returns the pending one. The snapshot is
// taken before the render it feeds: an add that lands mid-render goes into the
// fresh set and is reconsidered next tick, where a clear-after-render would
// swallow it (rendered — harmless; not rendered — lost until the next heal).
func (h *wsHub) takeDirty() map[string]struct{} {
	h.dirtyMu.Lock()
	defer h.dirtyMu.Unlock()
	d := h.dirty
	h.dirty = make(map[string]struct{})
	return d
}

func (h *wsHub) dirtyLen() int {
	h.dirtyMu.Lock()
	defer h.dirtyMu.Unlock()
	return len(h.dirty)
}

// healState reports when the last full render ran and whether it hit the
// jsonRowCap.
func (h *wsHub) healState() (time.Time, bool) {
	h.dirtyMu.Lock()
	defer h.dirtyMu.Unlock()
	return h.lastFull, h.truncated
}

// markHealed records a completed full render and its truncation flag.
func (h *wsHub) markHealed(truncated bool) {
	h.dirtyMu.Lock()
	h.lastFull = time.Now()
	h.truncated = truncated
	h.dirtyMu.Unlock()
}

func (h *wsHub) add(c *wsConn) bool {
	h.mu.Lock()
	defer h.mu.Unlock()
	// The cap decision runs under the same lock as the registration: a
	// separate count() check let N parallel upgrades all observe the pre-add
	// count and all register (check-then-act).
	if len(h.conns) >= wsMaxClients {
		return false
	}
	h.conns[c] = struct{}{}
	return true
}

func (h *wsHub) remove(c *wsConn) {
	h.mu.Lock()
	if !c.closed {
		c.closed = true
		close(c.send)
		delete(h.conns, c)
	}
	h.mu.Unlock()
}

func (h *wsHub) isClosed(c *wsConn) bool {
	h.mu.Lock()
	defer h.mu.Unlock()
	return c.closed
}

// broadcast sends a message to every connected client. A full client buffer
// drops the message rather than blocking the broadcaster: the page re-syncs
// from HTTP on its next poll anyway.
func (h *wsHub) broadcast(msg []byte) {
	h.mu.Lock()
	defer h.mu.Unlock()
	for c := range h.conns {
		select {
		case c.send <- msg:
		default:
		}
	}
}

func (h *wsHub) count() int {
	h.mu.Lock()
	defer h.mu.Unlock()
	return len(h.conns)
}

// handleWebSocket upgrades a connection to a WebSocket for live updates.
func (a *admin) handleWebSocket(ws *websocket.Conn) {
	// Cap the receive side before anything is read: the page never sends
	// payloads, and a single oversized frame (the length field is 8 bytes)
	// would otherwise be materialized whole in memory by
	// websocket.Message.Receive. ErrFrameTooLarge unwinds the reader loop
	// below and the connection is dropped.
	ws.MaxPayloadBytes = wsMaxFrameBytes

	// Bound the number of live pages: each holds a writer goroutine, a
	// reader goroutine, a 256-slot send buffer and a socket. A runaway
	// reconnect loop (or a scanner) must not grow those without limit. The
	// decision runs inside add() under the same lock as the count: checking
	// count() here and adding below were two separate acquisitions, and N
	// parallel upgrades all observed the pre-add count.
	c := &wsConn{conn: ws, send: make(chan []byte, 256)}
	if !a.ws.add(c) {
		_ = ws.Close()
		return
	}

	// Whatever deadline the server set before the hijack, drop it: this
	// connection now runs on the deadlines below.
	_ = ws.SetDeadline(time.Time{})

	// Send initial state.
	a.sendWSState(c)

	// Writer goroutine. remove is deferred so the connection is unregistered
	// even on the panic path: a recovered panic that skipped it would leave
	// the connection in the hub with nobody draining its channel, and every
	// broadcast would keep pushing into it.
	go func() {
		defer proxy.RecoverPanic("admin: ws writer")
		defer a.ws.remove(c)
		for msg := range c.send {
			// closed is only ever written under the hub mutex (remove), so read
			// it under the same lock instead of racing the writer.
			if a.ws.isClosed(c) {
				return
			}
			// Refresh on every write: an active page keeps its connection
			// alive indefinitely, a silent one ages out.
			_ = ws.SetWriteDeadline(time.Now().Add(wsWriteTimeout))
			if err := websocket.Message.Send(ws, string(msg)); err != nil {
				a.ws.remove(c)
				return
			}
			_ = ws.SetReadDeadline(time.Now().Add(wsIdleTimeout))
		}
	}()

	// Reader: keep alive, ignore messages. The idle deadline above is what
	// eventually unwinds a connection whose peer went quiet.
	var msg string
	for {
		if err := websocket.Message.Receive(ws, &msg); err != nil {
			a.ws.remove(c)
			return
		}
	}
}

// subscribeBucket wires bucket change events to the WebSocket delta: adds
// join the incremental insert set (markDirty), everything else just flags the
// notifier. The subscriber runs inline on the mutation path — every checker
// add, every revalidation drop, every serving-path eviction — so both actions
// stay allocation-free and lock-free w.r.t. the bucket: Key() is a cached
// string, requestNotify is a non-blocking channel send.
func (a *admin) subscribeBucket(bucket *proxy.Bucket) {
	bucket.Subscribe(func(p *proxy.Proxy, added bool) {
		if added {
			a.ws.markDirty(p.Key())
		}
		a.ws.requestNotify()
	})
}

// sendWSState sends the current state to a newly connected client.
//
// This is the only message that carries history: a periodic delta repeating a
// 1440-sample array is ~90 KB per broadcast per client, for data that only
// changes once a minute.
//
// The TLS flag is the listener's, not the connection's: the WebSocket frame
// does not carry it, and the page knows its own scheme anyway.
func (a *admin) sendWSState(c *wsConn) {
	proxies, truncated := a.liveDelta()
	msg := map[string]interface{}{
		"type":      "state",
		"health":    a.healthView(a.tlsConfigured),
		"proxies":   proxies,
		"truncated": truncated,
		"sources":   a.sources(),
		"history":   a.statsHistory(),
	}
	data, _ := json.Marshal(msg)
	select {
	case c.send <- data:
	default:
	}
}

// startWSNotifier turns the per-mutation flags into at most one delta
// broadcast per tick. The checker adds and revalidation drops arrive in
// bursts of hundreds per second; applying each one inline would put admin
// bookkeeping in the hot path of every worker.
//
// The tick either heals or applies incrementally (notifyWSChanged) — the
// subscription only flags a pending change and records add-side URLs, so the
// mutation side never sees a scan, a diff or a marshal. The interval follows
// the queue size, re-evaluated every tick so a queue that grows past the
// threshold slows down on its own: a delta over a few thousand entries is
// milliseconds, over two million the heal is seconds of scan plus megabytes
// of JSON per client. A dashboard that refreshes every few seconds instead of
// every second is still live; a proxy that spends its time rendering the
// admin page is not serving.
func (a *admin) startWSNotifier(ctx context.Context) {
	t := time.NewTicker(time.Second)
	defer t.Stop()
	pending := false
	var lastBroadcast time.Time
	for {
		select {
		case <-ctx.Done():
			return
		case <-a.ws.notify:
			pending = true
		case <-t.C:
			if !pending {
				continue
			}
			minInterval := time.Second
			if a.bucket != nil && a.bucket.Len() > 100_000 {
				minInterval = 5 * time.Second
			}
			if !lastBroadcast.IsZero() && time.Since(lastBroadcast) < minInterval {
				continue // stay pending; try again next tick
			}
			pending = false
			lastBroadcast = time.Now()
			a.notifyWSChangedSafe()
		}
	}
}

// notifyWSChangedSafe runs one delta broadcast. The rendering walks the whole
// live queue, builds rows and marshals JSON — all of it parsing live state —
// and the notifier is a bare goroutine: without the recover, one panic kills
// the process through the runtime (skipping main's defers), and without the
// per-broadcast placement a panic would also retire the notifier forever,
// leaving the page silently stale.
func (a *admin) notifyWSChangedSafe() {
	defer proxy.RecoverPanic("admin: ws notifier")
	a.notifyWSChanged()
}

// notifyWSChanged computes and broadcasts one delta.
//
// Two shapes, chosen by cost (P3). A full heal rebuilds the tracked set from
// a whole-queue scan (liveDelta) — authoritative, but O(queue), so it runs at
// most once per wsFullHealInterval and whenever a burst of adds cannot be
// applied as one incremental message. Everything else is incremental: applyDirty
// re-renders the rows the tracker already holds with per-row bucket lookups
// (jsonRowCap of them, about a millisecond against a two-million-entry queue —
// the scan it replaces cost a pointer copy of the whole queue plus a window
// filter) and lets only the add-side dirty set join the set between heals.
//
// The incremental shape keeps the field columns (latency, counters,
// served/checked flags) at their old one-tick latency: revalidation re-stamps
// an existing resident without any bucket event, so a dirty-adds-only render
// would freeze those columns until the next heal.
func (a *admin) notifyWSChanged() {
	if a.ws.count() == 0 {
		// No audience: the diff is pure cost. Drop the add-side set too —
		// it would otherwise pool up the adds of every closed-quiet hour and
		// hand the next connection a burst-sized set by surprise. A client
		// that connects later gets a full state render; whatever is due
		// next ticks either heals (fresh render) or diffs a set that is at
		// most this tick old.
		a.ws.takeDirty()
		return
	}
	lastFull, truncated := a.ws.healState()
	// A dirty set bigger than one render cannot go out as adds without a
	// message the size of the cap — resync instead, and the heal clears the
	// set. The nil-bucket case heals too: applyDirty needs Get.
	if a.bucket == nil || lastFull.IsZero() || time.Since(lastFull) >= wsFullHealInterval ||
		a.ws.dirtyLen() > jsonRowCap {
		a.fullHealWS()
		return
	}
	a.applyDirtyWS(truncated)
}

// fullHealWS rebuilds the tracked set from a whole-queue scan and broadcasts
// the diff against the previous one.
func (a *admin) fullHealWS() {
	// Snapshot the add-side set before rendering (takeDirty semantics).
	a.ws.takeDirty()
	live, truncated := a.liveDelta()
	current := make(map[string]liveRow, len(live))
	for _, p := range live {
		current[p.URL] = p
	}

	added, removed, updated := a.ws.diff(current)
	a.ws.markHealed(truncated)

	msg := map[string]interface{}{
		"type":      "delta",
		"health":    a.healthView(a.tlsConfigured),
		"added":     added,
		"removed":   removed,
		"updated":   updated,
		"truncated": truncated,
	}
	data, _ := json.Marshal(msg)
	a.ws.broadcast(data)
}

// applyDirtyWS renders one incremental delta: every row the tracker already
// holds (re-checked through a per-row bucket lookup), plus the URLs the bucket
// reported as added, diffed against the tracker in place — then broadcasts.
//
// Insertions are gated on the universe not being a cap-truncated sample
// (wsHub.truncated): inside a truncated universe a queue-tail row would be
// added here and then reported removed again by the next full render, whose
// scan stops at the cap. Outside one, the universe is the whole checked scope,
// so an inserted row is exactly what the next heal will still hold.
func (a *admin) applyDirtyWS(truncated bool) {
	dirty := a.ws.takeDirty()
	now := time.Now()

	a.ws.mu.Lock()
	var added []liveRow
	var removed []string
	var updated []liveRow
	// The tracked set is the render universe: every row is looked up and
	// re-rendered, so removals and field changes need no bucket event. Rows
	// dropped mid-iteration (delete during range) are simply not visited
	// again; rows mutated in place are safe map updates.
	for url, prev := range a.ws.prevProxies {
		p := a.bucket.Get(url)
		if p == nil {
			removed = append(removed, url)
			delete(a.ws.prevProxies, url)
			continue
		}
		row := newLiveRow(p, now)
		if !row.Served && !row.Checked {
			// Proof of life slipped past the window without a bucket
			// event: same verdict a full render would reach.
			removed = append(removed, url)
			delete(a.ws.prevProxies, url)
			continue
		}
		if rowChanged(prev, row) {
			a.ws.prevProxies[url] = row
			updated = append(updated, row)
		}
	}
	if !truncated {
		// The hard len cap also covers the stale-flag window: the universe
		// can grow past jsonRowCap between heals while truncated is still
		// false, and the next heal is what re-evaluates the flag.
		for url := range dirty {
			if _, ok := a.ws.prevProxies[url]; ok {
				continue
			}
			if len(a.ws.prevProxies) >= jsonRowCap {
				break
			}
			p := a.bucket.Get(url)
			if p == nil {
				continue
			}
			row := newLiveRow(p, now)
			if !row.Served && !row.Checked {
				continue
			}
			a.ws.prevProxies[url] = row
			added = append(added, row)
		}
	}
	a.ws.mu.Unlock()

	msg := map[string]interface{}{
		"type":      "delta",
		"health":    a.healthView(a.tlsConfigured),
		"added":     added,
		"removed":   removed,
		"updated":   updated,
		"truncated": truncated,
	}
	data, _ := json.Marshal(msg)
	a.ws.broadcast(data)
}

// rowChanged reports whether the fields the page renders from a delta moved.
// One definition for both delta paths (the full heal's diff and the
// incremental tick) so the comparison cannot drift between them.
func rowChanged(prev, cur liveRow) bool {
	return prev.Latency != cur.Latency || prev.Consec != cur.Consec || prev.InFlight != cur.InFlight ||
		prev.Served != cur.Served || prev.Checked != cur.Checked ||
		prev.Fails != cur.Fails || prev.OK != cur.OK
}

// diff compares the given render against the previous one, updates the stored
// state and returns (addedRows, removedURLs, changedRows). Rows, not URLs, for
// the added set: the page has no other source for a row it has never seen, and
// sending an identifier it cannot resolve would leave a blank line in the
// table.
func (h *wsHub) diff(current map[string]liveRow) (added []liveRow, removed []string, updated []liveRow) {
	h.mu.Lock()
	defer h.mu.Unlock()
	for url, p := range current {
		prev, ok := h.prevProxies[url]
		if !ok {
			added = append(added, p)
			continue
		}
		if rowChanged(prev, p) {
			updated = append(updated, p)
		}
	}
	for url := range h.prevProxies {
		if _, ok := current[url]; !ok {
			removed = append(removed, url)
		}
	}
	h.prevProxies = current
	return added, removed, updated
}
