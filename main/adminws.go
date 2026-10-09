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
	prevHealth  map[string]int
	// Coalesced change flags from bucket.Subscribe (cap 1: a pending flag is
	// all the notifier needs).
	notify chan struct{}
}

func newWSHub() *wsHub {
	return &wsHub{
		conns:       make(map[*wsConn]struct{}),
		prevProxies: make(map[string]liveRow),
		notify:      make(chan struct{}, 1),
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

func (h *wsHub) add(c *wsConn) {
	h.mu.Lock()
	h.conns[c] = struct{}{}
	h.mu.Unlock()
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
	// Whatever deadline the server set before the hijack, drop it: this
	// connection now runs on the deadlines below.
	_ = ws.SetDeadline(time.Time{})

	c := &wsConn{conn: ws, send: make(chan []byte, 256)}
	a.ws.add(c)

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

// sendWSState sends the current state to a newly connected client.
//
// This is the only message that carries history: a periodic delta repeating a
// 1440-sample array is ~90 KB per broadcast per client, for data that only
// changes once a minute.
//
// The TLS flag is the listener's, not the connection's: the WebSocket frame
// does not carry it, and the page knows its own scheme anyway.
func (a *admin) sendWSState(c *wsConn) {
	msg := map[string]interface{}{
		"type":    "state",
		"health":  a.healthView(a.tlsConfigured),
		"proxies": a.liveDelta(),
		"sources": a.sources(),
		"history": a.statsHistory(),
	}
	data, _ := json.Marshal(msg)
	select {
	case c.send <- data:
	default:
	}
}

// startWSNotifier turns the per-mutation flags into at most one delta
// broadcast per tick. The checker adds and revalidation drops arrive in
// bursts of hundreds per second; recomputing a whole-queue diff for each one
// inline would put admin bookkeeping in the hot path of every worker.
func (a *admin) startWSNotifier(ctx context.Context) {
	t := time.NewTicker(time.Second)
	defer t.Stop()
	pending := false
	for {
		select {
		case <-ctx.Done():
			return
		case <-a.ws.notify:
			pending = true
		case <-t.C:
			if pending {
				pending = false
				a.notifyWSChanged()
			}
		}
	}
}

// notifyWSChanged computes and broadcasts the delta: only changed proxies
// (added/removed/updated) plus health.
func (a *admin) notifyWSChanged() {
	if a.ws.count() == 0 {
		return // nobody is listening: the diff is pure cost
	}
	live := a.liveDelta()
	currentProxies := make(map[string]liveRow, len(live))
	for _, p := range live {
		currentProxies[p.URL] = p
	}

	added, removed, updated := a.ws.diff(currentProxies)

	msg := map[string]interface{}{
		"type":    "delta",
		"health":  a.healthView(a.tlsConfigured),
		"added":   added,
		"removed": removed,
		"updated": updated,
	}
	data, _ := json.Marshal(msg)
	a.ws.broadcast(data)
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
		if prev.Latency != p.Latency || prev.Consec != p.Consec || prev.InFlight != p.InFlight ||
			prev.Served != p.Served || prev.Checked != p.Checked || prev.Fails != p.Fails || prev.OK != p.OK {
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
