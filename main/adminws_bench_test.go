package main

// Benchmarks for the admin WebSocket delta path. Measurement only: the
// benchmarks exist so a later change to the render/diff/marshal shape shows
// up as a bench diff, not as a slower admin page.
//
// The hub runs without a real socket, exactly the way adminws_test.go drives
// it: a fake client is registered on the hub and each delta broadcast is read
// off (and drained from) its send channel, so the benchmark never drifts into
// the full-buffer drop path of broadcast.

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"golang.org/x/net/websocket"
	"protator/proxy"
)

// benchAdmin is newTestAdminBucket for benchmarks: that helper takes a
// *testing.T and a benchmark cannot pass itself. Same construction, same
// fields, *testing.B instead.
func benchAdmin(b *testing.B) (*admin, *proxy.Bucket) {
	b.Helper()
	bucket := proxy.NewBucket(jsonRowCap + 100)
	cfg := &proxy.Config{}
	cfg.Collector.SitesFile = filepath.Join(b.TempDir(), "sites.txt")
	if err := os.WriteFile(cfg.Collector.SitesFile, []byte("# bench\nhttps://bench.example/list.txt\n"), 0o644); err != nil {
		b.Fatal(err)
	}
	pool := proxy.NewCandidatePool(filepath.Join(b.TempDir(), "pool.lst"), 1<<20, 10)
	b.Cleanup(func() { pool.Close() })
	cfg.Collector.SiteMaxFails = 2
	cfg.Collector.SiteCooldown = proxy.Duration{Duration: 10 * time.Minute}
	a := &admin{cfg: cfg, bucket: bucket, pool: pool, started: time.Now(), ws: newWSHub(), cfgPath: "config/config.toml"}
	return a, bucket
}

// benchProxy is checkedProxy for benchmarks (same reason as benchAdmin).
// ParseProxyLine is the canonical constructor, so keyCache is filled at
// construction and Key() never builds a URL inside the timed loops.
func benchProxy(b *testing.B, host string, port int, latency time.Duration) *proxy.Proxy {
	b.Helper()
	p, err := proxy.ParseProxyLine(fmt.Sprintf("http://%s:%d", host, port))
	if err != nil {
		b.Fatal(err)
	}
	p.MarkAlive(latency)
	return p
}

// wsBenchClient registers a fake hub client the way wsClient does in
// adminws_test.go: the conn is never touched outside the hub's bookkeeping.
func wsBenchClient(b *testing.B, a *admin) *wsConn {
	b.Helper()
	c := &wsConn{conn: &websocket.Conn{}, send: make(chan []byte, 8)}
	if !a.ws.add(c) {
		b.Fatal("hub refused the bench client")
	}
	b.Cleanup(func() { a.ws.remove(c) })
	return c
}

// BenchmarkWSDelta covers both delta shapes over a tracked set at the render
// cap (jsonRowCap rows, one hub client attached, the subscription wired):
//
//   - tick: one incremental applyDirtyWS broadcast — the per-row bucket
//     lookups and re-renders of the tracked set, the dirty-add insertions,
//     the discovered removals, and the marshal. The churn between renders
//     models one second of production: ~25 collector adds (the rows dropped
//     last tick come back; bucket.Add marks them dirty through the
//     subscription), ~25 revalidation drops and ~50 revalidation re-stamps.
//   - heal: one fullHealWS broadcast — the whole-queue LiveListUnranked scan,
//     the full render, the diff against the tracked set, and the marshal.
//
// The setup heal runs before ResetTimer, so both sub-benchmarks measure
// steady state (tracked set already populated) and every timed tick takes
// the incremental path.
func BenchmarkWSDelta(b *testing.B) {
	a, bucket := benchAdmin(b)
	c := wsBenchClient(b, a)
	a.subscribeBucket(bucket)

	seeded := make([]*proxy.Proxy, jsonRowCap)
	for i := range seeded {
		seeded[i] = benchProxy(b, fmt.Sprintf("10.%d.%d.%d", (i>>16)&0xff, (i>>8)&0xff, i&0xff), 8080, 30*time.Millisecond)
		bucket.Add(seeded[i])
	}

	// Setup heal: one full render populates the tracked set and drains the
	// seeding burst out of the dirty set.
	a.notifyWSChanged()
	select {
	case <-c.send:
	default:
	}

	b.Run("tick", func(b *testing.B) {
		b.ReportAllocs()
		dropped := make([]*proxy.Proxy, 0, 25)
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			// Collector adds: the rows dropped last tick come back. Add marks
			// them dirty through the subscription — the same path every
			// production add takes.
			for _, p := range dropped {
				bucket.Add(p)
			}
			dropped = dropped[:0]
			// Revalidation drops: the tracker discovers them through the
			// failed per-row lookup, no bucket event needed.
			for j := 0; j < 25; j++ {
				if p := seeded[(i*25+j)%len(seeded)]; bucket.Remove(p) {
					dropped = append(dropped, p)
				}
			}
			// Revalidation re-stamps: a fresh proof of life moves the latency
			// EMA and the OK counter on tracked rows (no bucket event).
			for j := 0; j < 50; j++ {
				seeded[(i*50+j)%len(seeded)].MarkAlive(time.Duration(20+i%40) * time.Millisecond)
			}
			a.notifyWSChanged()
			select {
			case <-c.send:
			default:
			}
		}
	})

	b.Run("heal", func(b *testing.B) {
		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			// Rows that moved between heals: the diff must carry them.
			for j := 0; j < 25; j++ {
				seeded[(i*40+j)%len(seeded)].MarkAlive(time.Duration(20+i%40) * time.Millisecond)
			}
			// Pending adds at heal time: fullHealWS drains the dirty set
			// before the render, exactly as a burst-triggered resync does.
			for j := 0; j < 25; j++ {
				a.ws.markDirty(seeded[(i*25+400+j)%len(seeded)].Key())
			}
			// Force the heal path for every broadcast, the way backdateHeal
			// does in adminws_test.go.
			a.ws.dirtyMu.Lock()
			a.ws.lastFull = time.Now().Add(-2 * wsFullHealInterval)
			a.ws.dirtyMu.Unlock()
			a.notifyWSChanged()
			select {
			case <-c.send:
			default:
			}
		}
	})
}
