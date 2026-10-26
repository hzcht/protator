package proxy

import (
	"context"
	"fmt"
	"math/rand/v2"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// The bugs that hurt this program in production were all concurrency/capacity
// bugs that only appear under sustained load: a corrupted index, a hot tail
// pointing at evicted entries, a pin map disagreeing with its reverse index.
// Unit tests cover one operation at a time; this hammers the shared structures
// the way 600 checker workers, the revalidation pass and client dials do, and
// then asserts the invariants single-operation tests cannot see break.
func TestBucketSoakKeepsInvariants(t *testing.T) {
	const workers = 16
	const ops = 400
	b := NewBucket(0) // unbounded: eviction has its own test
	pins := NewPinPool(time.Minute, 100000)

	var notified atomic.Int64
	b.Subscribe(func(p *Proxy, added bool) { notified.Add(1) })

	var wg sync.WaitGroup
	for g := 0; g < workers; g++ {
		wg.Add(1)
		go func(g int) {
			defer wg.Done()
			r := rand.New(rand.NewPCG(uint64(g+1), uint64(g*7919+13)))
			var mine []*Proxy
			for i := 0; i < ops; i++ {
				switch r.IntN(10) {
				case 0, 1, 2, 3:
					// Add a unique proxy. Production arrivals carry the
					// identity precomputed; the soak does the same so it
					// measures the structure, not Sprintf.
					p := &Proxy{
						Schema: "http",
						Host:   fmt.Sprintf("10.%d.%d.%d", g, (i>>8)&0xff, i&0xff),
						Port:   10000 + (i % 50000),
					}
					p.keyCache = p.URL()
					if i%2 == 0 {
						p.SetSource("http://soak.test/list")
					}
					if b.Add(p) {
						mine = append(mine, p)
					}
				case 4:
					// Remove something we added (or nothing at all).
					if len(mine) > 0 {
						v := mine[r.IntN(len(mine))]
						b.Remove(v)
					}
				case 5:
					if len(mine) > 0 {
						b.Promote(mine[r.IntN(len(mine))])
					}
				case 6, 7:
					ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
					_, err := b.PickHealthy(ctx, 8, nil)
					cancel()
					if err != nil {
						t.Errorf("pick failed on non-empty queue: %v", err)
						return
					}
				case 8:
					_ = b.Len()
					_ = b.HotLen()
					_ = b.SourceCounts()
				case 9:
					k := fmt.Sprintf("soak-%d-%d", g, r.IntN(64))
					switch r.IntN(4) {
					case 0:
						if len(mine) > 0 {
							pins.Set(k, mine[r.IntN(len(mine))])
						}
					case 1:
						_ = pins.Get(k)
					case 2:
						pins.Del(k)
					case 3:
						if len(mine) > 0 {
							pins.DropProxy(mine[r.IntN(len(mine))].Key())
						}
					}
				}
			}
		}(g)
	}
	wg.Wait()

	if notified.Load() == 0 {
		t.Fatal("no bucket notifications observed during the soak")
	}

	// Index consistency: every slot's key maps back to its slot, no dupes.
	b.mu.RLock()
	defer b.mu.RUnlock()
	if len(b.proxies) != len(b.index) {
		t.Fatalf("proxies=%d index=%d: duplicate or missing keys", len(b.proxies), len(b.index))
	}
	for i, p := range b.proxies {
		if got, ok := b.index[p.Key()]; !ok || got != i {
			t.Fatalf("index[%q] = (%d, %v), want (%d, true)", p.Key(), got, ok, i)
		}
	}
	// Hot tail consistency, both directions: the tail must only hold queue
	// members, and the reverse map must agree with the array exactly.
	if len(b.hot) != len(b.hotIdx) {
		t.Fatalf("hot=%d hotIdx=%d", len(b.hot), len(b.hotIdx))
	}
	for i, p := range b.hot {
		if got, ok := b.hotIdx[p]; !ok || got != i {
			t.Fatalf("hotIdx mismatch at %d", i)
		}
		if _, ok := b.index[p.Key()]; !ok {
			t.Fatalf("hot entry %q not in the queue", p.Key())
		}
	}
	for p, idx := range b.hotIdx {
		if idx < 0 || idx >= len(b.hot) || b.hot[idx] != p {
			t.Fatalf("hotIdx points outside the tail")
		}
	}

	// Pin pool consistency, three ways: the map, the reverse index and the
	// LRU list must agree, with no empty reverse sets and no element the map
	// forgot.
	pins.mu.RLock()
	defer pins.mu.RUnlock()
	if len(pins.m) != pins.lru.Len() {
		t.Fatalf("pin map=%d lru=%d", len(pins.m), pins.lru.Len())
	}
	for k, e := range pins.m {
		entry, ok := e.Value.(*pinEntry)
		if !ok || entry == nil {
			t.Fatalf("pin %q holds no entry", k)
		}
		if entry.key != k {
			t.Fatalf("pin element key=%q indexed under %q", entry.key, k)
		}
		set, ok := pins.byPrx[entry.p.Key()]
		if !ok {
			t.Fatalf("pin %q missing from reverse index", k)
		}
		if _, ok := set[k]; !ok {
			t.Fatalf("pin %q not in its proxy's set", k)
		}
		found := false
		for le := pins.lru.Front(); le != nil; le = le.Next() {
			if le == e {
				found = true
				break
			}
		}
		if !found {
			t.Fatalf("pin %q in the map but not in the LRU list", k)
		}
	}
	for pk, set := range pins.byPrx {
		if len(set) == 0 {
			t.Fatalf("empty reverse set left for %q", pk)
		}
		for k := range set {
			e, ok := pins.m[k]
			if !ok {
				t.Fatalf("reverse index for %q references missing pin %q", pk, k)
			}
			if e.Value.(*pinEntry).p.Key() != pk {
				t.Fatalf("pin %q indexed under %q but points elsewhere", k, pk)
			}
		}
	}
}
