package proxy

import (
	"strconv"
	"testing"
	"time"
)

// pinProxy builds a throwaway proxy with a stable, unique address per index.
func pinProxy(t *testing.T, port int) *Proxy {
	t.Helper()
	p, err := ParseProxyLine("http://10.0.0." + strconv.Itoa(port%250) + ":" + strconv.Itoa(8000+port))
	if err != nil {
		t.Fatal(err)
	}
	return p
}

// At the cap the least recently used pin must be the one evicted, and a Get
// must count as use. The eviction used to scan the whole map under the write
// lock, so this also pins the ordering contract the list now provides in O(1).
func TestPinPoolLRUEviction(t *testing.T) {
	p := NewPinPool(time.Minute, 3)
	a, b, c := pinProxy(t, 1), pinProxy(t, 2), pinProxy(t, 3)
	p.Set("a", a)
	p.Set("b", b)
	p.Set("c", c)

	// Touch a: without this the first insertion would be evicted.
	if got := p.Get("a"); got != a {
		t.Fatalf("Get(a) = %v", got)
	}

	d := pinProxy(t, 4)
	p.Set("d", d)

	if p.Len() != 3 {
		t.Fatalf("pool grew past its cap: %d", p.Len())
	}
	for _, k := range []string{"a", "c", "d"} {
		if p.Get(k) == nil {
			t.Errorf("pin %q was evicted although it was recently used", k)
		}
	}
	if p.Get("b") != nil {
		t.Error("the least recently used pin (b) survived eviction")
	}
}

// Re-pinning the same key to a different proxy must refresh the reverse index:
// DropProxy for the old proxy has to release the pin, DropProxy for the new one
// must keep it.
func TestPinPoolRepinReverseIndex(t *testing.T) {
	p := NewPinPool(time.Minute, 8)
	old, new1 := pinProxy(t, 10), pinProxy(t, 11)
	p.Set("k", old)
	p.Set("k", new1)

	p.DropProxy(old.Key())
	if got := p.Get("k"); got != new1 {
		t.Fatalf("pin lost after dropping the *old* proxy: %v", got)
	}

	p.DropProxy(new1.Key())
	if got := p.Get("k"); got != nil {
		t.Fatalf("pin survived dropping its current proxy: %v", got)
	}
	if p.Len() != 0 {
		t.Fatalf("pool still reports %d pins", p.Len())
	}
}

// Expiry must release pins nobody asked about again: the sweep walks the LRU
// tail, which is ordered by recency, so it costs O(expired) rather than a full
// map scan. A single Get on an expired pin only removes that pin; the sweep
// runs from the next mutation, which is what this exercises.
func TestPinPoolExpirySweep(t *testing.T) {
	p := NewPinPool(50*time.Millisecond, 2048)
	for i := 0; i < 600; i++ { // past pinSweepEvery, so sweeps do run
		p.Set("k"+strconv.Itoa(i), pinProxy(t, i))
	}
	time.Sleep(120 * time.Millisecond)

	// A fresh pin is unaffected; the sweep below walks the LRU tail from the
	// back and stops at the first live entry.
	warm := pinProxy(t, 900)
	p.Set("warm", warm)
	if got := p.Get("warm"); got != warm {
		t.Fatalf("the fresh pin was swept: %v", got)
	}

	p.mu.Lock()
	p.ops = pinSweepEvery
	p.maybeSweepLocked(time.Now().UnixNano())
	p.mu.Unlock()

	if n := p.Len(); n != 1 {
		t.Fatalf("expiry sweep left %d pins alive, want 1 (the fresh one)", n)
	}
}
