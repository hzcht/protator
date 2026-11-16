package proxy

import (
	"context"
	"sync/atomic"
	"testing"
	"time"
)

// revalidateChecker returns a checker whose revalidation can only fail at the
// pre-dial stage (the test entries point at closed loopback ports), so these
// tests exercise RevalidateMany's own logic — filtering, sorting, capping,
// worker fan-out, counting, dropping — without any network traffic.
//
// Revalidate skips the bogon filter (preDial only dials), so no allowBogon is
// needed even though the entries are loopback addresses.
func revalidateChecker() *Checker {
	return testChecker(nil, "9.9.9.9")
}

// deadProxies builds n distinct queue entries, each on its own closed loopback
// port. Ports are allocated until unique because the bucket dedups by Key():
// two entries sharing host:port would collapse into one and quietly shrink the
// queue under the test.
func deadProxies(t *testing.T, n int) []*Proxy {
	t.Helper()
	used := make(map[int]struct{}, n)
	out := make([]*Proxy, 0, n)
	for len(out) < n {
		port := closedPort(t)
		if _, dup := used[port]; dup {
			continue
		}
		used[port] = struct{}{}
		// keyCache must be set before the bucket sees the proxy (AGENTS.md:
		// every construction site fills it), and meta is allocated up front so
		// no later SetGeoIP can race an admin read.
		p := &Proxy{Schema: "http", Host: "127.0.0.1", Port: port, meta: &ProxyMeta{}}
		p.keyCache = p.URL()
		out = append(out, p)
	}
	return out
}

// RevalidateMany must count what it actually checked, not what it planned: the
// pass budget sizes the next one from this number, and a cancelled pass that
// reported the planned length over-stated throughput forever.
func TestRevalidateManyCountsChecked(t *testing.T) {
	proxies := deadProxies(t, 8)
	bucket := NewBucket(1000)
	if n := bucket.Seed(proxies); n != len(proxies) {
		t.Fatalf("seeded %d of %d", n, len(proxies))
	}

	got := RevalidateMany(context.Background(), revalidateChecker(), bucket, bucket.Snapshot(), 4, 0, 0, nil)
	if got != len(proxies) {
		t.Fatalf("checked = %d, want %d (every entry was attempted)", got, len(proxies))
	}
	// Every entry failed its pre-dial, so all of them must be gone.
	if n := bucket.Len(); n != 0 {
		t.Errorf("bucket still holds %d dead entries", n)
	}
}

// The per-pass cap is what makes a huge queue converge: without it a pass over
// a million entries never reaches the stale tail twice.
func TestRevalidateManyCapsPass(t *testing.T) {
	proxies := deadProxies(t, 10)
	bucket := NewBucket(1000)
	bucket.Seed(proxies)

	got := RevalidateMany(context.Background(), revalidateChecker(), bucket, bucket.Snapshot(), 3, 0, 4, nil)
	if got != 4 {
		t.Fatalf("checked = %d, want the pass cap 4", got)
	}
	if n := bucket.Len(); n != 6 {
		t.Errorf("bucket holds %d entries, want 6 left after dropping the 4 checked", n)
	}
}

// Stale-first ordering: the cap must take the entries checked longest ago, or
// the tail never rotates and the same freshest entries are re-checked on every
// pass.
func TestRevalidateManyChecksStalestFirst(t *testing.T) {
	now := time.Now()
	proxies := deadProxies(t, 5)
	for i, p := range proxies {
		// i=0 is the stalest; each later entry is one minute fresher.
		atomic.StoreInt64(&p.lastCheck, now.Add(time.Duration(i)*time.Minute).UnixNano())
	}
	bucket := NewBucket(1000)
	bucket.Seed(proxies)

	// Snapshot order is internal; swap two entries so the sort is what decides,
	// not the seed order.
	snap := bucket.Snapshot()
	snap[0], snap[4] = snap[4], snap[0]

	if got := RevalidateMany(context.Background(), revalidateChecker(), bucket, snap, 1, 0, 2, nil); got != 2 {
		t.Fatalf("checked = %d, want 2", got)
	}
	// The two stalest were checked and dropped; the three freshest survive.
	if n := bucket.Len(); n != 3 {
		t.Fatalf("bucket holds %d, want 3 remaining", n)
	}
	for _, p := range bucket.Snapshot() {
		if d := p.LastCheck().Sub(now); d < 2*time.Minute {
			t.Errorf("a fresher entry was re-checked before an older one: lastCheck=+%s", d)
		}
	}
}

// Recently-served proxies are alive by real traffic, so a pass skips them:
// re-checking costs a full validation per entry, and live traffic is stronger
// evidence than a probe.
func TestRevalidateManySkipsRecentlyServed(t *testing.T) {
	proxies := deadProxies(t, 2)
	served, idle := proxies[0], proxies[1]
	served.MarkServeOK(time.Millisecond) // stamps lastOK

	bucket := NewBucket(1000)
	bucket.Seed(proxies)

	got := RevalidateMany(context.Background(), revalidateChecker(), bucket, bucket.Snapshot(), 1, time.Hour, 0, nil)
	if got != 1 {
		t.Fatalf("checked = %d, want 1 (the recently-served entry must be skipped)", got)
	}
	if n := bucket.Len(); n != 1 {
		t.Fatalf("bucket holds %d entries, want 1", n)
	}
	if bucket.Get(served.Key()) == nil {
		t.Error("recently-served entry was dropped")
	}
	if bucket.Get(idle.Key()) != nil {
		t.Error("the unserved entry survived a failed revalidation")
	}
}

// A cancelled context must check nothing: the pass is abandoned, not acted on
// (acting outlives the shutdown budget).
func TestRevalidateManyCancelledChecksNothing(t *testing.T) {
	proxies := deadProxies(t, 1)
	bucket := NewBucket(1000)
	bucket.Seed(proxies)

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	start := time.Now()
	if got := RevalidateMany(ctx, revalidateChecker(), bucket, bucket.Snapshot(), 2, 0, 0, nil); got != 0 {
		t.Errorf("checked = %d after cancel, want 0", got)
	}
	if elapsed := time.Since(start); elapsed > time.Second {
		t.Errorf("cancelled pass took %s", elapsed)
	}
	if n := bucket.Len(); n != 1 {
		t.Errorf("cancelled pass dropped an entry: %d left", n)
	}
}

// RevalidateNow backs the admin action: it re-checks exactly the selected
// entries and leaves the rest of the queue alone.
func TestRevalidateNowOnlyTouchesSelection(t *testing.T) {
	proxies := deadProxies(t, 2)
	selected, untouched := proxies[0], proxies[1]
	bucket := NewBucket(1000)
	bucket.Seed(proxies)

	RevalidateNow(context.Background(), revalidateChecker(), bucket, []*Proxy{selected}, 1, nil)

	if bucket.Get(selected.Key()) != nil {
		t.Error("selected dead proxy survived the forced revalidation")
	}
	if bucket.Get(untouched.Key()) == nil {
		t.Error("forced revalidation touched an unselected proxy")
	}
}

// Empty selection is a no-op, not a full-queue sweep: the admin action sends
// the rows the operator picked.
func TestRevalidateNowEmptyIsNoop(t *testing.T) {
	proxies := deadProxies(t, 1)
	bucket := NewBucket(1000)
	bucket.Seed(proxies)

	RevalidateNow(context.Background(), revalidateChecker(), bucket, nil, 1, nil)
	if n := bucket.Len(); n != 1 {
		t.Errorf("empty selection removed entries: %d left", n)
	}
}

// A nil *DebugProxies must be tolerated: the admin action and every test here
// run without one. A proxy that fails its pre-dial never reaches debug.Add, so
// this pins the drop path; the success path is covered by the pipeline test,
// which builds a real DebugProxies.
func TestRevalidateManyNilDebug(t *testing.T) {
	proxies := deadProxies(t, 1)
	bucket := NewBucket(10)
	bucket.Seed(proxies)
	if got := RevalidateMany(context.Background(), revalidateChecker(), bucket, bucket.Snapshot(), 1, 0, 0, nil); got != 1 {
		t.Fatalf("checked = %d, want 1", got)
	}
	if n := bucket.Len(); n != 0 {
		t.Errorf("dead entry survived: %d left", n)
	}
}

// strikeChecker is revalidateChecker with an explicit demotion threshold.
func strikeChecker(strikes int) *Checker {
	c := revalidateChecker()
	c.cfg.Storage.DemoteAfterFails = strikes
	return c
}

// One failed pass is the wire, not the proxy: with demote_after_fails = 2 the
// entry survives its first strike (and stays unstamped, so the stalest-first
// sort retries it next pass) and is removed only on the second. The old
// behaviour dropped it immediately, which is how a throttled test server
// emptied the queue.
func TestRevalidateDemotesOnlyAfterStrikes(t *testing.T) {
	proxies := deadProxies(t, 1)
	bucket := NewBucket(10)
	bucket.Seed(proxies)
	checker := strikeChecker(2)

	doubtBefore := Stats.RevalDoubt.Load()
	droppedBefore := Stats.RevalDropped.Load()

	RevalidateMany(context.Background(), checker, bucket, bucket.Snapshot(), 1, 0, 0, nil)
	if n := bucket.Len(); n != 1 {
		t.Fatalf("entry dropped on the first strike: %d left, want 1", n)
	}
	if got := proxies[0].CheckFails(); got != 1 {
		t.Errorf("strikes = %d, want 1", got)
	}
	if got := Stats.RevalDoubt.Load() - doubtBefore; got != 1 {
		t.Errorf("reval_doubt delta = %d, want 1 (the retained failure must be visible)", got)
	}

	RevalidateMany(context.Background(), checker, bucket, bucket.Snapshot(), 1, 0, 0, nil)
	if n := bucket.Len(); n != 0 {
		t.Fatalf("second strike did not demote: %d left", n)
	}
	if got := Stats.RevalDropped.Load() - droppedBefore; got != 1 {
		t.Errorf("reval_dropped delta = %d, want 1", got)
	}
}

// A cancelled pass must not read as a verdict: the in-flight check fails
// because we cancelled it, so the entry keeps its queue slot and its strikes.
func TestRevalidateOneIgnoresCancelledCheck(t *testing.T) {
	proxies := deadProxies(t, 1)
	bucket := NewBucket(10)
	bucket.Seed(proxies)

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := revalidateOne(ctx, revalidateChecker(), bucket, nil, proxies[0]); err != nil {
		t.Fatalf("revalidateOne: %v", err)
	}
	if n := bucket.Len(); n != 1 {
		t.Fatalf("entry removed on a cancelled pass: %d left", n)
	}
	if got := proxies[0].CheckFails(); got != 0 {
		t.Errorf("strikes = %d, want 0 after a cancelled check", got)
	}
}

// demoteAfter is the config gate for the strike policy. Unset (the literal
// Config{} every in-test checker gets) must mean one strike, i.e. the old
// drop-on-first-failure behaviour, not "never demote".
func TestDemoteAfter(t *testing.T) {
	cases := []struct {
		name  string
		set   int
		nilCk bool
		want  int64
	}{
		{"unset means one strike", 0, false, 1},
		{"explicit one", 1, false, 1},
		{"negative", -3, false, 1},
		{"three strikes", 3, false, 3},
		{"nil checker", 0, true, 1},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if tc.nilCk {
				if got := demoteAfter(nil); got != tc.want {
					t.Fatalf("demoteAfter(nil) = %d, want %d", got, tc.want)
				}
				return
			}
			if got := demoteAfter(strikeChecker(tc.set)); got != tc.want {
				t.Fatalf("demoteAfter(%d) = %d, want %d", tc.set, got, tc.want)
			}
		})
	}
}
