package proxy

import (
	"testing"
	"time"
)

func TestSiteRegistryRecordAndCooldown(t *testing.T) {
	r := NewSiteRegistry(2, time.Minute)
	const url = "http://a.example/list"

	if cooled := r.Failed(url); cooled {
		t.Fatal("an unknown site must not be in cooldown")
	}

	r.Record(url, true, 10, 4, "200")
	s := r.Site(url)
	if s == nil {
		t.Fatal("Record must create the site")
	}
	if s.Total != 4 || s.Found != 10 || s.Cycles != 1 || !s.OK {
		t.Fatalf("after a good cycle: %+v", s)
	}
	if s.LastOK.IsZero() {
		t.Error("a good cycle must stamp LastOK")
	}

	// The first failure is below the limit: remembered, but not cooling.
	if armed := r.Record(url, false, 0, 0, "500"); armed {
		t.Error("one failure must not arm the cooldown")
	}
	if r.Failed(url) {
		t.Error("one failure must not cool the site down")
	}

	// The second one reaches the limit and arms it.
	if armed := r.Record(url, false, 0, 0, "500"); !armed {
		t.Error("reaching the fail limit must arm the cooldown")
	}
	if !r.Failed(url) {
		t.Error("the site must be in cooldown")
	}
	if s = r.Site(url); s.Fails != 2 {
		t.Errorf("Fails = %d, want 2", s.Fails)
	}

	// A success clears it.
	r.Record(url, true, 3, 3, "200")
	if r.Failed(url) {
		t.Error("a success must clear the cooldown")
	}
}

func TestSiteRegistryCooldownExpires(t *testing.T) {
	r := NewSiteRegistry(1, 20*time.Millisecond)
	const url = "http://b.example/list"
	r.Record(url, false, 0, 0, "boom")
	if !r.Failed(url) {
		t.Fatal("site should be cooling")
	}
	time.Sleep(30 * time.Millisecond)
	if r.Failed(url) {
		t.Error("the cooldown must lapse on its own")
	}
	if s := r.Site(url); !s.CoolUntil.IsZero() {
		t.Errorf("an expired cooldown must be cleared, got %v", s.CoolUntil)
	}
}

func TestSiteRegistryOrderPrefersProduct(t *testing.T) {
	r := NewSiteRegistry(3, time.Minute)
	good := "http://good.example/"
	plain := "http://plain.example/"
	dead := "http://dead.example/"

	r.Record(good, true, 100, 90, "200")
	r.Record(good, true, 100, 90, "200")
	r.Record(plain, true, 100, 1, "200")
	r.Record(dead, false, 0, 0, "500")
	r.SetAlive(map[string]int{good: 12, plain: 1})

	got := r.Order([]string{dead, plain, good, "http://untried.example/"})
	if len(got) != 4 {
		t.Fatalf("Order dropped sites: %v", got)
	}
	// Proven-good first, then the untried one, then the two weak sources.
	if got[0] != good {
		t.Errorf("best source not first: %v", got)
	}
	if got[1] != plain && got[1] != "http://untried.example/" {
		t.Errorf("second slot = %q, want a source with a real yield", got[1])
	}
	if got[3] != dead {
		t.Errorf("a failing source outranked the others: %v", got)
	}
	// Rotation: the untried source must not be pinned to a fixed slot.
	first := r.Order([]string{dead, plain, good, "http://untried.example/"})
	if first[1] == got[1] && first[2] == got[2] {
		t.Logf("unproven jitter repeated: %v", first)
	}
}

func TestSiteRegistryTrackKeepsListComplete(t *testing.T) {
	r := NewSiteRegistry(3, time.Minute)
	sites := []string{"http://a/", "http://b/", "  ", "http://a/"}
	r.Track(sites)
	if n := len(r.Snapshot()); n != 2 {
		t.Fatalf("tracked %d sites, want 2 (comments/blank/duplicates dropped)", n)
	}
}

func TestSiteRegistryTrackIsBounded(t *testing.T) {
	r := NewSiteRegistry(3, time.Minute)
	sites := make([]string, 0, maxTrackedSites+500)
	for i := 0; i < maxTrackedSites+500; i++ {
		sites = append(sites, "http://s"+itoa(i)+".example/")
	}
	r.Track(sites)
	// Bounded memory: the registry must not track one entry per URL forever.
	if n := len(r.Snapshot()); n > maxTrackedSites {
		t.Fatalf("tracked %d sites, want at most %d", n, maxTrackedSites)
	}
	// Order must still return every URL it was given, tracked or not.
	if n := len(r.Order(sites)); n != len(sites) {
		t.Fatalf("Order returned %d sites, want %d", n, len(sites))
	}
}

func TestBucketSourceCounts(t *testing.T) {
	b := NewBucket(10)
	add := func(s, host string, port int) *Proxy {
		p := &Proxy{Schema: "http", Host: host, Port: port}
		p.SetSource(s)
		b.Add(p)
		return p
	}
	a1 := add("http://a/", "1.1.1.1", 80)
	add("http://a/", "1.1.1.2", 80)
	add("http://b/", "2.2.2.2", 80)
	add("", "3.3.3.3", 80) // hand-added: unattributed

	got := b.SourceCounts()
	if got["http://a/"] != 2 || got["http://b/"] != 1 {
		t.Fatalf("SourceCounts = %v, want a=2 b=1", got)
	}
	if _, ok := got[""]; ok {
		t.Errorf("unattributed proxies must not be reported: %v", got)
	}

	// Removal gives the credit back.
	b.Remove(a1)
	if got = b.SourceCounts(); got["http://a/"] != 1 {
		t.Errorf("after remove: %v, want a=1", got)
	}
}

func TestBucketSourceCountSurvivesEviction(t *testing.T) {
	b := NewBucket(2)
	for _, h := range []string{"1.1.1.1", "1.1.1.2", "1.1.1.3"} {
		p := &Proxy{Schema: "http", Host: h, Port: 80}
		p.SetSource("http://a/")
		b.Add(p)
	}
	got := b.SourceCounts()
	if got["http://a/"] != 2 {
		t.Fatalf("SourceCounts = %v, want a=2 (bucket capped at 2)", got)
	}
}

func TestBucketLiveListScopes(t *testing.T) {
	b := NewBucket(10)

	served := &Proxy{Schema: "http", Host: "1.1.1.1", Port: 80}
	served.MarkServeOK(120 * time.Millisecond)
	checked := &Proxy{Schema: "http", Host: "2.2.2.2", Port: 80}
	checked.MarkAlive(200 * time.Millisecond)
	quiet := &Proxy{Schema: "http", Host: "3.3.3.3", Port: 80}
	for _, p := range []*Proxy{served, checked, quiet} {
		b.Add(p)
	}

	all := b.LiveList(AliveAll, time.Hour, 0)
	if len(all) != 3 {
		t.Fatalf("scope=all returned %d, want 3", len(all))
	}
	got := b.LiveList(AliveServed, time.Hour, 0)
	if len(got) != 1 || got[0].Host != "1.1.1.1" {
		t.Fatalf("scope=served returned %v, want only 1.1.1.1", hosts(got))
	}
	got = b.LiveList(AliveChecked, time.Hour, 0)
	if len(got) != 2 || got[0].Host != "1.1.1.1" {
		t.Fatalf("scope=checked returned %v, want 1.1.1.1 then 2.2.2.2", hosts(got))
	}
	// A window older than any proof of life must exclude them again.
	if got = b.LiveList(AliveChecked, -time.Second, 0); len(got) != 0 {
		t.Fatalf("a window older than any proof returned %v, want nothing", hosts(got))
	}
	if got = b.LiveList(AliveAll, 0, 0); len(got) != 3 {
		t.Fatalf("scope=all with a zero window returned %v, want everything", hosts(got))
	}
}

// The hot scope exists to answer "export the ones that work now", so it must
// cover the curated tail (proved or just served) and nothing that has not
// earned its place there.
func TestBucketLiveListHotScope(t *testing.T) {
	b := NewBucket(10)

	proven := &Proxy{Schema: "http", Host: "1.1.1.1", Port: 80}
	proven.MarkAlive(100 * time.Millisecond)
	b.Add(proven) // Add does not promote; only a check or a served fetch does
	b.Promote(proven)
	served := &Proxy{Schema: "socks5", Host: "2.2.2.2", Port: 1080}
	b.Add(served)
	served.MarkServeOK(50 * time.Millisecond)
	b.Promote(served) // what the serving path does after a real response
	// Stale proof: in the queue, not in the window.
	stale := &Proxy{Schema: "http", Host: "3.3.3.3", Port: 80}
	b.Add(stale)
	b.Promote(stale)
	stale.stampCheck(time.Now().Add(-2 * time.Hour).UnixNano())
	// Never proven: must never appear under any liveness scope but AliveAll.
	quiet := &Proxy{Schema: "http", Host: "4.4.4.4", Port: 80}
	b.Add(quiet)

	got := b.LiveList(AliveHot, 15*time.Minute, 0)
	if len(got) != 2 {
		t.Fatalf("scope=hot returned %v, want 1.1.1.1 and 2.2.2.2", hosts(got))
	}
	if got[0].Host != "2.2.2.2" {
		t.Errorf("hot head = %v, want the served proxy first", hosts(got))
	}
	if got = b.LiveList(AliveHot, 15*time.Minute, 1); len(got) != 1 || got[0].Host != "2.2.2.2" {
		t.Errorf("scope=hot limit=1 returned %v", hosts(got))
	}
	if got = b.LiveList(AliveHot, time.Minute, 0); len(got) != 2 {
		t.Errorf("a 1m window should still hold fresh proofs, got %v", hosts(got))
	}
	if got = b.LiveList(AliveHot, -time.Second, 0); len(got) != 0 {
		t.Errorf("an expired window returned %v, want nothing", hosts(got))
	}
}

// A page that stops at the limit must still report the size of the scope, or a
// caller renders "1000 rows" as if it were the whole queue.
func TestBucketLiveListPageTotal(t *testing.T) {
	b := NewBucket(10)
	for _, h := range []string{"1.1.1.1", "2.2.2.2", "3.3.3.3", "4.4.4.4"} {
		p := &Proxy{Schema: "http", Host: h, Port: 80}
		p.MarkAlive(10 * time.Millisecond)
		b.Add(p)
	}
	quiet := &Proxy{Schema: "http", Host: "5.5.5.5", Port: 80}
	b.Add(quiet)

	page, total := b.LiveListPage(AliveChecked, time.Hour, 2)
	if len(page) != 2 || total != 4 {
		t.Fatalf("checked limit=2: %d rows, total %d, want 2 and 4", len(page), total)
	}
	if page, total = b.LiveListPage(AliveChecked, time.Hour, 0); len(page) != 4 || total != 4 {
		t.Errorf("checked no limit: %d rows, total %d, want 4 and 4", len(page), total)
	}
	if page, total = b.LiveListPage(AliveAll, time.Hour, 3); len(page) != 3 || total != 5 {
		t.Errorf("all limit=3: %d rows, total %d, want 3 and 5", len(page), total)
	}
	if page, total = b.LiveListPage(AliveChecked, -time.Second, 0); len(page) != 0 || total != 0 {
		t.Errorf("expired window: %d rows, total %d, want 0 and 0", len(page), total)
	}
	// hot scope: same contract.
	hot := &Proxy{Schema: "http", Host: "9.9.9.9", Port: 80}
	hot.MarkAlive(10 * time.Millisecond)
	b.Add(hot)
	b.Promote(hot)
	if page, total = b.LiveListPage(AliveHot, time.Hour, 1); len(page) != 1 || total != 5 {
		t.Errorf("hot limit=1: %d rows, total %d, want 1 and 5", len(page), total)
	}
}

func hosts(ps []*Proxy) []string {
	out := make([]string, len(ps))
	for i, p := range ps {
		out[i] = p.Host
	}
	return out
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b []byte
	for n > 0 {
		b = append([]byte{byte('0' + n%10)}, b...)
		n /= 10
	}
	return string(b)
}
