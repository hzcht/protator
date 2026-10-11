package proxy

import (
	"fmt"
	"path/filepath"
	"testing"
	"time"
)

// The hot paths of this program are invisible without numbers: a pick, a page
// of live rows and a queue save are all "fast enough" right up until the queue
// is two million entries, and then one of them is a second of CPU per client
// request. These exist so a regression in any of them shows up as a bench
// diff, not as "the proxy got slower".

func benchBucket(n int) *Bucket {
	b := NewBucket(0)
	proxies := make([]*Proxy, n)
	for i := range proxies {
		// One host per index: reusing a single host with Port: 8000+i%65535
		// collides past 65535 entries and Seed dedups them, so queue=70000
		// silently measured 65535.
		proxies[i] = &Proxy{Schema: "http", Host: fmt.Sprintf("10.%d.%d.%d", (i>>16)&0xff, (i>>8)&0xff, i&0xff), Port: 8080}
		// Production proxies arrive with the identity precomputed (the checker
		// sets it before publication); without it the bench measures a Sprintf
		// per Key() that production never pays.
		proxies[i].keyCache = proxies[i].URL()
	}
	b.Seed(proxies)
	// Prove a slice of them, so the picker has a tier worth sampling: the
	// all-unproven case measures a different thing (a scan that only ever
	// ranks stales).
	for i, p := range proxies {
		if i%20 == 0 {
			p.MarkServeOK(time.Second)
			b.Promote(p)
		}
	}
	return b
}

// BenchmarkPickHealthy is the serving path: every client request runs it, and
// every failover retry runs it again.
func BenchmarkPickHealthy(b *testing.B) {
	for _, n := range []int{1000, 70000} {
		bucket := benchBucket(n)
		b.Run(fmt.Sprintf("queue=%d", n), func(b *testing.B) {
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				if _, err := bucket.PickHealthy(b.Context(), 8, nil); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

// BenchmarkLiveListPage is the admin path: ranking a page of the queue is the
// most expensive read the list renders. (Country/ASN filtering happens one
// layer up, in admin live(), not in LiveListPage — there is no filter to pass
// here.)
func BenchmarkLiveListPage(b *testing.B) {
	bucket := benchBucket(70000)
	b.Run("scope=checked limit=1000", func(b *testing.B) {
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			if rows, _ := bucket.LiveListPage(AliveChecked, 15*time.Minute, 1000); len(rows) == 0 {
				b.Fatal("no rows")
			}
		}
	})
}

// BenchmarkSaveBucketAtomic covers the size pass and the write, which used to
// allocate a string per queue entry twice over.
func BenchmarkSaveBucketAtomic(b *testing.B) {
	proxies := make([]*Proxy, 50000)
	for i := range proxies {
		proxies[i] = &Proxy{Schema: "http", Host: "10.0.0.1", Port: 8000 + i%65535}
	}
	path := filepath.Join(b.TempDir(), "q.lst")
	const budget = 256 << 20
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if err := SaveBucketAtomic(path, proxies, budget); err != nil {
			b.Fatal(err)
		}
	}
}

// BenchmarkCandidatePoolAddAtCap is the checker's write path: at the pool's cap
// every Add also evicts, so the append cost must stay flat as the file grows.
func BenchmarkCandidatePoolAddAtCap(b *testing.B) {
	pool := NewCandidatePool(filepath.Join(b.TempDir(), "pool.lst"), 1<<40, 1000)
	defer pool.Close()
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		pool.Add(Candidate{Host: "10.0.0.1", Port: 9000 + i%65535})
	}
}

// BenchmarkPinPoolSetAtCap is the stickiness write path: at the cap it evicts,
// and eviction used to scan the whole table under the lock every dial needs.
func BenchmarkPinPoolSetAtCap(b *testing.B) {
	p := NewPinPool(time.Minute, 10000)
	// Prebuilt outside the timed loop: building the key with Sprintf and the
	// proxy literal on every iteration measured the benchmark's own allocation
	// instead of the Set. Twice the cap, rotating, so every Set still evicts.
	const rotating = 20000
	keys := make([]string, rotating)
	vals := make([]*Proxy, rotating)
	for i := range keys {
		keys[i] = fmt.Sprintf("k%d", i)
		vals[i] = &Proxy{Schema: "http", Host: "10.0.0.1", Port: 8000 + i}
		vals[i].keyCache = vals[i].URL()
	}
	for i := 0; i < 10000; i++ {
		p.Set(keys[i], vals[i])
	}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		p.Set(keys[i%rotating], vals[i%rotating])
	}
}

// BenchmarkExtractBase64Body guards the new base64 pass: it runs on every
// fetched body, so the guard has to reject plain pages quickly.
func BenchmarkExtractBase64Body(b *testing.B) {
	e, err := NewExtractor(nil)
	if err != nil {
		b.Fatal(err)
	}
	body := []byte("<html><body><table><tr><td>1.2.3.4</td><td>8080</td></tr></table></body></html>")
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		if got := e.Extract(body); len(got) != 0 {
			b.Fatalf("got %d candidates from a plain page", len(got))
		}
	}
}
