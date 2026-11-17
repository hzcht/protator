package main

// Benchmark for the export channel's periodic rebuild (measurement only).
// The rebuild runs every refresh interval (config default: every 5 minutes)
// and is the one O(queue) pass the distribution channel pays for.

import (
	"fmt"
	"io"
	"log"
	"testing"
	"time"

	"protator/proxy"
)

// benchExportBucket seeds n proven entries — a recent proof of life on every
// one, so the whole queue sits inside the AliveChecked window the rebuild
// samples. Hosts are unique per index the way proxy/pick_bench_test.go's
// benchBucket does it: reusing one host with a rotating port collides past
// 65535 entries and the bucket silently dedups them.
func benchExportBucket(b *testing.B, n int) *proxy.Bucket {
	b.Helper()
	bucket := proxy.NewBucket(0)
	proxies := make([]*proxy.Proxy, n)
	for i := range proxies {
		proxies[i] = &proxy.Proxy{Schema: "http", Host: fmt.Sprintf("10.%d.%d.%d", (i>>16)&0xff, (i>>8)&0xff, i&0xff), Port: 8080}
		proxies[i].MarkAlive(time.Second)
	}
	bucket.Seed(proxies)
	return bucket
}

// BenchmarkLiveListUnranked is one export rebuild: the unranked AliveChecked
// scan, the reshuffle, and the truncation to the sample size. listSize is the
// shipped config default (fillDefaults: list_size = 1000). The unranked scan
// is deliberately the cheap one — ranking the whole queue is the admin page's
// cost (BenchmarkLiveListPage in the proxy package) — so its price stays
// visible at the queue sizes production actually runs.
func BenchmarkLiveListUnranked(b *testing.B) {
	// rebuild logs one line per rebuild and a bench run is thousands of
	// rebuilds: discard the writes (the formatting stays — it is part of the
	// work) and put the old sink back when done.
	prev := log.Writer()
	log.SetOutput(io.Discard)
	b.Cleanup(func() { log.SetOutput(prev) })

	for _, n := range []int{1000, 70000} {
		svc := &exportService{bucket: benchExportBucket(b, n), listSize: 1000}
		b.Run(fmt.Sprintf("queue=%d", n), func(b *testing.B) {
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				svc.rebuild()
			}
		})
	}
}
