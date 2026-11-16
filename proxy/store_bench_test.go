package proxy

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// benchmarkAuditFile writes n proxy lines to a temp file. The audit trail on
// the author's box reached 500k lines (20 MB); 100k is enough to make the
// difference between a full-file read and a bounded tail read obvious without
// slowing the benchmark setup to disk speed.
func benchmarkAuditFile(b *testing.B, n int) string {
	b.Helper()
	path := filepath.Join(b.TempDir(), "good_proxies.last")
	var sb strings.Builder
	sb.Grow(n * 32)
	for i := 0; i < n; i++ {
		fmt.Fprintf(&sb, "http://10.%d.%d.%d:8080\n", i/65536%256, i/256%256, i%256)
	}
	if err := os.WriteFile(path, []byte(sb.String()), 0o644); err != nil {
		b.Fatal(err)
	}
	return path
}

// BenchmarkReadQueueLast measures the startup seed read: the cost must be
// bounded by the cap, not by the number of lines on disk.
func BenchmarkReadQueueLast(b *testing.B) {
	path := benchmarkAuditFile(b, 100000)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if got := ReadQueueLast(path, 5000); len(got) == 0 {
			b.Fatal("empty tail")
		}
	}
}
