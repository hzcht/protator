package proxy

import (
	"testing"
	"time"
)

// The two serving latencies are read as deltas between snapshots, so a sample
// must land in exactly one bucket: a cumulative bug would make every request
// look fast in every bucket and hide the tail the histogram exists for.
func TestDurationBandsObserve(t *testing.T) {
	var b DurationBands
	samples := []time.Duration{
		0,
		100 * time.Millisecond,
		101 * time.Millisecond,
		500 * time.Millisecond,
		500*time.Millisecond + 1,
		time.Second,
		3 * time.Second,
		10 * time.Second,
		10*time.Second + 1,
	}
	for _, d := range samples {
		b.Observe(d)
	}
	got := map[string]int64{}
	b.snapshot(got, "x")
	want := map[string]int64{
		"x_le_100ms_total": 2, // 0 and exactly 100ms
		"x_le_500ms_total": 2, // 101ms and exactly 500ms
		"x_le_1s_total":    2, // 500ms+1 and exactly 1s
		"x_le_3s_total":    1,
		"x_le_10s_total":   1,
		"x_gt_10s_total":   1,
	}
	var total int64
	for k, v := range want {
		if got[k] != v {
			t.Errorf("%s = %d, want %d", k, got[k], v)
		}
		total += got[k]
	}
	if total != int64(len(samples)) {
		t.Fatalf("bucket sum = %d, want %d (one bucket per sample)", total, len(samples))
	}
}

// The serve-funnel keys are a contract with the admin page and with anyone
// reading /api/metrics: a rename or a missing Reset entry breaks the operator's
// delta maths silently.
func TestRegistryServeFunnelSnapshot(t *testing.T) {
	var r Registry
	r.ServeDial.Observe(2 * time.Second)
	r.ServeTTFB.Observe(5 * time.Second)
	r.observeServeAttempts(0) // defensive: a zero count must not panic or vanish
	r.observeServeAttempts(1)
	r.observeServeAttempts(4)
	r.observeServeAttempts(7)
	r.ServeQueueWaits.Add(3)
	r.ServeQueueWaitNanos.Add(42)
	r.QueueShrinkWarnings.Add(1)

	got := r.Snapshot()
	want := map[string]int64{
		"serve_dial_le_3s_total":      1,
		"serve_ttfb_le_10s_total":     1,
		"serve_attempts_1_total":      2, // 0 and 1 both mean "first proxy"
		"serve_attempts_2_total":      0,
		"serve_attempts_3_total":      0,
		"serve_attempts_4plus_total":  2,
		"serve_queue_waits_total":     3,
		"serve_queue_wait_ns_total":   42,
		"queue_shrink_warnings_total": 1,
	}
	for k, v := range want {
		if got[k] != v {
			t.Errorf("%s = %d, want %d", k, got[k], v)
		}
	}

	r.Reset()
	got = r.Snapshot()
	for k := range want {
		if got[k] != 0 {
			t.Errorf("%s = %d after Reset, want 0", k, got[k])
		}
	}
}
