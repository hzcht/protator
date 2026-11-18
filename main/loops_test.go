package main

import "testing"

func TestQueueShrinking(t *testing.T) {
	cases := []struct {
		name string
		prev queueSample
		now  queueSample
		want bool
	}{
		{"a quarter gone", queueSample{live: 400}, queueSample{live: 300}, true},
		{"a third gone", queueSample{live: 4000}, queueSample{live: 2650}, true},
		{"a fifth gone", queueSample{live: 400}, queueSample{live: 320}, false},
		{"growth is not shrinkage", queueSample{live: 400}, queueSample{live: 500}, false},
		{"flat is not shrinkage", queueSample{live: 400}, queueSample{live: 400}, false},
		// Below the base the percentage is noise: losing half of a 150-entry
		// queue is a quiet minute, not a collapse.
		{"small base", queueSample{live: 150}, queueSample{live: 50}, false},
		// Exactly at the threshold the watchdog fires: the boundary belongs to
		// the alarm, not to silence.
		{"exactly a quarter", queueSample{live: 200}, queueSample{live: 150}, true},
	}
	for _, c := range cases {
		if got := queueShrinking(c.prev, c.now); got != c.want {
			t.Errorf("%s: queueShrinking(%d -> %d) = %v, want %v", c.name, c.prev.live, c.now.live, got, c.want)
		}
	}
}

func TestQueueTrendHourAgo(t *testing.T) {
	tr := newQueueTrend(3)
	tr.add(queueSample{live: 10, checksPassed: 100, revalDropped: 5})
	if _, ok := tr.hourAgo(); ok {
		t.Fatal("hourAgo reported a sample before the ring was full")
	}
	tr.add(queueSample{live: 20, checksPassed: 200, revalDropped: 10})
	tr.add(queueSample{live: 30, checksPassed: 300, revalDropped: 15})

	old, ok := tr.hourAgo()
	if !ok || old.live != 10 || old.checksPassed != 100 || old.revalDropped != 5 {
		t.Fatalf("hourAgo after fill = %+v, %v; want the oldest sample", old, ok)
	}

	tr.add(queueSample{live: 40, checksPassed: 400, revalDropped: 20})
	old, ok = tr.hourAgo()
	if !ok || old.live != 20 {
		t.Fatalf("hourAgo after eviction = %+v, %v; want the second sample", old, ok)
	}

	// The ring must never grow: a watchdog that allocates a minute of history
	// per minute of uptime is a leak with a nice name.
	if len(tr.samples) != 3 || tr.n != 3 {
		t.Fatalf("ring = len %d, n %d; want a fixed 3-sample window", len(tr.samples), tr.n)
	}
}
