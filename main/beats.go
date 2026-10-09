package main

import (
	"context"
	"log"
	"net"
	"strings"
	"sync/atomic"
	"time"

	"protator/proxy"
)

// beats records the last time each long-running subsystem made progress.
//
// The counters live in proxy.Stats (cycles, passes); this turns them into
// "when did it last do anything", which is what a health endpoint and an
// operator actually need. A collector that crashed five minutes ago and a
// collector that is merely slow look identical in a counter, and completely
// different in a timestamp.
type beats struct {
	collector  atomic.Int64 // unix nanos of the last completed collector cycle
	revalidate atomic.Int64 // last revalidation pass
	save       atomic.Int64 // last successful queue save
}

func newBeats() *beats {
	b := &beats{}
	now := time.Now().UnixNano()
	b.collector.Store(now)
	b.revalidate.Store(now)
	b.save.Store(now)
	return b
}

// startBeatTracker samples the counters every few seconds and stamps whichever
// one moved. The tracker is one goroutine for the whole process, so the cost
// does not scale with the number of tracked subsystems.
func startBeatTracker(ctx context.Context, b *beats) {
	var lastCycles, lastPasses int64
	go func() {
		defer proxy.RecoverPanic("beats")
		t := time.NewTicker(5 * time.Second)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				now := time.Now().UnixNano()
				if c := proxy.Stats.CollectorCycles.Load(); c != lastCycles {
					lastCycles = c
					b.collector.Store(now)
				}
				if p := proxy.Stats.RevalPasses.Load(); p != lastPasses {
					lastPasses = p
					b.revalidate.Store(now)
				}
			}
		}
	}()
}

// beatsView is the JSON shape: age in seconds plus a staleness verdict.
type beatsView struct {
	CollectorAgeS   float64 `json:"collector_age_s"`
	RevalidateAgeS  float64 `json:"revalidate_age_s"`
	SaveAgeS        float64 `json:"save_age_s"`
	CollectorStale  bool    `json:"collector_stale"`
	RevalidateStale bool    `json:"revalidate_stale"`
}

// view renders the beats. Stale means older than two of the subsystem's own
// intervals: one interval late is scheduling jitter, two is stuck.
func (b *beats) view(revalidateInterval, cycleSleep time.Duration) beatsView {
	now := time.Now().UnixNano()
	col := time.Duration(now - b.collector.Load())
	rev := time.Duration(now - b.revalidate.Load())
	save := time.Duration(now - b.save.Load())
	return beatsView{
		CollectorAgeS:   col.Seconds(),
		RevalidateAgeS:  rev.Seconds(),
		SaveAgeS:        save.Seconds(),
		CollectorStale:  col > 2*cycleSleep+30*time.Second,
		RevalidateStale: rev > 2*revalidateInterval+30*time.Second,
	}
}

// loopbackAddr reports whether addr is a loopback listen address ("127.0.0.1",
// "::1", "localhost" — with or without a port). Used for the admin token
// warning.
func loopbackAddr(addr string) bool {
	host := addr
	if i := strings.LastIndex(host, ":"); i >= 0 && !strings.HasSuffix(host, "]") {
		host = host[:i]
	}
	host = strings.Trim(host, "[]")
	if strings.EqualFold(host, "localhost") {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

// warnAdminExposure logs when the admin listener is reachable from outside the
// host and carries no token. Loud, because the alternative is discovering that
// during an incident: the page edits sites.txt and can drop proxies.
func warnAdminExposure(addr, token string) {
	if addr == "" || token != "" || loopbackAddr(addr) {
		return
	}
	log.Printf("admin: WARNING %s is not a loopback address and no admin_token is set — "+
		"the page can edit sites.txt and drop proxies; set server.admin_token", addr)
}
