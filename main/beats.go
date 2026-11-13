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
	export     atomic.Int64 // last list-service rebuild
}

func newBeats() *beats {
	b := &beats{}
	now := time.Now().UnixNano()
	b.collector.Store(now)
	b.revalidate.Store(now)
	b.save.Store(now)
	b.export.Store(now)
	return b
}

// startBeatTracker samples the counters every few seconds and stamps whichever
// one moved. The tracker is one goroutine for the whole process, so the cost
// does not scale with the number of tracked subsystems.
func startBeatTracker(ctx context.Context, b *beats) {
	var lastCycles, lastDones, lastExport int64
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
				// RevalLoopDone counts *completed* periodic passes, not
				// starts (RevalPasses): a healthy pass legitimately outruns
				// 2×interval+30s, so a start-stamped beat reported
				// revalidate_stale at the tail of every long pass — and a
				// wedged loop looked fresh as long as it kept starting
				// passes. Admin-forced revals bump ForcedReval, which is
				// deliberately not sampled here.
				if d := proxy.Stats.RevalLoopDone.Load(); d != lastDones {
					lastDones = d
					b.revalidate.Store(now)
				}
				if e := proxy.Stats.ExportListRebuilds.Load(); e != lastExport {
					lastExport = e
					b.export.Store(now)
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
	ExportAgeS      float64 `json:"export_age_s"`
	CollectorStale  bool    `json:"collector_stale"`
	RevalidateStale bool    `json:"revalidate_stale"`
	SaveStale       bool    `json:"save_stale"`
	ExportStale     bool    `json:"export_stale"`
}

// view renders the beats. Stale means older than two of the subsystem's own
// intervals: one interval late is scheduling jitter, two is stuck. The save
// beat only moves on a dirty save, so a quiet-but-healthy queue would show an
// ever-growing age with no verdict without SaveStale: it uses the same rule
// against the save interval. exportRefresh <= 0 means the list service is
// disabled: nothing will ever move that beat, so no verdict is given.
func (b *beats) view(revalidateInterval, cycleSleep, saveInterval, exportRefresh time.Duration) beatsView {
	now := time.Now().UnixNano()
	col := time.Duration(now - b.collector.Load())
	rev := time.Duration(now - b.revalidate.Load())
	save := time.Duration(now - b.save.Load())
	exp := time.Duration(now - b.export.Load())
	return beatsView{
		CollectorAgeS:   col.Seconds(),
		RevalidateAgeS:  rev.Seconds(),
		SaveAgeS:        save.Seconds(),
		ExportAgeS:      exp.Seconds(),
		CollectorStale:  col > 2*cycleSleep+30*time.Second,
		RevalidateStale: rev > 2*revalidateInterval+30*time.Second,
		SaveStale:       save > 2*saveInterval+30*time.Second,
		ExportStale:     exportRefresh > 0 && exp > 2*exportRefresh+30*time.Second,
	}
}

// loopbackAddr reports whether addr is a loopback listen address ("127.0.0.1",
// "::1", "localhost" — with or without a port). Used for the admin token
// warning.
func loopbackAddr(addr string) bool {
	// Split the port off only when the address actually carries one: a bare
	// IPv6 literal has no port, and hand-stripping at the last colon used to
	// turn "::1" into ":" — ParseIP failed, and a loopback-only admin listener
	// got the exposure warning as a false positive.
	host := addr
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
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
