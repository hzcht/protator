package proxy

import "sync/atomic"

// Registry holds the process-wide counters every long-running component feeds.
//
// Why a registry instead of log lines: the serving path is the only part of
// this program whose health is not otherwise observable. A request that fails
// three dials and is finally served through the fourth proxy looks identical
// to a clean one in the logs, and the queue-count line printed once a minute
// says nothing about whether the pool is getting worse. Counters make the
// degradation visible as a rate (dial failures/sec, retry share, evictions)
// instead of as a feeling.
//
// Every field is an atomic: the serving path, the checker workers (600 of
// them), the collector fetches and the revalidation workers all increment
// concurrently, and a mutex here would be a new contention point on the
// hottest path in the process.
type Registry struct {
	// Serving path (ForwardDialer / ProxyTransport).
	Requests      atomic.Int64 // client requests that reached the dialer
	DialAttempts  atomic.Int64 // upstream dial attempts, including retries
	DialFailures  atomic.Int64 // failed dials
	Evictions     atomic.Int64 // proxies the serving path evicted from the queue
	ServedOK      atomic.Int64 // requests the pool actually answered
	ServeFailures atomic.Int64 // tunnel established but the far side never answered
	BlockPages    atomic.Int64 // interstitials / device-junk answers detected
	BytesIn       atomic.Int64 // tunnel -> client
	BytesOut      atomic.Int64 // client -> tunnel

	// Checker pipeline.
	Checks       atomic.Int64 // candidate validations started
	ChecksPassed atomic.Int64
	ChecksFailed atomic.Int64

	// Collector.
	CollectorCycles      atomic.Int64
	CollectorSitesOK     atomic.Int64
	CollectorSitesFailed atomic.Int64
	CandidatesEmitted    atomic.Int64

	// Revalidation.
	RevalPasses   atomic.Int64 // periodic passes started
	RevalChecked  atomic.Int64
	RevalDropped  atomic.Int64
	ForcedReval   atomic.Int64 // re-checks requested from the admin page
	RecoverPanics atomic.Int64 // panics RecoverPanic logged
}

// Stats is the process-wide registry. Package-level on purpose: the components
// that must increment it (the dialer, the checker, the collector, the admin
// page) are wired together in main, and threading one more parameter through
// every constructor to reach a singleton buys nothing in a single-binary app.
var Stats = &Registry{}

// Reset zeroes every counter. Used by tests, and by anything that wants
// counters relative to "now" instead of "process start".
func (r *Registry) Reset() {
	r.Requests.Store(0)
	r.DialAttempts.Store(0)
	r.DialFailures.Store(0)
	r.Evictions.Store(0)
	r.ServedOK.Store(0)
	r.ServeFailures.Store(0)
	r.BlockPages.Store(0)
	r.BytesIn.Store(0)
	r.BytesOut.Store(0)
	r.Checks.Store(0)
	r.ChecksPassed.Store(0)
	r.ChecksFailed.Store(0)
	r.CollectorCycles.Store(0)
	r.CollectorSitesOK.Store(0)
	r.CollectorSitesFailed.Store(0)
	r.CandidatesEmitted.Store(0)
	r.RevalPasses.Store(0)
	r.RevalChecked.Store(0)
	r.RevalDropped.Store(0)
	r.ForcedReval.Store(0)
	r.RecoverPanics.Store(0)
}

// Snapshot copies every counter into a plain map, keyed by the metric name the
// admin API and the log line use. Counters are cumulative; rates are derived
// by the caller from two snapshots.
func (r *Registry) Snapshot() map[string]int64 {
	return map[string]int64{
		"requests_total":               r.Requests.Load(),
		"dial_attempts_total":          r.DialAttempts.Load(),
		"dial_failures_total":          r.DialFailures.Load(),
		"evictions_total":              r.Evictions.Load(),
		"served_ok_total":              r.ServedOK.Load(),
		"serve_failures_total":         r.ServeFailures.Load(),
		"block_pages_total":            r.BlockPages.Load(),
		"bytes_in_total":               r.BytesIn.Load(),
		"bytes_out_total":              r.BytesOut.Load(),
		"checks_total":                 r.Checks.Load(),
		"checks_passed_total":          r.ChecksPassed.Load(),
		"checks_failed_total":          r.ChecksFailed.Load(),
		"collector_cycles_total":       r.CollectorCycles.Load(),
		"collector_sites_ok_total":     r.CollectorSitesOK.Load(),
		"collector_sites_failed_total": r.CollectorSitesFailed.Load(),
		"candidates_emitted_total":     r.CandidatesEmitted.Load(),
		"reval_passes_total":           r.RevalPasses.Load(),
		"reval_checked_total":          r.RevalChecked.Load(),
		"reval_dropped_total":          r.RevalDropped.Load(),
		"forced_reval_total":           r.ForcedReval.Load(),
		"recovered_panics_total":       r.RecoverPanics.Load(),
	}
}
