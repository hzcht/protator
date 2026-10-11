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
	//
	// Requests used to be one counter incremented in three places with three
	// meanings: dial calls on plain HTTP (DialContext), CONNECT requests
	// (ServeConnect) and SOCKS5 sessions (DialContext again). That made
	// "req/s" in the watchdog and on the admin page a blend nobody could
	// interpret — a SOCKS5-heavy deploy and an HTTP-heavy deploy with the
	// same client load read different numbers. Now each front counts its own
	// unit; requests_total is their sum (Snapshot), so existing ratios and
	// graphs keep working, with the documented shift: plain HTTP counts one
	// per client request (RoundTrip) instead of one per transport dial call,
	// so a request that needed N transport retries no longer inflates req/s
	// N-fold. The watchdog's fail/req ratio therefore reads slightly higher
	// under retry storms — the alert direction is unchanged (more sensitive),
	// and the req floor now means client requests, which is what an operator
	// thinks in.
	HTTPRequests    atomic.Int64 // plain-HTTP client requests (ProxyTransport.RoundTrip)
	ConnectRequests atomic.Int64 // CONNECT client requests (ServeConnect)
	SOCKS5Sessions  atomic.Int64 // SOCKS5 client sessions (Socks5Server.handle)
	DialAttempts    atomic.Int64 // upstream dial attempts, including retries
	DialFailures    atomic.Int64 // failed dials
	Evictions       atomic.Int64 // proxies the serving path evicted from the queue
	ServedOK        atomic.Int64 // requests the pool actually answered
	ServeFailures   atomic.Int64 // tunnel established but the far side never answered
	BlockPages      atomic.Int64 // interstitials / device-junk answers detected
	BytesIn         atomic.Int64 // tunnel -> client
	BytesOut        atomic.Int64 // client -> tunnel

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
	RevalLoopDone atomic.Int64 // periodic passes completed (heartbeat source)
	RevalChecked  atomic.Int64
	RevalDropped  atomic.Int64
	ForcedReval   atomic.Int64 // re-checks requested from the admin page

	// Persistence / ops: failure modes that used to be log-only (or fully
	// silent) and were therefore invisible in /api/metrics during an incident.
	SaveFailures      atomic.Int64 // queue file save/rewrite failures
	QueueLoadFailures atomic.Int64 // proxy.lst unreadable at startup
	LogRotateFailures atomic.Int64 // log rotation rename failures
	LogWriteFailures  atomic.Int64 // per-category log file write failures
	PoolWriteFailures atomic.Int64 // candidate pool write/flush/compact failures
	GoodWriteFailures atomic.Int64 // good-proxy audit write/flush failures
	AdminAuthFailures atomic.Int64 // admin token rejections
	CollectorWakes    atomic.Int64 // emergency/admin collector wake signals

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
	r.HTTPRequests.Store(0)
	r.ConnectRequests.Store(0)
	r.SOCKS5Sessions.Store(0)
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
	r.RevalLoopDone.Store(0)
	r.RevalChecked.Store(0)
	r.RevalDropped.Store(0)
	r.ForcedReval.Store(0)
	r.SaveFailures.Store(0)
	r.QueueLoadFailures.Store(0)
	r.LogRotateFailures.Store(0)
	r.LogWriteFailures.Store(0)
	r.PoolWriteFailures.Store(0)
	r.GoodWriteFailures.Store(0)
	r.AdminAuthFailures.Store(0)
	r.CollectorWakes.Store(0)
	r.RecoverPanics.Store(0)
}

// Snapshot copies every counter into a plain map, keyed by the metric name the
// admin API and the log line use. Counters are cumulative; rates are derived
// by the caller from two snapshots.
func (r *Registry) Snapshot() map[string]int64 {
	httpReq := r.HTTPRequests.Load()
	connReq := r.ConnectRequests.Load()
	socksReq := r.SOCKS5Sessions.Load()
	return map[string]int64{
		// requests_total stays the sum of the three fronts so every existing
		// ratio, graph and the watchdog keep working unchanged (P47).
		"requests_total":               httpReq + connReq + socksReq,
		"http_requests_total":          httpReq,
		"connect_requests_total":       connReq,
		"socks5_sessions_total":        socksReq,
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
		"reval_loop_done_total":        r.RevalLoopDone.Load(),
		"reval_checked_total":          r.RevalChecked.Load(),
		"reval_dropped_total":          r.RevalDropped.Load(),
		"forced_reval_total":           r.ForcedReval.Load(),
		"save_failures_total":          r.SaveFailures.Load(),
		"queue_load_failures_total":    r.QueueLoadFailures.Load(),
		"log_rotate_failures_total":    r.LogRotateFailures.Load(),
		"log_write_failures_total":     r.LogWriteFailures.Load(),
		"pool_write_failures_total":    r.PoolWriteFailures.Load(),
		"good_write_failures_total":    r.GoodWriteFailures.Load(),
		"admin_auth_failures_total":    r.AdminAuthFailures.Load(),
		"collector_wakes_total":        r.CollectorWakes.Load(),
		"recovered_panics_total":       r.RecoverPanics.Load(),
	}
}
