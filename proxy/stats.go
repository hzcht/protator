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
	// Serve funnel: dial -> tunnel -> first byte -> served. Two adjacent
	// stages tell an operator what a dying pool actually looks like: the
	// upstream unreachable (dial), the upstream accepting TCP and never
	// answering (established without a first byte), or the upstream answering
	// and being useless (served failures). dial_failures_total alone says only
	// "something failed".
	DialOK             atomic.Int64 // dials the upstream accepted
	TunnelsEstablished atomic.Int64 // CONNECT: "200 Connection established" written
	FirstByteOK        atomic.Int64 // CONNECT: the far target produced its first byte
	// Dial failure classes (each dial failure increments the total and exactly
	// one class).
	DialTimeout atomic.Int64
	DialRefused atomic.Int64
	DialTLS     atomic.Int64
	DialReset   atomic.Int64
	DialOther   atomic.Int64
	Evictions   atomic.Int64 // proxies the serving path evicted from the queue
	// Eviction reasons: "the upstream is unreachable" and "the upstream lies"
	// are different problems with different fixes, and pool shrinkage used to
	// look identical for both.
	EvictDial     atomic.Int64 // evicted after dial-level failures
	EvictServe    atomic.Int64 // evicted after served-but-wrong answers
	ServedOK      atomic.Int64 // requests the pool actually answered
	ServeFailures atomic.Int64 // tunnel established but the far side never answered
	BlockPages    atomic.Int64 // interstitials / device-junk answers detected
	BytesIn       atomic.Int64 // tunnel -> client
	BytesOut      atomic.Int64 // client -> tunnel
	// Stickiness (PinPool). Without these the pin table is a black box: a
	// client reporting "my exit IP changes every few seconds" cannot be told
	// apart from one whose session header never arrives, and a pin table
	// thrashing at its cap looks exactly like a healthy one.
	PinHits    atomic.Int64 // pinned lookups that returned a live proxy
	PinRemaps  atomic.Int64 // pins released because their proxy failed
	PinEvicts  atomic.Int64 // pins evicted by serve_pin_max (LRU tail)
	PinExpired atomic.Int64 // pins released by serve_pin_ttl idleness

	// Checker pipeline.
	Checks       atomic.Int64 // candidate validations started
	ChecksPassed atomic.Int64
	ChecksFailed atomic.Int64

	// Validation cost. The checker is the pipeline's only real bottleneck, and
	// it used to be tuned from assumptions a live box disproved: the config
	// claimed "CPU-bound at 100%" while 600 workers ran at 6% of one core with
	// ~112s per check. These counters are what turns "a check is slow" into
	// "the SYN timeouts are slow" or "the far side is a blackhole".
	//
	// Failure stage of one failed Check: exactly one stage wins per failure.
	CheckFailPredial atomic.Int64 // rejected before any request: TCP pre-dial failed
	CheckFailIP      atomic.Int64 // first request through the proxy failed
	CheckFailLeak    atomic.Int64 // header-echo probe failed
	CheckFailE2E     atomic.Int64 // serving-path tunnel probe failed
	CheckFailContent atomic.Int64 // content/exit-confirmation stage failed
	CheckFailConnect atomic.Int64 // an http(s) proxy could not tunnel at all
	CheckFailBudget  atomic.Int64 // the candidate ran out of check_budget
	// Duration of one full Check (every stage, every protocol attempt),
	// bucketed. Cumulative: a histogram is read as deltas between snapshots.
	CheckDurLE1   atomic.Int64
	CheckDurLE5   atomic.Int64
	CheckDurLE15  atomic.Int64
	CheckDurLE60  atomic.Int64
	CheckDurLE230 atomic.Int64
	CheckDurGT230 atomic.Int64
	// The TCP pre-dial stage on its own: a dead host costs one SYN timeout per
	// attempt, and until this existed nobody could tell that cost apart from
	// the far side stalling after a successful connect.
	CheckTCPNanos    atomic.Int64 // total time spent inside pre-dials
	CheckTCPDials    atomic.Int64 // pre-dials attempted
	CheckTCPTimeouts atomic.Int64 // pre-dials that timed out
	// Exit honesty (checker.tls_probe_host): a forge is a proxy that answered
	// our TLS probe with a chain no verifier accepts. It is evidence, not a
	// rejection — such an exit still serves plain HTTP, it just loses to an
	// honest one in the picker.
	CheckTLSHonest       atomic.Int64 // the exit presented a chain that verified
	CheckTLSForged       atomic.Int64 // the exit presented a chain that did not
	CheckTLSInconclusive atomic.Int64 // timeout/reset/missing target: no verdict

	// Collector.
	CollectorCycles      atomic.Int64
	CollectorSitesOK     atomic.Int64
	CollectorSitesFailed atomic.Int64
	CandidatesEmitted    atomic.Int64
	// Progress heartbeat: site fetches completed (ok or failed), stamped even
	// when the cycle as a whole never finishes. The collector beat follows
	// this, not CollectorCycles — a cycle blocked in emit used to leave the
	// watchdog shouting collector_stale for a collector that was alive.
	CollectorSiteDones atomic.Int64
	// Backpressure of the blocking emit: sends that had to wait for channel
	// space (>= emitBlockedMin) and their total wait. "Candidates emitted" is
	// a volume number; this pair is the starvation signal.
	CollectorEmitBlocked atomic.Int64
	CollectorEmitWaitNS  atomic.Int64
	// CollectorZeroYield is a gauge, not a counter: the number of sources
	// that have been fetched at least collector.site_zero_yield_cycles times,
	// have never emitted a candidate, and are not cooling. Set by the stats
	// loop every minute. A source that stays here is burning a fetch slot and
	// a worker while producing nothing — visible now instead of only in
	// /api/sources after somebody thought to look.
	CollectorZeroYield atomic.Int64

	// Revalidation.
	RevalPasses   atomic.Int64 // periodic passes started
	RevalLoopDone atomic.Int64 // periodic passes completed (heartbeat source)
	RevalChecked  atomic.Int64
	RevalDropped  atomic.Int64
	// RevalDoubt counts checks that failed but did not yet demote the entry
	// (storage.demote_after_fails). Without it a pool full of proxies that
	// fail every other pass looks healthy in the metrics: nothing is dropped,
	// so reval_dropped_total stays flat while the proven tier starves.
	RevalDoubt atomic.Int64
	// RevalSeedSkipped counts startup seeds that found the candidate channel
	// full for a whole pacing interval. Seeds are best-effort (the periodic
	// pass re-checks them), fresh candidates from the collector are not: a
	// skipped seed is the fair alternative to blocking the only producer of
	// new proxies behind a 5k queue dump.
	RevalSeedSkipped atomic.Int64
	ForcedReval      atomic.Int64 // re-checks requested from the admin page

	// Persistence / ops: failure modes that used to be log-only (or fully
	// silent) and were therefore invisible in /api/metrics during an incident.
	SaveFailures        atomic.Int64 // queue file save/rewrite failures
	QueueLoadFailures   atomic.Int64 // proxy.lst unreadable at startup
	LogRotateFailures   atomic.Int64 // log rotation rename failures
	LogWriteFailures    atomic.Int64 // per-category log file write failures
	PoolWriteFailures   atomic.Int64 // candidate pool write/flush/compact failures
	GoodWriteFailures   atomic.Int64 // good-proxy audit write/flush failures
	GoodRotations       atomic.Int64 // good-proxy audit rotations at good_file_max_lines
	ProvenWriteFailures atomic.Int64 // proven index write/rename failures
	AdminAuthFailures   atomic.Int64 // admin token rejections
	CollectorWakes      atomic.Int64 // emergency/admin collector wake signals

	// List service (export.*): its own channel, deliberately NOT part of
	// requests_total — that sum is the three serving fronts, and the watchdog
	// rates built on it must not drift with list downloads.
	ExportRequests      atomic.Int64 // list downloads served
	ExportProxiesServed atomic.Int64 // proxies handed out in responses
	ExportListRebuilds  atomic.Int64 // served-list rebuilds (heartbeat source)

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
	r.DialOK.Store(0)
	r.TunnelsEstablished.Store(0)
	r.FirstByteOK.Store(0)
	r.DialTimeout.Store(0)
	r.DialRefused.Store(0)
	r.DialTLS.Store(0)
	r.DialReset.Store(0)
	r.DialOther.Store(0)
	r.Evictions.Store(0)
	r.EvictDial.Store(0)
	r.EvictServe.Store(0)
	r.ServedOK.Store(0)
	r.ServeFailures.Store(0)
	r.BlockPages.Store(0)
	r.BytesIn.Store(0)
	r.BytesOut.Store(0)
	r.PinHits.Store(0)
	r.PinRemaps.Store(0)
	r.PinEvicts.Store(0)
	r.PinExpired.Store(0)
	r.Checks.Store(0)
	r.ChecksPassed.Store(0)
	r.ChecksFailed.Store(0)
	r.CheckFailPredial.Store(0)
	r.CheckFailIP.Store(0)
	r.CheckFailLeak.Store(0)
	r.CheckFailE2E.Store(0)
	r.CheckFailContent.Store(0)
	r.CheckFailConnect.Store(0)
	r.CheckFailBudget.Store(0)
	r.CheckDurLE1.Store(0)
	r.CheckDurLE5.Store(0)
	r.CheckDurLE15.Store(0)
	r.CheckDurLE60.Store(0)
	r.CheckDurLE230.Store(0)
	r.CheckDurGT230.Store(0)
	r.CheckTCPNanos.Store(0)
	r.CheckTCPDials.Store(0)
	r.CheckTCPTimeouts.Store(0)
	r.CheckTLSHonest.Store(0)
	r.CheckTLSForged.Store(0)
	r.CheckTLSInconclusive.Store(0)
	r.CollectorCycles.Store(0)
	r.CollectorSitesOK.Store(0)
	r.CollectorSitesFailed.Store(0)
	r.CandidatesEmitted.Store(0)
	r.CollectorSiteDones.Store(0)
	r.CollectorEmitBlocked.Store(0)
	r.CollectorEmitWaitNS.Store(0)
	r.CollectorZeroYield.Store(0)
	r.RevalPasses.Store(0)
	r.RevalLoopDone.Store(0)
	r.RevalChecked.Store(0)
	r.RevalDropped.Store(0)
	r.RevalDoubt.Store(0)
	r.RevalSeedSkipped.Store(0)
	r.ForcedReval.Store(0)
	r.SaveFailures.Store(0)
	r.QueueLoadFailures.Store(0)
	r.LogRotateFailures.Store(0)
	r.LogWriteFailures.Store(0)
	r.PoolWriteFailures.Store(0)
	r.GoodWriteFailures.Store(0)
	r.GoodRotations.Store(0)
	r.ProvenWriteFailures.Store(0)
	r.AdminAuthFailures.Store(0)
	r.CollectorWakes.Store(0)
	r.ExportRequests.Store(0)
	r.ExportProxiesServed.Store(0)
	r.ExportListRebuilds.Store(0)
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
		"dial_ok_total":                r.DialOK.Load(),
		"tunnels_established_total":    r.TunnelsEstablished.Load(),
		"first_byte_ok_total":          r.FirstByteOK.Load(),
		"dial_fail_timeout_total":      r.DialTimeout.Load(),
		"dial_fail_refused_total":      r.DialRefused.Load(),
		"dial_fail_tls_total":          r.DialTLS.Load(),
		"dial_fail_reset_total":        r.DialReset.Load(),
		"dial_fail_other_total":        r.DialOther.Load(),
		"evictions_total":              r.Evictions.Load(),
		"evictions_dial_total":         r.EvictDial.Load(),
		"evictions_serve_total":        r.EvictServe.Load(),
		"served_ok_total":              r.ServedOK.Load(),
		"serve_failures_total":         r.ServeFailures.Load(),
		"block_pages_total":            r.BlockPages.Load(),
		"bytes_in_total":               r.BytesIn.Load(),
		"bytes_out_total":              r.BytesOut.Load(),
		"pin_hits_total":               r.PinHits.Load(),
		"pin_remaps_total":             r.PinRemaps.Load(),
		"pin_evictions_total":          r.PinEvicts.Load(),
		"pin_expired_total":            r.PinExpired.Load(),
		"checks_total":                 r.Checks.Load(),
		"checks_passed_total":          r.ChecksPassed.Load(),
		"checks_failed_total":          r.ChecksFailed.Load(),
		"check_fail_predial_total":     r.CheckFailPredial.Load(),
		"check_fail_ip_total":          r.CheckFailIP.Load(),
		"check_fail_leak_total":        r.CheckFailLeak.Load(),
		"check_fail_e2e_total":         r.CheckFailE2E.Load(),
		"check_fail_content_total":     r.CheckFailContent.Load(),
		"check_fail_connect_total":     r.CheckFailConnect.Load(),
		"check_fail_budget_total":      r.CheckFailBudget.Load(),
		"check_tls_honest_total":       r.CheckTLSHonest.Load(),
		"check_tls_forged_total":       r.CheckTLSForged.Load(),
		"check_tls_inconclusive_total": r.CheckTLSInconclusive.Load(),
		"check_duration_le_1s_total":   r.CheckDurLE1.Load(),
		"check_duration_le_5s_total":   r.CheckDurLE5.Load(),
		"check_duration_le_15s_total":  r.CheckDurLE15.Load(),
		"check_duration_le_60s_total":  r.CheckDurLE60.Load(),
		"check_duration_le_230s_total": r.CheckDurLE230.Load(),
		"check_duration_gt_230s_total": r.CheckDurGT230.Load(),
		"check_tcp_ns_total":           r.CheckTCPNanos.Load(),
		"check_tcp_dials_total":        r.CheckTCPDials.Load(),
		"check_tcp_timeouts_total":     r.CheckTCPTimeouts.Load(),
		"collector_cycles_total":       r.CollectorCycles.Load(),
		"collector_sites_ok_total":     r.CollectorSitesOK.Load(),
		"collector_sites_failed_total": r.CollectorSitesFailed.Load(),
		"candidates_emitted_total":     r.CandidatesEmitted.Load(),
		"collector_site_dones_total":   r.CollectorSiteDones.Load(),
		"collector_emit_blocked_total": r.CollectorEmitBlocked.Load(),
		"collector_emit_wait_ns_total": r.CollectorEmitWaitNS.Load(),
		"collector_zero_yield_sources": r.CollectorZeroYield.Load(),
		"reval_passes_total":           r.RevalPasses.Load(),
		"reval_loop_done_total":        r.RevalLoopDone.Load(),
		"reval_checked_total":          r.RevalChecked.Load(),
		"reval_dropped_total":          r.RevalDropped.Load(),
		"reval_doubt_total":            r.RevalDoubt.Load(),
		"reval_seed_skipped_total":     r.RevalSeedSkipped.Load(),
		"forced_reval_total":           r.ForcedReval.Load(),
		"save_failures_total":          r.SaveFailures.Load(),
		"queue_load_failures_total":    r.QueueLoadFailures.Load(),
		"log_rotate_failures_total":    r.LogRotateFailures.Load(),
		"log_write_failures_total":     r.LogWriteFailures.Load(),
		"pool_write_failures_total":    r.PoolWriteFailures.Load(),
		"good_write_failures_total":    r.GoodWriteFailures.Load(),
		"good_rotations_total":         r.GoodRotations.Load(),
		"proven_write_failures_total":  r.ProvenWriteFailures.Load(),
		"admin_auth_failures_total":    r.AdminAuthFailures.Load(),
		"collector_wakes_total":        r.CollectorWakes.Load(),
		"export_requests_total":        r.ExportRequests.Load(),
		"export_proxies_served_total":  r.ExportProxiesServed.Load(),
		"export_list_rebuilds_total":   r.ExportListRebuilds.Load(),
		"recovered_panics_total":       r.RecoverPanics.Load(),
	}
}
