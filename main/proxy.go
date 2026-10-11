// Command protator: transit proxy collector + rotating forward proxy
// (HTTP/HTTPS/SOCKS5). Data flow: collector and startup re-validation emit
// proxies -> checker validates -> live queue (bucket) serves client dials.
package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"protator/proxy"
)

// Version answers "which build is in production". There were no tags before
// versioning started, so this begins at 0.1.0-dev and the first tag defines
// 0.1.0; until then every build reports the same -dev version, which is
// honest: without a tag there is nothing else to name them by.
const protatorVersion = "0.1.0-dev"

func main() {
	cfgPath := flag.String("config", "config/config.toml", "path to TOML config")
	checkOnly := flag.Bool("check", false, "validate config and required files, then exit")
	showVersion := flag.Bool("version", false, "print the build version and exit")
	flag.Parse()

	if *showVersion {
		log.Printf("protator %s", protatorVersion)
		return
	}

	cfg, err := proxy.LoadConfig(*cfgPath)
	if err != nil {
		log.Fatalf("config: %v", err)
	}
	if *checkOnly {
		if err := checkConfig(cfg); err != nil {
			log.Fatalf("check: %v", err)
		}
		log.Println("config OK")
		return
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	// Keep a plain cancel for the cooperative admin shutdown: stop() from
	// NotifyContext unregisters the signal handlers as a side effect, which
	// a repeated /api/shutdown POST must not do.
	procCancel := func() { stop() }

	// Per-category file logs with rotation (main/logfiles.go). Every line is
	// mirrored to stderr so console / instance_err.log workflows keep working.
	sink := newFileLogSink(cfg.Logging)
	log.SetOutput(sink)

	// A crash between CreateTemp and rename leaves atomic-write temp files
	// forever (their cleanup defer never ran). Sweep them before any writer
	// starts: at this point every matching file is an orphan by definition.
	proxy.SweepOrphanTMP(
		filepath.Dir(cfg.Storage.QueueFile),
		filepath.Dir(cfg.Storage.CandidatesFile),
		filepath.Dir(cfg.Collector.SitesFile),
		filepath.Dir(cfg.Storage.DebugProxiesFile),
	)

	// One dampener shared by all listeners and goproxy loggers (see
	// logging.go): filters stdlib TLS-handshake noise and coalesces the
	// goproxy "Error dialing to ..." WARN flood. Its output also lands in the
	// per-category files below (system.log) via the same sink.
	logNoise := log.New(newNoiseWriter(sink, 30*time.Second), "", log.LstdFlags)

	bucket, checker, pool, debug, candidates := buildPipeline(cfg)

	// The validation worker pool is owned by its supervisor, which restarts any
	// worker that exits. Started before the first candidate is produced so
	// nothing is emitted into an empty pipeline.
	workers := startCheckerWorkers(cfg, checker, pool, bucket, debug, candidates)

	// Startup: revalidate the previous queue first (spec stage 5), while the
	// first collection runs in parallel.
	snap := bucket.Snapshot()
	log.Printf("queue: revalidating %d seeded proxies while collecting (rate-limited)", len(snap))
	go proxy.RevalidateSeeded(ctx, candidates, snap, cfg.Storage.RevalidateSeedRate, cfg.Storage.RevalidateSeedMax)

	// Shared dialer: every CONNECT/tunnel/direct dial is routed through the
	// live queue with per-attempt retries and eviction (proxy/upstream.go).
	fwd := proxy.NewForwardDialer(bucket, cfg)
	defer func() { saveQueue(cfg, bucket) }()
	// Flush the pool's buffered appends on the way out: without this the
	// last few KB of candidates never reach disk.
	defer pool.Close()
	// Same for the good-proxy audit: its buffer only reaches disk past 4 KB,
	// so the tail — exactly the newly-found set — was lost on every exit.
	defer proxy.CloseGoodWriters()

	shutdown := startServers(ctx, cfg, bucket, fwd, logNoise)
	collector, wakeCollector := startCollector(ctx, cfg, bucket, candidates)
	// Cached via-proxy fetcher transports hold idle sockets open to dead
	// upstreams; drop them on the way out.
	defer collector.CloseTransportCache()

	// Subsystem heartbeats: the last time each long-running loop made
	// progress, derived from its counters. The health endpoint and the
	// shutdown log both report them.
	beats := newBeats()
	startBeatTracker(ctx, beats)
	startAdminServer(ctx, cfg, bucket, pool, collector, checker, debug, sink, beats, workers, wakeCollector, candidates, logNoise, procCancel)
	startBackgroundLoops(ctx, cfg, bucket, pool, checker, debug, candidates, wakeCollector, beats)

	<-ctx.Done()
	stop()
	log.Println("shutting down")

	// Let new connections stop being accepted, then wait up to the shutdown
	// budget for in-flight requests to complete before saving the queue.
	drainCtx, cancel := context.WithTimeout(context.Background(), cfg.Server.ShutdownTimeout.Duration)
	defer cancel()
	shutdown(drainCtx)

	// Stop the validation workers here, between the drain and the deferred
	// saveQueue/pool.Close/CloseGoodWriters: they are the last writer of the
	// queue, the pool file and the good-proxy audit. The candidate channel is
	// never closed for the process's life, so stopping the pool is the only way
	// they learn to stop, and without it they keep appending through the
	// per-line fallback to files those deferred calls have just closed. It has
	// to happen after the drain so the last request's dial result is still
	// accounted for, and before the saves so they see every write. The wait is
	// bounded by the same shutdown budget: a worker inside a 230s check must
	// not turn SIGTERM into a SIGKILL that skips the saves.
	workers.stopAndWait(cfg.Server.ShutdownTimeout.Duration)
	log.Printf("checker: worker pool stopped (%d restarts total)", workers.Restarts())

	log.Println("stopped")
}

// checkConfig validates the non-daemon requirements of a config without
// starting listeners: required data files must exist, the log dir is usable.
//
// The checks are ordered (not map-driven) so the operator sees one stable
// failure per run instead of a different one each time several files are
// missing.
func checkConfig(cfg *proxy.Config) error {
	// Only files the daemon does NOT create on demand. The candidates pool
	// used to be on this list: a fresh deploy (no data/ yet) failed -check
	// for a file the first run would have created itself.
	required := []struct {
		name string
		path string
	}{
		{"sites", cfg.Collector.SitesFile},
		{"regexp", cfg.Collector.RegexFile},
		{"checkers", cfg.Checker.TestsFile},
	}
	for _, f := range required {
		if _, err := os.Stat(f.path); err != nil {
			return fmt.Errorf("%s file %s: %w", f.name, f.path, err)
		}
	}
	// Validate the tests file the way the daemon does: a Stat used to let a
	// file with zero [[tests]] entries pass -check and then log.Fatalf at
	// boot — the exact moment the pre-deploy validation was supposed to help.
	if _, err := proxy.LoadTests(cfg.Checker.TestsFile); err != nil {
		return fmt.Errorf("checkers %s: %w", cfg.Checker.TestsFile, err)
	}
	if err := os.MkdirAll(cfg.Logging.Dir, 0o755); err != nil {
		return fmt.Errorf("log dir %s: %w", cfg.Logging.Dir, err)
	}
	// A typo'd GeoIP path otherwise fails much later, inside the checker
	// constructor — after the queue was already seeded. The country/ASN filters
	// stay empty until a database is configured; that is a product decision
	// (ship the DB or drop the filters), but a wrong path is always a bug.
	if cfg.Checker.GeoIPDBPath != "" {
		if _, err := os.Stat(cfg.Checker.GeoIPDBPath); err != nil {
			return fmt.Errorf("geoip_db_path %s: %w", cfg.Checker.GeoIPDBPath, err)
		}
	}
	if cfg.Checker.GeoIPASNDBPath != "" {
		if _, err := os.Stat(cfg.Checker.GeoIPASNDBPath); err != nil {
			return fmt.Errorf("geoip_asn_db_path %s: %w", cfg.Checker.GeoIPASNDBPath, err)
		}
	}
	// The TLS pair outlives every other config: warn here, not at 3am when the
	// https:// dials start failing with errors that read like proxy death.
	if cfg.Server.TLSCertFile != "" && cfg.Server.TLSKeyFile != "" {
		cert, err := proxy.LoadOrCreateTLS(cfg.Server.TLSCertFile, cfg.Server.TLSKeyFile)
		if err != nil {
			return fmt.Errorf("tls pair %s/%s: %w", cfg.Server.TLSCertFile, cfg.Server.TLSKeyFile, err)
		}
		if exp, ok := proxy.CertNotAfter(cert); ok {
			if left := time.Until(exp); left <= 0 {
				return fmt.Errorf("tls certificate expired %s ago", -left)
			} else if left < proxy.CertWarnDays {
				log.Printf("check: WARNING tls certificate expires in %s", left.Round(24*time.Hour))
			}
		}
	}
	// Same exposure warning the daemon prints at start: a pre-deploy -check
	// that stays silent about a non-loopback tokenless admin listener misses
	// the one finding that is cheapest to fix before the box goes live.
	warnAdminExposure(cfg.Server.AdminListen, cfg.Server.AdminToken)
	return nil
}

// buildPipeline seeds the persisted queue and builds the checker, candidate
// pool and debug hook. It does NOT start the validation workers: those are
// owned by startCheckerWorkers, which keeps the pool at its configured size
// for the life of the process. Every candidate producer (startup
// revalidation, collector, pool re-probing) feeds the returned channel.
//
// The stop channel this used to hand back was `defer`red inside this function,
// so it closed when it *returned*, before a single request was served: every
// worker exited at startup, nothing consumed the candidate channel, the
// collector's blocking emit filled it and wedged, and the queue was never
// replenished again.
func buildPipeline(cfg *proxy.Config) (*proxy.Bucket, *proxy.Checker, *proxy.CandidatePool, *proxy.DebugProxies, chan proxy.Candidate) {
	// Seed from the queue file plus the append-only audit of every good
	// proxy (capped tail: the audit grows without bound). Seed dedups, so
	// overlap is free and completeness is maximal.
	bucket := proxy.NewBucket(cfg.Server.MaxProxies)
	// How recent a proof of life must be for an entry to count as proven when
	// picking an upstream. Set before the first Seed so the very first client
	// request already aims at the working tail.
	bucket.SetFreshnessWindows(cfg.Server.PickServeWindow.Duration, cfg.Server.PickFreshWindow.Duration)
	// Fail-closed serving: with nothing proven, requests fail instead of going
	// out through an unvalidated proxy. Off by default.
	bucket.SetRequireProven(cfg.Server.ServeRequireProven)
	log.Printf("queue: pick windows serve=%s fresh=%s (revalidate_interval=%s)",
		cfg.Server.PickServeWindow.Duration, cfg.Server.PickFreshWindow.Duration,
		cfg.Storage.RevalidateInterval.Duration)
	seedN := bucket.Seed(proxy.ReadQueue(cfg.Storage.QueueFile))
	log.Printf("queue: loaded %d unique proxies from %s", seedN, cfg.Storage.QueueFile)
	if cfg.Storage.GoodFile != "" {
		if extra := bucket.Seed(proxy.ReadQueueLast(cfg.Storage.GoodFile, 500000)); extra > 0 {
			log.Printf("queue: +%d from audit %s (total %d)", extra, cfg.Storage.GoodFile, bucket.Len())
		}
	}

	checker, err := proxy.NewChecker(cfg)
	if err != nil {
		log.Fatalf("checker: %v", err)
	}
	log.Printf("checker: self IP %s", checker.SelfIP())

	// Persisted candidate pool: candidates that fail validation are stored
	// here and re-probed on later cycles (host:port lines); when one finally
	// validates it is moved into the bucket and dropped from re-probing.
	pool := proxy.NewCandidatePool(cfg.Storage.CandidatesFile, cfg.Storage.MaxBytes, cfg.Collector.MaxCandidates)
	log.Printf("pool: loaded %d persisted candidates from %s", pool.Len(), cfg.Storage.CandidatesFile)

	// Debug hook: the last N freshly validated proxies, for direct-browser
	// testing (proves whether the fault is in our logic or in the pool).
	debug := proxy.NewDebugProxies(cfg.Storage.DebugProxiesFile, cfg.Storage.DebugProxiesMax)

	candidates := make(chan proxy.Candidate, cfg.Checker.ChannelSize)
	return bucket, checker, pool, debug, candidates
}

// startCollector launches the scraper; it emits candidates into the
// validation pipeline (see main/sites.txt). It returns the collector (so the
// admin page can report per-source telemetry) and the wake channel that
// background loops use to kick an emergency cycle when the queue is empty.
func startCollector(ctx context.Context, cfg *proxy.Config, bucket *proxy.Bucket, candidates chan<- proxy.Candidate) (*proxy.Collector, chan<- struct{}) {
	collector, err := proxy.NewCollector(cfg, bucket)
	if err != nil {
		log.Fatalf("collector: %v", err)
	}
	wake := make(chan struct{}, 1)
	go collector.Run(ctx, candidates, wake)
	return collector, wake
}
