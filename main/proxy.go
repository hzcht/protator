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
	"syscall"
	"time"

	"protator/proxy"
)

func main() {
	cfgPath := flag.String("config", "config/config.toml", "path to TOML config")
	checkOnly := flag.Bool("check", false, "validate config and required files, then exit")
	flag.Parse()

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

	// Per-category file logs with rotation (main/logfiles.go). Every line is
	// mirrored to stderr so console / instance_err.log workflows keep working.
	sink := newFileLogSink(cfg.Logging)
	log.SetOutput(sink)

	// One dampener shared by all listeners and goproxy loggers (see
	// logging.go): filters stdlib TLS-handshake noise and coalesces the
	// goproxy "Error dialing to ..." WARN flood. Its output also lands in the
	// per-category files below (system.log) via the same sink.
	logNoise := log.New(newNoiseWriter(sink, 30*time.Second), "", log.LstdFlags)

	bucket, checker, pool, debug, candidates := buildPipeline(cfg)

	// Startup: revalidate the previous queue first (spec stage 5), while the
	// first collection runs in parallel.
	snap := bucket.Snapshot()
	log.Printf("queue: revalidating %d seeded proxies while collecting (rate-limited)", len(snap))
	go revalidateSeeded(ctx, candidates, snap, cfg.Storage.RevalidateSeedRate, cfg.Storage.RevalidateSeedMax)

	// Shared dialer: every CONNECT/tunnel/direct dial is routed through the
	// live queue with per-attempt retries and eviction (proxy/upstream.go).
	fwd := proxy.NewForwardDialer(bucket, cfg)
	defer saveQueue(cfg, bucket)

	shutdown := startServers(ctx, cfg, bucket, fwd, logNoise)
	collector, wakeCollector := startCollector(ctx, cfg, bucket, candidates)
	startAdminServer(ctx, cfg, bucket, pool, collector, logNoise)
	startBackgroundLoops(ctx, cfg, bucket, pool, checker, debug, candidates, wakeCollector)

	<-ctx.Done()
	stop()
	log.Println("shutting down")

	// Let new connections stop being accepted, then wait up to the shutdown
	// budget for in-flight requests to complete before saving the queue.
	drainCtx, cancel := context.WithTimeout(context.Background(), cfg.Server.ShutdownTimeout.Duration)
	defer cancel()
	shutdown(drainCtx)
	log.Println("stopped")
}

// checkConfig validates the non-daemon requirements of a config without
// starting listeners: required data files must exist, the log dir is usable.
func checkConfig(cfg *proxy.Config) error {
	for name, path := range map[string]string{
		"sites":      cfg.Collector.SitesFile,
		"regexp":     cfg.Collector.RegexFile,
		"checkers":   cfg.Checker.TestsFile,
		"candidates": cfg.Storage.CandidatesFile,
	} {
		if _, err := os.Stat(path); err != nil {
			return fmt.Errorf("%s file %s: %w", name, path, err)
		}
	}
	if err := os.MkdirAll(cfg.Logging.Dir, 0o755); err != nil {
		return fmt.Errorf("log dir %s: %w", cfg.Logging.Dir, err)
	}
	return nil
}

// buildPipeline seeds the persisted queue, builds the checker, candidate pool
// and debug hook, and starts the validation worker pump. Every candidate
// producer (startup revalidation, collector, pool re-probing) feeds the
// returned channel; workers persist failures to the pool and move successes
// into the bucket.
func buildPipeline(cfg *proxy.Config) (*proxy.Bucket, *proxy.Checker, *proxy.CandidatePool, *debugProxies, chan proxy.Candidate) {
	// Seed from the queue file plus the append-only audit of every good
	// proxy (capped tail: the audit grows without bound). Seed dedups, so
	// overlap is free and completeness is maximal.
	bucket := proxy.NewBucket(cfg.Server.MaxProxies)
	// How recent a proof of life must be for an entry to count as proven when
	// picking an upstream. Set before the first Seed so the very first client
	// request already aims at the working tail.
	bucket.SetFreshnessWindows(cfg.Server.PickServeWindow.Duration, cfg.Server.PickFreshWindow.Duration)
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
	debug := newDebugProxies(cfg.Storage.DebugProxiesFile, cfg.Storage.DebugProxiesMax)

	candidates := make(chan proxy.Candidate, cfg.Checker.ChannelSize)
	for i := 0; i < cfg.Checker.Workers; i++ {
		go checkLoop(candidates, checker, pool, bucket, debug, cfg)
	}
	return bucket, checker, pool, debug, candidates
}

// checkLoop consumes candidates until the channel closes: failed validations
// go to the persisted pool, successes into the bucket (and the audit file).
func checkLoop(candidates <-chan proxy.Candidate, checker *proxy.Checker, pool *proxy.CandidatePool, bucket *proxy.Bucket, debug *debugProxies, cfg *proxy.Config) {
	for cand := range candidates {
		p, err := checker.Check(cand)
		if err != nil {
			if pool.Add(cand) && pool.Len()%1000 == 0 {
				log.Printf("checker: pool=%d candidates persisted", pool.Len())
			}
			continue
		}
		pool.Good(cand)
		debug.Add(p.URL())
		// Attribute the proxy to the sites.txt entry it came from before it
		// enters the bucket: the bucket keeps per-source live counts and the
		// admin page reports them, and the attribution is frozen from here on.
		p.SetSource(cand.Source)
		if bucket.Add(p) {
			proxy.AppendGood(cfg.Storage.GoodFile, p.URL())
			if bucket.Len()%1000 == 0 {
				log.Printf("checker: added %s queue=%d", p.URL(), bucket.Len())
			}
		}
	}
}

// revalidateSeeded feeds the seeded proxies into the validation pipeline once,
// at a controlled rate and up to a cap. Dumping all 65k seeds into the channel
// at once floods the checker: the fresh candidates from the collector and the
// pool re-probe then cannot get through (the re-probe loop sends only what
// fits and skips the tick otherwise). The seeds are mostly dead anyway — the
// periodic revalidation pass churns them — so there is no reason to let them
// starve everything else at startup.
func revalidateSeeded(ctx context.Context, candidates chan<- proxy.Candidate, snap []*proxy.Proxy, rate, maxSeeds int) {
	if rate <= 0 {
		rate = 200 // seeds per second
	}
	if maxSeeds > 0 && len(snap) > maxSeeds {
		snap = snap[:maxSeeds]
	}
	interval := time.Second / time.Duration(rate)
	t := time.NewTicker(interval)
	defer t.Stop()
	for _, p := range snap {
		select {
		case candidates <- proxy.Candidate{Host: p.Host, Port: p.Port, Schema: p.Schema, Source: p.Source()}:
		case <-ctx.Done():
			return
		}
		<-t.C
	}
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
