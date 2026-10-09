package main

import (
	"log"
	"sync"
	"sync/atomic"

	"protator/proxy"
)

// checkerWorkers runs the validation pipeline's worker pool and keeps it at
// its configured size.
//
// Why a supervisor instead of `for i := 0; i < n; i++ { go RunCheckLoop(...) }`:
// a worker can still die. A recovered panic beyond the streak cap, a channel
// close, a future bug — nothing else in the process notices one goroutine
// missing from a pool of hundreds, and the checker's throughput quietly decays
// over days of uptime until the queue starves and the proxy stops serving.
// The classic symptom is "it worked fine for a week and then never recovered",
// and the only visible trace is one panic line in checker.log.
//
// Every worker exit is reported on a channel, and the supervisor restarts it.
// The restart count is a metric: a process whose restarts climb is a process
// with a real bug, which is exactly what an operator needs to see.
type checkerWorkers struct {
	cfg        *proxy.Config
	checker    *proxy.Checker
	pool       *proxy.CandidatePool
	bucket     *proxy.Bucket
	debug      *proxy.DebugProxies
	candidates <-chan proxy.Candidate

	stop     chan struct{}
	exited   chan exitMsg
	wg       sync.WaitGroup
	restarts atomic.Int64

	// run executes one worker and reports why it stopped. A field so tests can
	// drive the supervisor without a live checker: the restart contract is in
	// the supervisor, not in the worker.
	run func(id int) proxy.ExitReason
}

// exitMsg is one worker's exit report: which worker, and why it stopped.
type exitMsg struct {
	id     int
	reason proxy.ExitReason
}

// startCheckerWorkers launches the pool and its supervisor.
func startCheckerWorkers(cfg *proxy.Config, checker *proxy.Checker, pool *proxy.CandidatePool, bucket *proxy.Bucket, debug *proxy.DebugProxies, candidates <-chan proxy.Candidate) *checkerWorkers {
	w := &checkerWorkers{
		cfg:        cfg,
		checker:    checker,
		pool:       pool,
		bucket:     bucket,
		debug:      debug,
		candidates: candidates,
		stop:       make(chan struct{}),
		exited:     make(chan exitMsg, cfg.Checker.Workers+1),
	}
	w.run = w.runWorker
	w.wg.Add(1)
	go w.supervise(cfg.Checker.Workers)
	log.Printf("checker: %d validation workers started (supervised)", cfg.Checker.Workers)
	return w
}

// supervise keeps the worker count constant. It exits once stop is closed and
// every worker it started has returned.
func (w *checkerWorkers) supervise(n int) {
	defer w.wg.Done()
	live := 0
	for i := 0; i < n; i++ {
		w.start(i)
		live++
	}
	for live > 0 {
		select {
		case <-w.stop:
			// Workers return on their own once stop is closed; keep draining
			// their exit reports so their goroutines are never blocked on the
			// channel on the way out.
			<-w.exited
			live--
		case msg := <-w.exited:
			// A closed candidate channel is the one exit a restart cannot fix:
			// the worker would return immediately and the supervisor would
			// spin, logging a restart per iteration.
			if msg.reason == proxy.ExitStopped || msg.reason == proxy.ExitChannelClosed {
				live--
				if msg.reason == proxy.ExitChannelClosed {
					log.Printf("checker: worker %d found the candidate channel closed; not restarting", msg.id)
				}
				continue
			}
			w.restarts.Add(1)
			log.Printf("checker: worker %d exited (%s, total restarts %d); restarting",
				msg.id, msg.reason, w.restarts.Load())
			w.start(msg.id)
		}
	}
}

// start launches one worker goroutine. The body owns its own lifetime (and
// its own WaitGroup, if it needs one); start only waits for it to return and
// reports the exit reason.
func (w *checkerWorkers) start(id int) {
	w.wg.Add(1)
	go func() {
		defer w.wg.Done()
		reason := w.run(id)
		select {
		case w.exited <- exitMsg{id: id, reason: reason}:
		default:
			// The supervisor is gone (shutdown raced the exit); nothing to do.
		}
	}()
}

// runWorker is the production worker body: one validation loop, with a
// per-worker WaitGroup so the exit report happens only after the loop really
// returned.
func (w *checkerWorkers) runWorker(id int) proxy.ExitReason {
	var one sync.WaitGroup
	one.Add(1)
	reason := proxy.RunCheckLoop(w.candidates, w.checker, w.pool, w.bucket, w.debug, w.cfg, w.stop, &one)
	one.Wait()
	return reason
}

// stopAndWait closes the stop channel and waits for every worker to return.
// It must run before pool.Close and the good-proxy audit close: the workers
// are the last writer of both files.
func (w *checkerWorkers) stopAndWait() {
	select {
	case <-w.stop:
		return // already stopped
	default:
	}
	close(w.stop)
	w.wg.Wait()
}

// Restarts reports how many workers have been restarted. Exposed for the admin
// page and the shutdown log line: a high count is a bug report.
func (w *checkerWorkers) Restarts() int64 { return w.restarts.Load() }
