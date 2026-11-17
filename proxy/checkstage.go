package proxy

import (
	"errors"
	"time"
)

// checkstage.go classifies where a validation died and how long it took.
//
// The checker is the pipeline's bottleneck, and its cost used to be invisible:
// 600 workers produced 5.4 checks/s (112 s per check) at 6% of one core, and
// nothing in the metrics could tell a dead host burning SYN timeouts apart from
// a live proxy whose far side never answered. Tuning timeouts under that
// blindness is guessing, so every failure now carries the stage that produced
// it and every fresh check lands in exactly one duration bucket.
//
// The counters themselves live in stats.go; this file only decides which one a
// given outcome belongs to.

// checkStage names the pipeline step that rejected a proxy. The order is the
// pipeline order: a failure is filed under the first stage that failed.
type checkStage int

const (
	stageNone checkStage = iota
	// stagePredial covers everything rejected before a single request was
	// sent: an impossible port, a bogon address, a TCP pre-dial that never
	// completed. This is the bucket that says "the host is dead", and it was
	// the one that consumed the pipeline in the 2026-11 soak.
	stagePredial
	stageIP      // the first request through the proxy failed
	stageLeak    // header-echo probe: the proxy forwards our IP
	stageE2E     // serving-path tunnel probe failed
	stageContent // content/exit-confirmation failed
	stageConnect // an http(s) proxy could not tunnel at all
	// stageBudget: the candidate ran out of check_budget before an attempt
	// could even start. It is a separate bucket because it means the *budget*
	// is wrong (too many protocols for the clock), not that the proxy is dead.
	stageBudget
)

// String implements fmt.Stringer for logs and tests.
func (s checkStage) String() string {
	switch s {
	case stagePredial:
		return "predial"
	case stageIP:
		return "ip"
	case stageLeak:
		return "leak"
	case stageE2E:
		return "e2e"
	case stageContent:
		return "content"
	case stageConnect:
		return "connect"
	case stageBudget:
		return "budget"
	}
	return "none"
}

// stagedError attaches a stage to an error without changing its text: existing
// callers log it exactly as before, and errors.Is/As still reach the cause.
type stagedError struct {
	stage checkStage
	err   error
}

func (e *stagedError) Error() string { return e.err.Error() }

func (e *stagedError) Unwrap() error { return e.err }

// stageErr tags err with the stage that produced it. A nil err stays nil, so
// it can wrap every return in a chain without changing control flow.
func stageErr(s checkStage, err error) error {
	if err == nil {
		return nil
	}
	return &stagedError{stage: s, err: err}
}

// stageOf reports the first tagged stage in the chain, or stageNone.
func stageOf(err error) checkStage {
	var se *stagedError
	if errors.As(err, &se) {
		return se.stage
	}
	return stageNone
}

// recordCheckFail files one failed validation under its death stage. It is
// called for fresh checks and revalidations alike: the question it answers
// ("where do validations die") is the same for both populations.
func recordCheckFail(err error) {
	switch stageOf(err) {
	case stagePredial:
		Stats.CheckFailPredial.Add(1)
	case stageIP:
		Stats.CheckFailIP.Add(1)
	case stageLeak:
		Stats.CheckFailLeak.Add(1)
	case stageE2E:
		Stats.CheckFailE2E.Add(1)
	case stageContent:
		Stats.CheckFailContent.Add(1)
	case stageConnect:
		Stats.CheckFailConnect.Add(1)
	case stageBudget:
		Stats.CheckFailBudget.Add(1)
	}
}

// recordCheckDuration files one completed fresh check (Checker.Check, all
// protocol attempts included) into a duration bucket. Revalidations are
// deliberately not filed here — they skip the protocol loop, so mixing the two
// populations would blur the one number step-2 tuning needs to move; their
// throughput is visible as reval_checked_total.
func recordCheckDuration(d time.Duration) {
	switch {
	case d <= time.Second:
		Stats.CheckDurLE1.Add(1)
	case d <= 5*time.Second:
		Stats.CheckDurLE5.Add(1)
	case d <= 15*time.Second:
		Stats.CheckDurLE15.Add(1)
	case d <= 60*time.Second:
		Stats.CheckDurLE60.Add(1)
	case d <= 230*time.Second:
		Stats.CheckDurLE230.Add(1)
	default:
		Stats.CheckDurGT230.Add(1)
	}
}
