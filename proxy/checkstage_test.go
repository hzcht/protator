package proxy

import (
	"errors"
	"fmt"
	"sync/atomic"
	"testing"
	"time"
)

// TestStageOfKeepsTextAndCause pins the two contracts of stagedError: tagging
// never changes what the log line says, and the cause stays reachable through
// the standard error chain (existing callers rely on both).
func TestStageOfKeepsTextAndCause(t *testing.T) {
	base := errors.New("dial tcp 10.0.0.1:8080: i/o timeout")
	tagged := stageErr(stagePredial, base)

	if got := stageOf(tagged); got != stagePredial {
		t.Fatalf("stageOf(tagged) = %v, want predial", got)
	}
	if !errors.Is(tagged, base) {
		t.Fatal("tagging broke errors.Is: the cause must stay reachable")
	}
	if tagged.Error() != base.Error() {
		t.Fatalf("Error() = %q, want the untagged text %q", tagged.Error(), base.Error())
	}
	// Wrapped again by an outer layer: the stage must survive.
	if got := stageOf(fmt.Errorf("check: %w", tagged)); got != stagePredial {
		t.Fatalf("stageOf(wrapped) = %v, want predial", got)
	}
	if got := stageOf(base); got != stageNone {
		t.Fatalf("stageOf(untagged) = %v, want none", got)
	}
	if got := stageOf(nil); got != stageNone {
		t.Fatalf("stageOf(nil) = %v, want none", got)
	}
	if err := stageErr(stageIP, nil); err != nil {
		t.Fatalf("stageErr(nil) = %v, want nil", err)
	}
}

// TestRecordCheckFailFilesOneBucket: each failure increments exactly its own
// stage counter, and an untagged error increments nothing. Without this a
// misordered switch would silently report every failure as "predial".
func TestRecordCheckFailFilesOneBucket(t *testing.T) {
	cases := []struct {
		stage checkStage
		n     *atomic.Int64
	}{
		{stagePredial, &Stats.CheckFailPredial},
		{stageIP, &Stats.CheckFailIP},
		{stageLeak, &Stats.CheckFailLeak},
		{stageE2E, &Stats.CheckFailE2E},
		{stageContent, &Stats.CheckFailContent},
		{stageConnect, &Stats.CheckFailConnect},
	}
	before := make([]int64, len(cases))
	for i, c := range cases {
		before[i] = c.n.Load()
	}

	for _, c := range cases {
		recordCheckFail(stageErr(c.stage, errors.New("boom")))
	}
	for i, c := range cases {
		if got := c.n.Load() - before[i]; got != 1 {
			t.Fatalf("stage %v moved %d, want 1", c.stage, got)
		}
	}
	// An untagged failure belongs to no stage and must leave every counter
	// alone — otherwise "unclassified" would quietly inflate predial.
	for i, c := range cases {
		before[i] = c.n.Load()
	}
	recordCheckFail(errors.New("untagged"))
	for i, c := range cases {
		if got := c.n.Load() - before[i]; got != 0 {
			t.Fatalf("untagged failure moved stage %v by %d, want 0", cases[i].stage, got)
		}
	}
}

// TestRecordCheckDurationBuckets pins every bucket boundary: the histogram is
// the input to the timeout tuning, so an off-by-one at 60s would make a slow
// pool look healthy.
func TestRecordCheckDurationBuckets(t *testing.T) {
	cases := []struct {
		d  time.Duration
		n  *atomic.Int64
		ok bool
	}{
		{0, &Stats.CheckDurLE1, true},
		{time.Second, &Stats.CheckDurLE1, true},
		{time.Second + time.Millisecond, &Stats.CheckDurLE5, true},
		{5 * time.Second, &Stats.CheckDurLE5, true},
		{5*time.Second + time.Millisecond, &Stats.CheckDurLE15, true},
		{15 * time.Second, &Stats.CheckDurLE15, true},
		{15*time.Second + time.Millisecond, &Stats.CheckDurLE60, true},
		{60 * time.Second, &Stats.CheckDurLE60, true},
		{60*time.Second + time.Millisecond, &Stats.CheckDurLE230, true},
		{230 * time.Second, &Stats.CheckDurLE230, true},
		{230*time.Second + time.Millisecond, &Stats.CheckDurGT230, true},
	}
	// Snapshot per case: two adjacent cases can share a bucket (0s and 1s both
	// land in LE1), so a single up-front baseline would read the pair as one
	// double increment.
	for _, c := range cases {
		before := c.n.Load()
		recordCheckDuration(c.d)
		if got := c.n.Load() - before; got != 1 {
			t.Fatalf("duration %v landed in the wrong bucket (moved %d)", c.d, got)
		}
	}
}
