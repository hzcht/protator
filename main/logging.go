package main

import (
	"io"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"
)

// noiseWriter dampens two known, expected log floods without hiding real
// failures:
//
//   - stdlib http.Server logs "http: TLS handshake error from <addr>: EOF"
//     whenever a client connects to the HTTPS front and hangs up before/during
//     the TLS handshake (probes, plain-HTTP-on-8443 mistakes, idle scanners).
//     These lines are dropped entirely.
//
//   - goproxy unconditionally prints "[%03d] WARN: Error dialing to ..." for
//     every failed CONNECT (its Warnf is not Verbose-gated). Under load this
//     floods stderr with a line per attempt. For a given target we keep the
//     first line and suppress repeats within the window, emitting one summary
//     line with the suppressed count when the flood resumes.
type noiseWriter struct {
	out    io.Writer
	window time.Duration

	mu   sync.Mutex
	last map[string]time.Time
	reps map[string]int
	// swept is when the last expiry pass ran over last/reps.
	swept time.Time
}

// noiseTargetsCap bounds the per-target bookkeeping. The key is whatever
// destination the client asked for, so without a bound anyone who can reach the
// proxy grows these maps with one timed-out dial per distinct target — the map
// that exists to reduce log pressure becoming a source of it.
const (
	noiseTargetsCap    = 4096
	noiseSweepInterval = time.Minute
)

var reDialErr = regexp.MustCompile(`\[\d+\] WARN: Error dialing to ([^\s:]+):([0-9]+):`)

func newNoiseWriter(out io.Writer, window time.Duration) *noiseWriter {
	return &noiseWriter{
		out:    out,
		window: window,
		last:   make(map[string]time.Time, 64),
		reps:   make(map[string]int, 64),
		swept:  time.Now(),
	}
}

func (w *noiseWriter) Write(p []byte) (int, error) {
	line := strings.TrimRight(string(p), "\r\n")

	if strings.Contains(line, "TLS handshake error from") {
		return len(p), nil
	}

	if m := reDialErr.FindStringSubmatch(line); m != nil {
		target := m[1] + ":" + m[2]
		now := time.Now()
		w.mu.Lock()
		if t, ok := w.last[target]; ok && now.Sub(t) < w.window {
			w.reps[target]++
			w.mu.Unlock()
			return len(p), nil
		}
		n := w.reps[target]
		w.last[target] = now
		w.reps[target] = 0
		w.sweepLocked(now)
		w.mu.Unlock()
		if n > 0 {
			if _, err := w.out.Write([]byte(now.Format("2006/01/02 15:04:05") +
				" rate: " + strconv.Itoa(n) + " dial errors to " + target + " suppressed\n")); err != nil {
				return len(p), err
			}
		}
		return w.out.Write(p)
	}

	return w.out.Write(p)
}

// sweepLocked forgets targets nobody has dialed again. Entries older than the
// window can never fire a summary line again, so keeping them is pure growth.
// The map is also hard-capped: past that, an over-cap insert clears the
// bookkeeping rather than letting a client-chosen key space run away.
func (w *noiseWriter) sweepLocked(now time.Time) {
	if len(w.last) <= noiseTargetsCap && now.Sub(w.swept) < noiseSweepInterval {
		return
	}
	w.swept = now
	if len(w.last) > noiseTargetsCap {
		w.last = make(map[string]time.Time, 64)
		w.reps = make(map[string]int, 64)
		return
	}
	cutoff := now.Add(-w.window)
	for k, t := range w.last {
		if t.Before(cutoff) {
			delete(w.last, k)
			delete(w.reps, k)
		}
	}
}
