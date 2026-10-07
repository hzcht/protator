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
//     floods EREALINE per attempt. For a given target we keep the first line
//     and suppress repeats within the window, emitting one summary line with
//     the suppressed count when the flood resumes.
type noiseWriter struct {
	out    io.Writer
	window time.Duration

	mu   sync.Mutex
	last map[string]time.Time
	reps map[string]int
}

var reDialErr = regexp.MustCompile(`\[\d+\] WARN: Error dialing to ([^\s:]+):([0-9]+):`)

func newNoiseWriter(out io.Writer, window time.Duration) *noiseWriter {
	return &noiseWriter{
		out:    out,
		window: window,
		last:   make(map[string]time.Time, 64),
		reps:   make(map[string]int, 64),
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
