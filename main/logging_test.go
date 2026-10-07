package main

import (
	"bytes"
	"strings"
	"testing"
	"time"
)

func TestNoiseWriterFiltersTLSErrors(t *testing.T) {
	var buf bytes.Buffer
	w := newNoiseWriter(&buf, time.Minute)
	_, err := w.Write([]byte("2026/09/21 00:13:31 http: TLS handshake error from 127.0.0.1:59512: EOF\n"))
	if err != nil {
		t.Fatal(err)
	}
	if buf.Len() != 0 {
		t.Fatalf("TLS handshake noise not dropped: %q", buf.String())
	}
}

func TestNoiseWriterCoalescesDialErrors(t *testing.T) {
	var buf bytes.Buffer
	w := newNoiseWriter(&buf, time.Minute)

	line := []byte("2026/09/21 00:13:35 [325] WARN: Error dialing to mtalk.google.com:5228: context deadline exceeded\n")
	for i := 0; i < 50; i++ {
		if _, err := w.Write(line); err != nil {
			t.Fatal(err)
		}
	}
	if n := strings.Count(buf.String(), "[325] WARN: Error dialing to"); n != 1 {
		t.Fatalf("first line should pass through, got %d passes:\n%s", n, buf.String())
	}

	// A different target must not be suppressed.
	if _, err := w.Write([]byte("2026/09/21 00:13:36 [326] WARN: Error dialing to other.host:443: timeout\n")); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(buf.String(), "other.host:443") {
		t.Fatalf("unrelated dial error was suppressed: %s", buf.String())
	}

	// Once the window elapses the next repeat is printed, with a summary.
	w.last["mtalk.google.com:5228"] = time.Now().Add(-2 * time.Minute)
	if _, err := w.Write(line); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(buf.String(), "49 dial errors to mtalk.google.com:5228 suppressed") {
		t.Fatalf("suppression summary missing:\n%s", buf.String())
	}
}
