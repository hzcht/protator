package main

import (
	"os"
	"path/filepath"
	"testing"

	"protator/proxy"
)

func TestFileLogSinkCategories(t *testing.T) {
	dir := t.TempDir()
	sink := newFileLogSink(proxy.LoggingConfig{Dir: dir, MaxBytes: 1 << 20, Keep: 2})

	lines := []string{
		"2026/09/26 00:11:50 collector: http://site.example -> 10 candidates\n",
		"2026/09/26 00:11:51 checker: added http://1.2.3.4:80 queue=100\n",
		"2026/09/26 00:11:52 serve: CONNECT host:443 via socks5://x dial failed: boom\n",
		"2026/09/26 00:11:53 queue: live proxies = 100 (hot 5)\n",
	}
	for _, l := range lines {
		if _, err := sink.Write([]byte(l)); err != nil {
			t.Fatal(err)
		}
	}
	defer sink.Close()

	for name, want := range map[string]string{
		"collector.log": "collector: http://site.example",
		"checker.log":   "checker: added http://1.2.3.4:80",
		"serve.log":     "serve: CONNECT host:443",
		"system.log":    "queue: live proxies",
	} {
		b, err := os.ReadFile(filepath.Join(dir, name))
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if !contains(string(b), want) {
			t.Fatalf("%s: missing %q in:\n%s", name, want, b)
		}
	}
}

// TLS-handshake noise must never reach the files, even from a listener that
// bypassed the dampener: it is client-side handshake garbage, not signal.
func TestFileLogSinkDropsTLSHandshakeNoise(t *testing.T) {
	dir := t.TempDir()
	sink := newFileLogSink(proxy.LoggingConfig{Dir: dir, MaxBytes: 1 << 20, Keep: 2})
	defer sink.Close()
	if _, err := sink.Write([]byte("2026/10/01 13:29:25 http: TLS handshake error from 127.0.0.1:63025: remote error: tls: bad certificate\n")); err != nil {
		t.Fatal(err)
	}
	if _, err := sink.Write([]byte("2026/10/01 13:29:26 queue: live proxies = 69444 (hot 11)\n")); err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(filepath.Join(dir, "system.log"))
	if err != nil {
		t.Fatal(err)
	}
	if contains(string(b), "TLS handshake") {
		t.Fatalf("handshake noise reached system.log:\n%s", b)
	}
	if !contains(string(b), "live proxies") {
		t.Fatalf("real line lost alongside the noise:\n%s", b)
	}
}

func TestFileLogSinkRotation(t *testing.T) {
	dir := t.TempDir()
	sink := newFileLogSink(proxy.LoggingConfig{Dir: dir, MaxBytes: 64, Keep: 2})

	line := []byte("2026/09/26 00:11:50 queue: filler filler filler filler filler filler filler filler\n")
	for i := 0; i < 8; i++ {
		if _, err := sink.Write(line); err != nil {
			t.Fatal(err)
		}
	}
	defer sink.Close()

	// 8 x ~75 bytes into a 64-byte cap must force several rotations.
	for _, name := range []string{"system.log", "system.log.1", "system.log.2"} {
		if _, err := os.Stat(filepath.Join(dir, name)); err != nil {
			t.Fatalf("expected %s to exist: %v", name, err)
		}
	}
	if _, err := os.Stat(filepath.Join(dir, "system.log.3")); err == nil {
		t.Fatal("system.log.3 exists but keep=2 (generations .1,.2 only)")
	}
}

func TestFileLogSinkDisabledDir(t *testing.T) {
	sink := newFileLogSink(proxy.LoggingConfig{Dir: "", MaxBytes: 1 << 20, Keep: 2})
	if _, err := sink.Write([]byte("2026/09/26 00:11:50 queue: live proxies = 1\n")); err != nil {
		t.Fatal(err)
	}
	sink.Close()
}

func contains(s, sub string) bool {
	return len(sub) == 0 || (len(s) >= len(sub) && indexOf(s, sub) >= 0)
}

func indexOf(s, sub string) int {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return i
		}
	}
	return -1
}

func TestHasPrefix(t *testing.T) {
	cases := []struct {
		line, prefix string
		want         bool
	}{
		{"2026/09/26 00:11:50 collector: x", "collector:", true},
		{"collector: x", "collector:", true},
		{"2026/09/26 00:11:50 checkered: x", "checker:", false},
		{"2026/09/26 00:11:50  checker: x", "checker:", true},
		{"x collector: y", "collector:", false},
		{"x", "collector:", false},
	}
	for _, c := range cases {
		if got := hasPrefix(c.line, c.prefix); got != c.want {
			t.Errorf("hasPrefix(%q, %q) = %v, want %v", c.line, c.prefix, got, c.want)
		}
	}
}
