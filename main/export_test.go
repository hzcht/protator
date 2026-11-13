package main

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"protator/proxy"
)

// exportTestSnapshot builds a fixed three-row snapshot: one plain http, one
// socks5, one credentialed (the credential line must ride ParseProxyLine —
// the canonical constructor — so the raw percent-encoded auth survives into
// the rendered URL).
func exportTestSnapshot(t *testing.T) *exportSnapshot {
	t.Helper()
	credentialed, err := proxy.ParseProxyLine("http://user:pass@9.9.9.9:8080")
	if err != nil {
		t.Fatalf("ParseProxyLine: %v", err)
	}
	return &exportSnapshot{list: []*proxy.Proxy{
		{Schema: "http", Host: "1.1.1.1", Port: 8080},
		{Schema: "socks5", Host: "2.2.2.2", Port: 1080},
		credentialed,
	}, built: time.Now()}
}

func TestExportHandler(t *testing.T) {
	svc := &exportService{listSize: 100}
	svc.snap.Store(exportTestSnapshot(t))

	const txtAll = "http://1.1.1.1:8080\nsocks5://2.2.2.2:1080\nhttp://user:pass@9.9.9.9:8080\n"
	const jsonAll = `[{"url":"http://1.1.1.1:8080","schema":"http","host":"1.1.1.1","port":8080},` +
		`{"url":"socks5://2.2.2.2:1080","schema":"socks5","host":"2.2.2.2","port":1080},` +
		`{"url":"http://user:pass@9.9.9.9:8080","schema":"http","host":"9.9.9.9","port":8080}]` + "\n"

	cases := []struct {
		name   string
		method string
		target string
		status int
		wantCT string
		want   string
		allow  string
	}{
		{"txt is the default format", http.MethodGet, "/", 200, "text/plain; charset=utf-8", txtAll, ""},
		{"count slices the head", http.MethodGet, "/?count=1", 200, "text/plain; charset=utf-8", "http://1.1.1.1:8080\n", ""},
		{"count equal to the list serves the whole list", http.MethodGet, "/?count=3", 200, "text/plain; charset=utf-8", txtAll, ""},
		{"count is clamped, not refused", http.MethodGet, "/?count=999999", 200, "text/plain; charset=utf-8", txtAll, ""},
		{"json carries url+schema+host+port", http.MethodGet, "/?format=json", 200, "application/json", jsonAll, ""},
		{"unknown format is a 400", http.MethodGet, "/?format=xml", 400, "text/plain; charset=utf-8", "format must be txt or json\n", ""},
		{"unparsable count is a 400", http.MethodGet, "/?count=abc", 400, "text/plain; charset=utf-8", "count must be a positive integer\n", ""},
		{"zero count is a 400", http.MethodGet, "/?count=0", 400, "text/plain; charset=utf-8", "count must be a positive integer\n", ""},
		{"negative count is a 400", http.MethodGet, "/?count=-3", 400, "text/plain; charset=utf-8", "count must be a positive integer\n", ""},
		{"other paths 404", http.MethodGet, "/list", 404, "text/plain; charset=utf-8", "404 page not found\n", ""},
		{"POST is a 405 with Allow", http.MethodPost, "/", 405, "text/plain; charset=utf-8", "list service answers GET only\n", http.MethodGet},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			req := httptest.NewRequest(c.method, c.target, nil)
			rec := httptest.NewRecorder()
			svc.ServeHTTP(rec, req)
			if rec.Code != c.status {
				t.Fatalf("status = %d, want %d (body %q)", rec.Code, c.status, rec.Body.String())
			}
			if ct := rec.Header().Get("Content-Type"); ct != c.wantCT {
				t.Errorf("Content-Type = %q, want %q", ct, c.wantCT)
			}
			if body := rec.Body.String(); body != c.want {
				t.Errorf("body = %q, want %q", body, c.want)
			}
			if allow := rec.Header().Get("Allow"); allow != c.allow {
				t.Errorf("Allow = %q, want %q", allow, c.allow)
			}
		})
	}
}

// An empty proven set must render an EMPTY list (txt: nothing, json: []),
// not null or a 500 — a fresh install is exactly this state for the first
// refresh period.
func TestExportHandlerEmptyList(t *testing.T) {
	svc := &exportService{listSize: 100}
	svc.snap.Store(&exportSnapshot{built: time.Now()})

	req := httptest.NewRequest(http.MethodGet, "/?format=json", nil)
	rec := httptest.NewRecorder()
	svc.ServeHTTP(rec, req)
	if rec.Code != 200 || rec.Body.String() != "[]\n" {
		t.Fatalf("json on an empty list = %d %q, want 200 []", rec.Code, rec.Body.String())
	}

	req = httptest.NewRequest(http.MethodGet, "/", nil)
	rec = httptest.NewRecorder()
	svc.ServeHTTP(rec, req)
	if rec.Code != 200 || rec.Body.String() != "" {
		t.Fatalf("txt on an empty list = %d %q, want 200 empty", rec.Code, rec.Body.String())
	}
}

// A snapshot not built yet (rebuild is synchronous at startup, so this is
// defense, not a state a request should ever see) answers 503.
func TestExportHandlerNotReady(t *testing.T) {
	svc := &exportService{listSize: 100}
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rec := httptest.NewRecorder()
	svc.ServeHTTP(rec, req)
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("no snapshot = %d, want 503", rec.Code)
	}
}

// rebuild must sample exactly the proven tier: entries with recent proof of
// life in, everything without proof out.
func TestExportRebuildSamplesProven(t *testing.T) {
	b := proxy.NewBucket(10)
	alive := &proxy.Proxy{Schema: "http", Host: "1.1.1.1", Port: 80}
	alive.MarkAlive(100 * time.Millisecond)
	served := &proxy.Proxy{Schema: "socks5", Host: "2.2.2.2", Port: 1080}
	served.MarkServeOK(50 * time.Millisecond)
	quiet := &proxy.Proxy{Schema: "http", Host: "3.3.3.3", Port: 80}
	for _, p := range []*proxy.Proxy{alive, served, quiet} {
		b.Add(p)
	}

	s := &exportService{bucket: b, listSize: 100}
	s.rebuild()
	snap := s.snap.Load()
	if snap == nil || len(snap.list) != 2 {
		t.Fatalf("rebuild kept %d entries, want the 2 proven ones", lenSnap(snap))
	}
	got := map[string]bool{}
	for _, p := range snap.list {
		got[p.Host] = true
	}
	if !got["1.1.1.1"] || !got["2.2.2.2"] || got["3.3.3.3"] {
		t.Fatalf("rebuild kept %v, want only the proven hosts", got)
	}
}

// listSize clamps the sample: the service never serves more proxies than the
// list holds.
func TestExportRebuildListSizeClamp(t *testing.T) {
	b := proxy.NewBucket(10)
	for i := 0; i < 5; i++ {
		p := &proxy.Proxy{Schema: "http", Host: "1.1.1.1", Port: 8080 + i}
		p.MarkAlive(time.Millisecond)
		b.Add(p)
	}
	s := &exportService{bucket: b, listSize: 2}
	s.rebuild()
	snap := s.snap.Load()
	if len(snap.list) != 2 {
		t.Fatalf("listSize=2 kept %d entries, want 2", lenSnap(snap))
	}
}

// An empty queue rebuilds to an empty snapshot without erroring.
func TestExportRebuildEmptyBucket(t *testing.T) {
	s := &exportService{bucket: proxy.NewBucket(10), listSize: 100}
	s.rebuild()
	snap := s.snap.Load()
	if snap == nil || len(snap.list) != 0 {
		t.Fatalf("empty bucket rebuilt to %v, want an empty snapshot", snap)
	}
}

func lenSnap(s *exportSnapshot) int {
	if s == nil {
		return -1
	}
	return len(s.list)
}
