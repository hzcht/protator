package main

import (
	"os"
	"path/filepath"
	"sync"
)

// debugProxies keeps a small rolling window of freshly validated proxies and
// persists it as one URL per line. Every entry survived the full checker
// pipeline (including the e2e serving-path probe) moments before being added,
// so it is as close to "guaranteed working" as this codebase can produce.
//
// Use case: connect a browser DIRECTLY to one of these (bypassing our local
// proxy) — if the page loads, the pool/checker are fine and the failure lives
// in the serving logic; if it still times out, the "good" proxies themselves
// are flaky or the experiment needs a different class of proxy.
type debugProxies struct {
	mu   sync.Mutex
	path string
	max  int
	ring []string
}

func newDebugProxies(path string, max int) *debugProxies {
	if max < 1 {
		max = 1
	}
	return &debugProxies{path: path, max: max}
}

// Add records a freshly validated proxy and rewrites the file. The same URL is
// recorded once per window so repeated revalidations do not flood the file.
func (d *debugProxies) Add(url string) {
	if d == nil || d.path == "" || url == "" {
		return
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	for _, u := range d.ring {
		if u == url {
			return
		}
	}
	d.ring = append(d.ring, url)
	if len(d.ring) > d.max {
		d.ring = d.ring[len(d.ring)-d.max:]
	}
	d.writeLocked()
}

func (d *debugProxies) writeLocked() {
	dir := filepath.Dir(d.path)
	tmp := filepath.Join(dir, filepath.Base(d.path)+".tmp")
	f, err := os.Create(tmp)
	if err != nil {
		return
	}
	for _, u := range d.ring {
		if _, werr := f.Write([]byte(u + "\n")); werr != nil {
			break
		}
	}
	f.Close()
	_ = os.Rename(tmp, d.path)
}
