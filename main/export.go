package main

import (
	"context"
	"encoding/json"
	"log"
	"math/rand/v2"
	"net"
	"net/http"
	"strconv"
	"sync/atomic"
	"time"

	"protator/proxy"
)

// The list distribution service: one more channel for handing out proxies,
// next to the serving fronts and the admin page. A plain HTTP listener that
// answers GET / with the requested number of live proxies (txt or json), from
// a list rebuilt as a random sample of the proven tier every n minutes.
//
// It is deliberately NOT part of the admin surface: no token, no editing, no
// per-request ranking. A consumer script polls it on a schedule; the served
// list is a snapshot, so two consumers inside one refresh window share it and
// consecutive windows hand out different proxies.

// exportListDefaultCount is what ?count absent means: small enough to eyeball,
// big enough to be useful from curl without parameters.
const exportListDefaultCount = 10

// exportSnapshot is one rebuilt list. The proxies are pointers into the live
// queue; identity fields (schema/host/port) are immutable after construction,
// so the snapshot stays valid even while the checker revalidates the same
// entries. A proxy evicted from the queue mid-window still serves from the
// snapshot — the list is n-minutes stale by design, the next rebuild drops it.
type exportSnapshot struct {
	list  []*proxy.Proxy
	built time.Time
}

type exportService struct {
	bucket *proxy.Bucket
	// listSize is both the rebuild sample size and the per-request count cap.
	listSize int

	snap atomic.Pointer[exportSnapshot]
}

// startExportListServer binds and serves the list endpoint when enabled. The
// first rebuild runs synchronously before the bind: the service starts fully
// ready and the 503 path stays unreachable in practice (kept for defense).
func startExportListServer(ctx context.Context, cfg *proxy.Config, bucket *proxy.Bucket, logNoise *log.Logger) {
	if !cfg.Export.Enabled {
		return
	}
	svc := &exportService{bucket: bucket, listSize: cfg.Export.ListSize}
	svc.rebuild()

	warnExportExposure(cfg.Export.Listen)

	ln, err := net.Listen("tcp", cfg.Export.Listen)
	if err != nil {
		log.Fatalf("export: listen %s: %v", cfg.Export.Listen, err)
	}
	srv := &http.Server{
		Handler:           svc,
		ErrorLog:          logNoise,
		ReadHeaderTimeout: 30 * time.Second,
	}
	go func() {
		defer proxy.RecoverPanic("export: listener")
		log.Printf("export: list service on %s (proven sample %d, refresh every %dm)",
			ln.Addr(), svc.listSize, cfg.Export.RefreshMinutes)
		// Runtime accept failure must not exit: log.Fatalf would skip main's
		// defers and lose the unsaved queue. The bind above is already fatal.
		if err := srv.Serve(ln); err != nil && err != http.ErrServerClosed {
			log.Printf("export: serve stopped on %s: %v", ln.Addr(), err)
		}
	}()
	go func() {
		defer proxy.RecoverPanic("export: shutdown")
		<-ctx.Done()
		shutCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		srv.Shutdown(shutCtx)
	}()

	go svc.refreshLoop(ctx, time.Duration(cfg.Export.RefreshMinutes)*time.Minute)
}

// refreshLoop rebuilds the served list every n minutes. The first rebuild ran
// synchronously at startup; the ticker only re-samples.
func (s *exportService) refreshLoop(ctx context.Context, period time.Duration) {
	defer proxy.RecoverPanic("export: refresh")
	t := time.NewTicker(period)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			s.rebuild()
		}
	}
}

// rebuild samples the proven tier: every entry that carries recent proof of
// life (served traffic or a passed validation inside the liveness window —
// the same set the admin's scope=checked lists, and the tier /ready and the
// picker trust). The sample is random, not ranked: a ranked top-N would hand
// the same head to every consumer, a random sample spreads the load. The
// unranked scan is the cheap one — ranking the whole queue is the admin
// page's cost, and a list rebuilt every n minutes does not need the order.
func (s *exportService) rebuild() {
	proven := s.bucket.LiveListUnranked(proxy.AliveChecked, liveWindow)
	rand.Shuffle(len(proven), func(i, j int) { proven[i], proven[j] = proven[j], proven[i] })
	total := len(proven)
	if total > s.listSize {
		proven = proven[:s.listSize]
	}
	s.snap.Store(&exportSnapshot{list: proven, built: time.Now()})
	proxy.Stats.ExportListRebuilds.Add(1)
	log.Printf("export: list rebuilt: %d sampled of %d proven (window %s)", len(proven), total, liveWindow)
}

// exportEntry is the json row of the list: the identity four of liveRow, and
// nothing else. The distribution channel is an external contract — country,
// latency and counters are the admin page's business; url is here because a
// vless/trojan row without its userinfo is not usable, and credentials ride
// the canonical renderer (Proxy.URL) so the raw percent-encoded auth survives.
type exportEntry struct {
	URL    string `json:"url"`
	Schema string `json:"schema"`
	Host   string `json:"host"`
	Port   int    `json:"port"`
}

func (s *exportService) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", http.MethodGet)
		http.Error(w, "list service answers GET only", http.StatusMethodNotAllowed)
		return
	}
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	q := r.URL.Query()
	count := exportListDefaultCount
	if raw := q.Get("count"); raw != "" {
		n, err := strconv.Atoi(raw)
		if err != nil || n <= 0 {
			http.Error(w, "count must be a positive integer", http.StatusBadRequest)
			return
		}
		// Above list_size a request clamps to the list instead of erroring:
		// "give me everything you have" is a legitimate ask, spelled count=999999.
		if n > s.listSize {
			n = s.listSize
		}
		count = n
	}
	format := q.Get("format")
	if format == "" {
		format = "txt"
	}
	if format != "txt" && format != "json" {
		http.Error(w, "format must be txt or json", http.StatusBadRequest)
		return
	}

	snap := s.snap.Load()
	if snap == nil {
		http.Error(w, "list is being built, retry shortly", http.StatusServiceUnavailable)
		return
	}
	rows := snap.list
	if count < len(rows) {
		rows = rows[:count]
	}

	proxy.Stats.ExportRequests.Add(1)
	proxy.Stats.ExportProxiesServed.Add(int64(len(rows)))
	switch format {
	case "json":
		out := make([]exportEntry, 0, len(rows)) // len 0, not nil: an empty list marshals [] not null
		for _, p := range rows {
			out = append(out, exportEntry{URL: p.URL(), Schema: p.Schema, Host: p.Host, Port: p.Port})
		}
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "no-store")
		_ = json.NewEncoder(w).Encode(out)
	default:
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.Header().Set("Cache-Control", "no-store")
		buf := make([]byte, 0, 64*len(rows))
		for _, p := range rows {
			buf = append(buf, p.URL()...)
			buf = append(buf, '\n')
		}
		_, _ = w.Write(buf)
	}
}

// warnExportExposure is warnAdminExposure's sibling: the admin token warning
// exists because the page edits files, this one because the endpoint gives
// away live proxies to anyone who can reach the port. Loopback default keeps
// a fresh deployment safe; firewalled distribution hosts are legitimate.
func warnExportExposure(addr string) {
	if addr == "" || loopbackAddr(addr) {
		return
	}
	log.Printf("export: WARNING %s is not a loopback address — the list service hands "+
		"live proxies to anyone who can reach the port; keep it firewalled or on loopback", addr)
}

// exportRefreshInterval is the export beat's staleness yardstick: the list
// refresh period, or 0 when the service is disabled — nothing will ever move
// that beat, so /health gives no verdict for it.
func exportRefreshInterval(cfg *proxy.Config) time.Duration {
	if !cfg.Export.Enabled {
		return 0
	}
	return time.Duration(cfg.Export.RefreshMinutes) * time.Minute
}
