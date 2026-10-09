# protator — audit findings

This file is written to be handed to another model (or a human reviewer) with
**no other context**. It contains: what the project is, the invariants a
reviewer must respect, what was recently fixed (so it is not re-reported), and
the open problems with exact locations.

Repo: Go 1.27 toolchain, module `protator`, Windows-primary dev box (no cgo,
`go test -race` does **not** run here).

## 0. How to verify anything you change

```powershell
gofmt -l main proxy util   # must print nothing
go build ./...
go vet ./...
go test ./... -count=1
go test ./proxy/ -run XXX -bench . -benchtime 200x   # hot paths
go run ./main -config config/config.toml -check
```

Run the binary from the **repo root**: all config/data paths are relative
(`config/`, `data/`). `go run ./main` from `main/` fails to load config.

Encoding hazard on this box: PowerShell `Set-Content`/`Get-Content -Raw`
round-trips mangle UTF-8 non-ASCII (em dashes become mojibake, a BOM appears).
Edit Go/markdown with an editor tool, never with shell text cmdlets. A byte-level
checker for the mojibake signature+D0 B2 D0 82 E2 80 9D; a BOM is EF BB BF.

## 1. What the system is

Transit proxy collector + rotating forward proxy (HTTP CONNECT, HTTPS front,
SOCKS5). Pipeline:

```
collector (fetch sites.txt) -> candidates channel -> checker workers (600)
    -> success: bucket (+ good_proxies.last)   failure: candidate pool (candidates.lst)
bucket -> ForwardDialer -> serving path (goproxy fronts + SOCKS5)
```

Serving picks by **evidence tier**: hot tail (proven by real traffic) → proven
pool (`freshPool`, cached ≤2s) → whole queue. Every request re-picks; failures
fail over to a distinct proxy and evict after `serve_max_fails`.

## 2. Layout (files worth knowing before proposing a fix)

- `proxy/bucket.go` — the live queue: membership, hot tail, `LiveList*`,
  `SourceCounts`, `Subscribe`, `Get`, `ProvenCount`.
- `proxy/pick.go` — serving-path policy: proof tiers (`freshGreen/Warm/Stale`),
  `rankPick`, `betterPick`, `PickHealthy`, `SetFreshnessWindows`.
- `proxy/pipeline.go` — `RunCheckLoop` (the checker worker), `runOne`,
  `RevalidateSeeded`, `ExitReason`.
- `proxy/revalidate.go` — `RevalidateLoop` / `RevalidateMany` / `revalidateOne`.
- `proxy/poolloop.go` — `PoolReprobeLoop` + non-blocking `emitPoolBatch`.
- `proxy/pool.go` — `CandidatePool`: rotation at cap, `compactAsync` (off-lock),
  `drift` flag, `Batch`/`Good`.
- `proxy/stats.go` — `Stats` registry (atomic counters; `Snapshot()`).
- `proxy/guard.go` — `RecoverPanic` / `GuardedSend` (panic → log + counter).
- `proxy/extract.go` — universal patterns + per-site regexes + base64 body pass.
- `proxy/store.go` — queue/sites persistence, `SaveBucketAtomic`, good-proxy audit.
- `proxy/sticky.go` — `PinPool` (LRU on `container/list` + reverse index).
- `proxy/upstream.go` — `ForwardDialer` (failover, tunnel supervision).
- `proxy/transport.go` — `ProxyTransport` (request-level failover, block pages).
- `proxy/socks5_server.go` — SOCKS5 front-end.
- `main/workers.go` — `checkerWorkers`: worker pool **and its supervisor**.
- `main/beats.go` — subsystem heartbeats + admin-exposure warning.
- `main/loops.go` — save/stats loops (wiring only).
- `main/adminapi.go`, `main/adminhealth.go`, `main/adminlive.go`,
  `main/adminws.go` — the admin surface.
- `main/adminweb/` — the UI files (HTML/CSS/JS), `//go:embed`-ed.
- `config/regexp.txt` — per-site extraction patterns.
- `config/sites.txt` — curated source list (~334 entries).

## 3. Invariants — do NOT "fix" these (they were deliberate)

- Collector `emit` is **blocking** on purpose (dropping candidates hurts
  completeness).
- `ForwardDialer.NewTransport` must keep `DisableKeepAlives: true` (it is what
  makes "new chain per request" true; enabling it breaks interstitial failover).
- `Bucket.PickHealthy` must not become uniform sampling: with a ~1.5% proven
  share, uniform hits an unvalidated proxy ~99% of the time.
- `/ready` must read `Bucket.ProvenCount`, never `Len()`.
- `CandidatePool` **rotates** at its cap (oldest evicted, newest kept) and keeps
  its newest on an oversized load; "reject when full" froze the production pool
  at 391k lines once.
- Pool lines may carry a `\t<source-url>` suffix (source attribution) — metadata,
  not garbage.
- `Proxy` health fields are `sync/atomic`; **never** add a mutex to `Proxy`.
- Bare goroutines must `defer proxy.RecoverPanic(...)`; parallel checker
  sub-probes must `proxy.GuardedSend` their one result.
- Never `log.Fatalf` outside a bind path (`os.Exit` skips every defer in main:
  no queue save, no pool flush, no audit close). Bind synchronously (fatal),
  then serve with a logging accept loop.
- The worker pool's stop channel must not be deferred inside `buildPipeline`
  (its defers run at return — before the first request).
- `RunCheckLoop`'s select must not have a `default:` branch (idle workers spin
  at 100% CPU).
- Sorting/ranking must never call `p.URL()` or `p.Key()` inside a comparator.
- `noiseWriter` filters stdlib TLS-handshake noise and coalesces the goproxy
  dial-error flood; don't bypass it with a fresh logger for listeners.
- Config defaults live in `Config.fillDefaults`; `config/config.toml` mirrors
  them. Change both.
- `sites_legacy.txt` (~87 MB) is history, never fed to the collector.
- `data/`, `*.exe`, `*.log`, `bk/`, `AGENTS.md`, `main/config/` are gitignored.

## 4. Already fixed — do not re-report

Both fixes are committed (`9a31d78`, `2945248`), tests exist for each:

- **Checker pipeline never started**: `stopWorkers` was deferred inside
  `buildPipeline` → all 600 workers exited at startup, the collector's blocking
  emit wedged the candidate channel, the queue never recovered.
- **Idle workers spun at 100% CPU**: `default:` in `RunCheckLoop`'s select.
  Regression test samples `/cpu/classes/total:cpu-seconds` (1492% before).
- **`LiveListPage` cost 146k allocs / 15 ms**: comparator called `p.Key()`.
- **`SaveBucketAtomic` allocated every URL twice** and kept the wrong end of an
  oversized queue (now: `URLLen` size pass, `AppendURL` render, newest tail).
- **Pool compaction held `mu` across the fsync** (now off-lock + `drift`).
- **`PinPool` evicted by scanning the table** under the dial lock (now O(1) LRU).
- **`/ready` trusted `Len()`** (now `ProvenCount` + reason).
- **VLESS buffer over-index on a 256-byte domain**; socks5/VLESS/SOCKS5-reply
  write deadlines armed on long-lived tunnels.
- **Panics in bare goroutines exited the process** (now `guard.go` + counters).
- **Listener accept failures called `log.Fatalf`** (bind still fatal).
- **Silent write failures** in the audit/pool/transport paths (now logged).
- **Site telemetry no-op'd at the registry cap** (`statLocked` returns nil).
- **`/api/proxies/revalidate` indexed a full queue snapshot** (now `Bucket.Get`).
- **`recordStatsSample` raced the metrics-window map** (now under `metricsMu`).

## 5. Open problems (prioritized)

### P1 — supervisor restarts with no backoff
`main/workers.go:97`. A deterministic per-candidate panic makes the worker exit
with `ExitPanicStreak` after `panicStreakLimit` (20) candidates, and the
supervisor restarts it immediately — start/panic/20-log-line cycles as fast as
the candidates arrive. The streak limit bounds the worker, not the supervisor.
Fix: per-worker backoff (1s → 2 → 4 … cap 60s), reset on a clean candidate;
report sustained restarts in `/health` (`worker_restarts` already exists) and
make `statsLoop` shout when restarts climb.

### P2 — admin write path blocks the queue
`proxy/bucket.go:582` (`LiveListUnranked` holds `mu.RLock` for an O(queue) scan)
called from the WS connect goroutine `main/adminws.go:168`. One admin page open
on a 2M-entry queue stalls `Add`/`Remove` (checker, revalidation, serving
evictions) for the scan duration. Fix: build the initial state outside the lock
by chunking under `RLock`/`RUnlock`, or cap the scope for the connect payload
and let the client page in the rest.

### P3 — WebSocket delta rebuilds the whole checked scope every second
`main/adminws.go:208` builds a fresh map of the `AliveChecked` scope (tens of
thousands of rows) once per second while any page is open: ~2 MB/s of garbage
and the P2 scan cost. Fix: diff incrementally against the stored map (insert /
compare / delete), or bound the delta to the `hot` scope (≤512 rows, `hotMax`)
and re-sync the full list on client request.

### P4 — SOCKS5 front has no total request budget
`proxy/socks5_server.go:162` uses `socks5.dial_timeout` (120s) per dial with no
total cap, while the HTTP front is bounded by `serve_total_timeout` (25s). A
client can therefore wait ~6 minutes (120s × `serve_retries`) through SOCKS5.
Fix: wrap the dial in a context bounded by `serve_total_timeout` when > 0, or
document the difference as intentional.

### P5 — revalidation cannot keep up with its own interval
`proxy/revalidate.go:13`. With `revalidate_max_per_pass = 30000` and a realistic
10–20 checks/s (a full check is ~12 requests through the proxy), one pass takes
25–50 minutes while `revalidate_interval = 15m`, and `RevalidateLoop` runs passes
serially — so the effective cadence is the pass length, not the config. Fix:
either lower the budget to what fits the interval, or make the target derive
from measured checker throughput (`Stats.Checks` rate) instead of a constant.

### P6 — TLS front cert is generated once and never rotated
`proxy/tlsutil.go`. `-check` and startup do not look at the cert's lifetime; an
expired pair makes every `https://` upstream dial fail with a TLS error that
looks like proxy death. Fix: warn at startup (and in `checkConfig`) when
`NotAfter` is within N days; document that regenerating means deleting the pair.

### P7 — no alerting
`main/loops.go:56` (`statsLoop`) prints rates but nobody watches them. Minimum:
a threshold on `dial_failures/requests` (e.g. >50% for 2 consecutive minutes)
→ loud log line + emergency collector wake; the counters are already in
`proxy.Stats`.

### P8 — no fail-closed mode on the serving path
`proxy/pick.go:471` (`PickHealthy`) falls back to the unverified bulk of the
queue when no proven entry exists. With `proven == 0` the proxy serves clients
through unvalidated entries. Add `serve_require_proven` (default false) so an
operator can choose 502 over "maybe".

### P9 — source tiers not solved
`config/sites.txt` ~334 entries, `max_sites_per_cycle = 60` → the tail is
fetched only after the head's cooldowns drop, i.e. effectively never. Decide:
two files (primary/secondary) or a measured cap. `statsLoop`/`/api/sources`
already report yield, so the cut can be evidence-based.

### P10 — soak / load test for the serving path
`proxy/pick_bench_test.go` measures single-call cost only. The bugs fixed in
`9a31d78` were all concurrency/capacity bugs that only appear under sustained
load. A soak test (N goroutines × M dials through in-test upstreams with random
failures, asserting queue/pool/pin invariants) would catch the next one.

### P11 — GeoIP not wired
`geoip_db_path` is commented out in `config/config.toml`, so `country`/`asn`
filters in the admin page and `/api/proxies` are always empty, and
`checkConfig` does not validate the path. Decide: ship the DB path, or drop the
filters from the UI.

### P12 — dead config knob
`logging.level` is parsed by `Config` but never read. Either implement
(level switch exposed on `/api/config`, no restart) or delete the knob from the
config, `fillDefaults` and docs.

### P13 — admin surface has no request protection
`/api/proxies?limit=0` ranks the whole queue, `/api/metrics` is cheap, `/ws`
state is P2 — all behind the token but not behind any per-client rate limit. A
page left open plus a scripted loop is a self-DoS. Fix: hard cap on `limit`,
short-TTL cache for the heaviest scopes, or a per-connection request budget.

### P14 — no end-to-end test through the fronts
Tests cover dial/pipeline level, but nothing drives goproxy
(CONNECT→upstream→ACL/waste rules) or the SOCKS5 handshake→tunnel path end to
end. That is the only thing that would catch a regression in the chain
"browser → front → upstream → target".

### P15 — no versioning / release
`CHANGELOG.md` has only `## [Unreleased]`; commits go straight to master with no
tags, so "which version is in production" is unanswerable. Add a version
constant + `-version` flag, tag releases, move Unreleased sections down.

### P16 — authenticated proxies unsupported
`regexp.txt` and the sources include `user:pass@host:port` shapes, but
`validSchema`/checker/dialer have no credential path, so those sources produce
candidates that always fail validation. Either implement credentials end to end
(schema → checker → dialer) or strip the patterns and document the gap.

### P17 — pool byte accounting drifts after compaction
`proxy/pool.go`: `compactLocked` rewrites from memory but does not recompute
`cp.bytes`; evictions decrement it incrementally, so the `maxBytes` eviction
trigger can drift from the real file size. Recompute on a successful rewrite.

### P18 — small things
- `proxy/pipeline.go:95`: the panic streak counter resets only on a fully clean
  candidate, so a panic every other candidate never reaches the limit. Document
  or count by time window instead.
- `proxy/bucket.go` `addLocked` at `max` evicts `proxies[0]` (oldest insertion),
  which can be a freshly proven hot entry. Correct today (demote), but the
  eviction policy deserves a test at `max`.
- `proxy/extract.go:210`: `tryBase64Text` walks every byte of every body before
  rejecting. Cheap per page, but it is a constant tax; a quick pre-filter (first
  non-base64 byte position, or a sampled check) would make it near-free.
