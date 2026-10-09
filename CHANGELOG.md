# Changelog

All notable changes to this project are documented here.
The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).
Everything not in a tag yet lives in `## [Unreleased]`, because this project
has no release process yet and an unmarked change is a change nobody can find.

## [Unreleased]

### Fixed — critical

- **The checker pipeline never started.** The `stopWorkers` close was
  `defer`red inside `buildPipeline`, so it ran when that function *returned*
  — before a single client request was served. All 600 workers exited at
  startup, nothing consumed the candidate channel, the collector's deliberately
  blocking `emit` filled it and wedged permanently, and the queue was never
  replenished again. Worker lifecycle now lives in `main`'s shutdown path
  (`main/workers.go`), between the listener drain and the final queue save.
- **600 idle workers spun the CPU at 100%.** `RunCheckLoop`'s `select` had a
  `default:` branch, so a worker whose channel was momentarily empty fell
  through and re-ran the whole validation path on a zero-value `Candidate`
  forever. Measured in the new regression test: **1492% of a core over 150 ms**
  for a single idle worker. The select now blocks.
- **`LiveListPage` cost 146k allocations and ~15 ms per admin request.** The
  sort comparator called `p.Key()` on evidence ties, and `Key()` builds the URL
  for any proxy that has not been through a pick yet — so ranking a page of a
  70k queue made a million `fmt.Sprintf` calls. Ties now keep queue order
  (stable sort), and the comparator allocates nothing. 15 ms → 2.4 ms.
- **`SaveBucketAtomic` allocated a string per queue entry twice over.** The
  size pass measured by rendering every URL, then the write pass rendered them
  again; `Proxy.URL()` is `fmt.Sprintf`-based, so a 2M-entry save produced a
  ~70 MB garbage spike every minute. The size pass now uses `Proxy.URLLen()`
  (length arithmetic, no allocation), only the surviving tail is rendered, and
  the render goes through `Proxy.AppendURL` into a reusable buffer. 250k
  allocations → 13.
- **Queue save kept the wrong tail.** An oversized queue was truncated from the
  head — re-seeding every restart with the stalest entries while silently
  dropping the freshest. It now keeps the newest entries, matching what the
  candidate pool does at its own cap, and logs the trim.
- **`/ready` reported healthy for an unproven queue.** It returned 200 when
  `bucket.Len() > 0`, so a supervisor kept routing clients into a queue of
  seeded-but-never-verified addresses. It now uses `Bucket.ProvenCount` — the
  tier the picker actually samples — and returns a machine-readable reason on
  503.
- **VLESS handshake could index past its buffer.** The fixed-size arithmetic
  double-counted a byte, and a 256-byte SOCKS5 domain address (one length byte,
  nothing validates it against the DNS limit) reached past the end of the
  array. The check is now on the destination host itself.
- **Deadline bugs on the tunnel paths**: h12.io/socks left a dial-time+timeout
  write deadline armed on socks5 connections (clearing it only on the socks4
  path), so long sessions died mid-flight; the VLESS handshake armed a 10 s
  write deadline on a long-lived tunnel; and the SOCKS5 success reply raced the
  120 s upstream dial budget and failed its own write deadline. All three now
  bound only what needs bounding and clear the rest.
- **The candidate pool's rewrite stalled every checker worker.** `compactLocked`
  holds the pool mutex across a multi-megabyte write plus its fsync, and the
  pool sits at its cap in production, so that fired every minute or two.
  Compaction now runs off the lock: snapshot the lines, drop `mu`, write temp +
  fsync + rename, then flush whatever was appended meanwhile
  (`compacting`/`pending`). `Close` uses the new `drift` flag for its final
  realignment.
- **Panic safety.** `proxy/guard.go` (`RecoverPanic`, `GuardedSend`) is now
  deferred in every bare goroutine the program spawns — checker workers and
  their sub-probes, collector site fetches, SOCKS5 sessions, tunnel relay legs,
  the admin WebSocket writer, the late SOCKS dial reaper. A recovered panic
  costs one candidate/proxy/session instead of exiting the process without
  running `main`'s defers (no queue save, no pool flush, no audit close).
  Panics are counted in `proxy.Stats`.
- **Worker capacity no longer decays silently.** A worker that exits (panic
  streak past a limit, or any future bug) is restarted by its supervisor, and
  the restart count is a metric. A closed candidate channel is the one exit
  that is *not* restarted — it would return immediately and spin the
  supervisor.
- **Silent persistence failures are now loud.** Every write path that used to
  swallow errors logs them: the good-proxy audit (write, flush, open, final
  close), the candidate pool, the collector's transport cache, the via-proxy
  fetcher. A full disk used to lose the audit trail with nothing in the logs.
- **`/ready` lost its Content-Type on 503** (set after `WriteHeader`, which is
  a no-op), and several other admin responses shipped sniffed content types.
  `httptest.ResponseRecorder` cannot reproduce that, which is why the tests
  passed while production did not.
- **Site telemetry silently stopped at the registry cap.** `statLocked`
  returned a scratch `&SiteStat` that was never stored, so `Record`/`Failed`
  mutated an object that was thrown away: for untracked sources every counter
  and the cooldown were no-ops. It now returns `nil` and every caller handles
  it; a new source past the cap is still fetched and still scored for the
  cycle order.
- **The site-rotation jitter froze for every unproven source**, because the
  "is it unproven" sentinel was `Priority == 0` and scoring wrote `Priority`
  back into the registry.
- **Transports cached by URL instead of key** in the collector let one address
  hold two cached transports and their sockets; the cache is also capped (1000)
  with eviction that closes idle connections, and the transports carry real
  `MaxIdleConns`/`IdleConnTimeout` so a dead upstream no longer pins sockets
  for the life of the process.

### Added

- **`proxy/stats.go` — the process-wide counter registry.** Serving path
  (requests, dial attempts/failures, evictions, served OK, response-level
  failures, block pages, bytes in/out), checker throughput, collector cycles
  and candidates, revalidation passes/drops, forced revalidation, recovered
  panics. `GET /api/metrics` exposes the counters, their per-second rates (two
  samples apart) and the live gauges, with `?format=text` for Prometheus. The
  1-minute `queue:` log line prints the same rates.
- **Subsystem heartbeats** (`main/beats.go`): the last time the collector ran a
  cycle, the last revalidation pass and the last successful queue save, derived
  from counter deltas. `/health` reports them with a staleness verdict, because
  a collector that crashed and a collector that is merely slow look identical
  in a counter.
- **Log tail in the admin page** — `/api/logs?category=collector|checker|serve|system&limit=N`,
  served from a 300-line-per-category ring in `fileLogSink`. No SSH needed for
  the first thing an operator asks during an incident.
- **Effective-config view** — `GET /api/config`, reflection-driven with secrets
  (`*token*`, `*key_file*`) redacted.
- **Admin token** — `server.admin_token` gates every endpoint except `/health`
  and `/ready` (Bearer header or `?token=`; the page remembers one it is given
  on the URL). A non-loopback listener without a token logs a loud warning at
  startup.
- **pprof on the admin port** (`/debug/pprof/...`, behind the token): CPU,
  heap, block and goroutine profiles of the running process.
- **Operator actions in the UI** — *Retest shown* (re-check up to 500 listed
  proxies through the full validator), per-proxy retest, per-source *retry now*
  (`POST /api/sources/cooldown`, backed by the new `SiteRegistry.ResetCooldown`),
  *Collect now* (`POST /api/collector/wake`), and a 24h history graph with the
  per-minute request/check/dial-failure rates drawn on a canvas.
- **Whole-body base64 extraction** — many list mirrors publish the plain text
  encoded. The extractor decodes an all-base64 body (padded or unpadded) and
  runs the full pipeline over it, with a guard that rejects anything that
  decodes to noise. 8 MB body cap.
- **New extraction patterns** in `config/regexp.txt`: `?ip=...&port=...` query
  APIs, unquoted CSV exports, Clash/QuanX/Surge `server:`/`port:` blocks (both
  orders), `data-proxy-ip`/`data-proxy-port`, and `"proxy":"ip:port"`.
- **New sources** in `config/sites.txt`: an API-style section (proxyscrape v2/v3,
  proxy-list.download, openproxylist, geonode, openproxy.space, proxylist.icu,
  pubproxy, multiproxy) and Telegram channel mirrors (`t.me/s/...`), alongside
  more raw GitHub lists.
- **Benchmarks** (`proxy/pick_bench_test.go`) for the five hot paths: pick, live
  page, queue save, pool add at cap, pin set at cap.
- **Tests**: idle-worker no-spin (CPU-sampling), supervisor restart / no-restart
  after channel close, LRU eviction and reverse-index re-pinning, expiry sweep,
  pool compaction under rotation, `URLLen` correctness and tail preservation,
  base64 extraction (padded, unpadded, false-positive guards), admin metrics
  rates + Prometheus text, log tail by category, config redaction + token
  gating, and the wake/cooldown endpoints.

### Changed

- **Shutdown order** in `main`: drain listeners → stop the validation workers →
  save the queue → close the pool → close the good-proxy writers → drop the
  collector's transport cache.
- **Listeners**: bind synchronously (bind failures stay fatal), then serve in
  the background with a runtime-error loop that logs instead of calling
  `log.Fatalf`. The HTTPS front now sets `NextProtos` explicitly, since the
  `Serve(tls.NewListener(...))` switch dropped HTTP/2 + ALPN negotiation.
- **Admin layout**: `adminapi.go` was split by concern — `adminhealth.go`
  (health/ready/metrics/logs/config/token), `adminlive.go` (row rendering,
  paging, exporters), `adminws.go` (the WebSocket hub). The old struct's four
  nearly-identical mutexes are now three clearly-scoped ones plus a hub.
- **`liveRow` rendering is single-sourced**: the HTTP list, the CSV/JSONL exports
  and the WebSocket delta all render through `newLiveRow`; the CSV header is a
  constant next to the struct so the two cannot drift.
- **WebSocket deltas no longer repeat the 24h history** (1440 samples per
  broadcast per client, for data that changes once a minute) and are skipped
  entirely when no client is connected. The initial state message is the only
  one that carries history.
- **Serving-path policy moved to `proxy/pick.go`** (proof tiers, `rankPick`,
  `betterPick`); `bucket.go` is now the queue itself.
- **The admin assets are real files** in `main/adminweb/`, `//go:embed`-ed by
  `main/adminassets.go`: proper editor support, linting and small diffs for a
  600-line JavaScript program that used to live inside a Go string.
- **`RunCheckLoop` reports an `ExitReason`** (stopped / channel closed / panic
  streak) so the supervisor can tell a restartable exit from a permanent one.
- **The pool re-probe and revalidation policies** keep their homes in
  `proxy/poolloop.go` / `proxy/revalidate.go`; `main/loops.go` stays wiring.
- **Docs**: new `docs/REGEX.md` (what the extractor reads, guards, how to add a
  pattern), README (new tabs, endpoints, token, metrics), DEVELOPER (new
  pitfalls, metrics/profiling/benchmark sections, updated file tree),
  ARCHITECTURE (component map, route table, loop table).
- `CHANGELOG.md` — new file; this project had no record of what changed.

### Known gaps (next)

- No metrics for the *serving* path over time beyond the 24h ring: alerts are
  still a human reading `/api/metrics`.
- `/api/logs` is a tail, not a search; an incident older than 300 lines still
  needs the rotated file.
- The admin page has no way to drop a proxy from the queue (only the checks
  that may drop it as a side effect).
- Authenticated proxies (`user:pass@host:port`) are still not supported: the
  checker and dialer have no credential path, so those sources are ignored
  rather than half-read.
- `README.md` still describes the collector's source ordering optimistically;
  the telemetry drive is `max_sites_per_cycle` and that is the number that
  decides whether the tail of `sites.txt` is ever reached.
