# Developer Guide

Comprehensive guide for contributors and maintainers of protator.

## 1. Quick Start

```powershell
# From repo root
go build ./...
go vet ./...
go test ./... -count=1

# Run from repo root (critical: config files are relative paths)
go run ./main -config config/config.toml
# Or use the management scripts:
powershell -NoProfile -ExecutionPolicy Bypass -File .\main\start.ps1
```

## 2. Project Structure

```
protator/
├── config/                  # Configuration files
│   ├── config.toml         # Main configuration
│   ├── sites.txt           # Curated source list
│   ├── regexp.txt          # Extraction regexes
│   ├── checkers.toml       # Content test templates
│   └── sites_legacy.txt   # Pre-curation original (history only)
├── data/                    # Runtime data
│   ├── proxy.lst           # Persisted live queue
│   ├── good_proxies.last   # Append-only audit of accepted proxies
│   ├── candidates.lst     # Failed candidates pool
│   ├── debug_proxies.txt   # Last N validated proxies
│   └── logs/               # Rotating log files
├── main/                    # Entrypoint & admin
│   ├── proxy.go            # main() + wiring (buildPipeline, startCollector)
│   ├── servers.go          # HTTP/HTTPS/SOCKS5 listeners
│   ├── loops.go            # Wiring + housekeeping loops (save, stats)
│   ├── admin.go            # Admin listener (mixed HTTP/HTTPS)
│   ├── adminapi.go         # Admin JSON API + WebSocket
│   ├── adminassets.go      # Embedded UI (HTML/CSS/JS)
│   ├── logfiles.go         # Per-category rotating log sinks
│   ├── logging.go          # noiseWriter (TLS noise filter + goproxy WARN coalesce)
│   ├── start.ps1           # Ops: start/restart
│   └── stop.ps1            # Ops: graceful stop
├── proxy/                   # Core logic
│   ├── model.go            # Proxy, Candidate, atomic health stats
│   ├── bucket.go           # Live queue, PickHealthy, per-source counts, LiveList, Subscribe
│   ├── pipeline.go         # RunCheckLoop (candidate -> pool/bucket), RevalidateSeeded
│   ├── revalidate.go       # RevalidateLoop / RevalidateMany (stale-first)
│   ├── poolloop.go         # PoolReprobeLoop (adaptive re-probe batch)
│   ├── checker.go          # Validation pipeline + GeoIP
│   ├── collector.go        # Site scraping + extraction
│   ├── upstream.go         # ForwardDialer with failover + passive feedback
│   ├── dial.go             # CONNECT, SOCKS, VLESS (uTLS + REALITY)
│   ├── extract.go          # Regex + spys XOR + document.write JS
│   ├── pool.go             # CandidatePool (persisted failed candidates, rotating)
│   ├── debugproxies.go     # Rolling window of freshly validated proxies
│   ├── sitestats.go        # SiteRegistry (telemetry + cooldown + priority)
│   ├── config.go           # TOML config structs + fillDefaults
│   ├── store.go            # File I/O (sites, queue, regex, atomic saves)
│   ├── socks5_server.go    # RFC 1928 SOCKS5 front-end
│   ├── tlsutil.go          # Cert loading / self-signed generation
│   ├── browser.go          # Playwright headless fallback
│   ├── sticky.go           # Connection/session pinning
│   └── transport.go        # ProxyTransport (request-level failover + block detection)
├── util/                    # Legacy stub (keep as-is)
└── docs/                    # Architecture, Developer guide
```

## 3. Key Design Principles

### 3.1 Lock-free health stats
`Proxy` uses `sync/atomic` for all health fields (`consecFails`, `okTotal`, `latencyEMA`, `lastCheck`, `lastOK`, `inFlight`). **Never add a mutex to `Proxy`** — serving path must stay allocation-free and non-blocking.

### 3.2 Blocking emit is intentional
`Collector.emit()` does a blocking send to the candidate channel. **Do not "optimize" to non-blocking** — dropping candidates hurts completeness under load. The channel buffer (10k) and checker throughput are the backpressure mechanism.

### 3.3 Tiered picking is mandatory
`PickHealthy` samples by evidence tier: `hot` → `freshPool` → whole queue. With 1.5% proven share, uniform sampling lands on unvalidated proxies ~99% of the time. **Do not simplify to uniform sampling**.

### 3.4 Source attribution is metadata, not garbage
`CandidatePool` lines may carry `\t<source-url>` suffix. `parsePoolLine` handles both forms. Legacy lines without suffix load with empty source — **honest, not fake**.

### 3.5 `pick_fresh_window` must outlast `revalidate_interval`
Between two revalidation passes the freshly-validated set is all the picker has to aim at. A shorter window empties it silently. `fillDefaults` warns at startup if they conflict.

### 3.6 Admin mixed listener
Single port answers both HTTP and HTTPS by sniffing first byte (`0x16` = TLS). `newAdminServer` wires `ErrorLog` to `noiseWriter`. **Never bypass with a fresh logger** — TLS handshake noise will flood logs.

## 4. Adding a New Protocol

1. **Model** (`proxy/model.go`):
   - Add schema constant to `validSchema()`
   - Add fields to `Candidate` and `Proxy` if needed
   - Update `ParseProxyLine` and `URL()`/`Key()`

2. **Dial** (`proxy/dial.go`):
   - Add case to `dialProxy()` switch
   - Implement `dialNewProto()` with proper timeout/context handling
   - Return `net.Conn` that wraps the protocol

3. **Checker** (`proxy/checker.go`):
   - Add to `probe_order` default in `fillDefaults`
   - Add case to `transportFor()` for custom `DialContext`
   - Update `needsConnect()` if protocol doesn't use CONNECT
   - Ensure `fullCheck()` handles the new schema

4. **Config** (`proxy/config.go`):
   - Add schema to `validSchema()`
   - Add any protocol-specific config fields

5. **Tests**: Add integration test in `proxy/pipeline_test.go` or new `*_test.go`

## 5. Testing

```powershell
# All tests
go test ./... -count=1

# Single test with verbose output
go test ./proxy/ -run TestCandidatePoolKeepsSource -v

# Integration test (fake site → candidate → validation → queue → disk)
go test ./proxy/ -run TestPipeline -v

# Admin tests
go test ./main/ -run TestAdmin -v
```

### Test Conventions
- Use `t.TempDir()` for all file I/O
- No network access in unit tests (use in-test CONNECT proxy from `proxy/pipeline_test.go`)
- `go test -race` does NOT work (no gcc/cgo) — don't try to fix

## 6. Logging Conventions

Prefix every log line with component:
```go
log.Printf("collector: %s -> %d candidates", site, len(cands))
log.Printf("checker: added %s queue=%d", p.URL(), bucket.Len())
log.Printf("serve: CONNECT %s via %s dial failed: %v", addr, p.URL(), err)
log.Printf("revalidate: dropped %s (%v)", p.URL(), err)
```

`noiseWriter` (in `main/logging.go`) filters:
- Stdlib `TLS handshake error from` → dropped entirely
- Goproxy `[n] WARN: Error dialing to host:port` → coalesced (1 line per 30s per target)

## 7. Configuration

Defaults live in `Config.fillDefaults()` (`proxy/config.go`); `main/config.toml` mirrors them with comments. **Change both** when adding new tunables.

### Key configs for developers
```toml
# Debug: last N freshly validated proxies (one URL per line)
debug_proxies_file = "debug_proxies.txt"
debug_proxies_max = 50

# Pool cap (checker throughput ~72k/hr, so 200k ≈ 3h of work)
max_candidates = 200000

# Collector caps (prevent huge lists from starving checker)
max_sites_per_cycle = 60
max_candidates_per_site = 1000
```

## 8. Common Pitfalls

| Pitfall | Consequence | Fix |
|---------|-------------|-----|
| Run `go run ./main` from repo root | Config files not found | Always `cd main; go run .` |
| Add mutex to `Proxy` | Serving path contention, allocations | Use `sync/atomic` only |
| Make `emit` non-blocking | Lost candidates under load | Keep blocking; channel buffer is backpressure |
| Shorten `pick_fresh_window` below `revalidate_interval` | Picker falls back to unproven bulk | Keep `pick_fresh_window > revalidate_interval` |
| Bypass `noiseWriter` for admin listener | TLS handshake noise floods logs | Use `newAdminServer(a, logNoise)` |
| Modify `CandidatePool` lines directly | Breaks source attribution | Use `Add`/`Batch`/`Good` methods |
| Hardcode ports in tests | Flaky on CI | Use `net.Listen("tcp", "127.0.0.1:0")` |

## 9. Debugging

### Live proxy for manual testing
```powershell
# debug_proxies.txt has last 50 validated proxies
Get-Content main/debug_proxies.txt | Select-Object -Last 5
# Copy one URL, test in browser:
# curl -x socks5://1.2.3.4:1080 https://httpbin.org/ip
```

### Admin API inspection
```powershell
Invoke-RestMethod http://127.0.0.1:9090/health
Invoke-RestMethod "http://127.0.0.1:9090/api/proxies?scope=hot&format=text"
Invoke-RestMethod http://127.0.0.1:9090/api/sources
```

### Log categories
```
logs/collector.log   - site scraping, extraction, retries
logs/checker.log     - validation pipeline, accept/reject reasons
logs/serve.log       - dial events, failover, evictions
logs/system.log      - queue stats, pool reprobe, revalidation, admin, noise
```

## 10. VLESS Development

### VLESS URL format
```
vless://<uuid>@<host>:<port>?flow=<flow>&sni=<sni>&pbk=<base64url>&sid=<sid>&spider=<spider>
```

### Adding REALITY support
1. Server provides: `pbk` (base64url x25519 pubkey), `sid` (short ID), optional `flow`
2. Client: `dialVLESSRealty` → x25519 keypair → HKDF-SHA256 keys → uTLS Chrome HelloID
3. Encrypted ClientHello sent as single padded packet

### Testing VLESS locally
```go
// In test, create a VLESS proxy config
p := &proxy.Proxy{
    Schema: "vless",
    Host: "test.example.com",
    Port: 443,
}
p.SetVLESS("uuid...", "xtls-rprx-vision", "test.example.com", "pbk...", "sid...", "")
```

## 11. Admin UI Development

Embedded assets in `main/adminassets.go` as string constants (`indexHTML`, `adminCSS`, `adminJS`). No external assets/CDN.

### Adding a new tab
1. Add `<section id="newtab" class="panel">` in `indexHTML`
2. Add tab button in `<nav class="tabs">`
2. Add API handler in `adminapi.go` (`handleNewtab`)
3. Add JS `loadNewtab()` + render function in `adminJS`
4. Register route in `admin.go:routes()`

### WebSocket protocol
```json
// Server → Client (on connect + every bucket change)
{"type": "state", "health": {...}, "proxies": [...], "sources": [...], "history": [...]}
{"type": "update", "health": {...}, "proxies": [...], "history": [...]}

// Client → Server: none (passive, keep-alive only)
```

## 12. Performance Tuning

| Bottleneck | Symptom | Fix |
|------------|---------|-----|
| Checker CPU 100% | `total_timeout` too high, too many self-IP URLs | Reduce `self_ip_urls` to 2-3, lower `total_timeout` |
| Pool fills, channel full | `pool_retry_batch` too large | Reduce to 1000 (3m interval = ~5.5/sec) |
| Collector starves checker | `max_candidates_per_site` too high | Cap at 1000, enable `max_sites_per_cycle=60` |
| Revalidation never finishes | `revalidate_max_per_pass` too low / queue too large | Increase to 30k-50k, enable `revalidate_fresh_servers` |
| Hot tail empty | `pick_fresh_window` < `revalidate_interval` | Set `pick_fresh_window=20m`, `revalidate_interval=15m` |

## 13. Release Checklist

```powershell
# From repo root
go fmt ./...
go vet ./...
go test ./... -count=1
go build ./...

# Update version in main/proxy.go if needed
# Tag: git tag vX.Y.Z && git push --tags
```

## 14. Useful Commands

```powershell
# Format check
gofmt -l main proxy util

# Single test with race detector (requires gcc - won't work here)
# go test -race ./proxy/ -run TestName

# Profile checker (requires running instance)
go tool pprof http://127.0.0.1:9090/debug/pprof/profile?seconds=30

# Check config without starting
go run ./main -config config/config.toml -check
# Or: powershell -File .\main\start.ps1 -Check
```

---

*Keep this guide updated when adding features or changing architecture.*