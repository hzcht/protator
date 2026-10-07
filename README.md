# Protator — transit proxy collector

Protator scrapes public proxy lists, validates every candidate (anonymity + content check), keeps a persistent queue of live proxies on disk, and serves clients as a **rotating forward proxy**: each client request is forwarded through a freshly picked healthy proxy, with transparent failover.

## Quickstart

```powershell
go run ./main -config config/config.toml
```

The working directory must be the repo root — all config and data paths are relative.
On start you will see `all listeners ready: http=... https=... socks5=... (queue=N)`.

## Listeners (defaults)

| Protocol | Address        | Notes                                            |
|----------|----------------|--------------------------------------------------|
| HTTP     | `0.0.0.0:8888` | Plain-HTTP + HTTPS via CONNECT                   |
| HTTPS    | `0.0.0.0:8443` | TLS front-end; self-signed cert auto-generated unless `tls_cert_file`/`tls_key_file` are set |
| SOCKS5   | `0.0.0.0:1080` | RFC 1928 CONNECT only, no auth                   |
| Admin    | `127.0.0.1:9090`| UI + `/health` + `/ready` + JSON API + WebSocket `/ws`. One port answers both HTTP and HTTPS. No auth, no proxy traffic. |

Point any scraper at one of these as its proxy. Every request gets a different upstream proxy; dead ones are retried transparently and evicted.

## Admin page

Open `http://127.0.0.1:9090/` (or `https://127.0.0.1:9090/` — the same port) for four tabs:

- **Live proxies** — the four honest definitions of "alive": `hot` (the curated tail the picker samples), `served` (carried real client traffic in the last 15 min), `checked` (validated in the window), `all` (whole queue, unproven included). Filter by `?country=US&asn=AS12345`. `&format=text|csv|jsonl` downloads the chosen scope. Copy `curl`/`wget` command via the button (LMB/RMB).
- **Sources** — per-source telemetry from `sites.txt`: how many candidates it produced, how many are still alive, yield, failures, cooldown. The collector visits sources in this order, so a source that stopped working is skipped rather than retried forever. Bulk delete via checkboxes.
- **sites.txt** — add/remove sources from the browser. Edits are validated, normalized, written atomically with a `.bak`, and picked up on the next collector cycle (no restart).
- **Stats** — 24h history graphs (queue live, hot, pool candidates) powered by WebSocket live updates.

## New in v2

- **VLESS + REALITY support** — full VLESS protocol with REALITY handshake (x25519 + HKDF-SHA256), uTLS Chrome fingerprinting, Vision flow support. Config via `vless://uuid@host:port?flow=...&sni=...&pbk=...&sid=...`.
- **GeoIP integration** — optional MaxMind GeoIP2-City.mmdb (`geoip_db_path` in config). Validated proxies get country/ASN attached; admin filters by `?country=US&asn=AS12345`.
- **WebSocket live updates** — `/ws` pushes health/proxy/source updates instantly; UI switches from 15s polling to real-time.
- **Admin enhancements** — CSV/JSONL export, bulk source delete, force revalidate selected proxies, copy curl/wget button, 24h stats history (`/api/stats/history` + graphs).
- **VLESS in candidate pool** — source attribution preserved via `addr\t<source-url>` suffix in `candidates.lst`.
- **SOCKS verdict by volume** — only sessions with downstream bytes earn `MarkServeOK`; client→silence is charged; nobody-spoke is neutral.

## How it works (short)

1. **Collect** — `sites.txt` URLs are fetched (direct → retry via live proxies → headless-browser fallback), proxies extracted by universal patterns + `regexp.txt` + built-in spys.one JS-XOR decoder + a `document.write` interpreter for lists that are assembled in the browser (ProxyNova, GeoNode). Sources are walked in telemetry order and capped per site and per cycle.
2. **Validate** — fast TCP pre-dial, bogon filter, anonymity check (egress IP ≠ ours, raced across self-IP services), content check against `checkers.toml` templates, CONNECT-capability required for http/https. VLESS validated via uTLS + REALITY handshake. GeoIP lookup on success.
3. **Queue** — live proxies live in memory and in `proxy.lst` (saved every minute, revalidated every 15 min stale-first, re-seeded on restart). Failed candidates persist in `candidates.lst` with source attribution, re-probed every 3m.
4. **Serve** — tiered pick: the curated hot tail first, then everything with a recent proof of life, then the raw queue as a last resort; inside a tier, fewest failures → lowest latency → least loaded. Per-request failover, passive health feedback from real traffic. VLESS dial via uTLS.

Details: [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md). Developer guide: [docs/DEVELOPER.md](docs/DEVELOPER.md).

## Files

| File | Purpose |
|------|---------|
| `config/config.toml` | All tunables (timeouts, workers, retries, thresholds). Defaults duplicated in `proxy/config.go:fillDefaults`. |
| `config/checkers.toml` | Test servers + expected-answer templates (`[[tests]]` with `url`, `must_contain`). |
| `config/sites.txt` | Proxy-list sources (raw lists, HTML tables, github blob URLs auto-converted to raw). Curated by measurement: only sources that actually produced candidates. |
| `config/sites_legacy.txt` | The pre-curation 87 MB list, kept as history. Not fed to the collector. |
| `config/regexp.txt` | Extra extraction regexes (1–2 capture groups: ip+port, either order). |
| `data/proxy.lst` | Persisted live queue (rewritten atomically every minute). |
| `data/good_proxies.last` | Append-only audit log of every accepted proxy. |
| `data/candidates.lst` | Failed candidates pool with source attribution (`addr\t<source-url>`). |
| `data/GeoIP2-City.mmdb` | Optional MaxMind GeoIP2 database for country/ASN lookup. |

## Verify

```powershell
go build ./...
go vet ./...
go test ./... -count=1
```

`proxy/pipeline_test.go` runs the full loop (fake list site → candidate → validation through an in-test CONNECT proxy → queue → disk round-trip) without internet.

## Documentation

- [Architecture](docs/ARCHITECTURE.md) — system design, data flow, component map
- [Developer Guide](docs/DEVELOPER.md) — contributing, testing, debugging, adding protocols