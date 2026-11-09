# Extractor: what it reads and why

`config/regexp.txt` is a list of one-regex-per-line patterns that run against
every fetched page body. The universal patterns in code (`proxy/extract.go`;
share links in `proxy/extract_share.go`, spys in `proxy/extract_spys.go`, and
the gate that may skip a pattern in `proxy/extract_gate.go`)
always run first:

| shape | notes |
|-------|-------|
| `scheme://ip:port` | http, https, socks4/5, protocol kept |
| `scheme://user:pass@ip:port` | raw userinfo kept for http/https/socks5; socks4 drops it (no protocol auth) |
| `user:pass@ip:port` | bare export form; `name@ip:port` without a colon is ignored (email/mention) |
| `ip:port:user:pass` | column exports: anonymous **and** credentialed candidates; the suffix needs a letter and bounded fields |
| bare `ip:port` | protocol unknown → probed later via `checker.probe_order` |
| `[ipv6]:port` | bracketed literal only; a bare IPv6 is ambiguous by design |
| spys.one JS ports | `document.write(":"+(a^b)+...)` decoded without a browser |
| whole-body base64 | padded or unpadded; see below |
| `trojan://` / `vless://` share links | `proxy/extract_share.go`; raw TCP only, credentials carried end to end |

The per-site patterns in `regexp.txt` exist for the shapes where the address and
the port are **not adjacent** — tables, JSON records, path-style links. Groups
are auto-detected: whichever group looks like an IP is the host, the other is
the port, in either order.

## How to add a pattern

1. Fetch the page and look at the bytes around a row (DevTools → view source,
   not the rendered DOM).
2. Write the smallest regex that captures the address and the port. Both must be
   capture groups (or one group plus a port in the preceding text).
3. Put it in `regexp.txt` with a comment saying which site it is for. The
   extractor compiles the file at startup and fails loudly on a bad regex.
4. Verify with the regression tests: they load the real
   `config/regexp.txt` (`liveExtractor`), so a pattern that breaks an existing
   page shape fails `go test ./proxy/ -run TestExtract`.

## Guards that exist on purpose

These look like limitations and are not:

- **`validHost` rejects hostnames.** Every match is an IP:port pair served by a
  proxy list, so a hostname-shaped match is noise. The old
  `net.ResolveIPAddr` check made hostnames *pass*, which is how junk entered
  the pool.
- **A partial IP followed by `.digit` is rejected** (`29.30.31.3` out of
  `29.30.31.32`).
- **The base64 pass needs the whole body to be base64.** One stray byte means
  the plain-text pass owns it — otherwise a normal page would be decoded on
  every fetch for nothing. The decoded payload also has to look like a list
  (newlines + digits, or a pile of colons), because base64 alphabet soup
  decodes to noise almost every time.
- **`schemaNear` only looks 80 bytes around a match.** It is a poor man's
  context sniffing, not a parser; a protocol token further away is ignored
  rather than guessed.
- **A credentialed token is emitted once, then blanked from the text the
  anonymous passes see.** The bare `ip:port` inside `scheme://user:pass@ip:port`
  is the same socket; validating it anonymously spends a check to earn a 407.
- **The `host:port:user:pass` suffix is conservative.** Both fields must be
  non-empty and bounded, at least one must contain an ASCII letter, and no
  `/?#@[]` byte may appear. A clock (`…:8080:10:00:30`) or a second port
  (`…:8080:3128`) is therefore not read as auth. The anonymous candidate is
  still emitted before the credentialed one — stale column credentials must
  not hide a working socket.

## Missing on purpose

- **Other credential permutations** (`user:pass:host:port`, CSV columns in
  another order): the `user:pass@host:port` and `host:port:user:pass` forms are
  supported end to end for `http`/`https`/`socks5` (raw percent-encoded
  `ProxyMeta.proxyAuth`, Basic in the CONNECT handshake, RFC 1929 on socks5 —
  `proxy/auth_test.go`). Further orderings have no measured source yet, and
  guessing them from arbitrary page text invites false positives. Socks4 auth
  is missing *on protocol grounds* — the protocol has none.
- **`ss://`** — no dial path exists. **`vmess://`** — needs a VMess AEAD
  transport, a crypto feature, not regexps. Neither carries a pattern in
  `regexp.txt`: every match would burn a full multi-protocol check on a
  candidate that can never validate.

Both trojan and VLESS share links have already crossed the line the other way:
each used to be "missing on purpose" for exactly these reasons, then got wired
end to end (`parseTrojanURL`/`parseVLESSURL` in `proxy/extract_share.go`,
credentials through Candidate → Proxy → dial → pool, invalid transports such
as `type=ws`/`grpc` rejected at extraction). `ss://` in fairness has no
transport between "RE2 pattern" and "a dialable protocol" — that is why it
stays out, and what any future protocol must bring with it.

## Where each pattern shape comes from

| shape | example source family |
|-------|-----------------------|
| `<td>ip</td><td>port</td>` variants | geonode, free-proxy-list.net, advanced.name, proxynova |
| `"ip":"...","port":...` in one JSON record | geonode API, openproxy.space, proxylist.icu |
| `?ip=...&port=...` | proxysearcher-style APIs |
| `1.2.3.4,8080,US,anonymous` | CSV exports (proxifly, proxy-gatherer) |
| `1.2.3.4:8080:user:pass` | column exports / spys-style dumps with credentials |
| `server: ip` + `port: N` | Clash/QuanX/Surge subscription blocks |
| `data-proxy-ip` / `data-proxy-port` | newer panel themes |
| `ss://…@ip:port`, `vless://…@ip:port`, `trojan://…` | protocol subscription lists |
