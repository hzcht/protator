# Extractor: what it reads and why

`config/regexp.txt` is a list of one-regex-per-line patterns that run against
every fetched page body. The universal patterns in code (`proxy/extract.go`)
always run first:

| shape | notes |
|-------|-------|
| `scheme://ip:port` | http, https, socks4/5, protocol kept |
| bare `ip:port` | protocol unknown → probed later via `checker.probe_order` |
| `[ipv6]:port` | bracketed literal only; a bare IPv6 is ambiguous by design |
| spys.one JS ports | `document.write(":"+(a^b)+...)` decoded without a browser |
| whole-body base64 | padded or unpadded; see below |

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

## Missing on purpose

- **Authenticated proxies** (`user:pass@host:port`, `host:port:user:pass`):
  the checker and dialer have no credential path, so such a list would only
  produce proxies that fail validation. If this is ever added, it is a schema
  change first (`http://user:pass@` through `ParseProxyLine`), then a regex.
- **Trojan/VLESS/SS/hysteria endpoints**: `regexp.txt` carries a few of these
  shapes, but `validSchema` only accepts http/https/socks4/socks5/vless, so
  those lines contribute bare host:port candidates at best. They are harmless
  but not useful until the dialer supports the protocol.

## Where each pattern shape comes from

| shape | example source family |
|-------|-----------------------|
| `<td>ip</td><td>port</td>` variants | geonode, free-proxy-list.net, advanced.name, proxynova |
| `"ip":"...","port":...` in one JSON record | geonode API, openproxy.space, proxylist.icu |
| `?ip=...&port=...` | proxysearcher-style APIs |
| `1.2.3.4,8080,US,anonymous` | CSV exports (proxifly, proxy-gatherer) |
| `server: ip` + `port: N` | Clash/QuanX/Surge subscription blocks |
| `data-proxy-ip` / `data-proxy-port` | newer panel themes |
| `ss://…@ip:port`, `vless://…@ip:port` | protocol subscription lists |
