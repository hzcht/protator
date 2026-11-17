# Extractor: what it reads and why

`config/regexp.txt` is a list of one-regex-per-line patterns that run against
every fetched page body. The universal patterns in code (`proxy/extract.go`;
share links in `proxy/extract_share.go`, spys in `proxy/extract_spys.go`,
the gate that may skip a pattern in `proxy/extract_gate.go`, and the
anchored fast path in `proxy/extract_anchor.go`)
always run first:

| shape | notes |
|-------|-------|
| `scheme://ip:port` | http, https, socks4/5, protocol kept |
| `scheme://user:pass@ip:port` | raw userinfo kept for http/https/socks5; socks4 drops it (no protocol auth); userinfo without `:` is a mention — the socket is kept with its scheme, anonymous |
| `user:pass@ip:port` | bare export form; `name@ip:port` without a colon is ignored (email/mention); best-effort, see below |
| `ip:port:user:pass` | column exports: anonymous **and** credentialed candidates; the suffix needs a letter and bounded fields |
| bare `ip:port` | protocol unknown → probed later via `checker.probe_order` |
| `[ipv6]:port` | bracketed literal only; a bare IPv6 is ambiguous by design |
| spys.one JS ports | `document.write(":"+(a^b)+...)` decoded without a browser |
| whole-body base64 | padded or unpadded; see below |
| `trojan://` / `vless://` share links | `proxy/extract_share.go`; raw TCP only, credentials carried end to end |

The bare credential form is deliberately best-effort. Its userinfo class has no
leading boundary and permits hyphens, so a token glued to prose
(`contact-user:pass@1.2.3.4:8080`) is read as a hyphenated username. Both rules
cannot hold at once: a left boundary would truncate legitimate hyphenated
usernames, and no boundary separates every word from every credential. Treat
bare credentials as a hint, prefer the scheme form when certainty matters, and
let validation reject credentials a proxy does not accept.

URI schemes are ASCII-case-insensitive. Universal scheme regexes spell this
with explicit byte classes (`[vV]`, `[sS]`, ...), and their pre-gates use the
same ASCII folding. Do not replace one side independently with Go's `(?i)`:
Unicode simple folding also admits LONG S and KELVIN SIGN, while URI scheme
syntax and the downstream dispatch/serialization are ASCII.

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

Two properties decide how cheap a pattern runs; both are pinned by tests, so
write them in deliberately:

- **Open the pattern with the quad when you honestly can.** A source that
  literally begins with the canonical group ([0-9]{1,3}×4) — or begins with
  `\b` and then the group — is anchored at the quad offsets instead of a
  full-body scan. Anything else runs the plain engine over the body; a
  pattern whose quad sits mid-shape stays there (see below).
- **Prefer single-byte class separators to alternations.** `(?:\A|[,;\r\n])`
  costs a scan; `(?:^|,|\r?\n|;)` pays an alternation walk at every byte of
  the body. The class form is also additive (it tolerates a lone `\r`, which
  no current exporter emits), so it is the safe direction to change in.

## Gates and the anchored fast path

Every backed pass exists because pattern cost is measured, and every pass
that cannot match a body is skipped. All of it is derived from the pattern's
own source at startup, never guessed:

- **Quad gates (`extract_gate.go`).** `startsWithIPv4Group` proves the
  pattern's head; `needsIPv4` proves the pattern *requires* the canonical
  quad anywhere in its parse (a concat requires its children, an alternation
  requires every branch, quest/star/`{0,n}` do not). On a body without a
  dotted quad — one byte scan, `hasIPv4Token` — every gated pattern is
  skipped. All shipped patterns except the IPv6 table one are gated; that is
  where the junk-page cost went (165 → 2.6 ms).
- **Pass filters.** The spys pass and `reBareV4` run only when a quad
  exists; the credentialed passes run only when an `'@'` is followed by a
  digit (the quad starts right after the `'@'`); the scheme passes run only
  when the body contains ASCII-case "http" or "socks". Each filter is one
  linear scan and can only ever be wrong in the slow direction because the
  regexes use the identical ASCII grammar.
- **Anchored fast path (`extract_anchor.go`).** Patterns that open with the
  quad are probed at the quad offsets inside a window their parse-derived
  tail plan cannot escape: each tail child advances by its maximum match
  length, and an unbounded single-class repeat (`\s*`, `[^>]*`) by the first
  byte outside that class. The probe must be indistinguishable from the
  legacy `FindAll` — same matches, same spans, same order — and
  `TestSiteAnchoredPathMatchesFindAll` runs both over every fixture body,
  including dense-digit pages that turn the anchored path off by a sparsity
  rule. Measured: an IP-leading pattern ~9 → ~0.5 ms on a 130 KB page;
  whole extraction 241 → ~130 ms on the proxynova fixture.

Restrictions the tests pin, so nobody "generalizes" them wrongly:

- Only *leading* quads anchor. A mid-pattern quad needs a window over a
  variable-length head, and that cannot be proven equivalent to FindAll
  (overlapping matches can carry different quads and race the leftmost
  policy either way) — the credentialed and spys shapes therefore stay on
  the full-body pass (problems.md §21).
- Keystones in front of the quad are restricted to `\b` (emulated by a
  one-byte precheck the window slice cannot perform). `\A`, `^`, `$` read
  the whole-string position; a window slice would lie about them, and such
  a pattern gets no anchor at all.
- A tail that cannot be bounded — a star over anything but one class, a
  repeat with absurd bounds — gets no anchor. `TestQuadHintsLeadOnly` pins
  which shipped shapes may anchor at all.
- The cap is on the plan's **total** window, not on each step: many
  individually-legal repeats must not add up to a window larger than a whole
  body scan would cost. `TestAnchoredPlanTotalIsBounded` pins both sides.
- The plan total is charged at *build* time, and a class-run step
  (`\s*`, `[^>]*`) cannot be charged then — its length is data, not syntax.
  The loop therefore caps what it *spends*: each pattern gets a budget of one
  body's worth of window, and once that runs out the pattern goes back to the
  legacy `FindAll`. Without it a page that is sparse in quads but short on `>`
  hands every token the whole rest of the body as its window — T·N engine
  scans instead of N, which froze a production collector for ~10 h inside
  `wg.Wait` with no log line. The fallback is the pre-anchoring path, so it
  cannot drop a match the anchored loop would have found.
  `TestFindAtQuadTokensBoundsTotalWindow` pins it.
- A case-folded literal in a site pattern is bounded at four UTF-8 bytes per
  rune. Go's `(?i)` can match a longer Unicode fold variant (`k` ↔ KELVIN
  SIGN, `s` ↔ LONG S); budgeting source-byte length would let the probe window
  end inside a valid match. `TestAnchoredWindowCoversFoldedLiterals` pins this.
- `FuzzAnchoredMatchesFindAll` compares every shipped anchored pattern and
  the universal bare pass against legacy `FindAll` on arbitrary bodies; its
  seed corpus runs in the normal suite, mutation is an explicit developer run.

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
