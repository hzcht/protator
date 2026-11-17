package proxy

import (
	"context"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/oschwald/geoip2-golang"
)

// Checker validates proxy candidates. A proxy is "good" when:
//  1. a TCP pre-dial to it succeeds (fast reject of dead hosts),
//  2. a request through it returns an IP different from our own (anonymity),
//  3. optionally, a header-echo probe shows it does not forward our client
//     IP in X-Forwarded-For/Via headers,
//  4. optionally, a second probe to the same service shows a stable exit IP
//     (rotating proxies are rejected),
//  5. optionally, an end-to-end tunnel over the exact serving dial path
//     (dialProxy) carries real traffic to the first self-IP URL,
//  6. a content request through it matches the expected-answer templates
//     from the tests config (checkers.toml),
//  7. for http/https proxies: at least one check used CONNECT (plain-GET-only
//     proxies are useless to the serving path, which always tunnels).
//
// Stages 2-5 race their sub-requests in parallel and take the first success,
// so one slow service never blocks a check; they all run sequentially before
// stage 6, and a failure in any of them skips the content check. All
// sub-requests of one check share a keep-alive client bound to that proxy.
// Optional stages (3-5) are gated by config and default to off.
//
// When a candidate has no explicit protocol the configured probe order tries
// http, socks5, socks4 (and https) until one passes every stage.
type Checker struct {
	cfg     *Config
	selfIP  net.IP
	tests   []ContentTest
	testsRe [][]*regexp.Regexp // parallel to tests; nil entry = substring match
	ipRe    *regexp.Regexp
	geoDB   *geoip2.Reader // City database (country); nil = off
	geoASN  *geoip2.Reader // ASN database (separate file); nil = off

	// transportCache caches http.Transport per proxy address to avoid
	// creating a new transport (and its connection pool) for every check.
	// Key: "schema://host:port", Value: *http.Transport
	transportCache sync.Map
	// transportCacheSize tracks the number of entries for eviction. It is
	// bumped by every checker worker (hundreds of goroutines), so it is an
	// atomic: a plain int race lets the counter drift, which either evicts
	// nothing or evicts on every insert.
	transportCacheSize int64
	// transportCacheMax bounds the cache size to prevent unbounded memory growth.
	transportCacheMax int64

	// allowBogon disables the loopback/private filter (integration tests
	// run everything on 127.0.0.1). Never set in production.
	allowBogon bool

	// Exit-honesty probe target (checker.tls_probe_host). Addr empty means the
	// probe is off. probeRoots overrides the system roots; tests set the test
	// server's own pool so "honest" is reachable without a public CA.
	tlsProbeAddr string
	tlsProbeName string
	probeRoots   *x509.CertPool
}

var reAnyIP = regexp.MustCompile(`([0-9]{1,3}(?:\.[0-9]{1,3}){3})`)

// NewChecker builds a Checker, resolving our own public IP first and loading
// the content-test templates.
func NewChecker(cfg *Config) (*Checker, error) {
	c := &Checker{cfg: cfg, ipRe: reAnyIP, transportCacheMax: 1000}
	self, err := c.resolveSelfIP()
	if err != nil {
		return nil, fmt.Errorf("resolve self IP: %w", err)
	}
	c.selfIP = self

	// Exit-honesty probe target: "host", "host:port", or "off".
	if host := strings.TrimSpace(cfg.Checker.TLSProbeHost); host != "" && !strings.EqualFold(host, "off") {
		addr := host
		if _, _, err := net.SplitHostPort(addr); err != nil {
			addr = net.JoinHostPort(host, "443")
		}
		if name, _, err := net.SplitHostPort(addr); err == nil {
			c.tlsProbeAddr = addr
			c.tlsProbeName = strings.Trim(name, "[]")
		}
	}

	// Initialize GeoIP database if path is configured
	if cfg.Checker.GeoIPDBPath != "" {
		db, err := geoip2.Open(cfg.Checker.GeoIPDBPath)
		if err != nil {
			return nil, fmt.Errorf("open GeoIP database %s: %w", cfg.Checker.GeoIPDBPath, err)
		}
		c.geoDB = db
	}
	// The ASN database is a separate MaxMind file (GeoLite2-ASN.mmdb); the
	// City database has no ASN data. Both readers are independent: a deploy
	// may ship either, both, or neither.
	if cfg.Checker.GeoIPASNDBPath != "" {
		db, err := geoip2.Open(cfg.Checker.GeoIPASNDBPath)
		if err != nil {
			if c.geoDB != nil {
				c.geoDB.Close()
			}
			return nil, fmt.Errorf("open GeoIP ASN database %s: %w", cfg.Checker.GeoIPASNDBPath, err)
		}
		c.geoASN = db
	}

	if cfg.Checker.TestsFile != "" && fileExists(cfg.Checker.TestsFile) {
		tests, err := LoadTests(cfg.Checker.TestsFile)
		if err != nil {
			return nil, err
		}
		// Compile the MustContain templates once here. They are matched
		// against every content-test body of every proxy check, and
		// regexp.Compile is orders of magnitude more expensive than
		// MatchString: doing it per match put the compiler in the hot loop
		// of hundreds of checker workers.
		for i := range tests {
			compiled := make([]*regexp.Regexp, 0, len(tests[i].MustContain))
			for _, pat := range tests[i].MustContain {
				if re, err := regexp.Compile(pat); err == nil {
					compiled = append(compiled, re)
				} else {
					compiled = append(compiled, nil) // plain-substring pattern
				}
			}
			c.testsRe = append(c.testsRe, compiled)
		}
		c.tests = tests
	} else if cfg.Checker.TestsFile != "" {
		return nil, fmt.Errorf("tests file %s does not exist", cfg.Checker.TestsFile)
	}
	return c, nil
}

// SelfIP returns our own public IP (used to reject transparent proxies).
func (c *Checker) SelfIP() net.IP { return c.selfIP }

// resolveSelfIP determines our public IP, racing the configured services and
// taking the first answer.
func (c *Checker) resolveSelfIP() (net.IP, error) {
	urls := c.cfg.Checker.SelfIPURLs
	type res struct {
		ip  net.IP
		err error
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	client := &http.Client{Timeout: 20 * time.Second}
	ch := make(chan res, len(urls))
	for _, u := range urls {
		go func(u string) {
			// Recovered per sub-probe: the caller reads a fixed number of
			// results, so a panic here would leave it blocked forever on a
			// receive that never comes.
			defer RecoverPanic("checker: self-ip " + u)
			body, err := getBodyCtx(ctx, client, u)
			if err != nil {
				GuardedSend(ch, res{err: err})
				return
			}
			if ip := c.firstIP(body); ip != nil {
				GuardedSend(ch, res{ip: ip})
				return
			}
			GuardedSend(ch, res{err: errors.New("no IP in service response")})
		}(u)
	}
	var lastErr error
	for range urls {
		if r := <-ch; r.err == nil {
			return r.ip, nil
		} else {
			lastErr = r.err
		}
	}
	if lastErr == nil {
		lastErr = errors.New("all self-ip services failed")
	}
	return nil, lastErr
}

// Check validates a candidate and returns the working Proxy.
// proxyForCandidate materializes the Proxy for one validation attempt with
// the schema already resolved (the candidate's explicit schema, or one
// element of the probe order). Both branches of Check must go through it:
// the credentials are part of the identity, so they are stamped before
// keyCache freezes the key — a late stamp would put one password's transport
// into another's cache slot and let dedup collapse entries that differ only
// by credential. The probe branch used to build the Proxy without the
// credential at all, silently validating bare `user:pass@host:port`
// candidates anonymously. socks4 has no protocol auth, so a credential is
// dropped here, at the single construction site, not per call site.
func proxyForCandidate(cand Candidate, schema string) *Proxy {
	// meta is allocated here, before publication: SetGeoIP/SetVLESS run
	// after the proxy is queued (revalidation) while admin live rows read
	// GetCountry/GetASN concurrently, and a lazily-initialized plain
	// pointer field is a data race on the hot read path.
	p := &Proxy{Schema: schema, Host: cand.Host, Port: cand.Port, meta: &ProxyMeta{}}
	if schema == "trojan" {
		p.SetTrojan(cand.TrojanPassword, cand.TrojanSNI, cand.TrojanNoTLS)
	}
	if schema == "vless" {
		p.SetVLESS(cand.VLESSUUID, cand.VLESSFlow, cand.VLESSSNI, cand.VLESSPbk, cand.VLESSSid, cand.VLESSSpider, cand.VLESSNoTLS)
	}
	if cand.ProxyAuth != "" && schema != "socks4" {
		p.SetProxyAuth(cand.ProxyAuth)
	}
	// Precompute the identity before the proxy is published: every Key()
	// on the productive population would otherwise rebuild the URL with
	// fmt.Sprintf (rankPick calls it once per probe, up to 256 per pick,
	// under the bucket read lock). Single goroutine here, so no race.
	p.keyCache = p.URL()
	return p
}

func (c *Checker) Check(cand Candidate) (found *Proxy, err error) {
	start := time.Now()
	// Measurement only: the named results let one defer see every exit path,
	// so no future branch can quietly fall out of the cost histogram.
	defer func() {
		recordCheckDuration(time.Since(start))
		recordCheckFail(err)
	}()
	Stats.Checks.Add(1)
	if cand.Port < 1 || cand.Port > 65535 {
		Stats.ChecksFailed.Add(1)
		return nil, stageErr(stagePredial, errors.New("bad port"))
	}
	if !c.allowBogon {
		if err := rejectBogon(cand.Host, c.selfIP); err != nil {
			Stats.ChecksFailed.Add(1)
			return nil, stageErr(stagePredial, err)
		}
	}
	// One budget for the whole candidate and one TCP pre-dial for its address.
	//
	// Both are deliberate: the SYN goes to the same host:port whichever
	// protocol turns out to be right, so probing four protocols against a dead
	// host used to burn four tcp_timeout waits, and every attempt then got a
	// fresh total_timeout, so one hopeless candidate could occupy a worker for
	// ~18 minutes. A candidate now costs at most check_budget end to end, which
	// is also the only way a worker count means anything.
	deadline := c.checkDeadline()
	if err := c.preDial(cand.Host, cand.Port, c.attemptBudget(deadline)); err != nil {
		Stats.ChecksFailed.Add(1)
		return nil, stageErr(stagePredial, err)
	}
	if cand.Schema != "" && validSchema(cand.Schema) {
		p, err := c.attempt(cand, cand.Schema, deadline)
		if err != nil {
			Stats.ChecksFailed.Add(1)
			return nil, err
		}
		Stats.ChecksPassed.Add(1)
		return p, nil
	}
	// A candidate with no explicit schema gets the configured probe order,
	// with an optional URL-derived hint reordering the first attempt. The
	// hint is non-binding: if the preferred protocol fails, the rest of the
	// order is still tried, so mislabeled lists lose nothing.
	order := c.cfg.Checker.ProbeOrder
	if cand.Prefer != "" && validSchema(cand.Prefer) {
		order = preferFirst(order, cand.Prefer)
	}
	var lastErr error
	for _, s := range order {
		p, err := c.attempt(cand, s, deadline)
		if err == nil {
			Stats.ChecksPassed.Add(1)
			return p, nil
		}
		lastErr = err
		if stageOf(err) == stageBudget {
			// Out of candidate budget: further protocols would only re-test
			// the same exhausted clock.
			break
		}
	}
	Stats.ChecksFailed.Add(1)
	if lastErr == nil {
		// Empty probe_order: nothing was attempted, so nothing can be blamed.
		lastErr = errors.New("no protocol works")
	}
	return nil, lastErr
}

// attempt makes one protocol attempt inside the candidate's budget. It never
// spends more than min(total_timeout, whatever is left of the candidate), so a
// long probe order cannot multiply the deadline.
func (c *Checker) attempt(cand Candidate, schema string, deadline time.Time) (*Proxy, error) {
	budget := c.attemptBudget(deadline)
	if budget <= 0 {
		return nil, stageErr(stageBudget, errors.New("check budget exhausted"))
	}
	p := proxyForCandidate(cand, schema)
	if err := c.fullCheck(p, budget); err != nil {
		return nil, err
	}
	return p, nil
}

// checkDeadline is the candidate's whole-check deadline. It returns the zero
// time when the budget is disabled (0), which attemptBudget reads as unbounded:
// a hand-built Config in tests then behaves like the old per-attempt clock
// instead of failing every check with "no time left".
func (c *Checker) checkDeadline() time.Time {
	if b := c.cfg.Checker.Budget.Duration; b > 0 {
		return time.Now().Add(b)
	}
	return time.Time{}
}

// attemptBudget is what a single attempt may spend: the per-attempt ceiling
// (total_timeout) clipped to what remains of the candidate budget.
func (c *Checker) attemptBudget(deadline time.Time) time.Duration {
	left := c.cfg.Checker.TotalT.Duration
	if !deadline.IsZero() {
		if rem := time.Until(deadline); rem < left {
			left = rem
		}
	}
	return left
}

// preferFirst returns the probe order with pref moved to the front (deduped).
func preferFirst(order []string, pref string) []string {
	out := make([]string, 0, len(order))
	out = append(out, pref)
	for _, s := range order {
		if s != pref {
			out = append(out, s)
		}
	}
	return out
}

// Revalidate confirms that a previously-good proxy still passes, without
// re-probing alternative protocols.
//
// It runs under the same budget a fresh check gets: a proxy that cannot be
// re-confirmed inside the acceptance window is not evidence of a working proxy,
// and the old total_timeout (230s in production) let a single revalidation
// occupy a worker for four minutes while the pool starved.
func (c *Checker) Revalidate(p *Proxy) (err error) {
	// Stage only, no duration: revalidation skips the protocol loop, and its
	// throughput is already counted as reval_checked_total.
	defer func() { recordCheckFail(err) }()
	deadline := c.checkDeadline()
	if err = c.preDial(p.Host, p.Port, c.attemptBudget(deadline)); err != nil {
		return stageErr(stagePredial, err)
	}
	budget := c.attemptBudget(deadline)
	if budget <= 0 {
		return stageErr(stageBudget, errors.New("check budget exhausted"))
	}
	return c.fullCheck(p, budget)
}

// rejectBogon refuses loopback/private/link-local addresses and our own IP.
// Hostnames (unresolvable here) pass through to the dial stage.
func rejectBogon(host string, selfIP net.IP) error {
	ip := net.ParseIP(host)
	if ip == nil {
		return nil
	}
	switch {
	case ip.IsLoopback(),
		ip.IsPrivate(),
		ip.IsLinkLocalUnicast(),
		ip.IsLinkLocalMulticast(),
		ip.IsMulticast(),
		ip.IsUnspecified():
		return fmt.Errorf("bogon address %s", host)
	}
	if selfIP != nil && ip.Equal(selfIP) {
		return fmt.Errorf("address is our own IP %s", host)
	}
	return nil
}

// preDial opens and immediately closes a TCP connection to the proxy.
// Dead hosts fail here in ~seconds instead of burning full HTTP timeouts.
//
// It takes host:port rather than a Proxy because it runs once per candidate,
// before any protocol has been chosen: the SYN reaches the same socket whether
// the proxy turns out to speak http or socks5. budget is what remains of the
// candidate's clock; the wait is clipped to it so a pre-dial can never outlive
// the check that owns it.
//
// The duration is measured separately from the rest of the check: on a dead
// host this stage is pure SYN timeout, and until the TCP counters existed there
// was no way to tell that cost from a proxy that connected and then stalled.
func (c *Checker) preDial(host string, port int, budget time.Duration) error {
	to := c.cfg.Checker.TCPTimeout.Duration
	if budget < to {
		to = budget
	}
	if to <= 0 {
		return errors.New("tcp pre-dial: no time left in the check budget")
	}
	ctx, cancel := context.WithTimeout(context.Background(), to)
	defer cancel()
	start := time.Now()
	conn, err := (&net.Dialer{}).DialContext(ctx, "tcp", net.JoinHostPort(host, strconv.Itoa(port)))
	Stats.CheckTCPNanos.Add(int64(time.Since(start)))
	Stats.CheckTCPDials.Add(1)
	if err != nil {
		var ne net.Error
		if errors.As(err, &ne) && ne.Timeout() {
			Stats.CheckTCPTimeouts.Add(1)
		}
		return fmt.Errorf("tcp pre-dial: %w", err)
	}
	conn.Close()
	return nil
}

// fullCheck runs every acceptance stage for one protocol attempt. budget is
// what this attempt may spend (see attemptBudget); it replaces the old
// per-client total_timeout, which was per protocol and let one candidate
// multiply the deadline by the length of probe_order.
func (c *Checker) fullCheck(p *Proxy, budget time.Duration) error {
	// Use the cached transport, not a throwaway: the whole point of the cache
	// is reusing this transport's connection pool across checks of the same
	// proxy. fullCheck used to CloseIdleConnections on the way out, which
	// tore down the pool it was about to hand back and left the "reuse
	// connection pools" comment describing behaviour that never happened.
	tr := c.transportFor(p)
	client := &http.Client{
		Transport: tr,
		Timeout:   budget,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	start := time.Now()
	ip, viaConnect, winURL, err := c.ipThrough(client, p)
	if err != nil {
		return stageErr(stageIP, err)
	}
	// Serve-grade gate: a proxy whose first answer through itself took longer
	// than proven_latency_max cannot serve a request inside the serving
	// budget either, so it enters the queue but never ranks as warm proven
	// stock (freshnessRank downgrades it). 0 disables the gate; the flag is
	// only meaningful on a real answer, which is why a failed probe does not
	// touch it.
	if lim := c.cfg.Checker.ProvenLatencyMax.Duration; lim > 0 {
		p.MarkCheckSlow(time.Since(start) > lim)
	}
	// Exit-honesty evidence on the same warm path: the proxy has just carried
	// a real HTTP request, so one TLS handshake to a known host is cheap and
	// settles whether it forges certificates for its clients. Non-fatal by
	// design — see tlsHonestyProbe.
	c.tlsHonestyProbe(p, budget)
	// IP-stage extras: header-leak must pass before content stage.
	if err := c.leakCheck(client, budget); err != nil {
		return stageErr(stageLeak, err)
	}
	if err := c.e2eProbe(p, budget); err != nil {
		return stageErr(stageE2E, err)
	}
	// Run confirmExitIP and contentPass in parallel to reduce per-check latency.
	var contentOK, testConnect bool
	var confirmErr error
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		// Recovered per branch: without it a panic here kills the worker and,
		// with hundreds of them, the process. wg.Done must be deferred first so
		// the sibling is never left waiting on a WaitGroup that never completes.
		defer RecoverPanic("checker: confirmExitIP")
		confirmErr = c.confirmExitIP(client, ip, winURL)
	}()
	go func() {
		defer wg.Done()
		defer RecoverPanic("checker: contentPass")
		contentOK, testConnect = c.contentPass(client, p, budget)
	}()
	wg.Wait()
	if confirmErr != nil {
		return stageErr(stageContent, confirmErr)
	}
	// A recovered panic in contentPass leaves the zero values, which read as a
	// clean pass. Fail closed instead of admitting an unchecked proxy.
	if !contentOK && len(c.tests) > 0 {
		return stageErr(stageContent, errors.New("content check failed"))
	}
	// CONNECT is proven only when some stage actually tunnelled. Skipping the
	// check when no evidence could exist at all is not the same as "no
	// evidence yet": with content tests and https self-IP urls both absent,
	// viaConnect and testConnect are both false by construction, and this
	// used to reject every http/https proxy purely for lack of
	// configuration.
	if needsConnect(p.Schema) && !viaConnect && !testConnect && c.connectEvidencePossible() {
		return stageErr(stageConnect, errors.New("proxy does not support CONNECT"))
	}
	p.MarkAlive(time.Since(start))
	// Set GeoIP from the exit IP discovered during validation
	if ip != nil {
		country, asn := c.lookupGeoIP(ip)
		p.SetGeoIP(country, asn)
	}
	return nil
}

// needsConnect reports whether the serving path requires CONNECT tunnelling
// for this proxy type (it always tunnels; only SOCKS handshakes differ).
// VLESS carries the target address in its handshake, not via CONNECT.
func needsConnect(schema string) bool {
	return schema == "http" || schema == "https"
}

// connectEvidencePossible reports whether this check could ever observe a
// CONNECT tunnel. The evidence has to come from somewhere: either a content
// test fetched over https, or an https self-IP url probed for the exit IP.
// With neither configured there is nothing to observe, and demanding proof
// turns optional configuration into a blanket rejection.
func (c *Checker) connectEvidencePossible() bool {
	for _, t := range c.tests {
		if viaConnectURL(t.URL) {
			return true
		}
	}
	for _, u := range c.cfg.Checker.SelfIPURLs {
		if viaConnectURL(u) {
			return true
		}
	}
	return false
}

// viaConnectURL reports whether fetching u through an http(s) proxy uses
// CONNECT (i.e. u itself is https).
func viaConnectURL(u string) bool {
	return strings.HasPrefix(strings.ToLower(u), "https://")
}
