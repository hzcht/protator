package proxy

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"regexp"
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
func (c *Checker) Check(cand Candidate) (*Proxy, error) {
	Stats.Checks.Add(1)
	if cand.Port < 1 || cand.Port > 65535 {
		Stats.ChecksFailed.Add(1)
		return nil, errors.New("bad port")
	}
	if !c.allowBogon {
		if err := rejectBogon(cand.Host, c.selfIP); err != nil {
			Stats.ChecksFailed.Add(1)
			return nil, err
		}
	}
	if cand.Schema != "" && validSchema(cand.Schema) {
		// meta is allocated here, before publication: SetGeoIP/SetVLESS run
		// after the proxy is queued (revalidation) while admin live rows read
		// GetCountry/GetASN concurrently, and a lazily-initialized plain
		// pointer field is a data race on the hot read path.
		p := &Proxy{Schema: cand.Schema, Host: cand.Host, Port: cand.Port, meta: &ProxyMeta{}}
		// Credentials ride along before the identity is frozen: a trojan or
		// vless entry without its password/UUID can never validate, and the
		// key (hence the transport cache and dedup) includes them — stamping
		// after keyCache would serve one password's transport to another's.
		if cand.Schema == "trojan" {
			p.SetTrojan(cand.TrojanPassword, cand.TrojanSNI, cand.TrojanNoTLS)
		}
		if cand.Schema == "vless" {
			p.SetVLESS(cand.VLESSUUID, cand.VLESSFlow, cand.VLESSSNI, cand.VLESSPbk, cand.VLESSSid, cand.VLESSSpider, cand.VLESSNoTLS)
		}
		// Precompute the identity before the proxy is published: every Key()
		// on the productive population would otherwise rebuild the URL with
		// fmt.Sprintf (rankPick calls it once per probe, up to 256 per pick,
		// under the bucket read lock). Single goroutine here, so no race.
		p.keyCache = p.URL()
		if err := c.preDial(p); err != nil {
			Stats.ChecksFailed.Add(1)
			return nil, err
		}
		if err := c.fullCheck(p); err != nil {
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
	for _, s := range order {
		p := &Proxy{Schema: s, Host: cand.Host, Port: cand.Port, meta: &ProxyMeta{}}
		p.keyCache = p.URL() // same precompute as above, same reason
		if err := c.preDial(p); err != nil {
			continue
		}
		if err := c.fullCheck(p); err == nil {
			Stats.ChecksPassed.Add(1)
			return p, nil
		}
	}
	Stats.ChecksFailed.Add(1)
	return nil, errors.New("no protocol works")
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
func (c *Checker) Revalidate(p *Proxy) error {
	if err := c.preDial(p); err != nil {
		return err
	}
	return c.fullCheck(p)
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
func (c *Checker) preDial(p *Proxy) error {
	to := c.cfg.Checker.TCPTimeout.Duration
	ctx, cancel := context.WithTimeout(context.Background(), to)
	defer cancel()
	conn, err := (&net.Dialer{}).DialContext(ctx, "tcp", p.Addr())
	if err != nil {
		return fmt.Errorf("tcp pre-dial: %w", err)
	}
	conn.Close()
	return nil
}

func (c *Checker) fullCheck(p *Proxy) error {
	// Use the cached transport, not a throwaway: the whole point of the cache
	// is reusing this transport's connection pool across checks of the same
	// proxy. fullCheck used to CloseIdleConnections on the way out, which
	// tore down the pool it was about to hand back and left the "reuse
	// connection pools" comment describing behaviour that never happened.
	tr := c.transportFor(p)
	client := &http.Client{
		Transport: tr,
		Timeout:   c.cfg.Checker.TotalT.Duration,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	start := time.Now()
	ip, viaConnect, winURL, err := c.ipThrough(client, p)
	if err != nil {
		return err
	}
	// IP-stage extras: header-leak must pass before content stage.
	if err := c.leakCheck(client); err != nil {
		return err
	}
	if err := c.e2eProbe(p); err != nil {
		return err
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
		contentOK, testConnect = c.contentPass(client, p)
	}()
	wg.Wait()
	if confirmErr != nil {
		return confirmErr
	}
	// A recovered panic in contentPass leaves the zero values, which read as a
	// clean pass. Fail closed instead of admitting an unchecked proxy.
	if !contentOK && len(c.tests) > 0 {
		return errors.New("content check failed")
	}
	// CONNECT is proven only when some stage actually tunnelled. Skipping the
	// check when no evidence could exist at all is not the same as "no
	// evidence yet": with content tests and https self-IP urls both absent,
	// viaConnect and testConnect are both false by construction, and this
	// used to reject every http/https proxy purely for lack of
	// configuration.
	if needsConnect(p.Schema) && !viaConnect && !testConnect && c.connectEvidencePossible() {
		return errors.New("proxy does not support CONNECT")
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
