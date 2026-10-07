package proxy

import (
	"bufio"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
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
	cfg    *Config
	selfIP net.IP
	tests  []ContentTest
	ipRe   *regexp.Regexp
	geoDB  *geoip2.Reader

	// transportCache caches http.Transport per proxy address to avoid
	// creating a new transport (and its connection pool) for every check.
	// Key: "schema://host:port", Value: *http.Transport
	transportCache sync.Map
	// transportCacheSize tracks the number of entries for eviction.
	transportCacheSize int
	// transportCacheMax bounds the cache size to prevent unbounded memory growth.
	// When full, the oldest entry is evicted (simple FIFO).
	transportCacheMax int

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

	if cfg.Checker.TestsFile != "" && fileExists(cfg.Checker.TestsFile) {
		tests, err := LoadTests(cfg.Checker.TestsFile)
		if err != nil {
			return nil, err
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
			body, err := getBodyCtx(ctx, client, u)
			if err != nil {
				ch <- res{err: err}
				return
			}
			if ip := c.firstIP(body); ip != nil {
				ch <- res{ip: ip}
				return
			}
			ch <- res{err: errors.New("no IP in service response")}
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
	if cand.Port < 1 || cand.Port > 65535 {
		return nil, errors.New("bad port")
	}
	if !c.allowBogon {
		if err := rejectBogon(cand.Host, c.selfIP); err != nil {
			return nil, err
		}
	}
	if cand.Schema != "" && validSchema(cand.Schema) {
		p := &Proxy{Schema: cand.Schema, Host: cand.Host, Port: cand.Port}
		if err := c.preDial(p); err != nil {
			return nil, err
		}
		if err := c.fullCheck(p); err != nil {
			return nil, err
		}
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
		p := &Proxy{Schema: s, Host: cand.Host, Port: cand.Port}
		if err := c.preDial(p); err != nil {
			continue
		}
		if err := c.fullCheck(p); err == nil {
			return p, nil
		}
	}
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
	tr := c.transportFor(p)
	defer tr.CloseIdleConnections()
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
	if err := c.leakCheck(client, p); err != nil {
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
		confirmErr = c.confirmExitIP(client, p, ip, winURL)
	}()
	go func() {
		defer wg.Done()
		contentOK, testConnect = c.contentPass(client, p)
	}()
	wg.Wait()
	if confirmErr != nil {
		return confirmErr
	}
	if !contentOK {
		return errors.New("content check failed")
	}
	if needsConnect(p.Schema) && !viaConnect && !testConnect {
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

// viaConnectURL reports whether fetching u through an http(s) proxy uses
// CONNECT (i.e. u itself is https).
func viaConnectURL(u string) bool {
	return strings.HasPrefix(strings.ToLower(u), "https://")
}

// ipThrough races the self-IP services via p and returns the seen IP and the
// URL that produced it (used by the stability re-probe). A transparent verdict
// requires unanimity: any single non-self IP wins, because services disagree
// on X-Forwarded-For handling.
func (c *Checker) ipThrough(client *http.Client, p *Proxy) (net.IP, bool, string, error) {
	urls := c.cfg.Checker.SelfIPURLs
	type res struct {
		ip          net.IP
		viaConnect  bool
		transparent bool
		err         error
		url         string
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	ch := make(chan res, len(urls))
	for _, u := range urls {
		go func(u string) {
			body, err := getBodyCtx(ctx, client, u)
			if err != nil {
				ch <- res{err: err}
				return
			}
			ip := c.firstIP(body)
			if ip == nil {
				ch <- res{err: errors.New("no IP in service response")}
				return
			}
			if ip.Equal(c.selfIP) {
				ch <- res{transparent: true}
				return
			}
			vc := needsConnect(p.Schema) && viaConnectURL(u)
			ch <- res{ip: ip, viaConnect: vc, url: u}
		}(u)
	}
	var lastErr error
	transparent := 0
	for range urls {
		r := <-ch
		switch {
		case r.transparent:
			transparent++
		case r.err == nil:
			return r.ip, r.viaConnect, r.url, nil
		default:
			lastErr = r.err
		}
	}
	if transparent > 0 {
		return nil, false, "", errors.New("proxy is transparent (returned our IP)")
	}
	if lastErr == nil {
		lastErr = errors.New("all self-ip services failed")
	}
	return nil, false, "", lastErr
}

// contentPass races the content tests; the first fully-matching test wins.
func (c *Checker) contentPass(client *http.Client, p *Proxy) (bool, bool) {
	if len(c.tests) == 0 {
		return true, false
	}
	type res struct {
		viaConnect bool
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	ch := make(chan res, len(c.tests))
	for _, t := range c.tests {
		go func(t ContentTest) {
			body, err := getBodyCtx(ctx, client, t.URL)
			if err != nil {
				return
			}
			for _, pat := range t.MustContain {
				if !matchesTemplate(pat, body) {
					return
				}
			}
			select {
			case ch <- res{viaConnect: needsConnect(p.Schema) && viaConnectURL(t.URL)}:
			case <-ctx.Done():
			}
		}(t)
	}
	select {
	case r := <-ch:
		return true, r.viaConnect
	case <-time.After(c.cfg.Checker.TotalT.Duration):
		return false, false
	}
}

// leakCheck rejects proxies that forward the client IP in hop-by-hop headers
// (X-Forwarded-For, Via, X-Real-IP, ...). A leak verdict is only trusted when
// the echo endpoint actually responded; service errors never fail a proxy.
func (c *Checker) leakCheck(client *http.Client, p *Proxy) error {
	urls := c.cfg.Checker.LeakProbeURLs
	if len(urls) == 0 {
		return nil
	}
	self := c.selfIP.String()
	type res struct{ leaked bool }
	ctx, cancel := context.WithTimeout(context.Background(), c.cfg.Checker.TotalT.Duration)
	defer cancel()
	ch := make(chan res, len(urls))
	for _, u := range urls {
		go func(u string) {
			req, err := http.NewRequestWithContext(ctx, "GET", u, nil)
			if err != nil {
				ch <- res{}
				return
			}
			resp, err := client.Do(req)
			if err != nil {
				ch <- res{}
				return
			}
			defer resp.Body.Close()
			leaked := false
			for _, values := range resp.Header {
				for _, v := range values {
					if strings.Contains(v, self) {
						leaked = true
					}
				}
			}
			if !leaked {
				if body, err := io.ReadAll(io.LimitReader(resp.Body, 16<<10)); err == nil &&
					strings.Contains(string(body), self) {
					leaked = true
				}
			}
			ch <- res{leaked}
		}(u)
	}
	for range urls {
		if r := <-ch; r.leaked {
			return errors.New("proxy forwards client IP in headers")
		}
	}
	return nil
}

// confirmExitIP re-fetches the self-IP URL that won the anonymity race and
// requires the exit IP to be identical, rejecting unstable rotating proxies.
func (c *Checker) confirmExitIP(client *http.Client, p *Proxy, first net.IP, u string) error {
	if !c.cfg.Checker.RequireStableExit {
		return nil
	}
	body, err := getBodyCtx(context.Background(), client, u)
	if err != nil {
		return nil // could not confirm; never fail on a service hiccup
	}
	second := c.firstIP(body)
	if second == nil {
		return nil
	}
	if !second.Equal(first) {
		return errors.New("proxy exit IP unstable across probes")
	}
	return nil
}

// e2eProbe opens a tunnel through the exact serving dial path (dialProxy,
// the same code the forward servers use) and carries a real GET over it,
// verifying the proxy can move actual client bytes end to end.
func (c *Checker) e2eProbe(p *Proxy) error {
	if !c.cfg.Checker.E2EProbe || len(c.cfg.Checker.SelfIPURLs) == 0 {
		return nil
	}
	u, err := url.Parse(c.cfg.Checker.SelfIPURLs[0])
	if err != nil {
		return err
	}
	host := u.Hostname()
	port := u.Port()
	if port == "" {
		if u.Scheme == "https" {
			port = "443"
		} else {
			port = "80"
		}
	}
	addr := net.JoinHostPort(host, port)
	total := c.cfg.Checker.ConnectT.Duration + c.cfg.Checker.ResponseT.Duration
	ctx, cancel := context.WithTimeout(context.Background(), total)
	defer cancel()
	conn, err := dialProxy(p, c.cfg.Checker.ConnectT.Duration, ctx, "tcp", addr)
	if err != nil {
		return fmt.Errorf("e2e tunnel: %w", err)
	}
	defer conn.Close()
	if u.Scheme == "https" {
		tconn := tls.Client(conn, &tls.Config{ServerName: host, InsecureSkipVerify: true})
		tconn.SetDeadline(time.Now().Add(total))
		if err := tconn.HandshakeContext(ctx); err != nil {
			return fmt.Errorf("e2e tls: %w", err)
		}
		conn = tconn
	}
	conn.SetDeadline(time.Now().Add(c.cfg.Checker.ResponseT.Duration))
	if _, err := fmt.Fprintf(conn, "GET / HTTP/1.1\r\nHost: %s\r\nUser-Agent: protator-check\r\nConnection: close\r\n\r\n", addr); err != nil {
		return fmt.Errorf("e2e write: %w", err)
	}
	resp, err := http.ReadResponse(bufio.NewReader(conn), nil)
	if err != nil {
		return fmt.Errorf("e2e read: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("e2e status %d", resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 16<<10))
	if err != nil {
		return fmt.Errorf("e2e body: %w", err)
	}
	ip := c.firstIP(string(body))
	if ip == nil || ip.Equal(c.selfIP) {
		return errors.New("e2e tunnel returned no foreign IP")
	}
	return nil
}

// transportFor returns a per-check transport routing through p with
// connection reuse across the check's sub-requests.
// Transports are cached per proxy address (schema://host:port) to reuse
// connection pools across checks for the same proxy.
// The cache is bounded: when full, the oldest entry is evicted (FIFO).
func (c *Checker) transportFor(p *Proxy) *http.Transport {
	key := p.URL() // schema://host:port (includes VLESS params)

	if tr, ok := c.transportCache.Load(key); ok {
		return tr.(*http.Transport)
	}

	tr := &http.Transport{
		Proxy: http.ProxyURL(&url.URL{Scheme: p.Schema, Host: p.Addr()}),
		DialContext: (&net.Dialer{
			Timeout:   c.cfg.Checker.ConnectT.Duration,
			KeepAlive: 30 * time.Second,
		}).DialContext,
		TLSHandshakeTimeout:   c.cfg.Checker.TLSHandshake.Duration,
		ResponseHeaderTimeout: c.cfg.Checker.ResponseT.Duration,
		MaxIdleConnsPerHost:   8,
		IdleConnTimeout:       30 * time.Second,
		TLSClientConfig:       &tls.Config{InsecureSkipVerify: true},
	}
	if isSocks(p.Schema) {
		tr.Proxy = nil
		to := c.cfg.Checker.ConnectT.Duration
		tr.DialContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
			return socksDialTimeout(p, to, ctx, network, addr)
		}
	}
	if p.IsVLESS() {
		tr.Proxy = nil
		to := c.cfg.Checker.ConnectT.Duration
		tr.DialContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
			return dialVLESS(p, to, ctx, network, addr)
		}
	}

	// Store in cache with eviction when full.
	c.transportCache.Store(key, tr)
	c.transportCacheSize++
	if c.transportCacheSize > c.transportCacheMax {
		// Evict oldest entry (simple FIFO: delete the first key we find).
		c.transportCache.Range(func(k, v interface{}) bool {
			c.transportCache.Delete(k)
			if tr, ok := v.(*http.Transport); ok {
				tr.CloseIdleConnections()
			}
			c.transportCacheSize--
			return false // stop after first deletion
		})
	}
	return tr
}

// firstIP extracts the first IPv4 from a body.
func (c *Checker) firstIP(body string) net.IP {
	m := c.ipRe.FindString(body)
	if m == "" {
		return nil
	}
	if ip := net.ParseIP(m); ip != nil {
		return ip
	}
	return nil
}

// getBodyCtx performs a cancellable GET and returns the (size-bounded) body.
func getBodyCtx(ctx context.Context, client *http.Client, u string) (string, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", u, nil)
	if err != nil {
		return "", err
	}
	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		io.Copy(io.Discard, io.LimitReader(resp.Body, 4<<10))
		return "", fmt.Errorf("http status %d from %s", resp.StatusCode, u)
	}
	b, err := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(b)), nil
}

// lookupGeoIP looks up the country and ASN for the given IP.
// This is a placeholder implementation that can be extended with a proper
// GeoIP database (e.g., MaxMind GeoLite2). For production use, replace
// with a local MMDB lookup or a cached API call.
func (c *Checker) lookupGeoIP(ip net.IP) (country, asn string) {
	// Try a simple public API as fallback (rate limited, not for high volume)
	// This is only called once per successful validation, so it's acceptable.
	// In production, use a local MMDB file for zero-latency lookups.
	// Example: https://ipapi.co/<ip>/json/ or http://ip-api.com/json/<ip>
	// For now, return empty to avoid external dependencies.
	if c.geoDB == nil {
		return "", ""
	}
	record, err := c.geoDB.City(ip)
	if err != nil {
		return "", ""
	}
	country = record.Country.IsoCode
	return country, ""
}

// matchesTemplate matches a template string either as a regexp or, if the
// string is not a valid expression, as a plain substring.
func matchesTemplate(template, body string) bool {
	re, err := regexp.Compile(template)
	if err == nil {
		return re.MatchString(body)
	}
	return strings.Contains(body, template)
}
