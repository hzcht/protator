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
	"sync/atomic"
	"time"
)

// Evidence probes: everything the checker asks the *outside world* through a
// candidate — exit IP, content/leak verdicts, the end-to-end serving probe,
// GeoIP lookup. Keep it separate from checker.go, which owns the decision
// pipeline and the candidate lifecycle; a probe here only answers "what did
// this proxy do", never "is it good".

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
			// Guarded like every other sub-probe: the reader below takes a
			// fixed number of results with no ctx escape, so a panic here
			// would hang its peers forever — and an unrecovered one exits the
			// process with the queue unsaved.
			defer RecoverPanic("checker: self-ip " + u)
			body, err := getBodyCtx(ctx, client, u)
			if err != nil {
				GuardedSend(ch, res{err: err})
				return
			}
			ip := c.firstIP(body)
			if ip == nil {
				GuardedSend(ch, res{err: errors.New("no IP in service response")})
				return
			}
			if ip.Equal(c.selfIP) {
				GuardedSend(ch, res{transparent: true})
				return
			}
			vc := needsConnect(p.Schema) && viaConnectURL(u)
			GuardedSend(ch, res{ip: ip, viaConnect: vc, url: u})
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
	for i, t := range c.tests {
		compiled := []*regexp.Regexp{}
		if i < len(c.testsRe) {
			compiled = c.testsRe[i]
		}
		patterns := t.MustContain
		go func(t ContentTest, compiled []*regexp.Regexp, patterns []string) {
			// No send is expected on the failure paths, so recovery here only
			// has to keep the process alive; the select below carries the
			// success value out under a ctx guard.
			defer RecoverPanic("checker: content test " + t.URL)
			body, err := getBodyCtx(ctx, client, t.URL)
			if err != nil {
				return
			}
			for j, pat := range patterns {
				var re *regexp.Regexp
				if j < len(compiled) {
					re = compiled[j]
				}
				if re != nil {
					if !re.MatchString(body) {
						return
					}
					continue
				}
				if !strings.Contains(body, pat) {
					return
				}
			}
			select {
			case ch <- res{viaConnect: needsConnect(p.Schema) && viaConnectURL(t.URL)}:
			case <-ctx.Done():
			}
		}(t, compiled, patterns)
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
//
// Every request here goes through `client`, which is already bound to the proxy
// under test, so no proxy identity is needed on the parameters.
func (c *Checker) leakCheck(client *http.Client) error {
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
			// Recovered per probe: the loop below reads one result per url, so
			// a panic without this leaves it blocked forever.
			defer RecoverPanic("checker: leak probe " + u)
			req, err := http.NewRequestWithContext(ctx, "GET", u, nil)
			if err != nil {
				GuardedSend(ch, res{})
				return
			}
			resp, err := client.Do(req)
			if err != nil {
				GuardedSend(ch, res{})
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
			GuardedSend(ch, res{leaked})
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
// `first` is the IP that race saw; `p` is not needed because client is already
// bound to it.
func (c *Checker) confirmExitIP(client *http.Client, first net.IP, u string) error {
	if !c.cfg.Checker.RequireStableExit {
		return nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), c.cfg.Checker.ResponseT.Duration)
	defer cancel()
	body, err := getBodyCtx(ctx, client, u)
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
// connection pools across checks for the same proxy. The cache is bounded;
// when full, one entry is evicted.
func (c *Checker) transportFor(p *Proxy) *http.Transport {
	// Probe by the precomputed key rather than URL(): URL() re-formats the
	// string on every call, which is what the cache exists to avoid.
	key := p.Key()

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
	if p.IsTrojan() {
		tr.Proxy = nil
		to := c.cfg.Checker.ConnectT.Duration
		tr.DialContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
			return dialTrojan(p, to, ctx, network, addr)
		}
	}

	// Store in cache with eviction when full. LoadOrStore, like the
	// collector's twin: two workers checking the same proxy concurrently both
	// miss Load, and a plain Store orphans the loser's transport mid-check
	// (up to 8 idle conns) while double-counting transportCacheSize for one
	// key — premature eviction of real entries under exactly the load spikes
	// the cache exists to absorb.
	actual, loaded := c.transportCache.LoadOrStore(key, tr)
	if loaded {
		tr.CloseIdleConnections() // lost the race; do not leak this handle
		return actual.(*http.Transport)
	}
	if atomic.AddInt64(&c.transportCacheSize, 1) > c.transportCacheMax {
		// Never evict the entry just inserted: Range order is undefined, so it
		// can return `key` itself, leaving the new transport uncached.
		c.transportCache.Range(func(k, v interface{}) bool {
			if kk, _ := k.(string); kk == key {
				return true // keep looking
			}
			if old, ok := v.(*http.Transport); ok {
				old.CloseIdleConnections()
			}
			c.transportCache.Delete(k)
			atomic.AddInt64(&c.transportCacheSize, -1)
			return false
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

// lookupGeoIP looks up the country and ASN for the given IP from the local
// MaxMind databases, if configured. Country comes from the City database
// (geoip_db_path), ASN from the separate ASN database (geoip_asn_db_path):
// the two are different MaxMind files, and neither field is invented when its
// database is absent.
func (c *Checker) lookupGeoIP(ip net.IP) (country, asn string) {
	if c.geoDB != nil {
		if record, err := c.geoDB.City(ip); err == nil {
			country = record.Country.IsoCode
		}
	}
	if c.geoASN != nil {
		if record, err := c.geoASN.ASN(ip); err == nil {
			if record.AutonomousSystemOrganization != "" {
				asn = fmt.Sprintf("AS%d %s", record.AutonomousSystemNumber, record.AutonomousSystemOrganization)
			} else if record.AutonomousSystemNumber != 0 {
				asn = fmt.Sprintf("AS%d", record.AutonomousSystemNumber)
			}
		}
	}
	return country, asn
}

// matchesTemplate matches a template string either as a regexp or, if the
// string is not a valid expression, as a plain substring.
//
// Kept for callers that have no precompiled pattern to hand (tests, tools);
// the hot path uses the compiled table built in NewChecker.
func matchesTemplate(template, body string) bool {
	re, err := regexp.Compile(template)
	if err == nil {
		return re.MatchString(body)
	}
	return strings.Contains(body, template)
}
