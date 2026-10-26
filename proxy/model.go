package proxy

import (
	"fmt"
	"net"
	"strconv"
	"strings"
	"sync/atomic"
	"time"
)

// Proxy describes a single validated upstream proxy.
//
// The stats fields are updated lock-free from the serving path (every dial)
// and from the checker (every validation), so weighted selection stays cheap
// on the hot path.
type Proxy struct {
	Schema string `json:"schema"` // http, https, socks4, socks5, vless, trojan
	Host   string `json:"host"`
	Port   int    `json:"port"`

	consecFails int64 // consecutive serving-path dial failures
	okTotal     int64 // lifetime successful dials/checks
	failTotal   int64 // lifetime failed dials/checks
	latencyEMA  int64 // exponential moving average of dial latency, ns
	inFlight    int64 // currently open upstream connections through this proxy
	lastCheck   int64 // unix nanos of last successful validation
	lastOK      int64 // unix nanos of last successful serving dial

	// source is the sites.txt entry this proxy was discovered on ("" for
	// hand-added entries and for anything loaded from disk). Written once,
	// before the proxy is handed to the bucket; read-only afterwards.
	source string

	// keyCache is the pre-computed URL string for Key(). Set once, on the
	// constructing goroutine before the proxy is published (ParseProxyLine,
	// Checker.Check), so every later Key() is a field read. Key() deliberately
	// does not fill it in lazily: that write would race the readers `Proxy`
	// must serve lock-free on every dial.
	keyCache string

	// Cold fields (admin/debug only) вЂ” allocated separately to keep Proxy small.
	meta *ProxyMeta
}

// SetSource records the proxy-list URL a proxy was discovered on. It must be
// called before the proxy is added to a bucket; after that the attribution is
// frozen so the bucket's per-source counters stay consistent.
func (p *Proxy) SetSource(s string) { p.source = s }

// Source returns the source URL the proxy was discovered on ("" if unknown).
func (p *Proxy) Source() string { return p.source }

// MarkInFlight increments the count of live tunnels through this proxy.
// Decremented when the wrapped connection closes. Used by the load-aware
// picker to spread concurrent requests over healthy proxies.
func (p *Proxy) MarkInFlight()     { atomic.AddInt64(&p.inFlight, 1) }
func (p *Proxy) MarkInFlightDone() { atomic.AddInt64(&p.inFlight, -1) }

// InFlight returns the number of currently open connections through this proxy.
func (p *Proxy) InFlight() int64 { return atomic.LoadInt64(&p.inFlight) }

// MarkDialOK records a successful upstream dial: a latency sample only. Health
// is settled later by MarkServeOK / MarkServeFail once the outcome is known вЂ”
// a dial that merely connected must never clear a failure streak, or every
// response-level charge (blackhole, device answer) would be wiped by the next
// request's dial to the same proxy.
func (p *Proxy) MarkDialOK(latency time.Duration) {
	p.sampleLatency(latency)
}

// MarkServeOK records a successful serving-path outcome (a real response was
// delivered): resets the failure streak, stamps lastOK, and folds the dial
// latency in.
func (p *Proxy) MarkServeOK(latency time.Duration) {
	atomic.StoreInt64(&p.consecFails, 0)
	atomic.AddInt64(&p.okTotal, 1)
	atomic.StoreInt64(&p.lastOK, time.Now().UnixNano())
	p.sampleLatency(latency)
}

// MarkServeFail records a failed serving-path dial and returns the new
// consecutive-failure count.
func (p *Proxy) MarkServeFail() int64 {
	atomic.AddInt64(&p.failTotal, 1)
	return atomic.AddInt64(&p.consecFails, 1)
}

// MarkAlive records a successful checker validation (proof of life): resets
// the failure streak, stamps lastCheck and folds the check latency in.
func (p *Proxy) MarkAlive(latency time.Duration) {
	atomic.StoreInt64(&p.consecFails, 0)
	atomic.AddInt64(&p.okTotal, 1)
	atomic.StoreInt64(&p.lastCheck, time.Now().UnixNano())
	p.sampleLatency(latency)
}

// sampleLatency folds a sample into the EMA (alpha = 1/8, CAS loop).
func (p *Proxy) sampleLatency(d time.Duration) {
	if d <= 0 {
		return
	}
	s := int64(d)
	for {
		old := atomic.LoadInt64(&p.latencyEMA)
		var next int64
		if old == 0 {
			next = s
		} else {
			next = old + (s-old)/8
		}
		if atomic.CompareAndSwapInt64(&p.latencyEMA, old, next) {
			return
		}
	}
}

// ConsecFails returns the current consecutive-failure streak.
func (p *Proxy) ConsecFails() int64 { return atomic.LoadInt64(&p.consecFails) }

// OKTotal is the lifetime count of successful dials/checks, FailTotal the
// count of failures. The admin page shows both so an operator can tell a
// proxy that has never been exercised from one that keeps failing.
func (p *Proxy) OKTotal() int64   { return atomic.LoadInt64(&p.okTotal) }
func (p *Proxy) FailTotal() int64 { return atomic.LoadInt64(&p.failTotal) }

// Latency returns the EMA dial latency (0 = not measured yet).
func (p *Proxy) Latency() time.Duration { return time.Duration(atomic.LoadInt64(&p.latencyEMA)) }

// latencyEMAValue is the raw EMA for in-package penalty comparison.
func (p *Proxy) latencyEMAValue() int64 { return atomic.LoadInt64(&p.latencyEMA) }

// LastCheck returns the time of the last successful validation (zero if never).
func (p *Proxy) LastCheck() time.Time {
	if ns := atomic.LoadInt64(&p.lastCheck); ns != 0 {
		return time.Unix(0, ns)
	}
	return time.Time{}
}

// LastServed returns the time of the last successful serving-path dial (zero
// if never). Real traffic is fresher proof of liveness than a validation
// stamp, so the revalidation loop skips recently-served proxies.
func (p *Proxy) LastServed() time.Time {
	if ns := atomic.LoadInt64(&p.lastOK); ns != 0 {
		return time.Unix(0, ns)
	}
	return time.Time{}
}

// lastOKNanos is the raw serving-success stamp for picker tiers: real traffic
// (MarkServeOK on a genuine response) is the strongest proof of liveness.
func (p *Proxy) lastOKNanos() int64 { return atomic.LoadInt64(&p.lastOK) }

// lastCheckNanos is the raw validation-success stamp.
func (p *Proxy) lastCheckNanos() int64 { return atomic.LoadInt64(&p.lastCheck) }

// stampCheck copies a validation-proof timestamp onto an existing resident
// entry (dedup hit in Bucket.addLocked): resets the failure streak and stamps
// lastCheck without touching latency/OK counters, which belong to the resident's
// own serving history rather than the throwaway re-validated object.
func (p *Proxy) stampCheck(ns int64) {
	atomic.StoreInt64(&p.consecFails, 0)
	atomic.StoreInt64(&p.lastCheck, ns)
}

// Candidate is an unvalidated host:port discovered from a proxy-list page.
// Schema may be empty, meaning the protocol is unknown and must be probed.
type Candidate struct {
	Host   string
	Port   int
	Schema string // http/https/socks4/socks5/vless/trojan or ""
	Prefer string // probe-protocol hint (from the source URL); non-binding
	Source string // site the candidate was found on: persisted by the pool
	// and, on validation, stamped onto the proxy for per-source accounting

	// VLESS-specific fields (when schema == "vless")
	VLESSUUID   string
	VLESSFlow   string
	VLESSSNI    string
	VLESSPbk    string
	VLESSSid    string
	VLESSSpider string
	VLESSNoTLS  bool // security=none: plaintext, no TLS

	// Trojan-specific fields (when schema == "trojan"): password in URL
	// form, SNI override (empty = host), plaintext flag (security=none).
	TrojanPassword string
	TrojanSNI      string
	TrojanNoTLS    bool
}

func (c Candidate) key() string {
	base := fmt.Sprintf("%s:%d", c.Host, c.Port)
	// Credentialed protocols: the same host:port with a different password
	// is a different proxy (trojan lists reuse hosts across passwords), so
	// the credential joins the identity вЂ” otherwise extraction dedup keeps
	// only the first password per host:port and the rest are never tried.
	switch c.Schema {
	case "vless":
		if c.VLESSUUID != "" {
			return "vless:" + c.VLESSUUID + "@" + base
		}
	case "trojan":
		if c.TrojanPassword != "" {
			return "trojan:" + c.TrojanPassword + "@" + base
		}
	}
	return base
}

// Addr returns host:port (bracket-form aware).
func (p *Proxy) Addr() string {
	return net.JoinHostPort(p.Host, strconv.Itoa(p.Port))
}

// URL returns e.g. "socks5://host:port" or "vless://uuid@host:port?flow=...&sni=...&pbk=...&sid=...&spider=...".
func (p *Proxy) URL() string {
	s := p.Schema
	if s == "" {
		s = "http"
	}
	if s == "vless" && p.GetVLESSUUID() != "" {
		return fmt.Sprintf("vless://%s@%s", p.GetVLESSUUID(), p.Addr()) + buildVLESSQuery(p)
	}
	if s == "trojan" && p.GetTrojanPassword() != "" {
		return fmt.Sprintf("trojan://%s@%s", p.GetTrojanPassword(), p.Addr()) + buildTrojanQuery(p)
	}
	return fmt.Sprintf("%s://%s", s, p.Addr())
}

// URLLen returns the length of URL() without building it.
//
// The queue save measures millions of entries to pick the tail that fits the
// byte budget, and rendering every URL just to throw most of them away was a
// ~70 MB allocation spike on every save. Length arithmetic is the same number
// for a fraction of the work.
func (p *Proxy) URLLen() int {
	addr := len(p.Host) + 1 + digits(p.Port)
	if strings.IndexByte(p.Host, ':') >= 0 {
		addr += 2 // net.JoinHostPort brackets an IPv6 literal
	}
	s := p.Schema
	if s == "" {
		s = "http"
	}
	if s == "vless" && p.GetVLESSUUID() != "" {
		return len("vless://") + len(p.GetVLESSUUID()) + 1 + addr + len(buildVLESSQuery(p))
	}
	if s == "trojan" && p.GetTrojanPassword() != "" {
		return len("trojan://") + len(p.GetTrojanPassword()) + 1 + addr + len(buildTrojanQuery(p))
	}
	return len(s) + 3 + addr // "://"
}

// digits returns the decimal length of n (n <= 0 counts as one digit).
func digits(n int) int {
	if n <= 0 {
		return 1
	}
	c := 0
	for n > 0 {
		c++
		n /= 10
	}
	return c
}

// AppendURL appends URL() to buf without the intermediate string. The queue
// save writes millions of these; URL() allocates through fmt.Sprintf for every
// entry (5 allocations each), which is the difference between a cheap save and
// a 5 MB garbage spike per cycle.
func (p *Proxy) AppendURL(buf []byte) []byte {
	s := p.Schema
	if s == "" {
		s = "http"
	}
	if s == "vless" && p.GetVLESSUUID() != "" {
		// Must include the addr, same as URL(): without host:port the queue
		// save rendered "vless://uuid@?flow=вЂ¦", ParseProxyLine failed at
		// splitHostPort("") on reload and silently dropped the entry вЂ” the
		// save/reload cycle deleted every VLESS proxy while URLLen (which
		// counts the addr) and AppendGood(p.URL()) stayed correct.
		buf = append(buf, "vless://"...)
		buf = append(buf, p.GetVLESSUUID()...)
		buf = append(buf, '@')
		buf = p.appendAddr(buf)
		return append(buf, buildVLESSQuery(p)...)
	}
	if s == "trojan" && p.GetTrojanPassword() != "" {
		// Same addr rule as VLESS above: the password alone is not an
		// address, and a reload must recover host:port plus credentials.
		buf = append(buf, "trojan://"...)
		buf = append(buf, p.GetTrojanPassword()...)
		buf = append(buf, '@')
		buf = p.appendAddr(buf)
		return append(buf, buildTrojanQuery(p)...)
	}
	buf = append(buf, s...)
	buf = append(buf, "://"...)
	return p.appendAddr(buf)
}

// appendAddr appends host:port, bracketing an IPv6 literal.
func (p *Proxy) appendAddr(buf []byte) []byte {
	if strings.IndexByte(p.Host, ':') >= 0 {
		buf = append(buf, '[')
		buf = append(buf, p.Host...)
		buf = append(buf, ']')
	} else {
		buf = append(buf, p.Host...)
	}
	buf = append(buf, ':')
	return strconv.AppendInt(buf, int64(p.Port), 10)
}

// Key returns a stable identity for deduplication.
// Uses a cached string to avoid fmt.Sprintf on the hot path.
//
// The cache is filled before the proxy is published to other goroutines (the
// checker sets it, then hands the object to the bucket), so reads never race a
// write; a caller that somehow gets an un-cached Proxy recomputes the same
// string rather than writing the shared field.
func (p *Proxy) Key() string {
	if k := p.keyCache; k != "" {
		return k
	}
	return p.URL()
}

// ParseProxyLine parses queue lines into a Proxy.
// Accepted forms: "host:port", "scheme://host:port", "scheme://user:pass@host:port",
// "vless://uuid@host:port?...", "trojan://password@host:port?...".
func ParseProxyLine(line string) (*Proxy, error) {
	s := strings.TrimSpace(line)
	if s == "" || strings.HasPrefix(s, "#") {
		return nil, fmt.Errorf("empty or comment")
	}

	schema := "http"
	rest := s
	if i := strings.Index(s, "://"); i >= 0 {
		schema = strings.ToLower(s[:i])
		// Umbrella spellings (socks5h://, socks4a://) normalize to dialer
		// names: the extractor already does this, but queue/pool files may
		// carry the raw spelling and validSchema would reject them. Mapped
		// explicitly (not via normScheme, whose default is "http" for the
		// extractor's unknown-schema case — routing trojan/vless through it
		// would silently re-tag them as http).
		switch schema {
		case "socks5h":
			schema = "socks5"
		case "socks4a", "socks":
			schema = "socks4"
		}
		if !validSchema(schema) {
			return nil, fmt.Errorf("unknown scheme %q", schema)
		}
		rest = s[i+3:]
	}
	// Handle VLESS URL parameters (uuid, flow, sni, pbk, sid, spider)
	vlessUUID, vlessFlow, vlessSNI, vlessPbk, vlessSid, vlessSpider := "", "", "", "", "", ""
	vlessNoTLS := false
	if schema == "vless" {
		// Format: vless://uuid@host:port?flow=...&sni=...&pbk=...&sid=...&spider=...
		if at := strings.LastIndex(rest, "@"); at >= 0 {
			vlessUUID = rest[:at]
			rest = rest[at+1:]
		}
		// Parse query parameters
		if q := strings.Index(rest, "?"); q >= 0 {
			query := rest[q+1:]
			rest = rest[:q]
			for _, kv := range strings.Split(query, "&") {
				if eq := strings.Index(kv, "="); eq >= 0 {
					k, v := kv[:eq], kv[eq+1:]
					switch k {
					case "flow":
						vlessFlow = v
					case "sni":
						vlessSNI = v
					case "pbk":
						vlessPbk = v
					case "sid":
						vlessSid = v
					case "spider":
						vlessSpider = v
					case "security":
						vlessNoTLS = v == "none"
					}
				}
			}
		}
	}

	// Handle trojan URL parameters (password in userinfo, sni, security).
	// Format: trojan://password@host:port?sni=...&security=none
	// The password stays in URL form (still percent-encoded): the handshake
	// decodes it once, and raw storage keeps URL()/ParseProxyLine a lossless
	// round trip for passwords containing #/@/? (LastIndex(@) still splits
	// userinfo correctly; # and ? would not survive a decode/re-encode).
	trojanPassword, trojanSNI, trojanNoTLS := "", "", false
	if schema == "trojan" {
		if at := strings.LastIndex(rest, "@"); at >= 0 {
			trojanPassword = rest[:at]
			rest = rest[at+1:]
		}
		if q := strings.Index(rest, "?"); q >= 0 {
			query := rest[q+1:]
			rest = rest[:q]
			for _, kv := range strings.Split(query, "&") {
				if eq := strings.Index(kv, "="); eq >= 0 {
					k, v := kv[:eq], kv[eq+1:]
					switch k {
					case "sni":
						trojanSNI = v
					case "security":
						trojanNoTLS = v == "none"
					}
				}
			}
		}
	}

	// strip credentials if present (user:pass@host:port)
	if at := strings.LastIndex(rest, "@"); at >= 0 {
		rest = rest[at+1:]
	}

	host, portStr, err := splitHostPort(rest)
	if err != nil {
		return nil, err
	}
	port, err := strconv.Atoi(portStr)
	if err != nil {
		return nil, fmt.Errorf("bad port %q", portStr)
	}
	if port < 1 || port > 65535 {
		return nil, fmt.Errorf("port out of range %d", port)
	}
	// meta is allocated eagerly: ParseProxyLine is one of the few remaining
	// construction sites, and a Proxy published with meta == nil lets
	// revalidation's SetGeoIP/SetVLESS race concurrent admin reads of the
	// same plain pointer field (ensureMeta's "before publication" contract
	// is broken by the revalidate path).
	p := &Proxy{Schema: schema, Host: host, Port: port, meta: &ProxyMeta{}}
	if schema == "vless" {
		p.SetVLESS(vlessUUID, vlessFlow, vlessSNI, vlessPbk, vlessSid, vlessSpider, vlessNoTLS)
	}
	if schema == "trojan" {
		p.SetTrojan(trojanPassword, trojanSNI, trojanNoTLS)
	}
	p.keyCache = p.URL()
	return p, nil
}

// splitHostPort splits host:port, handling [ipv6]:port and bare IPv6 without
// brackets followed by ":port" (which is ambiguous вЂ” treat as bracketed form
// requirement, i.e. require net.SplitHostPort for correctness).
func splitHostPort(s string) (string, string, error) {
	// Bracketed form or domain form: handled by net.SplitHostPort.
	if strings.HasPrefix(s, "[") {
		host, port, err := net.SplitHostPort(s)
		if err != nil {
			return "", "", err
		}
		return host, port, nil
	}
	// bare host:port with single colon (IPv4/domain) or [host]:port
	if strings.Count(s, ":") == 1 {
		host, port, err := net.SplitHostPort(s)
		if err != nil {
			return "", "", err
		}
		return host, port, nil
	}
	return "", "", fmt.Errorf("not a host:port string %q", s)
}
