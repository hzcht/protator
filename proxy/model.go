package proxy

import (
	"fmt"
	"net"
	"strconv"
	"strings"
	"sync/atomic"
	"time"
)

// ProxyMeta holds cold fields (admin/debug only) — not accessed on the hot serving path.
// Keeping these separate reduces Proxy size from ~200B to ~120B, reducing GC pressure.
type ProxyMeta struct {
	// GeoIP fields (populated by checker after successful validation)
	Country string `json:"country,omitempty"` // ISO 3166-1 alpha-2
	ASN     string `json:"asn,omitempty"`     // "AS12345 Provider Name"

	// VLESS-specific fields (populated when schema == "vless")
	VLESSUUID   string `json:"vless_uuid,omitempty"`
	VLESSFlow   string `json:"vless_flow,omitempty"`
	VLESSSNI    string `json:"vless_sni,omitempty"`
	VLESSPbk    string `json:"vless_pbk,omitempty"`    // REALITY public key
	VLESSSid    string `json:"vless_sid,omitempty"`    // REALITY short ID
	VLESSSpider string `json:"vless_spider,omitempty"` // spider header (for vision)
}

// Proxy describes a single validated upstream proxy.
//
// The stats fields are updated lock-free from the serving path (every dial)
// and from the checker (every validation), so weighted selection stays cheap
// on the hot path.
type Proxy struct {
	Schema string `json:"schema"` // http, https, socks4, socks5, vless
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

	// keyCache is the pre-computed URL string for Key(). Set once at creation
	// (or on first Key() call) to avoid fmt.Sprintf on the hot path.
	keyCache string

	// Cold fields (admin/debug only) — allocated separately to keep Proxy small.
	meta *ProxyMeta
}

// SetSource records the proxy-list URL a proxy was discovered on. It must be
// called before the proxy is added to a bucket; after that the attribution is
// frozen so the bucket's per-source counters stay consistent.
func (p *Proxy) SetSource(s string) { p.source = s }

// Source returns the source URL the proxy was discovered on ("" if unknown).
func (p *Proxy) Source() string { return p.source }

// GetCountry returns the ISO 3166-1 alpha-2 country code.
func (p *Proxy) GetCountry() string {
	if p.meta == nil {
		return ""
	}
	return p.meta.Country
}

// GetASN returns the ASN string (e.g., "AS12345 Provider Name").
func (p *Proxy) GetASN() string {
	if p.meta == nil {
		return ""
	}
	return p.meta.ASN
}

// SetGeoIP sets the country and ASN for the proxy (called by checker after validation).
func (p *Proxy) SetGeoIP(country, asn string) {
	p.ensureMeta()
	p.meta.Country = country
	p.meta.ASN = asn
}

// VLESS getters
func (p *Proxy) GetVLESSUUID() string {
	if p.meta == nil {
		return ""
	}
	return p.meta.VLESSUUID
}

func (p *Proxy) GetVLESSFlow() string {
	if p.meta == nil {
		return ""
	}
	return p.meta.VLESSFlow
}

func (p *Proxy) GetVLESSSNI() string {
	if p.meta == nil {
		return ""
	}
	return p.meta.VLESSSNI
}

func (p *Proxy) GetVLESSPbk() string {
	if p.meta == nil {
		return ""
	}
	return p.meta.VLESSPbk
}

func (p *Proxy) GetVLESSSid() string {
	if p.meta == nil {
		return ""
	}
	return p.meta.VLESSSid
}

func (p *Proxy) GetVLESSSpider() string {
	if p.meta == nil {
		return ""
	}
	return p.meta.VLESSSpider
}

// SetVLESS sets VLESS-specific fields (called by checker after validation).
func (p *Proxy) SetVLESS(uuid, flow, sni, pbk, sid, spider string) {
	p.ensureMeta()
	p.meta.VLESSUUID = uuid
	p.meta.VLESSFlow = flow
	p.meta.VLESSSNI = sni
	p.meta.VLESSPbk = pbk
	p.meta.VLESSSid = sid
	p.meta.VLESSSpider = spider
}

// ensureMeta lazily initializes the meta pointer.
func (p *Proxy) ensureMeta() {
	if p.meta == nil {
		p.meta = &ProxyMeta{}
	}
}

// IsVLESS reports whether the proxy uses the VLESS protocol.
func (p *Proxy) IsVLESS() bool { return p.Schema == "vless" }

// MarkInFlight increments the count of live tunnels through this proxy.
// Decremented when the wrapped connection closes. Used by the load-aware
// picker to spread concurrent requests over healthy proxies.
func (p *Proxy) MarkInFlight()     { atomic.AddInt64(&p.inFlight, 1) }
func (p *Proxy) MarkInFlightDone() { atomic.AddInt64(&p.inFlight, -1) }

// InFlight returns the number of currently open connections through this proxy.
func (p *Proxy) InFlight() int64 { return atomic.LoadInt64(&p.inFlight) }

// MarkDialOK records a successful upstream dial: a latency sample only. Health
// is settled later by MarkServeOK / MarkServeFail once the outcome is known —
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
	Schema string // http/https/socks4/socks5/vless or ""
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
}

func (c Candidate) key() string {
	return fmt.Sprintf("%s:%d", c.Host, c.Port)
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
	return fmt.Sprintf("%s://%s", s, p.Addr())
}

func buildVLESSQuery(p *Proxy) string {
	var params []string
	if p.GetVLESSFlow() != "" {
		params = append(params, "flow="+p.GetVLESSFlow())
	}
	if p.GetVLESSSNI() != "" {
		params = append(params, "sni="+p.GetVLESSSNI())
	}
	if p.GetVLESSPbk() != "" {
		params = append(params, "pbk="+p.GetVLESSPbk())
	}
	if p.GetVLESSSid() != "" {
		params = append(params, "sid="+p.GetVLESSSid())
	}
	if p.GetVLESSSpider() != "" {
		params = append(params, "spider="+p.GetVLESSSpider())
	}
	if len(params) > 0 {
		return "?" + strings.Join(params, "&")
	}
	return ""
}

// Key returns a stable identity for deduplication.
// Uses a cached string to avoid fmt.Sprintf on the hot path.
func (p *Proxy) Key() string {
	if p.keyCache == "" {
		p.keyCache = p.URL()
	}
	return p.keyCache
}

// ParseProxyLine parses queue lines into a Proxy.
// Accepted forms: "host:port", "scheme://host:port", "scheme://user:pass@host:port".
func ParseProxyLine(line string) (*Proxy, error) {
	s := strings.TrimSpace(line)
	if s == "" || strings.HasPrefix(s, "#") {
		return nil, fmt.Errorf("empty or comment")
	}

	schema := "http"
	rest := s
	if i := strings.Index(s, "://"); i >= 0 {
		schema = strings.ToLower(s[:i])
		if !validSchema(schema) {
			return nil, fmt.Errorf("unknown scheme %q", schema)
		}
		rest = s[i+3:]
	}

	// Handle VLESS URL parameters (uuid, flow, sni, pbk, sid, spider)
	vlessUUID, vlessFlow, vlessSNI, vlessPbk, vlessSid, vlessSpider := "", "", "", "", "", ""
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
	p := &Proxy{Schema: schema, Host: host, Port: port}
	if schema == "vless" {
		p.SetVLESS(vlessUUID, vlessFlow, vlessSNI, vlessPbk, vlessSid, vlessSpider)
	}
	p.keyCache = p.URL()
	return p, nil
}

// splitHostPort splits host:port, handling [ipv6]:port and bare IPv6 without
// brackets followed by ":port" (which is ambiguous — treat as bracketed form
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
