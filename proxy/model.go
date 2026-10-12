package proxy

import (
	"fmt"
	"net"
	"strconv"
	"strings"
	"sync/atomic"
	"time"
)

// ProxyMeta holds cold fields (admin/debug only) вЂ” not accessed on the hot serving path.
// Keeping these separate reduces Proxy size from ~200B to ~120B, reducing GC pressure.
//
// Every field is an atomic pointer because Proxy cannot carry a mutex: it is
// written by a checker goroutine (SetGeoIP / SetVLESS) and read by the admin
// page, the dialer and revalidation from any other. Plain fields there are a
// data race that -race would flag immediately and that can also hand a reader
// a torn UTF-8 string.
type ProxyMeta struct {
	country atomic.Pointer[string] // ISO 3166-1 alpha-2
	asn     atomic.Pointer[string] // "AS12345 Provider Name"

	vlessUUID   atomic.Pointer[string]
	vlessFlow   atomic.Pointer[string]
	vlessSNI    atomic.Pointer[string]
	vlessPbk    atomic.Pointer[string] // REALITY public key
	vlessSid    atomic.Pointer[string] // REALITY short ID
	vlessSpider atomic.Pointer[string] // spider header (for vision)
	vlessNoTLS  atomic.Pointer[bool]   // security=none: plaintext, no TLS

	trojanPassword atomic.Pointer[string] // as it appears in the URL (still
	// percent-encoded): the handshake decodes it once, and storing the raw
	// form keeps URL()/ParseProxyLine a lossless round trip even when the
	// password contains URL-significant bytes like # or @.
	trojanSNI   atomic.Pointer[string]
	trojanNoTLS atomic.Pointer[bool] // security=none: plaintext, no TLS
}

func (p *ProxyMeta) Country() string {
	if s := p.country.Load(); s != nil {
		return *s
	}
	return ""
}

func (p *ProxyMeta) ASN() string {
	if s := p.asn.Load(); s != nil {
		return *s
	}
	return ""
}

func (p *ProxyMeta) VLESSUUID() string {
	if s := p.vlessUUID.Load(); s != nil {
		return *s
	}
	return ""
}

func (p *ProxyMeta) VLESSFlow() string {
	if s := p.vlessFlow.Load(); s != nil {
		return *s
	}
	return ""
}

func (p *ProxyMeta) VLESSSNI() string {
	if s := p.vlessSNI.Load(); s != nil {
		return *s
	}
	return ""
}

func (p *ProxyMeta) VLESSPbk() string {
	if s := p.vlessPbk.Load(); s != nil {
		return *s
	}
	return ""
}

func (p *ProxyMeta) VLESSSid() string {
	if s := p.vlessSid.Load(); s != nil {
		return *s
	}
	return ""
}

func (p *ProxyMeta) VLESSSpider() string {
	if s := p.vlessSpider.Load(); s != nil {
		return *s
	}
	return ""
}

func (p *ProxyMeta) VLESSNoTLS() bool {
	if b := p.vlessNoTLS.Load(); b != nil {
		return *b
	}
	return false
}

func (p *ProxyMeta) TrojanPassword() string {
	if s := p.trojanPassword.Load(); s != nil {
		return *s
	}
	return ""
}

func (p *ProxyMeta) TrojanSNI() string {
	if s := p.trojanSNI.Load(); s != nil {
		return *s
	}
	return ""
}

func (p *ProxyMeta) TrojanNoTLS() bool {
	if b := p.trojanNoTLS.Load(); b != nil {
		return *b
	}
	return false
}

func (p *ProxyMeta) set(country, asn string) {
	// Publish empty values too, so a reader never sees the pre-set state of a
	// field that was explicitly cleared.
	p.country.Store(ptrTo(country))
	p.asn.Store(ptrTo(asn))
}

func (p *ProxyMeta) setVLESS(uuid, flow, sni, pbk, sid, spider string, noTLS bool) {
	// A fresh local slot per field: readers concurrently Load the same
	// pointer, and an atomic.Pointer cannot be copied, so the value has to be
	// published through one that outlives this call.
	p.vlessUUID.Store(ptrTo(uuid))
	p.vlessFlow.Store(ptrTo(flow))
	p.vlessSNI.Store(ptrTo(sni))
	p.vlessPbk.Store(ptrTo(pbk))
	p.vlessSid.Store(ptrTo(sid))
	p.vlessSpider.Store(ptrTo(spider))
	p.vlessNoTLS.Store(ptrToBool(noTLS))
}

func (p *ProxyMeta) setTrojan(password, sni string, noTLS bool) {
	p.trojanPassword.Store(ptrTo(password))
	p.trojanSNI.Store(ptrTo(sni))
	p.trojanNoTLS.Store(ptrToBool(noTLS))
}

func ptrTo(s string) *string { return &s }

func ptrToBool(b bool) *bool { return &b }

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

// GetCountry returns the ISO 3166-1 alpha-2 country code.
func (p *Proxy) GetCountry() string {
	if p.meta == nil {
		return ""
	}
	return p.meta.Country()
}

// GetASN returns the ASN string (e.g., "AS12345 Provider Name").
func (p *Proxy) GetASN() string {
	if p.meta == nil {
		return ""
	}
	return p.meta.ASN()
}

// SetGeoIP sets the country and ASN for the proxy (called by checker after validation).
func (p *Proxy) SetGeoIP(country, asn string) {
	p.ensureMeta()
	p.meta.set(country, asn)
}

// GetVLESSUUID returns the VLESS UUID, or "".
func (p *Proxy) GetVLESSUUID() string {
	if p.meta == nil {
		return ""
	}
	return p.meta.VLESSUUID()
}

// GetVLESSFlow returns the VLESS flow, or "".
func (p *Proxy) GetVLESSFlow() string {
	if p.meta == nil {
		return ""
	}
	return p.meta.VLESSFlow()
}

// GetVLESSSNI returns the VLESS SNI, or "".
func (p *Proxy) GetVLESSSNI() string {
	if p.meta == nil {
		return ""
	}
	return p.meta.VLESSSNI()
}

// GetVLESSPbk returns the REALITY public key, or "".
func (p *Proxy) GetVLESSPbk() string {
	if p.meta == nil {
		return ""
	}
	return p.meta.VLESSPbk()
}

// GetVLESSSid returns the REALITY short ID, or "".
func (p *Proxy) GetVLESSSid() string {
	if p.meta == nil {
		return ""
	}
	return p.meta.VLESSSid()
}

// GetVLESSSpider returns the spider header, or "".
func (p *Proxy) GetVLESSSpider() string {
	if p.meta == nil {
		return ""
	}
	return p.meta.VLESSSpider()
}

// SetVLESS sets VLESS-specific fields (called by checker after validation).
func (p *Proxy) SetVLESS(uuid, flow, sni, pbk, sid, spider string, noTLS bool) {
	p.ensureMeta()
	p.meta.setVLESS(uuid, flow, sni, pbk, sid, spider, noTLS)
}

// GetVLESSNoTLS reports security=none (plaintext VLESS, no TLS layer).
func (p *Proxy) GetVLESSNoTLS() bool {
	if p.meta == nil {
		return false
	}
	return p.meta.VLESSNoTLS()
}

// GetTrojanPassword returns the trojan password in URL form, or "".
func (p *Proxy) GetTrojanPassword() string {
	if p.meta == nil {
		return ""
	}
	return p.meta.TrojanPassword()
}

// GetTrojanSNI returns the trojan SNI override, or "" (dial falls back to host).
func (p *Proxy) GetTrojanSNI() string {
	if p.meta == nil {
		return ""
	}
	return p.meta.TrojanSNI()
}

// GetTrojanNoTLS reports security=none (plaintext trojan, no TLS layer).
func (p *Proxy) GetTrojanNoTLS() bool {
	if p.meta == nil {
		return false
	}
	return p.meta.TrojanNoTLS()
}

// SetTrojan sets trojan-specific fields (called by checker after validation).
func (p *Proxy) SetTrojan(password, sni string, noTLS bool) {
	p.ensureMeta()
	p.meta.setTrojan(password, sni, noTLS)
}

// ensureMeta is a fallback for Proxy values built outside the known
// construction sites (checker literals, ParseProxyLine вЂ” both allocate meta
// eagerly now). SetGeoIP/SetVLESS still call it, but on the normal path it is
// a nil check that never writes: the pointer is published before the bucket
// ever sees the Proxy, so concurrent readers never race the field.
func (p *Proxy) ensureMeta() {
	if p.meta == nil {
		p.meta = &ProxyMeta{}
	}
}

// IsVLESS reports whether the proxy uses the VLESS protocol.
func (p *Proxy) IsVLESS() bool { return p.Schema == "vless" }

// IsTrojan reports whether the proxy uses the Trojan protocol.
func (p *Proxy) IsTrojan() bool { return p.Schema == "trojan" }

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
	if p.GetVLESSNoTLS() {
		params = append(params, "security=none")
	}
	if len(params) > 0 {
		return "?" + strings.Join(params, "&")
	}
	return ""
}

// buildTrojanQuery renders the persisted trojan parameters: only the SNI
// override (empty = dial falls back to host) and the plaintext marker.
// The password rides in userinfo, not here; transport type is always TCP
// (ws/grpc entries are rejected at extraction, so there is nothing to keep).
func buildTrojanQuery(p *Proxy) string {
	var params []string
	if p.GetTrojanSNI() != "" {
		params = append(params, "sni="+p.GetTrojanSNI())
	}
	if p.GetTrojanNoTLS() {
		params = append(params, "security=none")
	}
	if len(params) > 0 {
		return "?" + strings.Join(params, "&")
	}
	return ""
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
