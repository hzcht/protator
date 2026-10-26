package proxy

import (
	"strings"
	"sync/atomic"
)

// Protocol metadata and its accessors: GeoIP plus the VLESS/trojan share-link
// parameters, kept out of Proxy so the hot struct stays ~120B (the meta itself
// is a pointer, allocated only when a proxy actually carries that data).
//
// The query builders live here too because they render exactly these fields
// back into a URL; AppendURL/URL/Key in model.go call them.

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
