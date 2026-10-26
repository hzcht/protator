package proxy

import (
	"net"
	"net/url"
	"strings"
)

// Share-link protocols: trojan:// and vless:// URLs, as published on list
// pages and in telegram dumps. Anything this file rejects (other transports,
// reality) would fail a dial anyway, so the rejection lives here.

// parseTrojanURL parses one trojan:// share link into a Candidate.
// Format: trojan://password@host:port?sni=...&type=...&security=...#remarks
//
// Only raw-TCP trojan is accepted (type empty/tcp/raw, security anything but
// reality): ws/grpc/xhttp need a different transport and reality needs the
// uTLS handshake — entries for those would burn a full check for a dial that
// cannot succeed, so they are rejected here, not in the checker.
//
// The password is kept in URL form (still percent-encoded): the handshake
// decodes it once, and raw storage keeps the queue file a lossless round
// trip for passwords containing #/@/?.
func parseTrojanURL(token string) (Candidate, bool) {
	rest := token
	if len(rest) < len("trojan://") || !strings.EqualFold(rest[:9], "trojan://") {
		return Candidate{}, false
	}
	rest = rest[9:]
	if i := strings.IndexByte(rest, '#'); i >= 0 {
		rest = rest[:i] // remarks (emoji, source tags)
	}
	query := ""
	if i := strings.IndexByte(rest, '?'); i >= 0 {
		query, rest = rest[i+1:], rest[:i]
	}
	var typ, security, sni string
	if query != "" {
		q, err := url.ParseQuery(query)
		if err != nil {
			return Candidate{}, false
		}
		typ = strings.ToLower(q.Get("type"))
		security = strings.ToLower(q.Get("security"))
		sni = q.Get("sni")
	}
	switch typ {
	case "", "tcp", "raw":
	default:
		return Candidate{}, false
	}
	if security == "reality" {
		return Candidate{}, false
	}
	// LastIndex: passwords may contain @ (observed in the wild).
	at := strings.LastIndex(rest, "@")
	if at <= 0 {
		return Candidate{}, false // no credentials: can never validate
	}
	pw := rest[:at]
	if len(pw) == 0 || len(pw) > 256 {
		return Candidate{}, false
	}
	host, portStr, err := net.SplitHostPort(rest[at+1:])
	if err != nil {
		return Candidate{}, false
	}
	port, ok := parsePort(portStr)
	if !ok {
		return Candidate{}, false
	}
	if !validShareHost(host) {
		return Candidate{}, false
	}
	return Candidate{
		Schema: "trojan", Host: host, Port: port,
		TrojanPassword: pw, TrojanSNI: sni, TrojanNoTLS: security == "none",
	}, true
}

// parseVLESSURL parses one vless:// share link into a Candidate.
// Format: vless://uuid@host:port?encryption=none&security=tls&sni=...&flow=...&pbk=...&sid=...&type=...#remarks
//
// Same transport rule as trojan (TCP/raw only; ws/grpc/xhttp rejected), plus
// security=none is accepted — dialVLESS runs the handshake on raw TCP then.
// REALITY (security=reality with pbk) rides the existing uTLS path.
func parseVLESSURL(token string) (Candidate, bool) {
	rest := token
	if len(rest) < len("vless://") || !strings.EqualFold(rest[:8], "vless://") {
		return Candidate{}, false
	}
	rest = rest[8:]
	if i := strings.IndexByte(rest, '#'); i >= 0 {
		rest = rest[:i] // remarks
	}
	query := ""
	if i := strings.IndexByte(rest, '?'); i >= 0 {
		query, rest = rest[i+1:], rest[:i]
	}
	var typ, security, flow, sni, pbk, sid, spider string
	if query != "" {
		q, err := url.ParseQuery(query)
		if err != nil {
			return Candidate{}, false
		}
		typ = strings.ToLower(q.Get("type"))
		security = strings.ToLower(q.Get("security"))
		flow = q.Get("flow")
		sni = q.Get("sni")
		pbk = q.Get("pbk")
		sid = q.Get("sid")
		spider = q.Get("spider")
	}
	switch typ {
	case "", "tcp", "raw":
	default:
		return Candidate{}, false
	}
	switch security {
	case "", "tls", "reality", "none":
	default:
		return Candidate{}, false
	}
	// LastIndex: UUIDs do not contain @, but be liberal like the trojan
	// parser — a malformed cut hurts less than a dropped node.
	at := strings.LastIndex(rest, "@")
	if at <= 0 {
		return Candidate{}, false // no UUID: can never validate
	}
	uuid := rest[:at]
	if len(uuid) == 0 || len(uuid) > 128 {
		return Candidate{}, false
	}
	host, portStr, err := net.SplitHostPort(rest[at+1:])
	if err != nil {
		return Candidate{}, false
	}
	port, ok := parsePort(portStr)
	if !ok {
		return Candidate{}, false
	}
	if !validShareHost(host) {
		return Candidate{}, false
	}
	return Candidate{
		Schema: "vless", Host: host, Port: port,
		VLESSUUID: uuid, VLESSFlow: flow, VLESSSNI: sni,
		VLESSPbk: pbk, VLESSSid: sid, VLESSSpider: spider,
		VLESSNoTLS: security == "none",
	}, true
}

// validShareHost accepts IP literals and DNS names for share-link
// extractors (trojan, vless). Single-label names are rejected: they are
// local junk (or a password fragment), never a public server.
func validShareHost(host string) bool {
	if host == "" || len(host) > 253 {
		return false
	}
	if ip := net.ParseIP(host); ip != nil {
		return true
	}
	if !strings.Contains(host, ".") {
		return false
	}
	for _, label := range strings.Split(host, ".") {
		if len(label) == 0 || len(label) > 63 {
			return false
		}
		for i := 0; i < len(label); i++ {
			c := label[i]
			if c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' ||
				c >= '0' && c <= '9' || c == '-' || c == '_' {
				continue
			}
			return false
		}
		if label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
	}
	return true
}
