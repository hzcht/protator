package proxy

import "encoding/base64"

// The base64 pass: a whole-body blob is a real publishing format for proxy
// lists, so Extract() decodes it before giving up — and looksLikeProxyText
// keeps that decode off ordinary pages, where it would be pure CPU.

// maxBase64Body bounds what will be decoded. A 200 MB page is not a base64
// blob worth the CPU, and a mirror that publishes that much encoded text is not
// a mirror.
const maxBase64Body = 8 << 20

// tryBase64Text decodes body when the whole thing is one base64 blob. It
// returns "" for anything else: the payload has to be *entirely* base64
// alphabet plus whitespace, because a single stray byte means decoding a page
// whose real content is the plain text on the first pass anyway.
//
// Padding is optional. Many mirrors emit unpadded base64 (long URLs, streaming
// writers), and rejecting those loses the source entirely.
func tryBase64Text(body []byte) string {
	if len(body) < 64 || len(body) > maxBase64Body {
		return ""
	}
	// Sample first: the walk below rejects at the first non-alphabet byte, so
	// a body that is base64 for megabytes and junk at the end costs a full
	// scan to learn what four probes already show. Whitespace is skipped at
	// the sample points for the same reason the walk skips it.
	for _, i := range []int{0, len(body) / 4, len(body) / 2, 3 * len(body) / 4} {
		c := body[i]
		if c == '\r' || c == '\n' || c == '\t' || c == ' ' || isBase64Byte(c) {
			continue
		}
		return ""
	}
	var buf []byte
	for _, c := range body {
		switch {
		case c == '\r', c == '\n', c == '\t', c == ' ':
			// Whitespace between lines is normal in a wrapped blob.
		case isBase64Byte(c):
			buf = append(buf, c)
		default:
			return "" // real page content: the plain-text pass owns this
		}
	}
	dec, err := base64.RawStdEncoding.DecodeString(string(buf))
	if err != nil {
		if dec, err = base64.StdEncoding.DecodeString(string(buf)); err != nil {
			return ""
		}
	}
	if !looksLikeProxyText(dec) {
		return ""
	}
	return string(dec)
}

func isBase64Byte(c byte) bool {
	switch {
	case c >= 'A' && c <= 'Z', c >= 'a' && c <= 'z', c >= '0' && c <= '9':
		return true
	case c == '+', c == '/', c == '=':
		return true
	}
	return false
}

// looksLikeProxyText is the false-positive guard for the base64 pass. A body
// made of base64 alphabet characters decodes to noise almost every time, and
// extracting from noise is pure CPU. What a proxy list looks like: repeated
// port numbers after addresses, one per line.
func looksLikeProxyText(b []byte) bool {
	digits, colons, newlines := 0, 0, 0
	for _, c := range b {
		if c == 0 {
			return false // binary payload, not a list
		}
		switch c {
		case '\n':
			newlines++
		case ':':
			colons++
		}
		if c >= '0' && c <= '9' {
			digits++
		}
	}
	return newlines >= 2 && digits >= 8 || colons >= 16 && digits >= 16
}

// portBefore returns the last valid port number in the text preceding a match
// group (used by single-group patterns like "port-8080 ... 1.2.3.4").
