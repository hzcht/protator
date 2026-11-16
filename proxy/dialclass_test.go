package proxy

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"syscall"
	"testing"
)

func TestClassifyDialErr(t *testing.T) {
	cases := []struct {
		name string
		err  error
		want dialFailClass
	}{
		{"nil", nil, dialFailOther},
		{"plain", errors.New("boom"), dialFailOther},
		{"dns timeout", &net.DNSError{Err: "i/o timeout", Name: "example.com", IsTimeout: true}, dialFailTimeout},
		{"context deadline", context.DeadlineExceeded, dialFailTimeout},
		{"socks sentinel", errSocksDialTimeout, dialFailTimeout},
		{"refused", &net.OpError{Op: "dial", Net: "tcp", Err: os.NewSyscallError("connect", syscall.ECONNREFUSED)}, dialFailRefused},
		{"wrapped reset", fmt.Errorf("handshake: %w", syscall.ECONNRESET), dialFailReset},
		{"eof", io.EOF, dialFailReset},
		{"tls record header", tls.RecordHeaderError{Msg: "first record does not look like a TLS handshake"}, dialFailTLS},
		{"unknown ca", x509.UnknownAuthorityError{}, dialFailTLS},
		{"hostname", x509.HostnameError{Host: "example.com"}, dialFailTLS},
	}
	for _, tc := range cases {
		if got := classifyDialErr(tc.err); got != tc.want {
			t.Errorf("%s: classifyDialErr(%v) = %d, want %d", tc.name, tc.err, got, tc.want)
		}
	}
}

// The class counters must always add up to dial_failures_total, otherwise the
// funnel disagrees with its own denominator in an incident.
func TestCountDialFailureKeepsClassesAdditive(t *testing.T) {
	baseFail := Stats.DialFailures.Load()
	baseClasses := []int64{
		Stats.DialTimeout.Load(), Stats.DialRefused.Load(),
		Stats.DialTLS.Load(), Stats.DialReset.Load(), Stats.DialOther.Load(),
	}

	errs := []error{
		&net.DNSError{Err: "timeout", IsTimeout: true},
		&net.OpError{Op: "dial", Net: "tcp", Err: os.NewSyscallError("connect", syscall.ECONNREFUSED)},
		syscall.ECONNRESET,
		tls.RecordHeaderError{Msg: "not tls"},
		errors.New("boom"),
	}
	for _, err := range errs {
		countDialFailure(err)
	}

	if got, want := Stats.DialFailures.Load()-baseFail, int64(len(errs)); got != want {
		t.Fatalf("dial_failures_total delta = %d, want %d", got, want)
	}
	classes := []int64{
		Stats.DialTimeout.Load(), Stats.DialRefused.Load(),
		Stats.DialTLS.Load(), Stats.DialReset.Load(), Stats.DialOther.Load(),
	}
	var sum int64
	for i, c := range classes {
		sum += c - baseClasses[i]
	}
	if sum != int64(len(errs)) {
		t.Fatalf("class deltas sum to %d, want %d (one per failure)", sum, len(errs))
	}
}
