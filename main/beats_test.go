package main

import "testing"

// loopbackAddr decides whether warnAdminExposure shouts. A bare IPv6 literal
// used to be hand-stripped at the last colon ("::1" → ":"), ParseIP failed, and
// a loopback-only admin listener got the exposure warning as a false positive.
func TestLoopbackAddr(t *testing.T) {
	cases := []struct {
		addr string
		want bool
	}{
		{"127.0.0.1", true},
		{"127.0.0.1:9090", true},
		{"::1", true},
		{"[::1]:9090", true},
		{"[::1]", true},
		{"localhost", true},
		{"localhost:9090", true},
		{"LOCALHOST:9090", true},
		{"0.0.0.0:9090", false},
		{"192.168.1.5:9090", false},
		{"example.com:9090", false},
		{"::", false},
		{"", false},
	}
	for _, c := range cases {
		if got := loopbackAddr(c.addr); got != c.want {
			t.Errorf("loopbackAddr(%q) = %v, want %v", c.addr, got, c.want)
		}
	}
}
