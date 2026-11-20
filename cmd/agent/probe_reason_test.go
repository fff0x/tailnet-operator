package main

import (
	"context"
	"errors"
	"net"
	"testing"
)

// An L4 dial that fails with a DNS resolution error is classified NameUnresolved; any other dial
// failure leaves the reason empty (a plain Unreachable). This is how the operator tells an
// unresolved tailnet-zone target apart from a missing grant.
func TestProbeClassifiesNameResolution(t *testing.T) {
	cases := []struct {
		name string
		err  error
		want string
	}{
		{"dns error", &net.DNSError{Err: "no such host", Name: "x.example.internal", IsNotFound: true}, "NameUnresolved"},
		{"dial refused", errors.New("dial tcp 10.0.0.1:443: connect: connection refused"), ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			probe := probeTarget{
				t:    target{Name: "api", Address: "x.example.internal", Port: 443},
				dial: func(context.Context, target) (net.Conn, error) { return nil, tc.err },
			}
			r := probeOne(context.Background(), probe)
			if r.Reachable {
				t.Fatal("dial failed but Reachable is true")
			}
			if r.Reason != tc.want {
				t.Fatalf("Reason = %q, want %q", r.Reason, tc.want)
			}
		})
	}
}
