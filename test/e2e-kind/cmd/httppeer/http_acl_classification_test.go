package main

import (
	"context"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"syscall"
	"testing"
)

func TestHTTPACLDialErrorCategories(t *testing.T) {
	// This is the real gonet.DialTCPWithBind error shape from our pinned
	// gvisor v0.0.0-20250205023644-9414b50a5633, not a flattened error string.
	gonet := func(message string) error {
		return &net.OpError{Op: "connect", Net: "tcp", Addr: &net.TCPAddr{IP: net.IPv4(100, 64, 0, 1), Port: 443}, Err: errors.New(message)}
	}
	for _, tc := range []struct {
		name string
		err  error
		want string
	}{
		{"success", nil, ""},
		{"context deadline", context.DeadlineExceeded, "timeout"},
		{"context canceled", context.Canceled, "canceled"},
		{"syscall timeout", syscall.ETIMEDOUT, "timeout"},
		{"syscall no route", syscall.EHOSTUNREACH, "noRoute"},
		{"syscall unreachable", syscall.ENETUNREACH, "unreachable"},
		{"syscall refused", syscall.ECONNREFUSED, "refused"},
		{"syscall reset", syscall.ECONNRESET, "reset"},
		{"syscall network reset", syscall.ENETRESET, "reset"},
		{"gonet no route", gonet("no route to host"), "noRoute"},
		{"gonet network unreachable", gonet("network is unreachable"), "unreachable"},
		{"host unreachable", gonet("host is unreachable"), "unreachable"},
		{"gonet timeout", gonet("operation timed out"), "timeout"},
		{"gonet refused", gonet("connection was refused"), "refused"},
		{"gonet reset", gonet("connection reset by peer"), "reset"},
		{"gonet aborted", gonet("operation aborted"), "other"},
		{"gonet unknown", gonet("private future failure"), "other"},
		{"no string prefix", gonet("no route to host: private"), "other"},
		{"no string suffix", gonet("private: no route to host"), "other"},
		{"no substring", gonet("private network is unreachable private"), "other"},
		{"no case folding", gonet("No route to host"), "other"},
		{"no trimming", gonet("no route to host\n"), "other"},
		{"no flattened wrapper", errors.New("connect tcp 100.64.0.1:443: no route to host"), "other"},
		{"no bare string", errors.New("no route to host"), "other"},
		{"wrong operation", &net.OpError{Op: "read", Net: "tcp", Err: errors.New("no route to host")}, "other"},
		{"wrong network", &net.OpError{Op: "connect", Net: "udp", Err: errors.New("no route to host")}, "other"},
		{"wrong operation with errno", &net.OpError{Op: "read", Net: "tcp", Err: syscall.EHOSTUNREACH}, "other"},
		{"wrong network with errno", &net.OpError{Op: "dial", Net: "udp", Err: syscall.ENETUNREACH}, "other"},
		{"TLS handshake deadline", &net.OpError{Op: "remote error", Net: "tcp", Err: context.DeadlineExceeded}, "other"},
		{"empty inner error", &net.OpError{Op: "connect", Net: "tcp"}, "other"},
		{"DNS timeout", &net.DNSError{Err: "private", IsTimeout: true}, "other"},
		{"DNS no route", &net.DNSError{Err: "no route to host"}, "other"},
		{"DNS unwrap no route", &net.DNSError{Err: "private", UnwrapErr: syscall.EHOSTUNREACH}, "other"},
		{"TLS unknown root", x509.UnknownAuthorityError{}, "other"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := classifyHTTPACLDialError(tc.err); got != tc.want {
				t.Fatalf("category=%q want %q", got, tc.want)
			}
			if tc.err != nil {
				if got := classifyHTTPACLDialError(fmt.Errorf("private wrapper: %w", tc.err)); got != tc.want {
					t.Fatalf("wrapped category=%q want %q", got, tc.want)
				}
			}
		})
	}
}

func TestHTTPACLDialErrorDoesNotInheritContextTimeout(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	got := probeHTTPACL(ctx, probeInput{Target: "100.64.0.1"}, nil, func(context.Context, string, string) (net.Conn, error) {
		cancel() // The returned dial error, not the ambient context, is evidence.
		return nil, syscall.ECONNREFUSED
	})
	if got.Connected || got.DialTimedOut || got.DialError != "refused" {
		t.Fatal("context cancellation hid a refused dial")
	}
}
