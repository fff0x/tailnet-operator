//go:build linux

package netproof

import (
	"context"
	"errors"
	"net"
	"time"

	"golang.org/x/sys/unix"
)

// CheckExternal is deliberately separate from Capture. It uses only fixed
// documentation IP literals, never DNS or a proxy. Call only inside the owned
// isolated fixture. No EAFNOSUPPORT exception is currently supported: proving
// IPv6 disabled independently is outside this model.
func CheckExternal(ctx context.Context) Dials {
	ctx, cancel := context.WithTimeout(ctx, 2500*time.Millisecond)
	defer cancel()
	return Dials{IPv4: externalDial(ctx, "tcp4", "192.0.2.1:9"), IPv6: externalDial(ctx, "tcp6", "[2001:db8::1]:9")}
}
func externalDial(ctx context.Context, network, address string) DialCategory {
	d := net.Dialer{Timeout: time.Second}
	c, err := d.DialContext(ctx, network, address)
	if c != nil {
		c.Close()
	}
	if ctx.Err() != nil {
		return OtherFailure
	}
	return dialCategory(err)
}
func dialCategory(err error) DialCategory {
	if err == nil {
		return Connected
	}
	var ne net.Error
	if errors.Is(err, context.DeadlineExceeded) || errors.As(err, &ne) && ne.Timeout() {
		return TimedOut
	}
	switch {
	case errors.Is(err, unix.ENETUNREACH):
		return NetworkUnreachable
	case errors.Is(err, unix.EAFNOSUPPORT):
		return AddressFamilyUnsupported
	case errors.Is(err, unix.ECONNREFUSED):
		return Refused
	default:
		return OtherFailure
	}
}
