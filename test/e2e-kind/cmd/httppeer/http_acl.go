package main

import (
	"context"
	"crypto/x509"
	"errors"
	"net"
	"sync/atomic"
	"syscall"
)

// A HTTP/TLS error is not ACL evidence. Observe the actual TCP dial separately;
// a connection followed by a TLS timeout or bad certificate is never a denial.
// The Kind negative assertions use IPv4, not DNS, to exclude lookup failures.
type httpACLProbeResult struct {
	probeResult
	Connected    bool   `json:"connected"`
	DialTimedOut bool   `json:"dialTimedOut"`
	DialError    string `json:"dialError"` // Empty on a successful or unattempted dial.
}

// Only fixed categories escape the fixture. In particular, a context that
// happens to expire after a refused/reset dial must not turn it into a timeout.
func classifyHTTPACLDialError(err error) string {
	if err == nil {
		return ""
	}
	var dns *net.DNSError
	if errors.As(err, &dns) {
		return "other" // Even DNS timeouts/unreachable resolvers are not TCP denial.
	}
	if errors.Is(err, context.Canceled) {
		return "canceled"
	}
	var op *net.OpError
	if errors.As(err, &op) && ((op.Op != "dial" && op.Op != "connect") || (op.Net != "tcp" && op.Net != "tcp4" && op.Net != "tcp6")) {
		return "other" // No UDP, read/write or TLS-handshake error can prove a TCP dial denial.
	}
	switch {
	case errors.Is(err, syscall.ECONNREFUSED):
		return "refused"
	case errors.Is(err, syscall.ECONNRESET), errors.Is(err, syscall.ENETRESET):
		return "reset"
	case errors.Is(err, syscall.EHOSTUNREACH):
		return "noRoute"
	case errors.Is(err, syscall.ENETUNREACH):
		return "unreachable"
	case errors.Is(err, context.DeadlineExceeded), errors.Is(err, syscall.ETIMEDOUT):
		return "timeout"
	}
	if op != nil && op.Op == "connect" && op.Net == "tcp" && op.Err != nil {
		// Pinned gonet.DialTCPWithBind wraps tcpip.Error.String() in errors.New,
		// losing its type. Match the exact inner connect error, never substrings
		// or the outer message (which includes an address). Unknowns fail closed.
		switch op.Err.Error() {
		case "no route to host":
			return "noRoute"
		case "host is unreachable", "network is unreachable":
			return "unreachable"
		case "connection was refused":
			return "refused"
		case "connection reset by peer":
			return "reset"
		case "operation timed out":
			return "timeout"
		}
	}
	var networkError net.Error
	if errors.As(err, &networkError) && networkError.Timeout() {
		return "timeout"
	}
	return "other"
}

func probeHTTPACL(ctx context.Context, input probeInput, roots *x509.CertPool, dial dialFunc) httpACLProbeResult {
	var result httpACLProbeResult
	_, _, validNames := input.names()
	if !allowedTarget(input.Target) || !validNames {
		return result
	}
	ctx, cancel := context.WithTimeout(ctx, probeTimeout)
	defer cancel()
	if ctx.Err() != nil {
		result.DialError = "canceled"
		return result // No attempted dial means no denial observation.
	}
	conn, err := dial(ctx, "tcp", net.JoinHostPort(input.Target, "443"))
	if conn != nil {
		result.Connected = true
		defer conn.Close()
	}
	if err != nil || conn == nil {
		result.DialError = classifyHTTPACLDialError(err)
		if err == nil {
			result.DialError = "other" // A nil connection is not a successful dial.
		}
		result.DialTimedOut = result.DialError == "timeout"
		return result
	}
	// Hand the one observed connection to the verified HTTP transport. No second
	// dial, retry, TLS bypass or idle connection reuse can change the evidence.
	var consumed atomic.Bool
	client, tr := probeClient(roots, func(context.Context, string, string) (net.Conn, error) {
		if consumed.Swap(true) {
			return nil, errRejected
		}
		return conn, nil
	}, input)
	defer tr.CloseIdleConnections()
	result.probeResult = probe(ctx, input, client.Do)
	return result
}
