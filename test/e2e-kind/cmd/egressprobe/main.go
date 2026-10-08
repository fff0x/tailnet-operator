// egressprobe completes the fixture peer's L4 challenge through a TailnetEgress Service, from
// inside the cluster. It is the counterpart to httppeer's probe, which can only dial into the
// tailnet. It is not evidence of policy enforcement, NetworkPolicy or tailnet isolation.
package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"runtime"
	"time"
)

const (
	// Fixed like controlprobe's URL: the egress target name, namespace and port are the test's
	// choice, not a runtime input, so there is no address override to abuse.
	address         = "peer.tailnet-system.svc:8081"
	requestPrefix   = "p1.8-l4-request\n"
	responsePrefix  = "p1.8-l4-response\n"
	nonceBytes      = 32
	resultJSON      = "{\"egressExchange\":true}\n"
	dialTimeout     = 3 * time.Second
	exchangeTimeout = 5 * time.Second
)

// Both errors carry the same text; only the exit code separates a failed exchange from setup,
// argument or output rejection, and neither discloses the underlying error.
var errRejected = errors.New("egressprobe: fixture operation failed")
var errExchange = errors.New("egressprobe: fixture operation failed")

func exitCode(err error) int {
	switch err {
	case nil:
		return 0
	case errExchange:
		return 3
	default:
		return 2
	}
}

type dialFunc func(ctx context.Context, network, address string) (net.Conn, error)

func main() {
	dialer := &net.Dialer{Timeout: dialTimeout, KeepAlive: -1}
	err := run(os.Args[1:], runtime.GOOS, os.Geteuid(), dialer.DialContext, rand.Read, os.Stdout)
	if err != nil {
		fmt.Fprintln(os.Stderr, errRejected)
		os.Exit(exitCode(err))
	}
}

// Dial and entropy are injected so unit tests never touch the host network. Production has no
// environment, address, port or transport override.
func run(args []string, goos string, euid int, dial dialFunc, entropy func([]byte) (int, error), out io.Writer) error {
	if goos != "linux" || euid != 65532 || len(args) != 1 || args[0] != "--fixture=p1.8-egress" {
		return errRejected
	}
	var nonce [nonceBytes]byte
	if n, err := entropy(nonce[:]); err != nil || n != nonceBytes {
		return errRejected
	}
	ctx, cancel := context.WithTimeout(context.Background(), exchangeTimeout)
	defer cancel()
	conn, err := dial(ctx, "tcp", address)
	if conn != nil {
		defer conn.Close()
	}
	if err != nil || conn == nil {
		return errExchange
	}
	stop := context.AfterFunc(ctx, func() { _ = conn.Close() })
	defer stop()
	deadline, _ := ctx.Deadline()
	if conn.SetDeadline(deadline) != nil {
		return errExchange
	}
	request := append([]byte(requestPrefix), nonce[:]...)
	if n, err := conn.Write(request); err != nil || n != len(request) {
		return errExchange
	}
	digest := sha256.Sum256(nonce[:])
	want := append([]byte(responsePrefix), digest[:]...)
	got := make([]byte, len(want))
	if _, err := io.ReadFull(conn, got); err != nil || !bytes.Equal(got, want) {
		return errExchange
	}
	// A fresh nonce makes a reflected or stale reply insufficient; the exact length plus a close
	// makes a valid prefix insufficient. One excess byte is read at most.
	var extra [1]byte
	if n, err := io.ReadFull(conn, extra[:]); n != 0 || err != io.EOF || ctx.Err() != nil {
		return errExchange
	}
	if n, err := io.WriteString(out, resultJSON); err != nil || n != len(resultJSON) {
		return errRejected
	}
	return nil
}
