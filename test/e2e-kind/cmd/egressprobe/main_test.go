package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"io"
	"net"
	"testing"
)

// serve answers one connection the way the fixture peer's L4 backend does. reply rewrites the
// response so a test can corrupt exactly one property of an otherwise correct exchange.
func serve(t *testing.T, reply func(nonce []byte) []byte, keepOpen bool) dialFunc {
	t.Helper()
	return func(ctx context.Context, network, address string) (net.Conn, error) {
		if network != "tcp" || address != "peer.tailnet-system.svc:8081" {
			t.Fatalf("dialled %s/%s", network, address)
		}
		client, server := net.Pipe()
		go func() {
			if !keepOpen {
				defer server.Close()
			}
			var request [len(requestPrefix) + nonceBytes]byte
			if _, err := io.ReadFull(server, request[:]); err != nil {
				return
			}
			if !bytes.HasPrefix(request[:], []byte(requestPrefix)) {
				return
			}
			_, _ = server.Write(reply(request[len(requestPrefix):]))
		}()
		return client, nil
	}
}

func correct(nonce []byte) []byte {
	digest := sha256.Sum256(nonce)
	return append([]byte(responsePrefix), digest[:]...)
}

func entropy(b []byte) (int, error) {
	for i := range b {
		b[i] = byte(i)
	}
	return len(b), nil
}

func TestCompletesExchange(t *testing.T) {
	var out bytes.Buffer
	if err := run([]string{"--fixture=p1.8-egress"}, "linux", 65532, serve(t, correct, false), entropy, &out); err != nil {
		t.Fatal("rejected a correct exchange")
	}
	if out.String() != resultJSON {
		t.Fatalf("wrote %q", out.String())
	}
}

func TestRejectsEnvironmentAndArguments(t *testing.T) {
	dial := serve(t, correct, false)
	for _, c := range []struct {
		args []string
		goos string
		euid int
	}{
		{nil, "linux", 65532},
		{[]string{}, "linux", 65532},
		{[]string{""}, "linux", 65532},
		{[]string{"--fixture=p1.8-http"}, "linux", 65532},
		{[]string{"--fixture=p1.8-egress", "--fixture=p1.8-egress"}, "linux", 65532},
		{[]string{"--fixture=p1.8-egress "}, "linux", 65532},
		{[]string{"--fixture=p1.8-egress"}, "darwin", 65532},
		{[]string{"--fixture=p1.8-egress"}, "linux", 0},
		{[]string{"--fixture=p1.8-egress"}, "linux", 65534},
	} {
		var out bytes.Buffer
		err := run(c.args, c.goos, c.euid, dial, entropy, &out)
		if err != errRejected || out.Len() != 0 {
			t.Fatalf("accepted %v/%s/%d", c.args, c.goos, c.euid)
		}
		if exitCode(err) != 2 {
			t.Fatal("setup rejection must not look like a failed exchange")
		}
	}
}

func TestRejectsWrongOrIncompleteReply(t *testing.T) {
	short := func(nonce []byte) []byte { return correct(nonce)[:len(responsePrefix)] }
	wrongDigest := func(nonce []byte) []byte {
		out := correct(nonce)
		out[len(out)-1] ^= 0xff
		return out
	}
	wrongPrefix := func(nonce []byte) []byte {
		digest := sha256.Sum256(nonce)
		return append([]byte(requestPrefix), digest[:]...)
	}
	// A reflected nonce is the replay a fresh challenge must defeat.
	reflected := func(nonce []byte) []byte { return append([]byte(responsePrefix), nonce...) }
	trailing := func(nonce []byte) []byte { return append(correct(nonce), 'x') }
	for name, reply := range map[string]func([]byte) []byte{
		"short": short, "wrongDigest": wrongDigest, "wrongPrefix": wrongPrefix,
		"reflected": reflected, "trailing": trailing,
	} {
		var out bytes.Buffer
		err := run([]string{"--fixture=p1.8-egress"}, "linux", 65532, serve(t, reply, false), entropy, &out)
		if err != errExchange || out.Len() != 0 {
			t.Fatalf("accepted the %s reply", name)
		}
		if exitCode(err) != 3 {
			t.Fatalf("%s reply did not report a failed exchange", name)
		}
	}
	// A server that answers correctly but never closes is not a complete exchange either.
	var out bytes.Buffer
	if err := run([]string{"--fixture=p1.8-egress"}, "linux", 65532, serve(t, correct, true), entropy, &out); err != errExchange {
		t.Fatal("accepted an unterminated exchange")
	}
}

func TestRejectsDialAndEntropyFailure(t *testing.T) {
	refused := func(context.Context, string, string) (net.Conn, error) { return nil, errors.New("refused") }
	var out bytes.Buffer
	if err := run([]string{"--fixture=p1.8-egress"}, "linux", 65532, refused, entropy, &out); err != errExchange || out.Len() != 0 {
		t.Fatal("a refused dial is a failed exchange")
	}
	// A nil connection without an error must not be treated as usable.
	nilConn := func(context.Context, string, string) (net.Conn, error) { return nil, nil }
	if err := run([]string{"--fixture=p1.8-egress"}, "linux", 65532, nilConn, entropy, &out); err != errExchange {
		t.Fatal("accepted a nil connection")
	}
	broken := func(b []byte) (int, error) { return 0, errors.New("no entropy") }
	if err := run([]string{"--fixture=p1.8-egress"}, "linux", 65532, serve(t, correct, false), broken, &out); err != errRejected {
		t.Fatal("probed without a fresh nonce")
	}
	partial := func(b []byte) (int, error) { return len(b) - 1, nil }
	if err := run([]string{"--fixture=p1.8-egress"}, "linux", 65532, serve(t, correct, false), partial, &out); err != errRejected {
		t.Fatal("probed with a partially filled nonce")
	}
}

func TestRejectsUnwritableOutput(t *testing.T) {
	err := run([]string{"--fixture=p1.8-egress"}, "linux", 65532, serve(t, correct, false), entropy, shortWriter{})
	if err != errRejected {
		t.Fatal("reported success without writing the result")
	}
}

type shortWriter struct{}

func (shortWriter) Write(b []byte) (int, error) { return len(b) - 1, nil }
