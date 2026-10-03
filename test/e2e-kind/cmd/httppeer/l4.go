package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"io"
	"net"
	"sync"
	"time"
)

const (
	l4BackendAddr    = ":8081"
	l4ProbePort      = "8443"
	l4RequestPrefix  = "p1.8-l4-request\n"
	l4ResponsePrefix = "p1.8-l4-response\n"
	l4NonceBytes     = 32
	l4BackendSlots   = 4
)

type l4ProbeInput struct {
	Target string
}

type l4ProbeResult struct {
	OK        bool `json:"ok"`
	Connected bool `json:"connected"`
	TimedOut  bool `json:"timedOut"`
}

// Exactly one string field; duplicate (including escaped) keys, nested values,
// trailing documents and endpoint overrides are not part of this control API.
func decodeL4Probe(reader io.Reader) (l4ProbeInput, error) {
	var input l4ProbeInput
	data, err := io.ReadAll(io.LimitReader(reader, maxProbeBytes+1))
	if err != nil || len(data) > maxProbeBytes {
		return input, errRejected
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	if token, err := dec.Token(); err != nil || token != json.Delim('{') {
		return input, errRejected
	}
	if token, err := dec.Token(); err != nil || token != "target" {
		return input, errRejected
	}
	token, err := dec.Token()
	target, ok := token.(string)
	if err != nil || !ok || !allowedTarget(target) {
		return input, errRejected
	}
	if token, err := dec.Token(); err != nil || token != json.Delim('}') {
		return input, errRejected
	}
	if _, err := dec.Token(); err != io.EOF {
		return input, errRejected
	}
	input.Target = target
	return input, nil
}

func l4TimedOut(ctx context.Context, err error) bool {
	if ctx.Err() != nil {
		return errors.Is(ctx.Err(), context.DeadlineExceeded)
	}
	var networkError net.Error
	return errors.Is(err, context.DeadlineExceeded) || (errors.As(err, &networkError) && networkError.Timeout())
}

// The only runtime dial is peer.Dial, always TCP/8443. A fresh challenge makes a
// mere accepted connection, reflected payload or stale reply insufficient.
func probeL4(ctx context.Context, input l4ProbeInput, dial dialFunc) l4ProbeResult {
	var result l4ProbeResult
	if !allowedTarget(input.Target) {
		return result
	}
	ctx, cancel := context.WithTimeout(ctx, probeTimeout)
	defer cancel()
	if ctx.Err() != nil {
		result.TimedOut = l4TimedOut(ctx, ctx.Err())
		return result
	}
	var nonce [l4NonceBytes]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return result
	}
	conn, err := dial(ctx, "tcp", net.JoinHostPort(input.Target, l4ProbePort))
	if conn != nil {
		defer conn.Close()
	}
	if err != nil || conn == nil {
		result.TimedOut = l4TimedOut(ctx, err)
		return result
	}
	result.Connected = true
	stop := context.AfterFunc(ctx, func() { _ = conn.Close() })
	defer stop()
	deadline, _ := ctx.Deadline()
	if err := conn.SetDeadline(deadline); err != nil {
		result.TimedOut = l4TimedOut(ctx, err)
		return result
	}
	request := append([]byte(l4RequestPrefix), nonce[:]...)
	if err := writeL4Frame(conn, request); err != nil {
		result.TimedOut = l4TimedOut(ctx, err)
		return result
	}
	digest := sha256.Sum256(nonce[:])
	want := append([]byte(l4ResponsePrefix), digest[:]...)
	got := make([]byte, len(want))
	if _, err := io.ReadFull(conn, got); err != nil {
		result.TimedOut = l4TimedOut(ctx, err)
		return result
	}
	if !bytes.Equal(got, want) {
		result.TimedOut = l4TimedOut(ctx, nil)
		return result
	}
	// Require a closed, exact reply, not just a valid prefix. Read at most one
	// excess byte; a server that never closes is bounded by the same deadline.
	var extra [1]byte
	n, err := io.ReadFull(conn, extra[:])
	result.TimedOut = l4TimedOut(ctx, err)
	result.OK = n == 0 && err == io.EOF && ctx.Err() == nil
	return result
}

func writeL4Frame(conn net.Conn, frame []byte) error {
	n, err := conn.Write(frame)
	if err == nil && n != len(frame) {
		return io.ErrShortWrite
	}
	return err
}

// One fixed-size request and reply per connection; no unbounded reads, payload
// echo, logging or address output. Closing the connection terminates the frame.
func serveL4Conn(ctx context.Context, conn net.Conn) {
	defer conn.Close()
	stop := context.AfterFunc(ctx, func() { _ = conn.Close() })
	defer stop()
	if ctx.Err() != nil || conn.SetDeadline(time.Now().Add(probeTimeout)) != nil {
		return
	}
	var request [len(l4RequestPrefix) + l4NonceBytes]byte
	if _, err := io.ReadFull(conn, request[:]); err != nil || !bytes.HasPrefix(request[:], []byte(l4RequestPrefix)) {
		return
	}
	digest := sha256.Sum256(request[len(l4RequestPrefix):])
	_ = writeL4Frame(conn, append([]byte(l4ResponsePrefix), digest[:]...))
}

// The caller supplies only the fixed :8081 Pod listener in production. Owning
// the listener here permits loopback-only tests without any runtime overrides.
// Cancellation or an accept failure closes every connection before returning.
func serveL4Backend(ctx context.Context, listener net.Listener) error {
	ctx, cancel := context.WithCancel(ctx)
	var workers sync.WaitGroup
	stop := context.AfterFunc(ctx, func() { _ = listener.Close() })
	defer func() {
		cancel()
		stop()
		_ = listener.Close()
		workers.Wait()
	}()
	slots := make(chan struct{}, l4BackendSlots)
	for {
		conn, err := listener.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			return errRejected
		}
		select {
		case slots <- struct{}{}:
			workers.Add(1)
			go func() {
				defer workers.Done()
				defer func() { <-slots }()
				serveL4Conn(ctx, conn)
			}()
		default:
			_ = conn.Close()
		}
	}
}
