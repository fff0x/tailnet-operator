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
	"net/http"
	"sync"
	"time"
)

const (
	l4BackendAddr    = ":8081"
	l4ProbePort      = "8443"
	l4RequestPrefix  = "p1.8-l4-request\n"
	l4ResponsePrefix = "p1.8-l4-response\n"
	// A request with this prefix keeps the connection: the backend answers every further request
	// on it. Same length as l4RequestPrefix, so both share one frame size.
	l4HoldPrefix   = "p1.8-l4-holding\n"
	l4NonceBytes   = 32
	l4BackendSlots = 4
)

// l4HoldLifetime bounds a held backend connection as probeTimeout bounds a single exchange. A held
// connection occupies one of the l4BackendSlots for that long.
var l4HoldLifetime = 12 * time.Minute

type l4ProbeInput struct {
	Target string
}

type l4ProbeResult struct {
	OK        bool   `json:"ok"`
	Connected bool   `json:"connected"`
	TimedOut  bool   `json:"timedOut"`
	DialError string `json:"dialError"` // Same categories as the HTTP ACL probe; empty after a dial.
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
		result.DialError = "canceled" // No attempted dial means no denial observation.
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
		result.DialError = classifyHTTPACLDialError(err)
		if err == nil {
			result.DialError = "other" // A nil connection is not a successful dial.
		}
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
// A hold request keeps the connection for further fixed-size hold requests until
// l4HoldLifetime; the first request decides and a connection never changes kind.
func serveL4Conn(ctx context.Context, conn net.Conn) {
	defer conn.Close()
	stop := context.AfterFunc(ctx, func() { _ = conn.Close() })
	defer stop()
	if ctx.Err() != nil || conn.SetDeadline(time.Now().Add(probeTimeout)) != nil {
		return
	}
	var request [len(l4RequestPrefix) + l4NonceBytes]byte
	if _, err := io.ReadFull(conn, request[:]); err != nil {
		return
	}
	hold := bytes.HasPrefix(request[:], []byte(l4HoldPrefix))
	if !hold && !bytes.HasPrefix(request[:], []byte(l4RequestPrefix)) {
		return
	}
	if hold && conn.SetDeadline(time.Now().Add(l4HoldLifetime)) != nil {
		return
	}
	for {
		digest := sha256.Sum256(request[len(l4RequestPrefix):])
		if writeL4Frame(conn, append([]byte(l4ResponsePrefix), digest[:]...)) != nil || !hold {
			return
		}
		if _, err := io.ReadFull(conn, request[:]); err != nil || !bytes.HasPrefix(request[:], []byte(l4HoldPrefix)) {
			return
		}
	}
}

// l4Hold keeps at most one connection to the fixed probe port open across control requests, so a
// test can observe what happens to an established connection when the policy changes under it.
type l4Hold struct {
	mu   sync.Mutex
	conn net.Conn
}

type l4HoldResult struct {
	OK       bool `json:"ok"`
	Held     bool `json:"held"` // A connection was held when the exchange started.
	TimedOut bool `json:"timedOut"`
}

// open replaces the held connection: one dial, as probeL4, and a first exchange inside the same
// probeTimeout. The connection is kept only when that exchange succeeds.
func (h *l4Hold) open(ctx context.Context, input l4ProbeInput, dial dialFunc) l4ProbeResult {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.drop()
	var result l4ProbeResult
	if !allowedTarget(input.Target) {
		return result
	}
	ctx, cancel := context.WithTimeout(ctx, probeTimeout)
	defer cancel()
	conn, err := dial(ctx, "tcp", net.JoinHostPort(input.Target, l4ProbePort))
	if err != nil || conn == nil {
		if conn != nil {
			_ = conn.Close()
		}
		result.TimedOut = l4TimedOut(ctx, err)
		result.DialError = classifyHTTPACLDialError(err)
		if err == nil {
			result.DialError = "other"
		}
		return result
	}
	result.Connected = true
	h.conn = conn
	deadline, _ := ctx.Deadline()
	first := h.exchangeLocked(deadline)
	result.OK, result.TimedOut = first.OK, first.TimedOut
	return result
}

// exchange runs one fresh challenge on the held connection. Any failure closes it: after a partial
// frame the stream cannot be trusted again, and the test reads the first failure as the cut.
func (h *l4Hold) exchange() l4HoldResult {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.exchangeLocked(time.Now().Add(probeTimeout))
}

func (h *l4Hold) exchangeLocked(deadline time.Time) l4HoldResult {
	var result l4HoldResult
	if h.conn == nil {
		return result
	}
	result.Held = true
	var nonce [l4NonceBytes]byte
	_, err := rand.Read(nonce[:])
	if err == nil {
		err = h.conn.SetDeadline(deadline)
	}
	if err == nil {
		err = writeL4Frame(h.conn, append([]byte(l4HoldPrefix), nonce[:]...))
	}
	digest := sha256.Sum256(nonce[:])
	want := append([]byte(l4ResponsePrefix), digest[:]...)
	got := make([]byte, len(want))
	if err == nil {
		_, err = io.ReadFull(h.conn, got)
	}
	if err == nil && bytes.Equal(got, want) && h.conn.SetDeadline(time.Time{}) == nil {
		result.OK = true
		return result
	}
	var networkError net.Error
	result.TimedOut = errors.As(err, &networkError) && networkError.Timeout()
	h.drop()
	return result
}

func (h *l4Hold) drop() {
	if h.conn != nil {
		_ = h.conn.Close()
		h.conn = nil
	}
}

func (h *l4Hold) close() {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.drop()
}

// holdHandler serves the two held-connection routes in front of the control handler. Both take the
// strict probe-l4 body; the exchange ignores its target, the held connection has one already.
func holdHandler(next http.Handler, open func(context.Context, l4ProbeInput) l4ProbeResult, exchange func() l4HoldResult) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		uri := r.URL.RequestURI()
		if uri != "/hold-l4" && uri != "/hold-l4-exchange" {
			next.ServeHTTP(w, r)
			return
		}
		if r.Method != http.MethodPost {
			http.Error(w, "rejected", http.StatusMethodNotAllowed)
			return
		}
		input, err := decodeL4Probe(r.Body)
		if err != nil {
			http.Error(w, "rejected", http.StatusBadRequest)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "no-store")
		if uri == "/hold-l4" {
			_ = json.NewEncoder(w).Encode(open(r.Context(), input))
			return
		}
		_ = json.NewEncoder(w).Encode(exchange())
	})
}

// serveL4Listeners runs the same bounded exchange on every listener and returns a function that
// waits for all of them. The peer needs two: the Pod-network one the ingress path reaches through
// a Service, and a tsnet one, because an egress agent dials this peer over the tailnet and tsnet
// delivers inbound TCP only to listeners registered on its own stack.
func serveL4Listeners(ctx context.Context, errs chan<- error, listeners ...net.Listener) func() {
	var done sync.WaitGroup
	for _, listener := range listeners {
		done.Add(1)
		go func() {
			defer done.Done()
			errs <- serveL4Backend(ctx, listener)
		}()
	}
	return done.Wait
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
