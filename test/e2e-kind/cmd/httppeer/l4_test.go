package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestStrictL4ProbeInput(t *testing.T) {
	for _, body := range []string{
		`{"target":"100.64.0.1"}`, ` {"target":"http-agent.fixture.test"} `,
		`{"tar\u0067et":"100.127.255.255"}`,
	} {
		if _, err := decodeL4Probe(strings.NewReader(body)); err != nil {
			t.Fatalf("rejected %q", body)
		}
	}
	for _, body := range []string{
		``, `null`, `[]`, `{}`, `{"target":`, `{"target":"100.64.0.1"`,
		`{"target":null}`, `{"target":false}`, `{"target":8443}`, `{"target":{}}`, `{"target":[]}`,
		`{"Target":"100.64.0.1"}`, `{"target":"100.64.0.1","target":"100.64.0.2"}`,
		`{"target":"100.64.0.1","tar\u0067et":"100.64.0.1"}`,
		`{"target":"100.64.0.1","http2":false}`, `{"target":"100.64.0.1","port":8443}`,
		`{"target":"100.64.0.1","path":"/"}`, `{"address":"100.64.0.1","target":"100.64.0.1"}`,
		`{"target":"100.64.0.1",}`, `{"target":"100.64.0.1"} {}`, `{"target":"100.64.0.1"} null`,
		`{"target":"100.64.0.1"} trailing`, strings.Repeat(" ", maxProbeBytes+1),
	} {
		if _, err := decodeL4Probe(strings.NewReader(body)); err != errRejected {
			t.Fatalf("accepted %q", body)
		}
	}
	body := `{"target":"100.64.0.1"}`
	if _, err := decodeL4Probe(strings.NewReader(body + strings.Repeat(" ", maxProbeBytes-len(body)))); err != nil {
		t.Fatal("rejected exact bound")
	}
	if _, err := decodeL4Probe(strings.NewReader(body + strings.Repeat(" ", maxProbeBytes-len(body)+1))); err != errRejected {
		t.Fatal("accepted oversized valid JSON")
	}
	r := new(countingReader)
	_, _ = decodeL4Probe(r)
	if r.n != maxProbeBytes+1 {
		t.Fatal("unbounded JSON read")
	}
	if _, err := decodeL4Probe(probeBodyReader(func([]byte) (int, error) { return 0, errors.New("private") })); err != errRejected {
		t.Fatal("reader error accepted")
	}
}

func TestL4TargetsRejectedBeforeDial(t *testing.T) {
	for _, target := range []string{
		"", "100.63.255.255", "100.128.0.0", "127.0.0.1", "192.168.1.1", "::ffff:100.64.0.1",
		"100.064.0.1", "100.64.0.1:8443", "100.64.0.1%zone", "https://" + publicDNS,
		publicDNS + ":8443", publicDNS + ".", "HTTP-AGENT.fixture.test", " " + publicDNS,
		"elsewhere.fixture.test", "100.64.0.1/path",
	} {
		body, _ := json.Marshal(map[string]string{"target": target})
		if _, err := decodeL4Probe(bytes.NewReader(body)); err != errRejected {
			t.Fatalf("decoded %q", target)
		}
		// Nil dial panics if validation ever permits an override.
		if got := probeL4(context.Background(), l4ProbeInput{Target: target}, nil); got != (l4ProbeResult{}) {
			t.Fatalf("invalid target result: %+v", got)
		}
	}
}

func waitL4(t *testing.T, done <-chan struct{}) {
	t.Helper()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("fixture did not stop")
	}
}

// These fake peers are in-memory only; the production dial remains peer.Dial.
func pipeL4Dial(t *testing.T, target string, serve func(net.Conn)) (dialFunc, <-chan struct{}) {
	t.Helper()
	done := make(chan struct{})
	return func(ctx context.Context, network, address string) (net.Conn, error) {
		if network != "tcp" || address != net.JoinHostPort(target, "8443") {
			t.Error("dial destination override")
		}
		if deadline, ok := ctx.Deadline(); !ok || time.Until(deadline) > probeTimeout {
			t.Error("missing dial deadline")
		}
		client, server := net.Pipe()
		go func() {
			defer close(done)
			defer server.Close()
			_ = server.SetDeadline(time.Now().Add(time.Second))
			serve(server)
		}()
		return client, nil
	}, done
}

func readL4Challenge(t *testing.T, conn net.Conn) []byte {
	t.Helper()
	request := make([]byte, len(l4RequestPrefix)+32)
	if _, err := io.ReadFull(conn, request); err != nil {
		t.Error(err)
		return nil
	}
	if !bytes.HasPrefix(request, []byte(l4RequestPrefix)) {
		t.Error("wrong request framing")
	}
	return request[len(l4RequestPrefix):]
}

func TestL4ReplyValidation(t *testing.T) {
	var lastNonce []byte
	for _, mode := range []string{"valid", "valid-again", "empty", "truncated", "wrong-prefix", "wrong-digest", "reflection", "excess", "stale"} {
		t.Run(mode, func(t *testing.T) {
			dial, done := pipeL4Dial(t, publicDNS, func(conn net.Conn) {
				nonce := readL4Challenge(t, conn)
				if len(nonce) != 32 || bytes.Equal(nonce, lastNonce) {
					t.Error("challenge not fresh")
				}
				digest := sha256.Sum256(nonce)
				response := append([]byte(l4ResponsePrefix), digest[:]...)
				switch mode {
				case "empty":
					response = nil
				case "truncated":
					response = response[:len(response)-1]
				case "wrong-prefix":
					response[0] ^= 1
				case "wrong-digest":
					response[len(response)-1] ^= 1
				case "reflection":
					response = append([]byte(l4RequestPrefix), nonce...)
				case "excess":
					response = append(response, 'x')
				case "stale":
					old := sha256.Sum256(lastNonce)
					response = append([]byte(l4ResponsePrefix), old[:]...)
				}
				lastNonce = bytes.Clone(nonce)
				_, _ = conn.Write(response)
			})
			got := probeL4(context.Background(), l4ProbeInput{Target: publicDNS}, dial)
			waitL4(t, done)
			wantOK := mode == "valid" || mode == "valid-again"
			if got != (l4ProbeResult{OK: wantOK, Connected: true}) {
				t.Fatalf("result: %+v", got)
			}
		})
	}
}

func TestL4DialFailureClassification(t *testing.T) {
	for _, tc := range []struct {
		name     string
		err      error
		timedOut bool
	}{
		{"refused", errors.New("private 100.64.0.9"), false},
		{"deadline", context.DeadlineExceeded, true},
		{"network-timeout", &net.DNSError{Err: "private", IsTimeout: true}, true},
		{"canceled", context.Canceled, false},
		{"nil-connection", nil, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := probeL4(context.Background(), l4ProbeInput{Target: "100.64.0.9"}, func(ctx context.Context, network, addr string) (net.Conn, error) {
				if network != "tcp" || addr != "100.64.0.9:8443" {
					t.Fatal("wrong target")
				}
				if deadline, ok := ctx.Deadline(); !ok || time.Until(deadline) > 5*time.Second {
					t.Fatal("unbounded dial")
				}
				return nil, tc.err
			})
			if got != (l4ProbeResult{TimedOut: tc.timedOut}) {
				t.Fatalf("result: %+v", got)
			}
		})
	}
}

func TestL4ContextCancellationAndTimeout(t *testing.T) {
	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	expired, expire := context.WithDeadline(context.Background(), time.Now().Add(-time.Second))
	defer expire()
	for _, ctx := range []context.Context{canceled, expired} {
		got := probeL4(ctx, l4ProbeInput{Target: publicDNS}, nil)
		if got != (l4ProbeResult{TimedOut: ctx == expired}) {
			t.Fatalf("pre-dial cancellation: %+v", got)
		}
	}
	for _, mode := range []string{"dial", "write", "read", "partial", "no-close", "cancel-read"} {
		t.Run(mode, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
			defer cancel()
			if mode == "dial" {
				got := probeL4(ctx, l4ProbeInput{Target: publicDNS}, func(ctx context.Context, _, _ string) (net.Conn, error) {
					<-ctx.Done()
					return nil, ctx.Err()
				})
				if got != (l4ProbeResult{TimedOut: true}) {
					t.Fatalf("dial timeout: %+v", got)
				}
				return
			}
			dial, done := pipeL4Dial(t, publicDNS, func(conn net.Conn) {
				if mode == "write" {
					<-ctx.Done()
					return
				}
				nonce := readL4Challenge(t, conn)
				if mode == "cancel-read" {
					cancel()
				} else if mode == "no-close" || mode == "partial" {
					digest := sha256.Sum256(nonce)
					reply := append([]byte(l4ResponsePrefix), digest[:]...)
					if mode == "partial" {
						reply = reply[:len(reply)-1]
					}
					_, _ = conn.Write(reply)
				}
				// Wait for the client to close, rather than creating a race
				// between server EOF and the client's deadline/cancellation.
				_, _ = conn.Read(make([]byte, 1))
			})
			got := probeL4(ctx, l4ProbeInput{Target: publicDNS}, dial)
			waitL4(t, done)
			if got != (l4ProbeResult{Connected: true, TimedOut: mode != "cancel-read"}) {
				t.Fatalf("result: %+v", got)
			}
		})
	}
}

type l4ObservedConn struct {
	net.Conn
	setDeadline func(time.Time) error
	closed      atomic.Bool
}

func (c *l4ObservedConn) SetDeadline(deadline time.Time) error { return c.setDeadline(deadline) }
func (c *l4ObservedConn) Close() error {
	c.closed.Store(true)
	return c.Conn.Close()
}

func TestL4ConnectionDeadlineAndCleanup(t *testing.T) {
	for _, fail := range []bool{false, true} {
		client, server := net.Pipe()
		observed := &l4ObservedConn{Conn: client}
		observed.setDeadline = func(deadline time.Time) error {
			if remaining := time.Until(deadline); remaining <= 0 || remaining > probeTimeout {
				t.Error("connection deadline not bounded")
			}
			if fail {
				return errors.New("private set deadline failure")
			}
			// Exercise a real blocked Write timeout without a five-second test.
			return client.SetDeadline(time.Now().Add(20 * time.Millisecond))
		}
		got := probeL4(context.Background(), l4ProbeInput{Target: publicDNS}, func(context.Context, string, string) (net.Conn, error) {
			return observed, nil
		})
		_ = server.Close()
		if got != (l4ProbeResult{Connected: true, TimedOut: !fail}) || !observed.closed.Load() {
			t.Fatalf("deadline/cleanup: %+v", got)
		}
	}
}

func TestL4DialErrorClosesPartialConnection(t *testing.T) {
	client, server := net.Pipe()
	defer server.Close()
	observed := &l4ObservedConn{Conn: client}
	got := probeL4(context.Background(), l4ProbeInput{Target: publicDNS}, func(context.Context, string, string) (net.Conn, error) {
		return observed, errors.New("private dial failure")
	})
	if got != (l4ProbeResult{}) || !observed.closed.Load() {
		t.Fatal("failed dial leaked connection/result")
	}
}

func TestL4ControlRoutesAndBoundedResult(t *testing.T) {
	calls := 0
	h := controlHandler(nil, func(ctx context.Context, input l4ProbeInput) l4ProbeResult {
		calls++
		return probeL4(ctx, input, func(context.Context, string, string) (net.Conn, error) {
			return nil, errors.New(strings.Repeat("private 100.64.0.1 nonce", 1000))
		})
	}, nil, nil)
	for _, tc := range []struct {
		method, path, body string
		status             int
	}{
		{"GET", "/probe-l4", "", 405}, {"PUT", "/probe-l4", "", 405},
		{"POST", "/probe-l4?target=100.64.0.1", "", 404}, {"POST", "/probe-l4/", "", 404},
		{"POST", "/probe-l4", `null`, 400}, {"POST", "/probe-l4", `{"target":"127.0.0.1"}`, 400},
		{"POST", "/probe-l4", `{"target":"100.64.0.1"}`, 200},
	} {
		w := httptest.NewRecorder()
		h.ServeHTTP(w, httptest.NewRequest(tc.method, tc.path, strings.NewReader(tc.body)))
		if w.Code != tc.status || w.Body.Len() > 64 || strings.Contains(w.Body.String(), "private") || strings.Contains(w.Body.String(), "100.64") {
			t.Fatalf("route result: %d %s", w.Code, w.Body.String())
		}
		if tc.status == 200 && (w.Body.String() != "{\"ok\":false,\"connected\":false,\"timedOut\":false}\n" || w.Header().Get("Content-Type") != "application/json" || w.Header().Get("Cache-Control") != "no-store") {
			t.Fatal("unexpected result shape/headers")
		}
	}
	if calls != 1 {
		t.Fatal("invalid control input reached probe")
	}
}

func TestAllProbesShareControlConcurrencyLimit(t *testing.T) {
	entered, release := make(chan struct{}, 4), make(chan struct{})
	defer close(release)
	block := func() { entered <- struct{}{}; <-release }
	h := controlHandler(func(context.Context, probeInput) probeResult {
		block()
		return probeResult{}
	}, func(context.Context, l4ProbeInput) l4ProbeResult {
		block()
		return l4ProbeResult{}
	}, func(context.Context, l4ProbeInput) webSocketProbeResult {
		block()
		return webSocketProbeResult{}
	}, func(context.Context, probeInput) httpACLProbeResult {
		block()
		return httpACLProbeResult{}
	})
	paths := []string{"/probe", "/probe-l4", "/probe-websocket", "/probe-http-acl"}
	for _, path := range paths {
		body := `{"target":"100.64.0.1"}`
		if path == "/probe" || path == "/probe-http-acl" {
			body = `{"target":"100.64.0.1","http2":false}`
		}
		done := make(chan struct{})
		go func() {
			defer close(done)
			h.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest("POST", path, strings.NewReader(body)))
		}()
		t.Cleanup(func() { waitL4(t, done) })
		select {
		case <-entered:
		case <-time.After(time.Second):
			t.Fatal("control did not start")
		}
	}
	for _, path := range paths {
		body := `{"target":"100.64.0.1"}`
		if path == "/probe" || path == "/probe-http-acl" {
			body = `{"target":"100.64.0.1","http2":false}`
		}
		w := httptest.NewRecorder()
		h.ServeHTTP(w, httptest.NewRequest("POST", path, strings.NewReader(body)))
		if w.Code != http.StatusServiceUnavailable || w.Body.String() != "busy\n" {
			t.Fatal("control concurrency limit bypassed")
		}
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, httptest.NewRequest("GET", "/readyz", nil))
	if w.Code != http.StatusNoContent {
		t.Fatal("readiness blocked by probes")
	}
}

// This listener exists only in tests and binds ephemeral loopback, never an
// external interface or a tsnet peer. SetDeadline observes admitted workers.
type l4ObservedListener struct {
	net.Listener
	started chan struct{}
}

func (l *l4ObservedListener) Accept() (net.Conn, error) {
	conn, err := l.Listener.Accept()
	if err != nil {
		return nil, err
	}
	return &l4ObservedConn{Conn: conn, setDeadline: func(deadline time.Time) error {
		l.started <- struct{}{}
		return conn.SetDeadline(deadline)
	}}, nil
}

func loopbackL4Backend(t *testing.T) (*l4ObservedListener, context.CancelFunc, <-chan struct{}) {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	observed := &l4ObservedListener{Listener: listener, started: make(chan struct{}, 32)}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		if err := serveL4Backend(ctx, observed); err != nil {
			t.Error(err)
		}
	}()
	t.Cleanup(func() { cancel(); waitL4(t, done) })
	return observed, cancel, done
}

func TestL4LoopbackBackend(t *testing.T) {
	if l4BackendAddr != ":8081" || l4ProbePort != "8443" || l4BackendSlots != 4 || l4NonceBytes != 32 || l4RequestPrefix == l4ResponsePrefix {
		t.Fatal("fixed protocol changed")
	}
	listener, _, _ := loopbackL4Backend(t)
	got := probeL4(context.Background(), l4ProbeInput{Target: "100.64.0.9"}, func(ctx context.Context, network, address string) (net.Conn, error) {
		if network != "tcp" || address != "100.64.0.9:8443" {
			t.Fatal("probe target changed")
		}
		return (&net.Dialer{}).DialContext(ctx, "tcp", listener.Addr().String())
	})
	if got != (l4ProbeResult{OK: true, Connected: true}) {
		t.Fatalf("round trip: %+v", got)
	}
	for _, frame := range [][]byte{nil, []byte(l4RequestPrefix), make([]byte, len(l4RequestPrefix)+32)} {
		conn, err := net.DialTimeout("tcp", listener.Addr().String(), time.Second)
		if err != nil {
			t.Fatal(err)
		}
		_ = conn.SetDeadline(time.Now().Add(time.Second))
		_, _ = conn.Write(frame)
		_ = conn.(*net.TCPConn).CloseWrite()
		var reply [1]byte
		n, err := conn.Read(reply[:])
		_ = conn.Close()
		if n != 0 || err != io.EOF {
			t.Fatal("backend accepted malformed/truncated request")
		}
	}
}

func TestL4BackendConcurrencyAndShutdown(t *testing.T) {
	listener, cancel, done := loopbackL4Backend(t)
	var conns []net.Conn
	defer func() {
		for _, conn := range conns {
			_ = conn.Close()
		}
	}()
	for range 4 {
		conn, err := net.DialTimeout("tcp", listener.Addr().String(), time.Second)
		if err != nil {
			t.Fatal(err)
		}
		conns = append(conns, conn)
		select {
		case <-listener.started:
		case <-time.After(time.Second):
			t.Fatal("backend worker not admitted")
		}
	}
	excess, err := net.DialTimeout("tcp", listener.Addr().String(), time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer excess.Close()
	_ = excess.SetDeadline(time.Now().Add(time.Second))
	var b [1]byte
	if n, err := excess.Read(b[:]); n != 0 || err != io.EOF {
		t.Fatal("fifth backend connection not rejected")
	}
	select {
	case <-listener.started:
		t.Fatal("fifth backend worker started")
	default:
	}
	cancel()
	waitL4(t, done)
	for _, conn := range conns {
		_ = conn.SetReadDeadline(time.Now().Add(time.Second))
		if n, err := conn.Read(b[:]); n != 0 || err != io.EOF {
			t.Fatal("backend connection survived shutdown")
		}
	}
	if conn, err := net.DialTimeout("tcp", listener.Addr().String(), time.Second); err == nil {
		_ = conn.Close()
		t.Fatal("backend listener survived shutdown")
	}
}

type l4FailingListener struct {
	conn    net.Conn
	started <-chan struct{}
	closed  atomic.Bool
}

func (l *l4FailingListener) Accept() (net.Conn, error) {
	if l.conn != nil {
		conn := l.conn
		l.conn = nil
		return conn, nil
	}
	<-l.started
	return nil, errors.New("private accept failure")
}
func (l *l4FailingListener) Close() error   { l.closed.Store(true); return nil }
func (l *l4FailingListener) Addr() net.Addr { return nil }

func TestL4BackendAcceptFailureClosesWorkers(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()
	started := make(chan struct{})
	observed := &l4ObservedConn{Conn: server, setDeadline: func(deadline time.Time) error {
		close(started)
		return server.SetDeadline(deadline)
	}}
	listener := &l4FailingListener{conn: observed, started: started}
	done := make(chan struct{})
	go func() {
		defer close(done)
		if err := serveL4Backend(context.Background(), listener); err != errRejected {
			t.Error("accept error not sanitized")
		}
	}()
	waitL4(t, done)
	if !observed.closed.Load() || !listener.closed.Load() {
		t.Fatal("accept failure leaked connection/listener")
	}
}

func TestL4BackendDeadlineAndCancellation(t *testing.T) {
	for _, mode := range []string{"read-timeout", "write-timeout", "canceled", "deadline-error"} {
		t.Run(mode, func(t *testing.T) {
			client, server := net.Pipe()
			defer client.Close()
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			set := make(chan struct{})
			observed := &l4ObservedConn{Conn: server, setDeadline: func(deadline time.Time) error {
				close(set)
				if remaining := time.Until(deadline); remaining <= 0 || remaining > probeTimeout {
					t.Error("backend deadline not bounded")
				}
				if mode == "deadline-error" {
					return errors.New("private")
				}
				return server.SetDeadline(time.Now().Add(50 * time.Millisecond))
			}}
			done := make(chan struct{})
			go func() { defer close(done); serveL4Conn(ctx, observed) }()
			waitL4(t, set)
			if mode == "canceled" {
				cancel()
			}
			if mode == "write-timeout" {
				_ = client.SetDeadline(time.Now().Add(time.Second))
				_, _ = client.Write(append([]byte(l4RequestPrefix), make([]byte, 32)...))
			}
			waitL4(t, done)
			if !observed.closed.Load() {
				t.Fatal("backend failed to close connection")
			}
		})
	}
}
