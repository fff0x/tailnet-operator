package main

import (
	"context"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
	"net/url"
	"sync"
	"testing"
	"time"
)

// net.Pipe gives deterministic backpressure: even a small buffered HTTP response cannot be
// flushed until the client reads. A TCP socket's generous send buffer would mask these cases.
type timeoutPipeListener struct {
	conn   net.Conn
	mu     sync.Mutex
	taken  bool
	closed chan struct{}
	once   sync.Once
}

func (l *timeoutPipeListener) Accept() (net.Conn, error) {
	l.mu.Lock()
	if !l.taken {
		l.taken = true
		l.mu.Unlock()
		return l.conn, nil
	}
	l.mu.Unlock()
	<-l.closed
	return nil, net.ErrClosed
}
func (l *timeoutPipeListener) Close() error   { l.once.Do(func() { close(l.closed) }); return nil }
func (l *timeoutPipeListener) Addr() net.Addr { return l.conn.LocalAddr() }

func timeoutPipeServer(t *testing.T, h http.Handler) (net.Conn, <-chan struct{}, <-chan struct{}) {
	t.Helper()
	return timeoutPipeRequest(t, h, "GET / HTTP/1.1\r\nHost: fixture.test\r\n\r\n")
}

func timeoutPipeRequest(t *testing.T, h http.Handler, request string) (net.Conn, <-chan struct{}, <-chan struct{}) {
	t.Helper()
	server, client := net.Pipe()
	ln := &timeoutPipeListener{conn: server, closed: make(chan struct{})}
	served, closed, stopped := make(chan struct{}), make(chan struct{}), make(chan struct{})
	s := &http.Server{
		ErrorLog: log.New(io.Discard, "", 0),
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			defer close(served)
			h.ServeHTTP(w, r)
		}),
		ConnState: func(_ net.Conn, state http.ConnState) {
			if state == http.StateClosed {
				close(closed)
			}
		},
	}
	go func() { defer close(stopped); _ = s.Serve(ln) }()
	t.Cleanup(func() { client.Close(); s.Close(); <-stopped })
	if _, err := io.WriteString(client, request); err != nil {
		t.Fatal(err)
	}
	return client, served, closed
}

func TestHTTPWholeResponseTimeoutBackpressure(t *testing.T) {
	for _, tc := range []struct {
		name    string
		backend http.HandlerFunc
	}{
		{"informational headers", func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Link", "</style.css>; rel=preload")
			w.WriteHeader(http.StatusEarlyHints)
			io.WriteString(w, "ok")
		}},
		{"final buffered response", func(w http.ResponseWriter, _ *http.Request) {
			io.WriteString(w, "small buffered response")
		}},
		{"generated timeout response", func(_ http.ResponseWriter, r *http.Request) {
			<-r.Context().Done()
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			upstream := httptest.NewServer(tc.backend)
			defer upstream.Close()
			u, _ := url.Parse(upstream.URL)
			proxy := httputil.NewSingleHostReverseProxy(u)
			proxy.ErrorLog = log.New(io.Discard, "", 0)
			client, served, closed := timeoutPipeServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				serveHTTPWithTimeout(w, r, proxy, 40*time.Millisecond)
			}))
			defer client.Close()
			// Includes the bounded one-second delivery budget for a generated 504.
			ctx, cancel := context.WithTimeout(t.Context(), 2*time.Second)
			defer cancel()
			for _, done := range []<-chan struct{}{served, closed} {
				select {
				case <-done:
				case <-ctx.Done():
					t.Fatal("non-reading client retained handler or final flush beyond its deadline")
				}
			}
		})
	}
}
