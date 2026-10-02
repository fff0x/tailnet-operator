package main

import (
	"bufio"
	"context"
	"errors"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httptest"
	"net/http/httptrace"
	"net/http/httputil"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"
)

func timeoutProxy(t *testing.T, backend http.Handler, timeout time.Duration, h2 bool) *httptest.Server {
	t.Helper()
	upstream := httptest.NewServer(backend)
	t.Cleanup(upstream.Close)
	u, _ := url.Parse(upstream.URL)
	proxy := httputil.NewSingleHostReverseProxy(u)
	proxy.ErrorLog = log.New(io.Discard, "", 0)
	proxy.ErrorHandler = func(w http.ResponseWriter, _ *http.Request, _ error) {
		http.Error(w, "backend unavailable", http.StatusBadGateway)
	}
	s := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		serveHTTPWithTimeout(w, r, proxy, timeout)
	}))
	s.Config.ErrorLog = log.New(io.Discard, "", 0)
	s.EnableHTTP2 = h2
	if h2 {
		s.StartTLS()
	} else {
		s.Start()
	}
	t.Cleanup(s.Close)
	return s
}

func TestHTTPWholeResponseTimeoutBeforeHeaders(t *testing.T) {
	s := timeoutProxy(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		<-r.Context().Done()
	}), 40*time.Millisecond, false)
	client := s.Client()
	client.Timeout = 2 * time.Second
	resp, err := client.Get(s.URL)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil || resp.StatusCode != http.StatusGatewayTimeout || string(body) != "backend request timed out\n" {
		t.Fatalf("timeout response: code=%d body=%q err=%v", resp.StatusCode, body, err)
	}
}

func TestHTTPWholeResponseTimeoutAfterHeaders(t *testing.T) {
	s := timeoutProxy(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		io.WriteString(w, "data: ready\n\n")
		w.(http.Flusher).Flush()
		<-r.Context().Done()
	}), 100*time.Millisecond, false)
	resp, err := s.Client().Get(s.URL)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err == nil || resp.StatusCode != http.StatusOK || string(body) != "data: ready\n\n" {
		t.Fatalf("committed response must abort without appended error: code=%d body=%q err=%v", resp.StatusCode, body, err)
	}
}

func TestHTTPWholeResponseTimeoutIncludesUpload(t *testing.T) {
	s := timeoutProxy(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.Copy(io.Discard, r.Body)
	}), 60*time.Millisecond, false)
	// Send an unfinished chunked upload. The timer must interrupt the downstream read too.
	conn, err := net.DialTimeout("tcp", strings.TrimPrefix(s.URL, "http://"), time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(2 * time.Second))
	_, err = io.WriteString(conn, "POST / HTTP/1.1\r\nHost: fixture.test\r\nTransfer-Encoding: chunked\r\n\r\n1\r\nx\r\n")
	if err != nil {
		t.Fatal(err)
	}
	resp, err := http.ReadResponse(bufio.NewReader(conn), &http.Request{Method: "POST"})
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusGatewayTimeout {
		t.Fatalf("slow upload status=%d", resp.StatusCode)
	}
}

func TestHTTPWholeResponseTimeoutDisabled(t *testing.T) {
	entered, release := make(chan struct{}), make(chan struct{})
	s := timeoutProxy(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		close(entered)
		select {
		case <-release:
			io.WriteString(w, "ok")
		case <-r.Context().Done():
		}
	}), 0, false)
	done := make(chan error, 1)
	go func() {
		resp, err := s.Client().Get(s.URL)
		if err == nil {
			defer resp.Body.Close()
			var body []byte
			body, err = io.ReadAll(resp.Body)
			if err == nil && string(body) != "ok" {
				err = errors.New("unexpected body")
			}
		}
		done <- err
	}()
	<-entered
	close(release)
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}

func TestHTTPWholeResponseTimeoutDoesNotLimitUpgradedTunnel(t *testing.T) {
	s := timeoutProxy(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		conn, rw, err := http.NewResponseController(w).Hijack()
		if err != nil {
			return
		}
		defer conn.Close()
		_ = conn.SetDeadline(time.Now().Add(3 * time.Second))
		io.WriteString(rw, "HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: fixture\r\n\r\n")
		_ = rw.Flush()
		line, err := rw.ReadString('\n')
		if err == nil {
			io.WriteString(rw, line)
			_ = rw.Flush()
		}
	}), 50*time.Millisecond, false)
	conn, err := net.DialTimeout("tcp", strings.TrimPrefix(s.URL, "http://"), time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(3 * time.Second))
	io.WriteString(conn, "GET / HTTP/1.1\r\nHost: fixture.test\r\nConnection: Upgrade\r\nUpgrade: fixture\r\n\r\n")
	rw := bufio.NewReader(conn)
	resp, err := http.ReadResponse(rw, &http.Request{Method: "GET"})
	if err != nil || resp.StatusCode != http.StatusSwitchingProtocols {
		t.Fatalf("upgrade: resp=%v err=%v", resp, err)
	}
	// Intentionally outlive the HTTP timer before exercising the established tunnel.
	<-time.After(120 * time.Millisecond)
	io.WriteString(conn, "still connected\n")
	line, err := rw.ReadString('\n')
	if err != nil || line != "still connected\n" {
		t.Fatalf("tunnel closed at HTTP deadline: %q %v", line, err)
	}
}

func TestHTTPWholeResponseTimeoutHTTP2StreamIsolation(t *testing.T) {
	s := timeoutProxy(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/slow" {
			io.WriteString(w, "started")
			w.(http.Flusher).Flush()
			<-r.Context().Done()
			return
		}
		io.WriteString(w, "ok")
	}), 150*time.Millisecond, true)
	client := s.Client()
	client.Timeout = 3 * time.Second
	var shared net.Conn
	get := func(path string) (*http.Response, error) {
		req, _ := http.NewRequest("GET", s.URL+path, nil)
		req = req.WithContext(httptrace.WithClientTrace(req.Context(), &httptrace.ClientTrace{GotConn: func(info httptrace.GotConnInfo) {
			if shared == nil {
				shared = info.Conn
			} else if info.Conn != shared {
				t.Error("HTTP/2 connection was replaced")
			}
		}}))
		return client.Do(req)
	}
	slow, err := get("/slow")
	if err != nil {
		t.Fatal(err)
	}
	defer slow.Body.Close()
	if slow.ProtoMajor != 2 {
		t.Fatal("HTTP/2 not negotiated")
	}
	checkFast := func() {
		resp, err := get("/fast")
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		body, err := io.ReadAll(resp.Body)
		if err != nil || string(body) != "ok" {
			t.Fatalf("unrelated stream: %q %v", body, err)
		}
	}
	checkFast()
	if _, err := io.ReadAll(slow.Body); err == nil {
		t.Fatal("slow stream did not abort")
	}
	checkFast()
}

type blockedTimeoutWriter struct {
	header http.Header
	done   chan struct{}
	once   sync.Once
}

func (w *blockedTimeoutWriter) Header() http.Header { return w.header }
func (w *blockedTimeoutWriter) WriteHeader(int)     {}
func (w *blockedTimeoutWriter) Write([]byte) (int, error) {
	<-w.done
	return 0, context.DeadlineExceeded
}
func (w *blockedTimeoutWriter) SetWriteDeadline(t time.Time) error {
	if !t.IsZero() {
		if delay := time.Until(t); delay > 0 {
			time.AfterFunc(delay, func() { w.once.Do(func() { close(w.done) }) })
		} else {
			w.once.Do(func() { close(w.done) })
		}
	}
	return nil
}
func (*blockedTimeoutWriter) SetReadDeadline(time.Time) error { return nil }

func TestHTTPWholeResponseTimeoutUnblocksDownstreamWrite(t *testing.T) {
	w := &blockedTimeoutWriter{header: make(http.Header), done: make(chan struct{})}
	defer func() {
		if got := recover(); got != http.ErrAbortHandler {
			t.Errorf("committed timeout panic=%v", got)
		}
	}()
	serveHTTPWithTimeout(w, httptest.NewRequest("GET", "/", nil), http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("body"))
	}), 20*time.Millisecond)
}
