package main

import (
	"bufio"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestHTTPACLDialClassification(t *testing.T) {
	for _, tc := range []struct {
		name     string
		err      error
		timeout  bool
		category string
	}{
		{"timeout", context.DeadlineExceeded, true, "timeout"},
		{"unknown", errors.New("private 100.64.0.1"), false, "other"},
		{"canceled", context.Canceled, false, "canceled"},
		{"nil connection", nil, false, "other"},
		{"gonet no route", &net.OpError{Op: "connect", Net: "tcp", Err: errors.New("no route to host")}, false, "noRoute"},
		{"gonet unreachable", &net.OpError{Op: "connect", Net: "tcp", Err: errors.New("network is unreachable")}, false, "unreachable"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			calls := 0
			got := probeHTTPACL(t.Context(), probeInput{Target: "100.64.0.1"}, nil, func(ctx context.Context, network, addr string) (net.Conn, error) {
				calls++
				if network != "tcp" || addr != "100.64.0.1:443" {
					t.Fatal("wrong dial target")
				}
				deadline, ok := ctx.Deadline()
				if !ok || time.Until(deadline) > probeTimeout {
					t.Fatal("unbounded dial")
				}
				return nil, tc.err
			})
			if calls != 1 || got.Connected || got.DialTimedOut != tc.timeout || got.DialError != tc.category || got.probeResult != (probeResult{}) {
				t.Fatalf("unexpected classification: %+v", got)
			}
			data, _ := json.Marshal(got)
			if len(data) > 512 || strings.Contains(string(data), "private") || strings.Contains(string(data), "100.64") {
				t.Fatal("unsanitized result")
			}
		})
	}
	c, s := net.Pipe()
	defer s.Close()
	observed := &l4ObservedConn{Conn: c}
	got := probeHTTPACL(t.Context(), probeInput{Target: "100.64.0.1"}, nil, func(context.Context, string, string) (net.Conn, error) {
		return observed, context.DeadlineExceeded
	})
	if !got.Connected || !got.DialTimedOut || got.DialError != "timeout" || !observed.closed.Load() {
		t.Fatal("connection with dial error leaked or counted as denial")
	}
	for _, input := range []probeInput{{Target: "127.0.0.1"}, {Target: publicDNS, SNI: "unknown", Host: publicDNS}} {
		if got := probeHTTPACL(t.Context(), input, nil, nil); got != (httpACLProbeResult{}) {
			t.Fatal("invalid input reached dial")
		}
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if got := probeHTTPACL(ctx, probeInput{Target: publicDNS}, nil, nil); got != (httpACLProbeResult{DialError: "canceled"}) {
		t.Fatal("canceled before dial counted as denial")
	}
}

func TestHTTPACLTLSFailuresAreNotDenials(t *testing.T) {
	data, root, key := makeCA(t, nil)
	roots, _ := parseRoot(data, time.Now())
	for _, mode := range []string{"valid", "wrong-ca", "wrong-name", "tls-timeout", "http-error"} {
		t.Run(mode, func(t *testing.T) {
			pool, name := roots, publicDNS
			if mode == "wrong-ca" {
				pool = x509.NewCertPool()
			}
			if mode == "wrong-name" {
				name = "wrong.fixture.test"
			}
			leaf := makeLeaf(t, root, key, name)
			ctx, cancel := context.WithTimeout(t.Context(), time.Second)
			defer cancel()
			done := make(chan struct{})
			calls := 0
			got := probeHTTPACL(ctx, probeInput{Target: "100.64.0.1"}, pool, func(context.Context, string, string) (net.Conn, error) {
				calls++
				c, s := net.Pipe()
				go func() {
					defer close(done)
					defer s.Close()
					if mode == "tls-timeout" {
						<-ctx.Done()
						return
					}
					_ = s.SetDeadline(time.Now().Add(time.Second))
					server := tls.Server(s, &tls.Config{Certificates: []tls.Certificate{leaf}, NextProtos: []string{"http/1.1"}, MinVersion: tls.VersionTLS12})
					if server.Handshake() != nil {
						return
					}
					req, err := http.ReadRequest(bufio.NewReader(server))
					if err != nil {
						return
					}
					defer req.Body.Close()
					status := 200
					if mode == "http-error" {
						status = 502
					}
					resp := &http.Response{StatusCode: status, ProtoMajor: 1, ProtoMinor: 1, Header: http.Header{"X-Fixture-Verified": []string{"yes"}}, Body: io.NopCloser(strings.NewReader(backendBody)), ContentLength: int64(len(backendBody))}
					_ = resp.Write(server)
				}()
				return c, nil
			})
			waitL4(t, done)
			if calls != 1 || !got.Connected || got.DialTimedOut || got.DialError != "" || got.OK != (mode == "valid") {
				t.Fatalf("TLS/HTTP failure confused with denial: %+v", got)
			}
			if mode == "http-error" && (got.Status != 502 || len(got.LeafSHA256) != 64) {
				t.Fatal("verified error response missing")
			}
		})
	}
}

func TestHTTPACLControlRoutes(t *testing.T) {
	calls := 0
	h := controlHandler(nil, nil, nil, func(context.Context, probeInput) httpACLProbeResult {
		calls++
		return httpACLProbeResult{DialTimedOut: true, DialError: "timeout"}
	})
	for _, tc := range []struct {
		method, path, body string
		status             int
	}{
		{"POST", "/probe-http-acl", `{"target":"100.64.0.1","http2":true}`, 200},
		{"GET", "/probe-http-acl", "", 405},
		{"POST", "/probe-http-acl?x=1", "", 404},
		{"POST", "/probe-http-acl/", "", 404},
		{"POST", "/probe-http-acl", `{"target":"127.0.0.1","http2":true}`, 400},
		{"POST", "/probe-http-acl", `{"target":"100.64.0.1","http2":true,"port":80}`, 400},
		{"POST", "/probe-http-acl", `{"target":"100.64.0.1","http2":false,"http2":true}`, 400},
	} {
		w := httptest.NewRecorder()
		h.ServeHTTP(w, httptest.NewRequest(tc.method, tc.path, strings.NewReader(tc.body)))
		if w.Code != tc.status {
			t.Fatalf("control status %d, want %d", w.Code, tc.status)
		}
	}
	if calls != 1 {
		t.Fatal("invalid request reached probe")
	}
}
