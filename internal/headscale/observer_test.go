package headscale

import (
	"context"
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"
)

type observerTransport func(*http.Request) (*http.Response, error)

func (f observerTransport) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func TestObserverSafeLabelsAndOnce(t *testing.T) {
	for _, tc := range []struct{ method, path, wantMethod, wantPath string }{
		{"GET", "/health", "GET", "/health"},
		{"GET", "/api/v1/health", "GET", "/api/v1/health"},
		{"POST", "/api/v1/policy/check", "POST", "/api/v1/policy/check"},
		{"GET", "/api/v1/policy", "GET", "/api/v1/policy"},
		{"PUT", "/api/v1/policy", "PUT", "/api/v1/policy"},
		{"GET", "/api/v1/node", "GET", "/api/v1/node"},
		{"DELETE", "/api/v1/node/private-id", "DELETE", "/api/v1/node/{id}"},
		{"POST", "/api/v1/node/private-id/rename/private-name", "POST", "/api/v1/node/{id}/rename/{name}"},
		{"POST", "/api/v1/node/private-id/approve_routes", "POST", "/api/v1/node/{id}/approve_routes"},
		{"POST", "/api/v1/preauthkey", "POST", "/api/v1/preauthkey"},
		{"POST", "/api/v1/preauthkey/expire", "POST", "/api/v1/preauthkey/expire"},
		{"GET", "/api/v1/apikey", "GET", "/api/v1/apikey"},
		{"POST", "/api/v1/apikey/expire", "POST", "/api/v1/apikey/expire"},
		{"SECRET", "/private-path?token=private-token", "request", "unknown endpoint"},
	} {
		t.Run(tc.method+tc.path, func(t *testing.T) {
			calls := 0
			c := New("https://private-host", "private-token", func(method, path string, code int, elapsed time.Duration) {
				calls++
				if method != tc.wantMethod || path != tc.wantPath || code != 200 || elapsed < 0 {
					t.Fatalf("unexpected safe observation: %s %s %d %v", method, path, code, elapsed)
				}
			})
			c.http = &http.Client{Transport: observerTransport(func(*http.Request) (*http.Response, error) {
				return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader(`{}`)), Header: make(http.Header)}, nil
			})}
			if err := c.do(context.Background(), tc.method, tc.path, map[string]string{"secret": "body"}, nil); err != nil {
				t.Fatal(err)
			}
			if calls != 1 {
				t.Fatalf("observations=%d", calls)
			}
		})
	}
}

func TestObserverFailuresPreserveSafeErrors(t *testing.T) {
	sentinel := errors.New("private-token private-host private-body")
	for _, stage := range []string{"transport", "status", "decode", "encode", "create"} {
		t.Run(stage, func(t *testing.T) {
			calls := 0
			gotCode := -1
			c := New("https://private-host", "private-token", func(method, path string, code int, elapsed time.Duration) {
				calls++
				gotCode = code
				if method != "GET" || path != "/api/v1/apikey" || elapsed < 0 {
					t.Fatal("unsafe observation")
				}
			})
			c.http = &http.Client{Transport: observerTransport(func(*http.Request) (*http.Response, error) {
				if stage == "transport" {
					return nil, sentinel
				}
				code := 200
				if stage == "status" {
					code = 401
				}
				return &http.Response{StatusCode: code, Status: "private-status", Body: io.NopCloser(strings.NewReader("private-body")), Header: make(http.Header)}, nil
			})}
			var body any
			if stage == "encode" {
				body = make(chan int)
			}
			if stage == "create" {
				c.baseURL = ":private-token"
			}
			var out map[string]any
			err := c.do(context.Background(), "GET", "/api/v1/apikey", body, &out)
			if err == nil || strings.Contains(err.Error(), "private-") {
				t.Fatalf("unsafe or missing error: %v", err)
			}
			if stage == "transport" && !errors.Is(err, sentinel) {
				t.Fatal("lost errors.Is")
			}
			if IsUnauthorized(err) != (stage == "status") {
				t.Fatal("lost unauthorized detection")
			}
			wantCode := 0
			if stage == "decode" {
				wantCode = 200
			}
			if stage == "status" {
				wantCode = 401
			}
			if calls != 1 || gotCode != wantCode {
				t.Fatalf("observations=%d code=%d", calls, gotCode)
			}
		})
	}
}
