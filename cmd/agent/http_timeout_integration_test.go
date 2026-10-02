package main

import (
	"context"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestHTTPConfiguredTimeouts(t *testing.T) {
	for _, tc := range []struct {
		name, request, backend string
		status                 int
	}{
		{"defaults", "", "", 200},
		{"header deadline", "0s", "40ms", 504},
		{"whole request deadline", "40ms", "0s", 504},
		{"explicit disabled", "0s", "0s", 200},
		{"whole request wins", "40ms", "1s", 504},
	} {
		t.Run(tc.name, func(t *testing.T) {
			backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				select {
				case <-time.After(120 * time.Millisecond):
					io.WriteString(w, "complete")
				case <-r.Context().Done():
				}
			}))
			defer backend.Close()
			cfg := validHTTPTarget(t)
			cfg.RequestTimeout, cfg.BackendRequestTimeout = tc.request, tc.backend
			ln, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			h, err := serveHTTPIngress(context.Background(), ln, cfg, func(ctx context.Context, _ target) (net.Conn, error) {
				var dialer net.Dialer
				return dialer.DialContext(ctx, "tcp", backend.Listener.Addr().String())
			})
			if err != nil {
				ln.Close()
				t.Fatal(err)
			}
			defer h.Close()
			for _, h2 := range []bool{false, true} {
				client := localHTTPClient(t, h, cfg, h2)
				resp, err := client.Get("https://" + testDNS + "/")
				if err != nil {
					t.Fatal(err)
				}
				body, err := io.ReadAll(resp.Body)
				resp.Body.Close()
				if err != nil || resp.StatusCode != tc.status {
					t.Fatalf("h2=%t code=%d expected=%d err=%v", h2, resp.StatusCode, tc.status, err)
				}
				if tc.status == 200 && string(body) != "complete" {
					t.Fatalf("response body differs: %q", body)
				}
			}
		})
	}
}
