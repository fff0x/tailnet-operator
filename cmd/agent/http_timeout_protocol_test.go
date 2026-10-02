package main

import (
	"context"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
	"net/url"
	"strings"
	"testing"
	"time"
)

func TestHTTPTimeoutBoundsUpgradeHandshake(t *testing.T) {
	for _, readPrefix := range []bool{false, true} {
		t.Run(fmt.Sprint("read-prefix=", readPrefix), func(t *testing.T) {
			backendDone := make(chan struct{})
			backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				defer close(backendDone)
				conn, rw, err := http.NewResponseController(w).Hijack()
				if err != nil {
					return
				}
				defer conn.Close()
				fmt.Fprintf(rw, "HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: fixture\r\nX-Large: %s\r\n\r\n", strings.Repeat("x", 8192))
				_ = rw.Flush()
				_, _ = io.Copy(io.Discard, rw)
			}))
			defer backend.Close()
			u, _ := url.Parse(backend.URL)
			proxy := httputil.NewSingleHostReverseProxy(u)
			proxy.ErrorLog = log.New(io.Discard, "", 0)
			conn, served, _ := timeoutPipeRequest(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				serveHTTPWithTimeout(w, r, proxy, 100*time.Millisecond)
			}), "GET / HTTP/1.1\r\nHost: fixture.test\r\nConnection: Upgrade\r\nUpgrade: fixture\r\n\r\n")
			defer conn.Close()
			if readPrefix {
				_ = conn.SetReadDeadline(time.Now().Add(time.Second))
				if _, err := io.ReadFull(conn, make([]byte, 4096)); err != nil {
					t.Fatal(err)
				}
			}
			for _, done := range []<-chan struct{}{served, backendDone} {
				select {
				case <-done:
				case <-time.After(time.Second):
					t.Fatal("unfinished 101 response retained proxy or upstream beyond its deadline")
				}
			}
		})
	}
}

func TestHTTPTimeoutBoundsAutomaticContinue(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		select {
		case <-r.Context().Done():
		case <-time.After(time.Second):
		}
	}))
	defer backend.Close()
	u, _ := url.Parse(backend.URL)
	proxy := httputil.NewSingleHostReverseProxy(u)
	proxy.ErrorLog = log.New(io.Discard, "", 0)
	// Production's zero ExpectContinueTimeout starts forwarding the body immediately. Reading
	// it triggers net/http's automatic downstream 100 outside the ResponseWriter wrapper.
	tr := &http.Transport{}
	defer tr.CloseIdleConnections()
	proxy.Transport = tr
	conn, served, closed := timeoutPipeRequest(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		serveHTTPWithTimeout(w, r, proxy, 40*time.Millisecond)
	}), "POST / HTTP/1.1\r\nHost: fixture.test\r\nExpect: 100-continue\r\nContent-Length: 1\r\n\r\n")
	defer conn.Close()
	ctx, cancel := context.WithTimeout(t.Context(), 2*time.Second)
	defer cancel()
	for _, done := range []<-chan struct{}{served, closed} {
		select {
		case <-done:
		case <-ctx.Done():
			t.Fatal("automatic 100 retained request beyond timeout and bounded error-delivery budget")
		}
	}
}

func TestHTTPTimeoutAllowsSubsequentRequests(t *testing.T) {
	for _, h2 := range []bool{false, true} {
		t.Run(fmt.Sprint("h2=", h2), func(t *testing.T) {
			backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path == "/slow" {
					<-r.Context().Done()
					return
				}
				io.WriteString(w, "ok")
			}))
			defer backend.Close()
			cfg := validHTTPTarget(t)
			cfg.RequestTimeout = "40ms"
			ln, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			h, err := serveHTTPIngress(t.Context(), ln, cfg, func(ctx context.Context, _ target) (net.Conn, error) {
				var dialer net.Dialer
				return dialer.DialContext(ctx, "tcp", backend.Listener.Addr().String())
			})
			if err != nil {
				ln.Close()
				t.Fatal(err)
			}
			defer h.Close()
			client := localHTTPClient(t, h, cfg, h2)
			for _, path := range []string{"/fast", "/slow", "/fast"} {
				resp, err := client.Get("https://" + testDNS + path)
				if err != nil {
					t.Fatal(err)
				}
				_, err = io.ReadAll(resp.Body)
				resp.Body.Close()
				want := http.StatusOK
				if path == "/slow" {
					want = http.StatusGatewayTimeout
					if !h2 && !resp.Close {
						t.Error("timed-out HTTP/1 connection must not be reused")
					}
				}
				if err != nil || resp.StatusCode != want {
					t.Fatalf("%s: status=%d want=%d err=%v", path, resp.StatusCode, want, err)
				}
			}
		})
	}
}
