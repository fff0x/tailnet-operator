package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/coder/websocket"
)

const webSocketTestPeer = "100.64.0.2"

// All real sockets in these tests are loopback-only. The fixture hostname is
// used for verification, never resolved by the host or used as a dial address.
func webSocketTestTLS(t *testing.T, name string, handler http.Handler) (*x509.CertPool, dialFunc, string) {
	t.Helper()
	_, root, key := makeCA(t, nil)
	leaf := makeLeaf(t, root, key, name)
	roots := x509.NewCertPool()
	roots.AddCert(root)
	server := httptest.NewUnstartedServer(handler)
	server.Config.ErrorLog = log.New(io.Discard, "", 0)
	server.TLS = &tls.Config{Certificates: []tls.Certificate{leaf}, MinVersion: tls.VersionTLS12, NextProtos: []string{"http/1.1"}}
	server.StartTLS()
	t.Cleanup(server.Close)
	dial := func(ctx context.Context, network, address string) (net.Conn, error) {
		if network != "tcp" || (address != publicDNS+":443" && address != "100.64.0.8:443") {
			t.Error("probe changed its fixed destination")
			return nil, errRejected
		}
		deadline, ok := ctx.Deadline()
		if !ok || time.Until(deadline) > probeTimeout {
			t.Error("dial lacks bounded context")
		}
		return (&net.Dialer{}).DialContext(ctx, "tcp", server.Listener.Addr().String())
	}
	digest := sha256.Sum256(leaf.Certificate[0])
	return roots, dial, hex.EncodeToString(digest[:])
}

func webSocketTestHeaders() http.Header {
	headers := make(http.Header)
	headers.Set("Forwarded", fmt.Sprintf("for=%q;proto=https;host=%q", webSocketTestPeer, publicDNS))
	headers.Set("X-Forwarded-For", webSocketTestPeer)
	headers.Set("X-Forwarded-Host", publicDNS)
	headers.Set("X-Forwarded-Proto", "https")
	return headers
}

func assertWebSocketResultBounded(t *testing.T, got webSocketProbeResult) {
	t.Helper()
	data, err := json.Marshal(got)
	if err != nil || len(data) > 150 {
		t.Fatal("unbounded result")
	}
	var fields map[string]any
	if json.Unmarshal(data, &fields) != nil || len(fields) != 4 {
		t.Fatal("unexpected result fields")
	}
	for _, name := range []string{"ok", "upgraded", "exchanged"} {
		if _, ok := fields[name].(bool); !ok {
			t.Fatal("non-boolean result")
		}
	}
	if got.LeafSHA256 != "" {
		digest, err := hex.DecodeString(got.LeafSHA256)
		if err != nil || len(digest) != sha256.Size || hex.EncodeToString(digest) != got.LeafSHA256 {
			t.Fatal("result contains non-digest evidence")
		}
	}
	if got.OK && (!got.Upgraded || !got.Exchanged || got.LeafSHA256 == "") {
		t.Fatal("success without full evidence")
	}
}

func TestWebSocketFullExchange(t *testing.T) {
	backend := httptest.NewServer(webSocketBackendHandler(webSocketTestPeer))
	defer backend.Close()
	backendURL, err := url.Parse(backend.URL)
	if err != nil {
		t.Fatal(err)
	}
	proxy := httputil.NewSingleHostReverseProxy(backendURL)
	proxy.ErrorLog = log.New(io.Discard, "", 0)
	// Use Rewrite like the actual agent: remove every spoofed forwarding field,
	// including unknown X-Forwarded-* fields, then supply verified values.
	proxy.Director = nil
	proxy.Rewrite = func(req *httputil.ProxyRequest) {
		req.SetURL(backendURL)
		req.Out.Host = req.In.Host
		for name := range req.Out.Header {
			if strings.EqualFold(name, "Forwarded") || strings.HasPrefix(strings.ToLower(name), "x-forwarded-") {
				req.Out.Header.Del(name)
			}
		}
		for name, values := range webSocketTestHeaders() {
			req.Out.Header[name] = values
		}
	}
	roots, dial, digest := webSocketTestTLS(t, publicDNS, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "GET" || r.Host != publicDNS || r.URL.RequestURI() != "/socket" || r.ProtoMajor != 1 ||
			r.TLS == nil || r.TLS.ServerName != publicDNS || (r.TLS.NegotiatedProtocol != "" && r.TLS.NegotiatedProtocol != "http/1.1") {
			t.Error("wrong verified wire request")
		}
		for _, name := range []string{"Forwarded", "X-Forwarded-For", "X-Forwarded-Host", "X-Forwarded-Proto", "X-Forwarded-Port", "X-Forwarded-Arbitrary"} {
			if !exactHeader(r.Header, name, "fixture-spoof") {
				t.Error("missing spoofed forwarding header")
			}
		}
		proxy.ServeHTTP(w, r)
	}))
	for _, target := range []string{publicDNS, "100.64.0.8"} {
		got := probeWebSocket(context.Background(), l4ProbeInput{Target: target}, roots, dial)
		assertWebSocketResultBounded(t, got)
		if !got.OK || got.LeafSHA256 != digest {
			t.Fatalf("full exchange failed: %+v", got)
		}
	}
}

func TestWebSocketHandshakeRejections(t *testing.T) {
	for _, mode := range []string{"wrong-ca", "wrong-name", "nonupgrade", "rejected", "redirect", "fake-upgrade"} {
		t.Run(mode, func(t *testing.T) {
			name := publicDNS
			if mode == "wrong-name" {
				name = "wrong.fixture.test"
			}
			var requests atomic.Int32
			roots, dial, _ := webSocketTestTLS(t, name, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				requests.Add(1)
				switch mode {
				case "redirect":
					http.Redirect(w, r, "https://"+publicDNS+"/socket", http.StatusFound)
				case "fake-upgrade":
					w.Header().Set("Connection", "Upgrade")
					w.Header().Set("Upgrade", "websocket")
					w.Header().Set("Sec-WebSocket-Accept", "private-invalid-key")
					w.WriteHeader(http.StatusSwitchingProtocols)
					// A fake 101 body is a bidirectional stream, so close it
					// rather than leave Dial's bounded diagnostic read waiting.
					conn, _, err := w.(http.Hijacker).Hijack()
					if err == nil {
						_ = conn.Close()
					}
				case "rejected":
					http.Error(w, "private 100.64.0.8 certificate key", http.StatusBadRequest)
				default:
					_, _ = io.WriteString(w, "private non-websocket body")
				}
			}))
			if mode == "wrong-ca" {
				_, other, _ := makeCA(t, nil)
				roots = x509.NewCertPool()
				roots.AddCert(other)
			}
			got := probeWebSocket(context.Background(), l4ProbeInput{Target: publicDNS}, roots, dial)
			assertWebSocketResultBounded(t, got)
			if got != (webSocketProbeResult{}) {
				t.Fatalf("accepted invalid handshake: %+v", got)
			}
			if requests.Load() > 1 || ((mode == "wrong-ca" || mode == "wrong-name") && requests.Load() != 0) {
				t.Fatal("redirect followed or TLS verification bypassed")
			}
		})
	}
}

// Scripted endpoints still perform real RFC 6455 handshakes. Only the
// application frames differ; no fixture production code is replaced.
func webSocketTestScript(t *testing.T, script func(context.Context, *websocket.Conn)) http.Handler {
	t.Helper()
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		conn, err := websocket.Accept(w, r, nil)
		if err != nil {
			t.Error("test WebSocket accept failed")
			return
		}
		defer conn.CloseNow()
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		conn.SetReadLimit(webSocketBytes)
		script(ctx, conn)
	})
}

func TestWebSocketFrameRejections(t *testing.T) {
	for _, mode := range []string{
		"no-greeting", "greeting-type", "greeting-size", "greeting-body", "no-reply",
		"reply-type", "reply-short", "reply-size", "reply-body", "reflected-nonce",
		"truncated-close", "extra-frame", "wrong-close",
	} {
		t.Run(mode, func(t *testing.T) {
			handler := webSocketTestScript(t, func(ctx context.Context, conn *websocket.Conn) {
				if mode == "no-greeting" {
					return
				}
				kind, greeting := websocket.MessageText, []byte(webSocketGreeting)
				switch mode {
				case "greeting-type":
					kind = websocket.MessageBinary
				case "greeting-size":
					greeting = bytes.Repeat([]byte("x"), webSocketBytes+1)
				case "greeting-body":
					greeting = []byte("private wrong greeting")
				}
				if conn.Write(ctx, kind, greeting) != nil {
					return
				}
				kind, nonce, err := conn.Read(ctx)
				if err != nil || mode == "no-reply" {
					return
				}
				if kind != websocket.MessageBinary || len(nonce) != webSocketBytes {
					t.Error("invalid client challenge")
					return
				}
				digest := sha256.Sum256(nonce)
				reply := digest[:]
				switch mode {
				case "reply-type":
					kind = websocket.MessageText
				case "reply-short":
					reply = reply[:len(reply)-1]
				case "reply-size":
					reply = append(reply, 'x')
				case "reply-body":
					reply = bytes.Repeat([]byte("x"), webSocketBytes)
				case "reflected-nonce":
					reply = nonce
				}
				if conn.Write(ctx, kind, reply) != nil || mode == "truncated-close" {
					return
				}
				if mode == "extra-frame" {
					_ = conn.Write(ctx, websocket.MessageBinary, []byte("extra private data"))
				}
				status := websocket.StatusNormalClosure
				if mode == "wrong-close" {
					status = websocket.StatusInternalError
				}
				_ = conn.Close(status, "private close reason")
			})
			roots, dial, digest := webSocketTestTLS(t, publicDNS, handler)
			got := probeWebSocket(context.Background(), l4ProbeInput{Target: publicDNS}, roots, dial)
			assertWebSocketResultBounded(t, got)
			if got.OK || got.Exchanged || !got.Upgraded || got.LeafSHA256 != digest {
				t.Fatalf("invalid exchange accepted or missing handshake evidence: %+v", got)
			}
		})
	}
}

func TestWebSocketFreshNonce(t *testing.T) {
	nonces := make(chan []byte, 2)
	roots, dial, _ := webSocketTestTLS(t, publicDNS, webSocketTestScript(t, func(ctx context.Context, conn *websocket.Conn) {
		if conn.Write(ctx, websocket.MessageText, []byte(webSocketGreeting)) != nil {
			return
		}
		kind, nonce, err := conn.Read(ctx)
		if err != nil || kind != websocket.MessageBinary || len(nonce) != webSocketBytes {
			t.Error("invalid challenge")
			return
		}
		nonces <- bytes.Clone(nonce)
		digest := sha256.Sum256(nonce)
		_ = conn.Write(ctx, websocket.MessageBinary, digest[:])
		_ = conn.Close(websocket.StatusNormalClosure, "")
	}))
	for range 2 {
		if !probeWebSocket(context.Background(), l4ProbeInput{Target: publicDNS}, roots, dial).OK {
			t.Fatal("nonce exchange failed")
		}
	}
	if bytes.Equal(<-nonces, <-nonces) {
		t.Fatal("reused nonce")
	}
}

func TestWebSocketAllowlistAndCancellation(t *testing.T) {
	roots := x509.NewCertPool()
	for _, target := range []string{"", "127.0.0.1", "192.168.0.1", "100.128.0.1", "::ffff:100.64.0.1", publicDNS + ":443", publicDNS + ".", "wss://" + publicDNS + "/socket", "100.64.0.8/socket", virtualDNS} {
		got := probeWebSocket(context.Background(), l4ProbeInput{Target: target}, roots, func(context.Context, string, string) (net.Conn, error) {
			t.Fatal("dial before allowlist")
			return nil, nil
		})
		if got != (webSocketProbeResult{}) {
			t.Fatal("invalid target accepted")
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if probeWebSocket(ctx, l4ProbeInput{Target: publicDNS}, roots, nil) != (webSocketProbeResult{}) ||
		probeWebSocket(context.Background(), l4ProbeInput{Target: publicDNS}, nil, nil) != (webSocketProbeResult{}) {
		t.Fatal("cancellation or explicit CA guard failed")
	}
	got := probeWebSocket(context.Background(), l4ProbeInput{Target: publicDNS}, roots, func(context.Context, string, string) (net.Conn, error) {
		return nil, errors.New(strings.Repeat("private 100.64.0.8 certificate key ", 1000))
	})
	if got != (webSocketProbeResult{}) {
		t.Fatal("dial error leaked")
	}
	assertWebSocketResultBounded(t, got)

	accepted := make(chan struct{})
	done := make(chan struct{})
	roots, dial, _ := webSocketTestTLS(t, publicDNS, webSocketTestScript(t, func(ctx context.Context, conn *websocket.Conn) {
		defer close(done)
		close(accepted)
		_, _, _ = conn.Read(ctx) // Withhold the server-first greeting.
	}))
	ctx, cancel = context.WithCancel(context.Background())
	defer cancel()
	result := make(chan webSocketProbeResult, 1)
	go func() { result <- probeWebSocket(ctx, l4ProbeInput{Target: publicDNS}, roots, dial) }()
	select {
	case <-accepted:
	case <-time.After(2 * time.Second):
		t.Fatal("handshake stalled")
	}
	cancel()
	select {
	case got := <-result:
		assertWebSocketResultBounded(t, got)
		if got.OK || got.Exchanged {
			t.Fatal("canceled exchange accepted")
		}
	case <-time.After(time.Second):
		t.Fatal("cancellation did not close client")
	}
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("cancellation left backend connection open")
	}
}

func TestWebSocketClientDeadline(t *testing.T) {
	for _, upgraded := range []bool{false, true} {
		t.Run(fmt.Sprintf("upgraded=%t", upgraded), func(t *testing.T) {
			done := make(chan struct{})
			var handler http.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				defer close(done)
				w.Header().Set("Content-Length", "1024")
				w.WriteHeader(http.StatusBadRequest)
				w.(http.Flusher).Flush()
				<-r.Context().Done() // No diagnostic response body ever arrives.
			})
			if upgraded {
				handler = webSocketTestScript(t, func(ctx context.Context, conn *websocket.Conn) {
					defer close(done)
					_, _, _ = conn.Read(ctx) // No server-first greeting ever arrives.
				})
			}
			roots, dial, _ := webSocketTestTLS(t, publicDNS, handler)
			ctx, cancel := context.WithTimeout(context.Background(), 250*time.Millisecond)
			defer cancel()
			start := time.Now()
			got := probeWebSocket(ctx, l4ProbeInput{Target: publicDNS}, roots, dial)
			assertWebSocketResultBounded(t, got)
			if got.OK || got.Exchanged || got.Upgraded != upgraded || time.Since(start) > time.Second {
				t.Fatal("stalled exchange escaped caller deadline")
			}
			select {
			case <-done:
			case <-time.After(time.Second):
				t.Fatal("deadline left connection open")
			}
		})
	}
}

func webSocketTestRequest() *http.Request {
	r := httptest.NewRequest(http.MethodGet, "/socket", nil)
	r.Host = publicDNS
	r.Header = webSocketTestHeaders()
	r.Header.Set("Connection", "Upgrade")
	r.Header.Set("Upgrade", "websocket")
	r.Header.Set("Sec-WebSocket-Version", "13")
	r.Header.Set("Sec-WebSocket-Key", "MDEyMzQ1Njc4OWFiY2RlZg==")
	return r
}

func TestWebSocketBackendRejectsBeforeUpgrade(t *testing.T) {
	handler := webSocketBackendHandler(webSocketTestPeer)
	if !validWebSocketRequest(webSocketTestRequest(), webSocketTestPeer) {
		t.Fatal("valid handshake rejected")
	}
	mutations := []func(*http.Request){
		func(r *http.Request) { r.Method = "POST" },
		func(r *http.Request) { r.Method = "HEAD" },
		func(r *http.Request) { r.URL.Path = "/other" },
		func(r *http.Request) { r.URL.Path += "/" },
		func(r *http.Request) { r.URL.RawQuery = "secret=value" },
		func(r *http.Request) { r.URL.ForceQuery = true },
		func(r *http.Request) { r.URL.RawPath = "/%73ocket" },
		func(r *http.Request) { r.URL.Scheme, r.URL.Host = "http", publicDNS },
		func(r *http.Request) { r.Host += ":443" },
		func(r *http.Request) { r.Host = "wrong.fixture.test" },
		func(r *http.Request) { r.TLS = &tls.ConnectionState{} },
		func(r *http.Request) { r.ProtoMajor = 2 },
		func(r *http.Request) { r.ProtoMinor = 0 },
		func(r *http.Request) { r.ContentLength = 1 },
		func(r *http.Request) { r.TransferEncoding = []string{"chunked"} },
		func(r *http.Request) { r.Header.Set("X-Forwarded-Port", "443") },
		func(r *http.Request) { r.Header.Set("X-Forwarded-Arbitrary", "fixture-spoof") },
		func(r *http.Request) { r.Header.Set("X-Forwarded-Unknown", "") },
		func(r *http.Request) { r.Header.Set("Origin", "https://private.example") },
		func(r *http.Request) { r.Header.Set("Sec-WebSocket-Protocol", "private") },
		func(r *http.Request) { r.Header.Set("Sec-WebSocket-Extensions", "permessage-deflate") },
		func(r *http.Request) { r.Header.Set("Private", strings.Repeat("p", maxHeaderBytes)) },
	}
	for _, name := range []string{"Forwarded", "X-Forwarded-For", "X-Forwarded-Host", "X-Forwarded-Proto", "Connection", "Upgrade", "Sec-WebSocket-Version", "Sec-WebSocket-Key"} {
		mutations = append(mutations,
			func(r *http.Request) { r.Header.Set(name, "private malformed value") },
			func(r *http.Request) { r.Header.Add(name, r.Header.Get(name)) },
			func(r *http.Request) { r.Header.Del(name) })
	}
	for i, mutate := range mutations {
		r := webSocketTestRequest()
		mutate(r)
		w := httptest.NewRecorder() // Cannot hijack: rejection must come first.
		handler.ServeHTTP(w, r)
		if w.Code != http.StatusBadRequest || w.Body.String() != "rejected\n" || w.Header().Get("Upgrade") != "" {
			t.Fatalf("invalid handshake %d was not sanitized: %d", i, w.Code)
		}
	}
}

func webSocketTestBackendDial(ctx context.Context, serverURL string) (*websocket.Conn, *http.Response, error) {
	return websocket.Dial(ctx, serverURL+"/socket", &websocket.DialOptions{
		Host: publicDNS, HTTPHeader: webSocketTestHeaders(),
		HTTPClient: &http.Client{Transport: &http.Transport{Proxy: nil, DisableKeepAlives: true}},
	})
}

func TestWebSocketBackendRejectsInvalidChallenge(t *testing.T) {
	for _, mode := range []string{"text", "short", "oversized", "empty"} {
		t.Run(mode, func(t *testing.T) {
			server := httptest.NewServer(webSocketBackendHandler(webSocketTestPeer))
			defer server.Close()
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			defer cancel()
			conn, _, err := webSocketTestBackendDial(ctx, server.URL)
			if err != nil {
				t.Fatal("backend upgrade failed")
			}
			defer conn.CloseNow()
			kind, greeting, err := conn.Read(ctx)
			if err != nil || kind != websocket.MessageText || string(greeting) != webSocketGreeting {
				t.Fatal("missing server-first greeting")
			}
			kind, body := websocket.MessageBinary, bytes.Repeat([]byte("x"), webSocketBytes)
			switch mode {
			case "text":
				kind = websocket.MessageText
			case "short":
				body = body[:len(body)-1]
			case "oversized":
				body = append(body, 'x')
			case "empty":
				body = nil
			}
			_ = conn.Write(ctx, kind, body)
			if _, _, err := conn.Read(ctx); err == nil || websocket.CloseStatus(err) == websocket.StatusNormalClosure || ctx.Err() != nil {
				t.Fatal("backend accepted invalid challenge or failed to close promptly")
			}
		})
	}
}

func TestWebSocketBackendSlotsAndHijackedDeadline(t *testing.T) {
	handler := webSocketBackendHandler(webSocketTestPeer)
	done := make(chan struct{}, webSocketSlots+1)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() { done <- struct{}{} }()
		handler.ServeHTTP(w, r)
	}))
	defer server.Close()
	ctx, cancel := context.WithTimeout(context.Background(), probeTimeout+2*time.Second)
	defer cancel()
	var connections []*websocket.Conn
	for range webSocketSlots {
		conn, _, err := webSocketTestBackendDial(ctx, server.URL)
		if err != nil {
			t.Fatal("backend slot rejected")
		}
		defer conn.CloseNow()
		connections = append(connections, conn)
		if _, _, err := conn.Read(ctx); err != nil {
			t.Fatal("backend greeting failed")
		}
	}
	conn, resp, err := webSocketTestBackendDial(ctx, server.URL)
	if conn != nil {
		_ = conn.CloseNow()
	}
	if err == nil || resp == nil || resp.StatusCode != http.StatusServiceUnavailable {
		t.Fatal("backend concurrency bound bypassed")
	}
	server.Close() // net/http cannot close its hijacked connections.
	for _, conn := range connections {
		if _, _, err := conn.Read(ctx); err == nil {
			t.Fatal("idle connection unexpectedly returned data")
		}
	}
	for range webSocketSlots + 1 {
		select {
		case <-done:
		case <-ctx.Done():
			t.Fatal("deadline did not retire every hijacked backend handler")
		}
	}
	if ctx.Err() != nil {
		t.Fatal("backend relied on the client deadline to close hijacked connections")
	}
}
