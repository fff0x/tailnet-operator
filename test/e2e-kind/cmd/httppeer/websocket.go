package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/coder/websocket"
)

const (
	webSocketGreeting = "p1.8-websocket-ready\n"
	webSocketBytes    = 32
	webSocketSlots    = 4
)

type webSocketProbeResult struct {
	OK         bool   `json:"ok"`
	Upgraded   bool   `json:"upgraded"`
	LeafSHA256 string `json:"leafSHA256"`
	Exchanged  bool   `json:"exchanged"`
}

// A verified RFC 6455 handshake, server-first greeting, fresh challenge/reply,
// and normal close are all required. Only bounded evidence escapes this probe.
func probeWebSocket(ctx context.Context, input l4ProbeInput, roots *x509.CertPool, dial dialFunc) webSocketProbeResult {
	var result webSocketProbeResult
	if !allowedTarget(input.Target) || roots == nil || ctx.Err() != nil {
		return result
	}
	ctx, cancel := context.WithTimeout(ctx, probeTimeout)
	defer cancel()
	deadline, _ := ctx.Deadline()
	client, tr := probeClient(roots, func(_ context.Context, network, address string) (net.Conn, error) {
		conn, err := dial(ctx, network, address)
		if err != nil || conn == nil {
			if conn != nil {
				_ = conn.Close()
			}
			return nil, errRejected
		}
		if conn.SetDeadline(deadline) != nil {
			_ = conn.Close()
			return nil, errRejected
		}
		// Also bounds library-internal close/error-body reads after hijacking.
		context.AfterFunc(ctx, func() { _ = conn.Close() })
		return conn, nil
	}, probeInput{Target: input.Target})
	defer tr.CloseIdleConnections()
	headers := make(http.Header)
	for _, name := range []string{"Forwarded", "X-Forwarded-For", "X-Forwarded-Host", "X-Forwarded-Proto", "X-Forwarded-Port", "X-Forwarded-Arbitrary"} {
		headers.Set(name, "fixture-spoof")
	}
	conn, resp, err := websocket.Dial(ctx, "wss://"+publicDNS+"/socket", &websocket.DialOptions{
		HTTPClient: client, HTTPHeader: headers, CompressionMode: websocket.CompressionDisabled,
	})
	if conn != nil {
		defer conn.CloseNow()
	}
	if err != nil || conn == nil || ctx.Err() != nil || resp == nil || resp.ProtoMajor != 1 ||
		resp.TLS == nil || len(resp.TLS.PeerCertificates) == 0 || len(resp.TLS.VerifiedChains) == 0 ||
		(resp.TLS.NegotiatedProtocol != "" && resp.TLS.NegotiatedProtocol != "http/1.1") {
		return result
	}
	result.Upgraded = true
	leafDigest := sha256.Sum256(resp.TLS.PeerCertificates[0].Raw)
	result.LeafSHA256 = hex.EncodeToString(leafDigest[:])
	conn.SetReadLimit(webSocketBytes)
	kind, greeting, err := conn.Read(ctx)
	if err != nil || kind != websocket.MessageText || string(greeting) != webSocketGreeting {
		return result
	}
	var nonce [webSocketBytes]byte
	if _, err := rand.Read(nonce[:]); err != nil || conn.Write(ctx, websocket.MessageBinary, nonce[:]) != nil {
		return result
	}
	kind, reply, err := conn.Read(ctx)
	want := sha256.Sum256(nonce[:])
	if err != nil || kind != websocket.MessageBinary || !bytes.Equal(reply, want[:]) {
		return result
	}
	// No extra data frames or a truncated TCP stream may masquerade as a full
	// exchange. Read handles the RFC 6455 close reply, within the same deadline.
	_, _, err = conn.Read(ctx)
	result.Exchanged = websocket.CloseStatus(err) == websocket.StatusNormalClosure && ctx.Err() == nil
	result.OK = result.Exchanged
	return result
}

// Strictly validate before Accept: library handshake errors can quote attacker
// headers. This fixture supports only the exact handshake its peer emits.
func validWebSocketRequest(r *http.Request, peerIP string) bool {
	if r.Method != http.MethodGet || r.ProtoMajor != 1 || r.ProtoMinor != 1 ||
		r.URL.RequestURI() != "/socket" || r.URL.IsAbs() || r.Host != publicDNS || r.TLS != nil ||
		r.ContentLength != 0 || len(r.TransferEncoding) != 0 ||
		!exactHeader(r.Header, "Forwarded", fmt.Sprintf("for=%q;proto=https;host=%q", peerIP, publicDNS)) ||
		!exactHeader(r.Header, "X-Forwarded-For", peerIP) ||
		!exactHeader(r.Header, "X-Forwarded-Host", publicDNS) ||
		!exactHeader(r.Header, "X-Forwarded-Proto", "https") ||
		!exactHeader(r.Header, "Sec-WebSocket-Version", "13") {
		return false
	}
	for _, name := range []string{"Connection", "Upgrade"} {
		want := "upgrade"
		if name == "Upgrade" {
			want = "websocket"
		}
		values := r.Header.Values(name)
		if len(values) != 1 || !strings.EqualFold(values[0], want) {
			return false
		}
	}
	keys := r.Header.Values("Sec-WebSocket-Key")
	if len(keys) != 1 {
		return false
	}
	key, err := base64.StdEncoding.DecodeString(keys[0])
	if err != nil || len(key) != 16 || base64.StdEncoding.EncodeToString(key) != keys[0] {
		return false
	}
	size := 0
	for name, values := range r.Header {
		lower := strings.ToLower(name)
		if (strings.HasPrefix(lower, "x-forwarded-") && lower != "x-forwarded-for" && lower != "x-forwarded-host" && lower != "x-forwarded-proto") ||
			lower == "origin" || lower == "sec-websocket-protocol" || lower == "sec-websocket-extensions" {
			return false
		}
		for _, value := range values {
			size += len(name) + len(value) + 4
			if size > maxHeaderBytes {
				return false
			}
		}
	}
	return true
}

// net/http clears its read deadline when hijacking. Reinstate an absolute
// deadline on the raw connection, including library-internal close operations;
// http.Server.Shutdown cannot close or wait for these connections.
type webSocketDeadlineWriter struct {
	http.ResponseWriter
	deadline time.Time
}

func (w webSocketDeadlineWriter) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	conn, rw, err := http.NewResponseController(w.ResponseWriter).Hijack()
	if err != nil {
		return nil, nil, errRejected
	}
	if conn.SetDeadline(w.deadline) != nil {
		_ = conn.Close()
		return nil, nil, errRejected
	}
	return conn, rw, nil
}

func webSocketBackendHandler(peerIP string) http.Handler {
	slots := make(chan struct{}, webSocketSlots)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !validWebSocketRequest(r, peerIP) {
			http.Error(w, "rejected", http.StatusBadRequest)
			return
		}
		select {
		case slots <- struct{}{}:
			defer func() { <-slots }()
		default:
			http.Error(w, "busy", http.StatusServiceUnavailable)
			return
		}
		// Do not depend on the request context after Accept has hijacked it.
		ctx, cancel := context.WithTimeout(context.Background(), probeTimeout)
		defer cancel()
		deadline, _ := ctx.Deadline()
		conn, err := websocket.Accept(webSocketDeadlineWriter{w, deadline}, r, &websocket.AcceptOptions{
			CompressionMode: websocket.CompressionDisabled,
		})
		if err != nil {
			return
		}
		defer conn.CloseNow()
		conn.SetReadLimit(webSocketBytes)
		if conn.Write(ctx, websocket.MessageText, []byte(webSocketGreeting)) != nil {
			return
		}
		kind, nonce, err := conn.Read(ctx)
		if err != nil || kind != websocket.MessageBinary || len(nonce) != webSocketBytes {
			return
		}
		digest := sha256.Sum256(nonce)
		if conn.Write(ctx, websocket.MessageBinary, digest[:]) == nil {
			_ = conn.Close(websocket.StatusNormalClosure, "")
		}
	})
}
