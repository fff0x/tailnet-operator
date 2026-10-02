package main

import (
	"bufio"
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"os"
	"sync/atomic"
	"testing"
	"time"
)

func TestBackendTLSFreshHandshakeNotPooled(t *testing.T) {
	cert, ca := backendCertificate(t, time.Now().Add(time.Hour))
	wrong, _ := backendCertificate(t, time.Now().Add(time.Hour))
	var pair atomic.Pointer[tls.Certificate]
	pair.Store(&cert)
	b := backendTestServer(t, &pair, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { io.WriteString(w, "ok") }))
	h, cfg := tlsBackendIngress(t, b, ca, backendDNS)
	client := localHTTPClient(t, h, cfg, false)
	response, err := client.Get("https://" + testDNS)
	if err != nil {
		t.Fatal(err)
	}
	io.Copy(io.Discard, response.Body)
	response.Body.Close()
	if response.StatusCode != 200 {
		t.Fatal("initial request failed")
	}
	pair.Store(&wrong)
	// A pooled connection with the previous valid certificate still exists; readiness must
	// nevertheless independently verify what a fresh backend connection receives now.
	result := probeOne(context.Background(), probeTarget{t: cfg, ln: h})
	if result.Reachable || *result.BackendReachable || !*result.TLSReady || result.BackendTLSReason != backendTLSFailed {
		t.Fatalf("probe reused pooled TLS success: %+v", result)
	}
}

func TestBackendTLSMinimumVersion(t *testing.T) {
	cert, ca := backendCertificate(t, time.Now().Add(time.Hour))
	b := httptest.NewUnstartedServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { t.Error("obsolete TLS backend received request") }))
	b.Config.ErrorLog = log.New(io.Discard, "", 0)
	b.TLS = &tls.Config{MinVersion: tls.VersionTLS10, MaxVersion: tls.VersionTLS11, Certificates: []tls.Certificate{cert}}
	b.StartTLS()
	defer b.Close()
	h, cfg := tlsBackendIngress(t, b, ca, backendDNS)
	proof := probeOne(context.Background(), probeTarget{t: cfg, ln: h})
	if proof.Reachable || proof.BackendTLSReason != backendTLSFailed {
		t.Fatal("obsolete backend TLS accepted")
	}
	response, err := localHTTPClient(t, h, cfg, false).Get("https://" + testDNS)
	if err != nil {
		t.Fatal(err)
	}
	response.Body.Close()
	if response.StatusCode != 502 {
		t.Fatal("serving accepted obsolete backend TLS")
	}
}

func TestBackendTLSUpgradeSurvivesRotationAndJoinsShutdown(t *testing.T) {
	cert, ca := backendCertificate(t, time.Now().Add(time.Hour))
	replacement, nextCA := backendCertificate(t, time.Now().Add(time.Hour))
	var pair atomic.Pointer[tls.Certificate]
	pair.Store(&cert)
	backendDone := make(chan struct{})
	b := backendTestServer(t, &pair, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer close(backendDone)
		conn, rw, err := w.(http.Hijacker).Hijack()
		if err != nil {
			t.Error(err)
			return
		}
		defer conn.Close()
		fmt.Fprint(rw, "HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\r\n")
		rw.Flush()
		frame := make([]byte, 8)
		if _, err := io.ReadFull(rw, frame); err != nil {
			t.Error(err)
			return
		}
		if string(frame) != string([]byte{0x81, 0x82, 1, 2, 3, 4, 'h' ^ 1, 'i' ^ 2}) {
			t.Error("frame changed")
		}
		conn.Write([]byte{0x81, 2, 'h', 'i'})
		io.Copy(io.Discard, rw)
	}))
	h, cfg := tlsBackendIngress(t, b, ca, backendDNS)
	front, err := os.ReadFile(cfg.CertFile)
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(front) {
		t.Fatal("frontend roots")
	}
	conn, err := tls.Dial("tcp", h.Addr().String(), &tls.Config{RootCAs: roots, ServerName: testDNS})
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(5 * time.Second))
	fmt.Fprintf(conn, "GET /socket HTTP/1.1\r\nHost: %s\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\r\n", testDNS)
	reader := bufio.NewReader(conn)
	response, err := http.ReadResponse(reader, &http.Request{Method: "GET"})
	if err != nil {
		t.Fatal(err)
	}
	if response.StatusCode != 101 {
		t.Fatalf("upgrade status %d", response.StatusCode)
	}
	pair.Store(&replacement)
	if err := os.WriteFile(cfg.BackendCAFile, nextCA, 0600); err != nil {
		t.Fatal(err)
	}
	if _, _, reason := h.probeBackendTLS(context.Background()); reason != "" {
		t.Fatalf("rotated probe: %s", reason)
	}
	conn.Write([]byte{0x81, 0x82, 1, 2, 3, 4, 'h' ^ 1, 'i' ^ 2})
	echo := make([]byte, 4)
	if _, err := io.ReadFull(reader, echo); err != nil || string(echo) != string([]byte{0x81, 2, 'h', 'i'}) {
		t.Fatalf("rotated stream: %v %v", echo, err)
	}
	closed := make(chan struct{})
	go func() { h.Close(); close(closed) }()
	select {
	case <-closed:
	case <-time.After(3 * time.Second):
		t.Fatal("upgraded handler leaked")
	}
	select {
	case <-backendDone:
	case <-time.After(3 * time.Second):
		t.Fatal("upgraded backend leaked")
	}
	if _, err := reader.ReadByte(); err == nil {
		t.Fatal("upgraded downstream retained")
	}
}

func TestBackendTLSRepeatedRotationsCloseIdle(t *testing.T) {
	cert, ca := backendCertificate(t, time.Now().Add(time.Hour))
	var pair atomic.Pointer[tls.Certificate]
	pair.Store(&cert)
	addresses := make(chan string, 1)
	b := backendTestServer(t, &pair, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { addresses <- r.RemoteAddr; io.WriteString(w, "ok") }))
	h, cfg := tlsBackendIngress(t, b, ca, backendDNS)
	client := localHTTPClient(t, h, cfg, false)
	previous := ""
	for i := 0; i < 12; i++ {
		response, err := client.Get("https://" + testDNS)
		if err != nil {
			t.Fatal(err)
		}
		io.Copy(io.Discard, response.Body)
		response.Body.Close()
		if response.StatusCode != 200 {
			t.Fatal("rotation request failed")
		}
		currentAddress := <-addresses
		if currentAddress == previous {
			t.Fatal("retired pooled connection served new work")
		}
		previous = currentAddress
		h.transport.mu.Lock()
		old := h.transport.current
		h.transport.mu.Unlock()
		ca = append(ca, '\n')
		if err := os.WriteFile(cfg.BackendCAFile, ca, 0600); err != nil {
			t.Fatal(err)
		}
		if _, _, err := h.transport.proofConfig(); err != nil {
			t.Fatal(err)
		}
		req, _ := http.NewRequest("GET", "https://"+backendDNS, nil)
		if response, err := old.transport.RoundTrip(req); err == nil {
			response.Body.Close()
			t.Fatal("retired transport reused idle connection")
		}
	}
	h.Close()
	h.transport.mu.Lock()
	closed, current := h.transport.closed, h.transport.current
	h.transport.mu.Unlock()
	if !closed || current != nil {
		t.Fatal("shutdown retained current transport")
	}
}
