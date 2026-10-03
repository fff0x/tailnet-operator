package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"io"
	"log"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

const backendDNS = "service.backend.test"

func backendCertificate(t *testing.T, expiry time.Time) (tls.Certificate, []byte) {
	t.Helper()
	return backendCertificateFor(t, backendDNS, expiry)
}

func backendCertificateFor(t *testing.T, name string, expiry time.Time) (tls.Certificate, []byte) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	ca := &x509.Certificate{SerialNumber: big.NewInt(1), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign, NotBefore: time.Now().Add(-2 * time.Hour), NotAfter: time.Now().Add(2 * time.Hour)}
	caDER, err := x509.CreateCertificate(rand.Reader, ca, ca, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	ca, err = x509.ParseCertificate(caDER)
	if err != nil {
		t.Fatal(err)
	}
	leaf := &x509.Certificate{SerialNumber: big.NewInt(2), DNSNames: []string{name}, NotBefore: time.Now().Add(-time.Hour), NotAfter: expiry, KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	leafDER, err := x509.CreateCertificate(rand.Reader, leaf, ca, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{leafDER, caDER}, PrivateKey: key}, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER})
}

func backendTestServer(t *testing.T, pair *atomic.Pointer[tls.Certificate], handler http.Handler) *httptest.Server {
	t.Helper()
	b := httptest.NewUnstartedServer(handler)
	b.Config.ErrorLog = log.New(io.Discard, "", 0)
	b.TLS = &tls.Config{MinVersion: tls.VersionTLS12, Certificates: []tls.Certificate{*pair.Load()}, GetCertificate: func(*tls.ClientHelloInfo) (*tls.Certificate, error) { return pair.Load(), nil }}
	b.StartTLS()
	t.Cleanup(b.Close)
	return b
}

func tlsBackendIngress(t *testing.T, b *httptest.Server, ca []byte, name string) (*httpIngress, target) {
	t.Helper()
	cfg := validHTTPTarget(t)
	cfg.BackendCAFile = filepath.Join(t.TempDir(), "ca.crt")
	cfg.BackendServerName = name
	if err := os.WriteFile(cfg.BackendCAFile, ca, 0600); err != nil {
		t.Fatal(err)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	h, err := serveHTTPIngress(context.Background(), ln, cfg, func(ctx context.Context, got target) (net.Conn, error) {
		if got.Address != cfg.Address || got.Port != cfg.Port {
			t.Error("TLS name changed dial destination")
		}
		return (&net.Dialer{}).DialContext(ctx, "tcp", b.Listener.Addr().String())
	})
	if err != nil {
		ln.Close()
		t.Fatal(err)
	}
	t.Cleanup(func() { h.Close() })
	return h, cfg
}

func TestBackendTLSVerificationHostAndProbe(t *testing.T) {
	for _, kind := range []string{"trusted", "wrong-ca", "wrong-name", "expired", "plaintext"} {
		t.Run(kind, func(t *testing.T) {
			expiry := time.Now().Add(time.Hour)
			if kind == "expired" {
				expiry = time.Now().Add(-time.Minute)
			}
			cert, ca := backendCertificate(t, expiry)
			var pair atomic.Pointer[tls.Certificate]
			pair.Store(&cert)
			seen := make(chan *http.Request, 1)
			handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { seen <- r; io.WriteString(w, "ok") })
			var b *httptest.Server
			if kind == "plaintext" {
				b = httptest.NewServer(handler)
				t.Cleanup(b.Close)
			} else {
				b = backendTestServer(t, &pair, handler)
			}
			if kind == "wrong-ca" {
				ambient := filepath.Join(t.TempDir(), "system-roots.pem")
				if err := os.WriteFile(ambient, ca, 0600); err != nil {
					t.Fatal(err)
				}
				t.Setenv("SSL_CERT_FILE", ambient)
				_, ca = backendCertificate(t, time.Now().Add(time.Hour))
			}
			t.Setenv("HTTPS_PROXY", "http://127.0.0.1:1")
			t.Setenv("HTTP_PROXY", "http://127.0.0.1:1")
			name := backendDNS
			if kind == "wrong-name" {
				name = "wrong.backend.test"
			}
			h, cfg := tlsBackendIngress(t, b, ca, name)
			client := localHTTPClient(t, h, cfg, true)
			req, _ := http.NewRequest("GET", "https://"+testDNS+"/path", nil)
			req.Host = "APP.EXAMPLE.TEST:443"
			response, err := client.Do(req)
			if err != nil {
				t.Fatal(err)
			}
			response.Body.Close()
			probe := probeTarget{t: cfg, ln: h}
			proof := probeOne(context.Background(), probe)
			if proof.TLSReady == nil || !*proof.TLSReady {
				t.Fatal("backend failure polluted frontend proof")
			}
			if kind == "trusted" {
				if response.StatusCode != 200 || !proof.Reachable || proof.BackendCAHash == "" || proof.BackendTLSNotAfter == nil || proof.BackendTLSReason != "" {
					t.Fatalf("trusted backend rejected: %d %+v", response.StatusCode, proof)
				}
				got := <-seen
				if got.Host != req.Host || got.TLS.ServerName != backendDNS {
					t.Fatalf("Host/SNI changed: %s %s", got.Host, got.TLS.ServerName)
				}
			} else {
				if response.StatusCode != 502 || proof.Reachable || *proof.BackendReachable || proof.BackendCAHash != "" || proof.BackendTLSNotAfter != nil || proof.BackendTLSReason != backendTLSFailed {
					t.Fatalf("invalid backend accepted: %d %+v", response.StatusCode, proof)
				}
			}
		})
	}
}

func TestBackendTLSRotationPreservesActiveStream(t *testing.T) {
	first, ca1 := backendCertificate(t, time.Now().Add(time.Hour))
	second, ca2 := backendCertificate(t, time.Now().Add(time.Hour))
	var pair atomic.Pointer[tls.Certificate]
	pair.Store(&first)
	finish := make(chan struct{})
	b := backendTestServer(t, &pair, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/stream" {
			io.WriteString(w, "first\n")
			w.(http.Flusher).Flush()
			<-finish
			io.WriteString(w, "last\n")
			return
		}
		io.WriteString(w, "ok")
	}))
	h, cfg := tlsBackendIngress(t, b, ca1, backendDNS)
	client := localHTTPClient(t, h, cfg, true)
	stream, err := client.Get("https://" + testDNS + "/stream")
	if err != nil {
		close(finish)
		t.Fatal(err)
	}
	prefix := make([]byte, 6)
	if _, err := io.ReadFull(stream.Body, prefix); err != nil {
		close(finish)
		t.Fatal(err)
	}
	h.transport.mu.Lock()
	old := h.transport.current
	h.transport.mu.Unlock()
	pair.Store(&second)
	if err := os.WriteFile(cfg.BackendCAFile, ca2, 0600); err != nil {
		close(finish)
		t.Fatal(err)
	}
	response, err := client.Get("https://" + testDNS + "/new")
	if err != nil {
		close(finish)
		t.Fatal(err)
	}
	response.Body.Close()
	if response.StatusCode != 200 {
		close(finish)
		t.Fatal("rotated trust did not reach newly signed backend")
	}
	h.transport.mu.Lock()
	retired, replaced := old.retired, h.transport.current != old
	h.transport.mu.Unlock()
	if !retired || !replaced {
		close(finish)
		t.Fatal("transport not retired")
	}
	// Even a retained internal transport cannot start a fresh connection after retirement.
	request, _ := http.NewRequest("GET", "https://"+backendDNS, nil)
	if response, err := old.transport.RoundTrip(request); err == nil {
		response.Body.Close()
		close(finish)
		t.Fatal("retired transport admitted a new request")
	}
	close(finish)
	rest, err := io.ReadAll(stream.Body)
	stream.Body.Close()
	if err != nil || string(prefix)+string(rest) != "first\nlast\n" {
		t.Fatalf("rotation aborted established stream: %q %v", rest, err)
	}
	// The retired transport has no idle sockets after the last old response completes.
	h.Close()
	if _, err := h.transport.RoundTrip(httptest.NewRequest("GET", "https://"+backendDNS, nil)); err == nil {
		t.Fatal("closed source admitted work")
	}
}

func TestBackendTLSProjectionReadinessRecovery(t *testing.T) {
	cert, ca := backendCertificate(t, time.Now().Add(time.Hour))
	var pair atomic.Pointer[tls.Certificate]
	pair.Store(&cert)
	b := backendTestServer(t, &pair, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { io.WriteString(w, "ok") }))
	h, cfg := tlsBackendIngress(t, b, ca, backendDNS)
	fw := probeForwarder(h, cfg)
	probe := probeTarget{t: cfg, ln: h, generation: 1}
	p := &prober{}
	publish := func() { p.publish(fw, probeOne(context.Background(), probe)) }
	publish()
	initial := p.snapshotFor(fw)[0]
	if !initial.Reachable {
		t.Fatalf("initial proof: %+v", initial)
	}
	client := localHTTPClient(t, h, cfg, false)
	checkRequest := func(want int) {
		t.Helper()
		response, err := client.Get("https://" + testDNS)
		if err != nil {
			t.Fatal(err)
		}
		response.Body.Close()
		if response.StatusCode != want {
			t.Fatalf("response %d, want %d", response.StatusCode, want)
		}
	}
	for _, invalid := range []string{"invalid", "missing", "rotated"} {
		switch invalid {
		case "invalid":
			if err := os.WriteFile(cfg.BackendCAFile, []byte("PRIVATE KEY sentinel"), 0600); err != nil {
				t.Fatal(err)
			}
		case "missing":
			if err := os.Remove(cfg.BackendCAFile); err != nil {
				t.Fatal(err)
			}
		case "rotated":
			_, other := backendCertificate(t, time.Now().Add(time.Hour))
			if err := os.WriteFile(cfg.BackendCAFile, other, 0600); err != nil {
				t.Fatal(err)
			}
		}
		if healthCode(p, fw, "Running") != 503 {
			t.Fatal("stale trust passed readiness")
		}
		r := p.snapshotFor(fw)[0]
		if !*r.TLSReady || *r.BackendReachable || r.BackendCAHash != "" || r.BackendTLSNotAfter != nil {
			t.Fatalf("proof independence/clearing: %+v", r)
		}
		checkRequest(502)
		publish()
		r = p.snapshotFor(fw)[0]
		if r.BackendTLSReason == "" || strings.Contains(r.Error, "sentinel") {
			t.Fatal("unbounded/missing reason")
		}
		if err := os.WriteFile(cfg.BackendCAFile, ca, 0600); err != nil {
			t.Fatal(err)
		}
		if healthCode(p, fw, "Running") != 503 {
			t.Fatal("proof resurrected without fresh handshake")
		}
		checkRequest(200)
		publish()
		if healthCode(p, fw, "Running") != 200 {
			t.Fatal("restored CA failed to recover")
		}
	}
	// Exact raw digest changes invalidate the observation, even if roots are identical.
	if err := os.WriteFile(cfg.BackendCAFile, append(ca, '\n'), 0600); err != nil {
		t.Fatal(err)
	}
	p.publish(fw, initial)
	if healthCode(p, fw, "Running") != 503 {
		t.Fatal("in-flight old digest published")
	}
	publish()
	p.mu.Lock()
	r := p.results[cfg.Name]
	expired := time.Now().Add(-time.Second)
	r.BackendTLSNotAfter = &expired
	p.results[cfg.Name] = r
	p.mu.Unlock()
	if healthCode(p, fw, "Running") != 503 {
		t.Fatal("expired backend proof accepted")
	}
	publish()
	p.mu.Lock()
	r = p.results[cfg.Name]
	r.LastProbe = time.Now().Add(-httpProofMaxAge - time.Second)
	p.results[cfg.Name] = r
	p.mu.Unlock()
	if healthCode(p, fw, "Running") != 503 {
		t.Fatal("stale backend proof accepted")
	}
	publish()
	fw.mu.Lock()
	owned := fw.run[cfg.Name]
	owned.generation++
	fw.run[cfg.Name] = owned
	fw.mu.Unlock()
	if healthCode(p, fw, "Running") != 503 {
		t.Fatal("old listener ownership certified new instance")
	}
	h.Close()
	if h.currentBackendProof(initial.BackendCAHash, *initial.BackendTLSNotAfter) {
		t.Fatal("closed listener retained proof")
	}
}

func TestBackendTLSProbeShutdown(t *testing.T) {
	cert, ca := backendCertificate(t, time.Now().Add(time.Hour))
	var pair atomic.Pointer[tls.Certificate]
	pair.Store(&cert)
	b := backendTestServer(t, &pair, http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	h, _ := tlsBackendIngress(t, b, ca, backendDNS)
	entered := make(chan struct{})
	h.transport.dial = func(ctx context.Context, _ target) (net.Conn, error) {
		close(entered)
		<-ctx.Done()
		return nil, ctx.Err()
	}
	done := make(chan struct{})
	go func() { h.probeBackendTLS(context.Background()); close(done) }()
	<-entered
	closed := make(chan struct{})
	go func() { h.Close(); close(closed) }()
	select {
	case <-closed:
	case <-time.After(time.Second):
		t.Fatal("shutdown failed to join backend probe")
	}
	<-done
}
