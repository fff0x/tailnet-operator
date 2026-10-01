package main

import (
	"bufio"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
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

const testDNS = "app.example.test"

func testCertificate(t *testing.T, dir, dns string, notBefore, notAfter time.Time, serial int64, mutate ...func(*x509.Certificate)) target {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(serial), Subject: pkix.Name{CommonName: dns}, DNSNames: []string{dns},
		NotBefore: notBefore, NotAfter: notAfter, KeyUsage: x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	for _, change := range mutate {
		change(template)
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	certFile, keyFile := filepath.Join(dir, "tls.crt"), filepath.Join(dir, "tls.key")
	if err := os.WriteFile(certFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyFile, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}), 0o600); err != nil {
		t.Fatal(err)
	}
	return target{Name: "http", Mode: "http", Address: "backend.test", Port: 8080, ListenPort: 443, DNSName: testDNS, CertFile: certFile, KeyFile: keyFile}
}

func validHTTPTarget(t *testing.T) target {
	return testCertificate(t, t.TempDir(), testDNS, time.Now().Add(-time.Hour), time.Now().Add(time.Hour), 1)
}

func localHTTPIngress(t *testing.T, backend http.Handler) (*httpIngress, target) {
	t.Helper()
	b := httptest.NewServer(backend)
	t.Cleanup(b.Close)
	cfg := validHTTPTarget(t)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	h, err := serveHTTPIngress(context.Background(), ln, cfg, func(ctx context.Context, _ target) (net.Conn, error) {
		var d net.Dialer
		return d.DialContext(ctx, "tcp", b.Listener.Addr().String())
	})
	if err != nil {
		ln.Close()
		t.Fatal(err)
	}
	t.Cleanup(func() { h.Close() })
	return h, cfg
}

func localHTTPClient(t *testing.T, h *httpIngress, cfg target, h2 bool) *http.Client {
	t.Helper()
	cert, err := os.ReadFile(cfg.CertFile)
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(cert) {
		t.Fatal("root certificate")
	}
	tr := &http.Transport{
		TLSClientConfig:   &tls.Config{RootCAs: roots, ServerName: testDNS},
		ForceAttemptHTTP2: h2,
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			var d net.Dialer
			return d.DialContext(ctx, "tcp", h.Addr().String())
		},
	}
	t.Cleanup(tr.CloseIdleConnections)
	return &http.Client{Transport: tr, Timeout: 5 * time.Second}
}

func TestHTTPProxyHeadersAndHTTP2(t *testing.T) {
	seen := make(chan *http.Request, 2)
	h, cfg := localHTTPIngress(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen <- r.Clone(context.Background())
		io.WriteString(w, "backend response")
	}))
	for _, h2 := range []bool{false, true} {
		t.Run(fmt.Sprintf("http2=%v", h2), func(t *testing.T) {
			client := localHTTPClient(t, h, cfg, h2)
			r, _ := http.NewRequest("GET", "https://"+testDNS+"/path?token=request-secret", nil)
			r.Host = "APP.EXAMPLE.TEST:443"
			for _, k := range []string{"Forwarded", "X-Forwarded-For", "X-Forwarded-Host", "X-Forwarded-Proto", "X-Forwarded-Port"} {
				r.Header.Set(k, "spoof-secret")
			}
			r.Header.Set("Authorization", "Bearer auth-secret")
			res, err := client.Do(r)
			if err != nil {
				t.Fatal(err)
			}
			defer res.Body.Close()
			body, _ := io.ReadAll(res.Body)
			if res.StatusCode != 200 || string(body) != "backend response" {
				t.Fatalf("status %d body %q", res.StatusCode, body)
			}
			if h2 && res.ProtoMajor != 2 {
				t.Fatalf("not HTTP/2: %s", res.Proto)
			}
			got := <-seen
			if got.Host != r.Host || got.URL.RequestURI() != "/path?token=request-secret" {
				t.Fatalf("Host/path not preserved: %q %q", got.Host, got.URL.RequestURI())
			}
			if got.Header.Get("X-Forwarded-For") != "127.0.0.1" || got.Header.Get("X-Forwarded-Proto") != "https" || got.Header.Get("X-Forwarded-Host") != r.Host {
				t.Fatalf("forwarding headers: %v", got.Header)
			}
			if got.Header.Get("Forwarded") != `for="127.0.0.1";proto=https;host="APP.EXAMPLE.TEST:443"` {
				t.Fatalf("Forwarded=%q", got.Header.Get("Forwarded"))
			}
			if got.Header.Get("X-Forwarded-Port") != "" {
				t.Fatal("untrusted forwarding header survived")
			}
			if got.Header.Get("Authorization") != "Bearer auth-secret" {
				t.Fatal("backend auth not preserved")
			}
		})
	}
}

func TestHTTPRejectHostAndSNI(t *testing.T) {
	var backendCalls atomic.Int32
	h, cfg := localHTTPIngress(t, http.HandlerFunc(func(http.ResponseWriter, *http.Request) { backendCalls.Add(1) }))
	client := localHTTPClient(t, h, cfg, true)
	for _, host := range []string{"wrong.example.test", testDNS + ":80", testDNS + ".", testDNS + ":0443"} {
		r, _ := http.NewRequest("GET", "https://"+testDNS, nil)
		r.Host = host
		res, err := client.Do(r)
		if err != nil {
			t.Fatal(err)
		}
		res.Body.Close()
		if res.StatusCode != http.StatusMisdirectedRequest {
			t.Errorf("Host %q: status %d", host, res.StatusCode)
		}
	}
	for _, sni := range []string{"", "wrong.example.test"} {
		c, err := tls.DialWithDialer(&net.Dialer{Timeout: time.Second}, "tcp", h.Addr().String(), &tls.Config{ServerName: sni, InsecureSkipVerify: true}) // test server rejection, not client verification
		if err == nil {
			c.Close()
			t.Errorf("accepted SNI %q", sni)
		}
	}
	if backendCalls.Load() != 0 {
		t.Fatal("rejected requests reached backend")
	}
}

func TestHTTPCertificateRotationAndExpiry(t *testing.T) {
	now := time.Now().Truncate(time.Second)
	cfg := testCertificate(t, t.TempDir(), testDNS, now.Add(-time.Hour), now.Add(2*time.Hour), 1)
	s := &certificateSource{t: cfg, now: func() time.Time { return now }}
	cert, err := s.get(&tls.ClientHelloInfo{ServerName: strings.ToUpper(testDNS)})
	if err != nil || cert.Leaf.SerialNumber.Int64() != 1 {
		t.Fatalf("initial certificate: %v", err)
	}
	testCertificate(t, filepath.Dir(cfg.CertFile), testDNS, now.Add(-time.Hour), now.Add(2*time.Hour), 2)
	cert, err = s.get(nil)
	if err != nil || cert.Leaf.SerialNumber.Int64() != 1 {
		t.Fatal("cache not used")
	}
	now = now.Add(time.Minute)
	cert, err = s.get(nil)
	if err != nil || cert.Leaf.SerialNumber.Int64() != 2 {
		t.Fatal("rotation not observed within one minute")
	}

	// Expiry is enforced even inside the cache interval, without a refresh or restart.
	testCertificate(t, filepath.Dir(cfg.CertFile), testDNS, now.Add(-time.Hour), now.Add(90*time.Second), 3)
	now = now.Add(time.Minute)
	if _, err := s.get(nil); err != nil {
		t.Fatal(err)
	}
	now = now.Add(30 * time.Second)
	if _, err := s.get(nil); !errors.Is(err, errCertificate) {
		t.Fatalf("expired cached certificate accepted: %v", err)
	}
}

func TestHTTPRejectUnsafeCertificateLeaves(t *testing.T) {
	for _, tt := range []struct {
		name   string
		mutate func(*x509.Certificate)
	}{
		{"ca-not-leaf", func(c *x509.Certificate) { c.IsCA = true; c.BasicConstraintsValid = true }},
		{"unknown-critical-extension", func(c *x509.Certificate) {
			c.ExtraExtensions = []pkix.Extension{{Id: asn1.ObjectIdentifier{1, 2, 3, 4}, Critical: true, Value: []byte{5, 0}}}
		}},
		{"client-only", func(c *x509.Certificate) { c.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth} }},
		{"unknown-purpose-only", func(c *x509.Certificate) {
			c.ExtKeyUsage = nil
			c.UnknownExtKeyUsage = []asn1.ObjectIdentifier{{1, 2, 3, 4}}
		}},
	} {
		t.Run(tt.name, func(t *testing.T) {
			now := time.Now()
			cfg := testCertificate(t, t.TempDir(), testDNS, now.Add(-time.Hour), now.Add(time.Hour), 1, tt.mutate)
			s := &certificateSource{t: cfg, now: func() time.Time { return now }}
			pair, err := s.get(&tls.ClientHelloInfo{ServerName: testDNS})
			if pair != nil || !errors.Is(err, errCertificate) {
				t.Fatal("unsafe leaf accepted or error was not bounded")
			}
		})
	}
}

func TestHTTPCertificateInvalid(t *testing.T) {
	for _, kind := range []string{"wrong-san", "expired", "future", "mismatched-key", "invalid-pem", "missing"} {
		t.Run(kind, func(t *testing.T) {
			now := time.Now()
			dns, start, end := testDNS, now.Add(-time.Hour), now.Add(time.Hour)
			if kind == "wrong-san" {
				dns = "wrong.example.test"
			}
			if kind == "expired" {
				end = now.Add(-time.Minute)
			}
			if kind == "future" {
				start = now.Add(time.Minute)
			}
			cfg := testCertificate(t, t.TempDir(), dns, start, end, 1)
			switch kind {
			case "mismatched-key":
				other := validHTTPTarget(t)
				key, _ := os.ReadFile(other.KeyFile)
				if err := os.WriteFile(cfg.KeyFile, key, 0o600); err != nil {
					t.Fatal(err)
				}
			case "invalid-pem":
				if err := os.WriteFile(cfg.CertFile, []byte("PRIVATE DATA"), 0o600); err != nil {
					t.Fatal(err)
				}
			case "missing":
				if err := os.Remove(cfg.KeyFile); err != nil {
					t.Fatal(err)
				}
			}
			s := &certificateSource{t: cfg}
			if _, err := s.get(nil); !errors.Is(err, errCertificate) {
				t.Fatalf("invalid cert: %v", err)
			}
		})
	}
}

func TestHTTPCertificateProjectedSnapshot(t *testing.T) {
	dir := t.TempDir()
	now := time.Now()
	a := testCertificate(t, filepath.Join(dir, "generation-a"), testDNS, now.Add(-time.Hour), now.Add(time.Hour), 1)
	testCertificate(t, filepath.Join(dir, "generation-b"), testDNS, now.Add(-time.Hour), now.Add(time.Hour), 2)
	link := func(from, to string) {
		t.Helper()
		if err := os.Symlink(from, to); err != nil {
			t.Fatal(err)
		}
	}
	link("generation-a", filepath.Join(dir, "..data"))
	link("..data/tls.crt", filepath.Join(dir, "tls.crt"))
	link("..data/tls.key", filepath.Join(dir, "tls.key"))
	cfg := a
	cfg.CertFile, cfg.KeyFile = filepath.Join(dir, "tls.crt"), filepath.Join(dir, "tls.key")
	s := &certificateSource{t: cfg, now: func() time.Time { return now }}
	if _, err := s.get(nil); err != nil {
		t.Fatal(err)
	}
	link("generation-b", filepath.Join(dir, "..next"))
	if err := os.Rename(filepath.Join(dir, "..next"), filepath.Join(dir, "..data")); err != nil {
		t.Fatal(err)
	}
	now = now.Add(time.Minute)
	cert, err := s.get(nil)
	if err != nil || cert.Leaf.SerialNumber.Int64() != 2 {
		t.Fatalf("projection rotation failed: %v", err)
	}
	// Siblings pinned to different generations are rejected, even before parsing a pair.
	if err := os.Remove(cfg.KeyFile); err != nil {
		t.Fatal(err)
	}
	link(a.KeyFile, cfg.KeyFile)
	if _, _, err := readCertificateSnapshot(cfg.CertFile, cfg.KeyFile); err == nil {
		t.Fatal("mixed projection accepted")
	}
}

func TestHTTPWebSocketAndShutdown(t *testing.T) {
	backendDone := make(chan struct{})
	h, cfg := localHTTPIngress(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer close(backendDone)
		if r.Header.Get("Upgrade") != "websocket" {
			t.Error("upgrade not preserved")
			return
		}
		c, rw, err := w.(http.Hijacker).Hijack()
		if err != nil {
			t.Error(err)
			return
		}
		defer c.Close()
		rw.WriteString("HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: websocket\r\nSec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=\r\n\r\n")
		rw.Flush()
		// One masked RFC 6455 text frame ("hi"), followed by a server text frame.
		frame := make([]byte, 8)
		if _, err := io.ReadFull(rw, frame); err != nil {
			t.Error(err)
			return
		}
		if string(frame) != string([]byte{0x81, 0x82, 1, 2, 3, 4, 'h' ^ 1, 'i' ^ 2}) {
			t.Error("WebSocket frame not passed through")
		}
		c.Write([]byte{0x81, 2, 'h', 'i'})
		io.Copy(io.Discard, rw)
	}))
	c, err := tls.Dial("tcp", h.Addr().String(), &tls.Config{ServerName: testDNS, InsecureSkipVerify: true})
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	c.SetDeadline(time.Now().Add(5 * time.Second))
	fmt.Fprintf(c, "GET /socket HTTP/1.1\r\nHost: %s\r\nConnection: Upgrade\r\nUpgrade: websocket\r\nSec-WebSocket-Version: 13\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\r\n", testDNS)
	br := bufio.NewReader(c)
	res, err := http.ReadResponse(br, &http.Request{Method: "GET"})
	if err != nil {
		t.Fatal(err)
	}
	if res.StatusCode != 101 {
		t.Fatalf("upgrade status %d", res.StatusCode)
	}
	// Rotation changes future handshakes and proof without closing this established WebSocket.
	before, err := h.probeTLS(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	listener := h.Listener
	testCertificate(t, filepath.Dir(cfg.CertFile), testDNS, time.Now().Add(-time.Hour), time.Now().Add(time.Hour), 2)
	after, err := h.probeTLS(context.Background())
	if err != nil || before.sha256 == after.sha256 || h.Listener != listener {
		t.Fatal("certificate rotation replaced the listener or retained old TLS proof")
	}
	c.Write([]byte{0x81, 0x82, 1, 2, 3, 4, 'h' ^ 1, 'i' ^ 2})
	echo := make([]byte, 4)
	if _, err := io.ReadFull(br, echo); err != nil || string(echo) != string([]byte{0x81, 2, 'h', 'i'}) {
		t.Fatalf("echo=%v err=%v", echo, err)
	}
	closed := make(chan struct{})
	go func() {
		// Removal uses the same synchronous stop path as target reload/shutdown.
		running{ln: h, cancel: func() {}}.stop()
		close(closed)
	}()
	select {
	case <-closed:
	case <-time.After(3 * time.Second):
		t.Fatal("HTTP Close leaked upgraded handler")
	}
	select {
	case <-backendDone:
	case <-time.After(3 * time.Second):
		t.Fatal("upgraded upstream still open")
	}
	if _, err := br.ReadByte(); err == nil {
		t.Fatal("upgraded downstream still open")
	}
}

func TestHTTPErrorRedaction(t *testing.T) {
	cfg := validHTTPTarget(t)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	h, err := serveHTTPIngress(context.Background(), ln, cfg, func(context.Context, target) (net.Conn, error) {
		return nil, errors.New("https://user:password@example.test/?token=query-secret Authorization: Bearer auth-secret PRIVATE KEY")
	})
	if err != nil {
		t.Fatal(err)
	}
	defer h.Close()
	client := localHTTPClient(t, h, cfg, false)
	res, err := client.Get("https://" + testDNS + "/?token=query-secret")
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	body, _ := io.ReadAll(res.Body)
	if res.StatusCode != 502 || string(body) != "backend unavailable\n" {
		t.Fatalf("unsafe error response: %s", body)
	}
}

func TestHTTPValidationAndComparableReload(t *testing.T) {
	cfg := validHTTPTarget(t)
	for _, mode := range []string{"", "l4"} {
		l4 := target{Name: "l4", Address: "10.0.0.1", Port: 80, ListenPort: 10000, Mode: mode}
		if err := l4.validateHTTP(); err != nil {
			t.Fatal(err)
		}
	}
	changes := []func(*target){
		func(t *target) { t.Mode = "bogus" }, func(t *target) { t.ListenPort = 80 },
		func(t *target) { t.DNSName = "" }, func(t *target) { t.DNSName = "*.example.test" },
		func(t *target) { t.CertFile = "" }, func(t *target) { t.KeyFile = "" },
		func(t *target) { t.Address = "https://user:secret@backend.test?token=secret" },
	}
	for _, change := range changes {
		bad := cfg
		change(&bad)
		if err := bad.validateHTTP(); err == nil {
			t.Fatal("accepted invalid HTTP target")
		}
	}
	fw := &forwarder{mode: "egress", run: map[string]running{}}
	path := filepath.Join(t.TempDir(), "targets.json")
	writeVersionedTargets(t, path, []target{cfg})
	if _, err := fw.reload(context.Background(), path); err == nil {
		t.Fatal("egress accepted HTTP")
	}
	for _, change := range []func(*target){
		func(t *target) { t.Mode = "l4" }, func(t *target) { t.DNSName = "other.example.test" },
		func(t *target) { t.ConfigID = "new-revision" },
		func(t *target) { t.CertFile = "/new.crt" }, func(t *target) { t.KeyFile = "/new.key" },
	} {
		changed := cfg
		change(&changed)
		start, stop := diffTargets(map[string]target{cfg.Name: cfg}, []target{changed})
		if len(start) != 1 || len(stop) != 1 {
			t.Fatal("HTTP change missed by value diff")
		}
	}
	writeVersionedTargets(t, path, []target{cfg})
	loaded, err := loadTargets(path)
	if err != nil {
		t.Fatal(err)
	}
	start, stop := diffTargets(map[string]target{cfg.Name: cfg}, loaded)
	if len(start) != 0 || len(stop) != 0 {
		t.Fatal("reloaded unchanged HTTP target causes restart")
	}
}

func TestHTTPCancelStopsListener(t *testing.T) {
	cfg := validHTTPTarget(t)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	h, err := serveHTTPIngress(ctx, ln, cfg, func(context.Context, target) (net.Conn, error) {
		return nil, errors.New("unused")
	})
	if err != nil {
		ln.Close()
		t.Fatal(err)
	}
	defer h.Close()
	// An idle TLS handshake must also be closed, not just active HTTP handlers.
	c, err := net.Dial("tcp", h.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	cancel()
	select {
	case <-h.done:
	case <-time.After(3 * time.Second):
		t.Fatal("canceled listener is still serving")
	}
	h.Close()
	c.SetReadDeadline(time.Now().Add(time.Second))
	if _, err := c.Read(make([]byte, 1)); err == nil {
		t.Fatal("incomplete handshake survived shutdown")
	} else if ne, ok := err.(net.Error); ok && ne.Timeout() {
		t.Fatal("incomplete handshake leaked")
	}
}

func TestHTTPHealthDoesNotClaimTLSFromTCP(t *testing.T) {
	backend, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer backend.Close()
	cfg := validHTTPTarget(t)
	cfg.Address, cfg.Port = "127.0.0.1", backend.Addr().(*net.TCPAddr).Port
	fw := &forwarder{mode: "ingress", run: map[string]running{cfg.Name: {t: cfg}}}
	p := &prober{}
	p.probe(context.Background(), fw)
	r := p.snapshot()[0]
	if r.Reachable || r.TLSReady == nil || *r.TLSReady || r.Error != "local TLS component probe failed" {
		t.Fatalf("overclaimed TLS: %+v", r)
	}
	b, _ := json.Marshal(r)
	if !strings.Contains(string(b), `"tlsReady":false`) {
		t.Fatal("missing explicit TLS evidence")
	}
	l4, _ := json.Marshal(probeResult{Name: "l4", Reachable: true})
	if strings.Contains(string(l4), "tlsReady") {
		t.Fatal("L4 schema changed")
	}
}
