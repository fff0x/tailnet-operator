package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	admissionv1 "k8s.io/api/admission/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	kruntime "k8s.io/apimachinery/pkg/runtime"

	"tsunaro.io/tailnet-operator/test/internal/kindfixture"
)

func fixtureArgs() []string {
	return []string{"--mode=admission", "--fixture=p1.8-http", "--namespace=owned-test",
		"--agent-image=localhost/agent:exact-test", "--ca-config-map=fixture-control-ca",
		"--tls-cert=/fixture-tls/tls.crt", "--tls-key=/fixture-tls/tls.key"}
}

func fixtureConfig(t *testing.T) config {
	t.Helper()
	cfg, err := parseConfig(fixtureArgs(), "linux", 65532)
	if err != nil {
		t.Fatal(err)
	}
	return cfg
}

func TestOptionalNetworkGateConfig(t *testing.T) {
	image := "localhost/tn-source-netprobe:tn-kind-012345abcd"
	cfg, err := parseConfig(append(fixtureArgs(), "--network-gate-image="+image), "linux", 65532)
	if err != nil || cfg.networkGateImage != image {
		t.Fatal("explicit owned network gate rejected")
	}
	for _, value := range []string{"", "registry.example/fixture:tag", image + "x"} {
		if _, err := parseConfig(append(fixtureArgs(), "--network-gate-image="+value), "linux", 65532); err != errConfig {
			t.Fatal("invalid optional gate accepted")
		}
	}
}

func TestConfigGuards(t *testing.T) {
	cfg := fixtureConfig(t)
	if cfg.serviceDNS() != "fixture-admission.owned-test.svc" {
		t.Fatal("unexpected service DNS")
	}
	for _, identity := range []struct {
		os  string
		uid int
	}{{"linux", 0}, {"linux", 65534}, {"linux", -1}, {"darwin", 65532}, {"windows", 65532}} {
		if _, err := parseConfig(fixtureArgs(), identity.os, identity.uid); !errors.Is(err, errConfig) {
			t.Fatal("accepted invalid runtime identity")
		}
	}
	for i := range fixtureArgs() {
		args := fixtureArgs()
		args = append(args[:i], args[i+1:]...)
		if _, err := parseConfig(args, "linux", 65532); !errors.Is(err, errConfig) {
			t.Fatal("accepted omitted flag")
		}
	}
	for _, tc := range []struct {
		name, arg string
		index     int
	}{
		{"proxy", "--mode=proxy", 0}, {"backend", "--mode=backend", 0}, {"peer", "--mode=peer", 0},
		{"marker", "--fixture=p1.8-layered-isolation", 1}, {"empty-marker", "--fixture=", 1},
		{"empty-namespace", "--namespace=", 2}, {"namespace-dot", "--namespace=owned.test", 2},
		{"namespace-long", "--namespace=" + strings.Repeat("a", 64), 2},
		{"namespace-uppercase", "--namespace=Owned", 2}, {"empty-image", "--agent-image=", 3},
		{"wildcard-image", "--agent-image=agent:*", 3}, {"space-image", "--agent-image=agent tag", 3},
		{"control-image", "--agent-image=agent:\x00", 3}, {"long-image", "--agent-image=" + strings.Repeat("a", 513), 3},
		{"empty-configmap", "--ca-config-map=", 4}, {"bad-configmap", "--ca-config-map=../ca", 4},
		{"cert-path", "--tls-cert=/tmp/tls.crt", 5}, {"key-path", "--tls-key=/tmp/tls.key", 6},
		{"unknown", "--listen=:1234", 6}, {"duplicate", "--mode=admission", 6},
		{"positional", "admission", 0}, {"help", "--help", 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			args := fixtureArgs()
			args[tc.index] = tc.arg
			if _, err := parseConfig(args, "linux", 65532); !errors.Is(err, errConfig) {
				t.Fatal("accepted invalid configuration")
			}
		})
	}
	if _, err := parseConfig(append(fixtureArgs(), "--namespace=foreign"), "linux", 65532); !errors.Is(err, errConfig) {
		t.Fatal("accepted extra flag")
	}
}

func servingPEM(t *testing.T, change func(*x509.Certificate)) ([]byte, []byte) {
	t.Helper()
	pub, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	leaf := &x509.Certificate{
		SerialNumber: big.NewInt(1), DNSNames: []string{fixtureConfig(t).serviceDNS()},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}
	if change != nil {
		change(leaf)
	}
	der, err := x509.CreateCertificate(rand.Reader, leaf, leaf, pub, key)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})
}

func fixtureServer(t *testing.T) (*http.Server, []byte) {
	t.Helper()
	cert, key := servingPEM(t, nil)
	s, err := newServer(fixtureConfig(t), cert, key)
	if err != nil {
		t.Fatal(err)
	}
	return s, cert
}

func TestServingCertificatePolicy(t *testing.T) {
	for _, tc := range []struct {
		name   string
		change func(*x509.Certificate)
	}{
		{"ca", func(c *x509.Certificate) { c.IsCA = true }},
		{"expired", func(c *x509.Certificate) { c.NotAfter = time.Now().Add(-time.Minute) }},
		{"future", func(c *x509.Certificate) { c.NotBefore = time.Now().Add(time.Minute) }},
		{"client-only", func(c *x509.Certificate) { c.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth} }},
		{"wrong-dns", func(c *x509.Certificate) { c.DNSNames = []string{"fixture-admission.foreign.svc"} }},
		{"no-san", func(c *x509.Certificate) { c.DNSNames = nil; c.Subject.CommonName = fixtureConfig(t).serviceDNS() }},
		{"critical-extension", func(c *x509.Certificate) {
			c.ExtraExtensions = []pkix.Extension{{Id: asn1.ObjectIdentifier{1, 2, 3, 4}, Critical: true, Value: []byte{5, 0}}}
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cert, key := servingPEM(t, tc.change)
			if _, err := newServer(fixtureConfig(t), cert, key); !errors.Is(err, errTLS) {
				t.Fatal("accepted invalid server certificate")
			}
		})
	}
	cert, key := servingPEM(t, nil)
	_, differentKey := servingPEM(t, nil)
	for _, pair := range [][2][]byte{{cert, differentKey}, {[]byte("invalid"), key}, {cert, []byte("invalid")}, {bytes.Repeat([]byte("x"), maxPEMBytes+1), key}} {
		if _, err := newServer(fixtureConfig(t), pair[0], pair[1]); !errors.Is(err, errTLS) {
			t.Fatal("accepted invalid key pair")
		}
	}
	cfg := fixtureConfig(t)
	cfg.fixture = "wrong"
	if _, err := newServer(cfg, cert, key); !errors.Is(err, errConfig) {
		t.Fatal("server construction bypassed config validation")
	}
}

func TestServerBoundsAndCachedValidity(t *testing.T) {
	s, _ := fixtureServer(t)
	if s.Addr != ":9443" || s.ReadHeaderTimeout != 5*time.Second || s.ReadTimeout != 10*time.Second ||
		s.WriteTimeout != 10*time.Second || s.IdleTimeout != 30*time.Second || s.MaxHeaderBytes != 16<<10 ||
		s.ErrorLog == nil || s.ErrorLog.Writer() != io.Discard || s.TLSConfig.MinVersion != tls.VersionTLS12 ||
		len(s.TLSConfig.Certificates) != 0 || s.TLSConfig.GetCertificate == nil {
		t.Fatal("server bounds or TLS configuration changed")
	}
	pair, err := s.TLSConfig.GetCertificate(&tls.ClientHelloInfo{})
	if err != nil {
		t.Fatal(err)
	}
	if !validAt(pair, pair.Leaf.NotBefore) || validAt(pair, pair.Leaf.NotBefore.Add(-time.Nanosecond)) || validAt(pair, pair.Leaf.NotAfter) {
		t.Fatal("invalid lifetime boundaries")
	}
	// No concurrent server is running: move the cached leaf's expiry to verify
	// both handshake selection and readiness fail without reloading any files.
	pair.Leaf.NotAfter = time.Now().Add(-time.Second)
	if _, err := s.TLSConfig.GetCertificate(&tls.ClientHelloInfo{}); !errors.Is(err, errTLS) {
		t.Fatal("cached expired leaf accepted")
	}
	w := httptest.NewRecorder()
	s.Handler.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/readyz", nil))
	if w.Code != http.StatusServiceUnavailable {
		t.Fatal("expired server is ready")
	}
}

func TestHandlerRoutes(t *testing.T) {
	s, _ := fixtureServer(t)
	for _, tc := range []struct {
		method, path string
		status       int
	}{
		{"GET", "/readyz", 200}, {"HEAD", "/readyz", 405}, {"POST", "/readyz", 405},
		{"GET", "/mutate-agent", 405}, {"POST", "/mutate-agent", 400},
		{"GET", "/", 404}, {"GET", "/metrics", 404}, {"GET", "/debug/pprof", 404},
		{"POST", "/mutate-agent/", 404}, {"GET", "/readyz/", 404}, {"GET", "/secret-token", 404},
	} {
		w := httptest.NewRecorder()
		s.Handler.ServeHTTP(w, httptest.NewRequest(tc.method, tc.path, nil))
		if w.Code != tc.status || strings.Contains(w.Body.String(), "secret-token") {
			t.Fatalf("%s %s: unexpected response status/body", tc.method, tc.path)
		}
		if tc.status == 200 && w.Body.String() != "ready\n" {
			t.Fatal("unexpected readiness body")
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	w := httptest.NewRecorder()
	s.Handler.ServeHTTP(w, httptest.NewRequest("GET", "/readyz", nil).WithContext(ctx))
	if w.Code != http.StatusServiceUnavailable {
		t.Fatal("cancelled server is ready")
	}
}

func TestAdmissionDelegation(t *testing.T) {
	s, _ := fixtureServer(t)
	cfg := fixtureConfig(t)
	no := false
	pod := corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Namespace: cfg.namespace, Labels: map[string]string{
			"app.kubernetes.io/name": "tailnet-ingress", "app.kubernetes.io/managed-by": "tailnet-operator",
		}},
		Spec: corev1.PodSpec{AutomountServiceAccountToken: &no, Containers: []corev1.Container{{
			Name: "agent", Image: cfg.agentImage, Command: []string{"/tailnet-agent"},
			Env: []corev1.EnvVar{{Name: "SSL_CERT_FILE", Value: "/ca-certificates.crt"}, {Name: "AGENT_MODE", Value: "ingress"}},
		}}},
	}
	for _, foreign := range []bool{false, true} {
		if foreign {
			pod.Spec.Containers[0].Image = "localhost/agent:foreign"
		}
		raw, err := json.Marshal(pod)
		if err != nil {
			t.Fatal(err)
		}
		req := &admissionv1.AdmissionRequest{
			UID: "test", Operation: admissionv1.Create, Namespace: cfg.namespace,
			Kind:     metav1.GroupVersionKind{Version: "v1", Kind: "Pod"},
			Resource: metav1.GroupVersionResource{Version: "v1", Resource: "pods"}, Object: kruntime.RawExtension{Raw: raw},
		}
		body, err := json.Marshal(admissionv1.AdmissionReview{
			TypeMeta: metav1.TypeMeta{APIVersion: "admission.k8s.io/v1", Kind: "AdmissionReview"}, Request: req,
		})
		if err != nil {
			t.Fatal(err)
		}
		w := httptest.NewRecorder()
		r := httptest.NewRequest("POST", "/mutate-agent", bytes.NewReader(body))
		r.Header.Set("Content-Type", "application/json")
		s.Handler.ServeHTTP(w, r)
		var got admissionv1.AdmissionReview
		if w.Code != http.StatusOK || json.Unmarshal(w.Body.Bytes(), &got) != nil || got.Response == nil || got.Response.Allowed == foreign {
			t.Fatal("unexpected admission result")
		}
		if !foreign {
			want, err := kindfixture.AgentCAPatch(req, kindfixture.AgentCAConfig{Namespace: cfg.namespace, Image: cfg.agentImage, ConfigMap: cfg.caConfigMap})
			if err != nil || !bytes.Equal(got.Response.Patch, want) {
				t.Fatal("delegated patch differs")
			}
		}
	}
}

func tlsClient(t *testing.T, cert []byte, version uint16) *http.Client {
	t.Helper()
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(cert) {
		t.Fatal("invalid test root")
	}
	transport := &http.Transport{TLSClientConfig: &tls.Config{
		RootCAs: roots, ServerName: fixtureConfig(t).serviceDNS(), MinVersion: version, MaxVersion: version,
	}}
	t.Cleanup(transport.CloseIdleConnections)
	return &http.Client{Transport: transport, Timeout: 2 * time.Second}
}

func TestHTTPSAndCancellation(t *testing.T) {
	s, cert := fixtureServer(t)
	// Only httptest allocates a loopback listener; the fixed production listener
	// and mounted certificate paths are never used by unit tests.
	ts := httptest.NewUnstartedServer(nil)
	defer ts.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- serve(ctx, s, ts.Listener) }()
	url := "https://" + ts.Listener.Addr().String() + "/readyz"
	for _, version := range []uint16{tls.VersionTLS12, tls.VersionTLS13} {
		resp, err := tlsClient(t, cert, version).Get(url)
		if err != nil {
			t.Fatal("TLS request failed:", err)
		}
		body, err := io.ReadAll(resp.Body)
		resp.Body.Close()
		if err != nil || resp.StatusCode != 200 || string(body) != "ready\n" || resp.TLS.Version != version {
			t.Fatal("unexpected TLS readiness response")
		}
	}
	resp, err := tlsClient(t, cert, tls.VersionTLS11).Get(url)
	if err == nil {
		resp.Body.Close()
		t.Fatal("TLS 1.1 accepted")
	}
	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(shutdownTimeout + time.Second):
		t.Fatal("server failed to stop")
	}
	if resp, err := tlsClient(t, cert, tls.VersionTLS12).Get(url); err == nil {
		resp.Body.Close()
		t.Fatal("listener remains open after cancellation")
	}
}

func TestCancellationDrainsActiveRequest(t *testing.T) {
	s, cert := fixtureServer(t)
	started := make(chan struct{})
	finished := make(chan struct{})
	s.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		close(started)
		<-r.Context().Done()
		w.WriteHeader(http.StatusServiceUnavailable)
		close(finished)
	})
	ts := httptest.NewUnstartedServer(nil)
	defer ts.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- serve(ctx, s, ts.Listener) }()
	client := tlsClient(t, cert, tls.VersionTLS13)
	requestDone := make(chan error, 1)
	go func() {
		resp, err := client.Get("https://" + ts.Listener.Addr().String() + "/readyz")
		if err == nil {
			resp.Body.Close()
			if resp.StatusCode != http.StatusServiceUnavailable {
				err = errors.New("unexpected shutdown response")
			}
		}
		requestDone <- err
	}()
	select {
	case <-started:
	case <-time.After(3 * time.Second):
		t.Fatal("request did not start")
	}
	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(shutdownTimeout + time.Second):
		t.Fatal("active request prevented shutdown")
	}
	select {
	case <-finished:
	default:
		t.Fatal("server did not drain handler")
	}
	select {
	case err := <-requestDone:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("client did not finish")
	}
}

func TestServeCancelledBeforeStart(t *testing.T) {
	s, _ := fixtureServer(t)
	ts := httptest.NewUnstartedServer(nil)
	defer ts.Close()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := serve(ctx, s, ts.Listener); err != nil {
		t.Fatal(err)
	}
	if _, err := ts.Listener.Accept(); err == nil {
		t.Fatal("cancelled listener remains open")
	}
}

func TestServeListenerFailure(t *testing.T) {
	s, _ := fixtureServer(t)
	ts := httptest.NewUnstartedServer(nil)
	defer ts.Close()
	if err := ts.Listener.Close(); err != nil {
		t.Fatal(err)
	}
	if err := serve(context.Background(), s, ts.Listener); !errors.Is(err, errServe) {
		t.Fatal("unexpected listener failure category")
	}
}
