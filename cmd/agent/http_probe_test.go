package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"tailscale.com/ipn/ipnstate"
)

type fixedStatus string

func (s fixedStatus) Status(context.Context) (*ipnstate.Status, error) {
	return &ipnstate.Status{BackendState: string(s)}, nil
}

func probeIngress(t *testing.T, cfg target) *httpIngress {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	h, err := serveHTTPIngress(context.Background(), ln, cfg, func(context.Context, target) (net.Conn, error) {
		return nil, errors.New("not used by component probe")
	})
	if err != nil {
		ln.Close()
		t.Fatal(err)
	}
	t.Cleanup(func() { h.Close() })
	return h
}

func probeForwarder(h *httpIngress, cfg target) *forwarder {
	return &forwarder{mode: "ingress", desired: []target{cfg}, run: map[string]running{
		cfg.Name: {t: cfg, ln: h, cancel: func() {}, generation: 1},
	}}
}

func healthCode(p *prober, fw *forwarder, state string) int {
	rr := httptest.NewRecorder()
	healthMux(fixedStatus(state), fw, p).ServeHTTP(rr, httptest.NewRequest("GET", "/healthz", nil))
	return rr.Code
}

func TestHTTPLocalTLSAndBackendReadiness(t *testing.T) {
	h, cfg, metrics := measuredHTTPIngress(t, context.Background(), http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	cfg.ConfigID = "static-source-revision"
	fw := probeForwarder(h, cfg)
	fw.metrics = metrics
	p := &prober{}
	if healthCode(p, fw, "Running") != 503 {
		t.Fatal("HTTP without a probe passed readiness")
	}
	p.probe(context.Background(), fw)
	r := p.snapshotFor(fw)[0]
	if !r.Reachable || r.BackendReachable == nil || !*r.BackendReachable || r.TLSReady == nil || !*r.TLSReady || r.ConfigID != cfg.ConfigID || r.TLSNotAfter == nil || r.Error != "" {
		t.Fatalf("healthy local components: %+v", r)
	}
	cert, err := h.certs.fresh()
	if err != nil || r.TLSCertSHA256 != leafSHA256(cert.Leaf) || !r.TLSNotAfter.Equal(cert.Leaf.NotAfter) {
		t.Fatal("wrong presented leaf observation")
	}
	if healthCode(p, fw, "Running") != 200 || healthCode(p, fw, "Starting") != 503 {
		t.Fatal("readiness did not combine Running with local components")
	}
	if metricValue(t, metrics, "tailnet_agent_dial_duration_seconds", "", "") != 1 {
		t.Fatal("backend probe missing generation-bound metric")
	}
	if metricValue(t, metrics, "tailnet_agent_connections_active", "", "") != 0 {
		t.Fatal("local TLS component probe traversed public listener")
	}
	// Backend failure is separate from successful local TLS proof and is always redacted.
	probe := fw.probeTargets()[0]
	probe.dial = func(context.Context, target) (net.Conn, error) {
		return nil, errors.New("PRIVATE KEY /secret/path user:password")
	}
	p.publish(fw, probeOne(context.Background(), probe))
	r = p.snapshotFor(fw)[0]
	if r.Reachable || *r.BackendReachable || !*r.TLSReady || r.Error != "backend TCP probe failed" || healthCode(p, fw, "Running") != 503 {
		t.Fatalf("backend/TLS evidence not separated: %+v", r)
	}
	encoded, _ := json.Marshal(r)
	for _, forbidden := range []string{"PRIVATE", "/secret", cfg.CertFile, cfg.KeyFile} {
		if strings.Contains(string(encoded), forbidden) {
			t.Fatal("health leaked private diagnostics")
		}
	}
}

func TestHTTPLocalTLSRejectsInvalidCertificates(t *testing.T) {
	for _, kind := range []string{"wrong-san", "expired", "future", "mismatched-key", "invalid-pem", "missing", "ca", "unknown-critical"} {
		t.Run(kind, func(t *testing.T) {
			now := time.Now()
			dns, before, after := testDNS, now.Add(-time.Hour), now.Add(time.Hour)
			if kind == "wrong-san" {
				dns = "wrong.example.test"
			}
			if kind == "expired" {
				after = now.Add(-time.Second)
			}
			if kind == "future" {
				before = now.Add(time.Minute)
			}
			cfg := testCertificate(t, t.TempDir(), dns, before, after, 1, func(c *x509.Certificate) {
				if kind == "ca" {
					c.IsCA, c.BasicConstraintsValid = true, true
				}
				if kind == "unknown-critical" {
					c.ExtraExtensions = []pkix.Extension{{Id: asn1.ObjectIdentifier{1, 2, 3, 4}, Critical: true, Value: []byte{5, 0}}}
				}
			})
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
			h := probeIngress(t, cfg)
			proof, err := h.probeTLS(context.Background())
			if !errors.Is(err, errLocalTLS) || proof.sha256 != "" {
				t.Fatal("invalid material certified or diagnostics escaped")
			}
		})
	}
}

func TestHTTPLocalTLSIndependentVerification(t *testing.T) {
	cfg := validHTTPTarget(t)
	cert, err := (&certificateSource{t: cfg}).fresh()
	if err != nil {
		t.Fatal(err)
	}
	// Failed TLS peers may both write alerts on an unbuffered pipe; cancellation must bound
	// that exchange too. Keep rejection cases short without weakening production deadlines.
	rejected := func(server *tls.Config, dns string) {
		t.Helper()
		ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
		defer cancel()
		if proof, err := localTLSHandshake(ctx, server, cert.Leaf, dns); !errors.Is(err, errLocalTLS) || proof.sha256 != "" {
			t.Fatal("invalid handshake produced a TLS observation")
		}
	}
	for _, version := range []uint16{tls.VersionTLS12, tls.VersionTLS13} {
		server := &tls.Config{MinVersion: version, MaxVersion: version, Certificates: []tls.Certificate{*cert}, SessionTicketsDisabled: true}
		proof, err := localTLSHandshake(context.Background(), server, cert.Leaf, testDNS)
		if err != nil || proof.sha256 != leafSHA256(cert.Leaf) {
			t.Fatal("TLS handshake failed", err)
		}
		rejected(server, "wrong.example.test")
	}
	other, err := (&certificateSource{t: validHTTPTarget(t)}).fresh()
	if err != nil {
		t.Fatal(err)
	}
	// Files/selected leaf alone are not sufficient: a different presented leaf must fail.
	server := &tls.Config{MinVersion: tls.VersionTLS12, Certificates: []tls.Certificate{*other}, SessionTicketsDisabled: true}
	rejected(server, testDNS)
	server = &tls.Config{MinVersion: tls.VersionTLS10, MaxVersion: tls.VersionTLS11, Certificates: []tls.Certificate{*cert}}
	rejected(server, testDNS)
}

func TestHTTPProofProjectionRotationAndInvalidation(t *testing.T) {
	dir := t.TempDir()
	now := time.Now()
	cfg := testCertificate(t, filepath.Join(dir, "a"), testDNS, now.Add(-time.Hour), now.Add(time.Hour), 1)
	testCertificate(t, filepath.Join(dir, "b"), testDNS, now.Add(-time.Hour), now.Add(time.Hour), 2)
	link := func(from, to string) {
		t.Helper()
		if err := os.Symlink(from, to); err != nil {
			t.Fatal(err)
		}
	}
	link("a", filepath.Join(dir, "..data"))
	link("..data/tls.crt", filepath.Join(dir, "tls.crt"))
	link("..data/tls.key", filepath.Join(dir, "tls.key"))
	cfg.CertFile, cfg.KeyFile = filepath.Join(dir, "tls.crt"), filepath.Join(dir, "tls.key")
	h := probeIngress(t, cfg)
	fw := probeForwarder(h, cfg)
	p := &prober{}
	probe := fw.probeTargets()[0]
	probe.dial = func(context.Context, target) (net.Conn, error) { a, b := net.Pipe(); b.Close(); return a, nil }
	p.publish(fw, probeOne(context.Background(), probe))
	old := p.snapshotFor(fw)[0]
	if !old.Reachable {
		t.Fatal("initial probe failed")
	}
	ln := h.Listener
	link("b", filepath.Join(dir, "..next"))
	if err := os.Rename(filepath.Join(dir, "..next"), filepath.Join(dir, "..data")); err != nil {
		t.Fatal(err)
	}
	// No one-minute cache timeout or periodic probe has elapsed. Fresh health must invalidate.
	r := p.snapshotFor(fw)[0]
	if *r.TLSReady || r.TLSCertSHA256 != "" || r.TLSNotAfter != nil || healthCode(p, fw, "Running") != 503 {
		t.Fatal("rotation retained old successful observation")
	}
	p.publish(fw, probeOne(context.Background(), probe))
	r = p.snapshotFor(fw)[0]
	if !r.Reachable || r.TLSCertSHA256 == old.TLSCertSHA256 || h.Listener != ln {
		t.Fatal("rotation did not obtain a new proof on the same public listener")
	}
	if err := os.Remove(cfg.KeyFile); err != nil {
		t.Fatal(err)
	}
	if healthCode(p, fw, "Running") != 503 {
		t.Fatal("missing key retained cached TLS proof")
	}
	link("..data/tls.key", cfg.KeyFile)
	if healthCode(p, fw, "Running") != 503 {
		t.Fatal("invalidated observation resurrected without handshake")
	}
	p.publish(fw, probeOne(context.Background(), probe))
	if healthCode(p, fw, "Running") != 200 {
		t.Fatal("restored material did not recover on new proof")
	}
}

func TestHTTPReadinessStaleExpiryMissingAndL4(t *testing.T) {
	h, cfg, _ := measuredHTTPIngress(t, context.Background(), http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	fw := probeForwarder(h, cfg)
	p := &prober{}
	p.probe(context.Background(), fw)
	p.mu.Lock()
	r := p.results[cfg.Name]
	r.LastProbe = time.Now().Add(-httpProofMaxAge - time.Second)
	p.results[cfg.Name] = r
	p.mu.Unlock()
	if healthCode(p, fw, "Running") != 503 {
		t.Fatal("stale proof passed readiness")
	}
	p.probe(context.Background(), fw)
	// Advance only certificateSource's clock beyond expiry, still within a minute of cache read.
	h.certs.mu.Lock()
	expired := h.certs.cert.Leaf.NotAfter
	h.certs.now = func() time.Time { return expired }
	h.certs.checked = expired.Add(-time.Second)
	h.certs.mu.Unlock()
	if healthCode(p, fw, "Running") != 503 {
		t.Fatal("expired source proof passed readiness")
	}
	r = p.snapshotFor(fw)[0]
	if *r.TLSReady || r.TLSCertSHA256 != "" || r.TLSNotAfter != nil {
		t.Fatal("expired proof disclosed fingerprint")
	}
	fw.mu.Lock()
	delete(fw.run, cfg.Name) // desired still contains the HTTP listener (failed bind)
	fw.mu.Unlock()
	if healthCode(p, fw, "Running") != 503 || len(p.snapshotFor(fw)) != 1 {
		t.Fatal("missing bind disappeared from readiness")
	}
	fw.mu.Lock()
	fw.desired = []target{{Name: "l4"}}
	fw.mu.Unlock()
	if healthCode(p, fw, "Running") != 200 || healthCode(p, fw, "Starting") != 503 {
		t.Fatal("L4 readiness changed")
	}
	encoded, _ := json.Marshal(probeResult{Name: "l4", Reachable: true})
	for _, field := range []string{"configID", "tlsReady", "tlsCertSHA256", "tlsNotAfter", "backendReachable"} {
		if strings.Contains(string(encoded), field) {
			t.Fatal("L4 leaked optional HTTP fields")
		}
	}
}

func TestHTTPProbeRejectsSameNameRecreation(t *testing.T) {
	cfg := validHTTPTarget(t)
	h := probeIngress(t, cfg)
	fw := probeForwarder(h, cfg)
	p := &prober{}
	old := fw.probeTargets()[0]
	entered, release, done := make(chan struct{}), make(chan struct{}), make(chan struct{})
	old.dial = func(ctx context.Context, _ target) (net.Conn, error) {
		close(entered)
		<-release
		// Listener closure schedules cancellation through context.AfterFunc; it may
		// not have reached this dial yet. Never return the invalid (nil, nil) pair.
		<-ctx.Done()
		return nil, ctx.Err()
	}
	go func() { defer close(done); p.publish(fw, probeOne(context.Background(), old)) }()
	<-entered // old local TLS succeeded; its backend observation is in flight
	h.Close()
	replacement := probeIngress(t, cfg)
	fw.mu.Lock()
	delete(fw.run, cfg.Name)
	fw.run[cfg.Name] = running{t: cfg, ln: replacement, cancel: func() {}, generation: 2}
	fw.mu.Unlock()
	close(release)
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("old probe did not finish")
	}
	if len(p.snapshot()) != 0 || healthCode(p, fw, "Running") != 503 {
		t.Fatal("old proof certified recreated target")
	}
	// Even identical listener/static fields cannot cross a generation boundary.
	current := fw.probeTargets()[0]
	fw.mu.Lock()
	r := fw.run[cfg.Name]
	r.generation++
	fw.run[cfg.Name] = r
	fw.mu.Unlock()
	p.publish(fw, probeResult{Name: cfg.Name, owner: current, Reachable: true})
	if len(p.snapshot()) != 0 {
		t.Fatal("ABA generation was accepted")
	}
}

func TestHTTPLocalTLSCancellationAndClosureJoin(t *testing.T) {
	cfg := validHTTPTarget(t)
	h := probeIngress(t, cfg)
	original := h.srv.TLSConfig.GetCertificate
	entered, exited := make(chan struct{}), make(chan struct{})
	h.srv.TLSConfig.GetCertificate = func(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
		close(entered)
		defer close(exited)
		<-hello.Context().Done()
		return original(hello)
	}
	done := make(chan error, 1)
	go func() { _, err := h.probeTLS(context.Background()); done <- err }()
	<-entered
	closed := make(chan struct{})
	go func() { h.Close(); close(closed) }()
	select {
	case <-closed:
	case <-time.After(time.Second):
		t.Fatal("Close did not cancel/join local TLS probe")
	}
	select {
	case <-exited:
	default:
		t.Fatal("server handshake outlived Close")
	}
	if err := <-done; !errors.Is(err, errLocalTLS) {
		t.Fatal("closed owner certified TLS")
	}
	if _, err := h.probeTLS(context.Background()); !errors.Is(err, errLocalTLS) {
		t.Fatal("closed listener certified TLS")
	}
	// A canceled caller must also join both handshake sides without requiring owner closure.
	cert, err := (&certificateSource{t: cfg}).fresh()
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	entered = make(chan struct{})
	server := &tls.Config{MinVersion: tls.VersionTLS12, GetCertificate: func(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
		close(entered)
		<-hello.Context().Done()
		return nil, errLocalTLS
	}}
	go func() { _, err := localTLSHandshake(ctx, server, cert.Leaf, testDNS); done <- err }()
	<-entered
	cancel()
	select {
	case err := <-done:
		if !errors.Is(err, errLocalTLS) {
			t.Fatal("canceled handshake succeeded")
		}
	case <-time.After(time.Second):
		t.Fatal("canceled handshake leaked")
	}
}

func TestHTTPProbeBoundedConcurrencyAndL4Isolation(t *testing.T) {
	h, cfg, _ := measuredHTTPIngress(t, context.Background(), http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	fw := probeForwarder(h, cfg)
	var active, maximum, started atomic.Int32
	for i := range 32 {
		name := fmt.Sprintf("dead-%d", i)
		fw.run[name] = running{t: target{Name: name}, generation: 1}
	}
	probes := fw.probeTargets()
	for i := range probes {
		if probes[i].t.Mode == "http" {
			continue
		}
		probes[i].dial = func(ctx context.Context, _ target) (net.Conn, error) {
			n := active.Add(1)
			defer active.Add(-1)
			started.Add(1)
			for old := maximum.Load(); n > old && !maximum.CompareAndSwap(old, n); old = maximum.Load() {
			}
			<-ctx.Done()
			return nil, ctx.Err()
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	p := &prober{}
	done := make(chan struct{})
	go func() { p.probeBatch(ctx, fw, probes, false); close(done) }()
	deadline := time.NewTimer(time.Second)
	defer deadline.Stop()
	tick := time.NewTicker(time.Millisecond)
	defer tick.Stop()
	for {
		ready := false
		for _, r := range p.snapshot() {
			ready = ready || (r.Name == cfg.Name && r.Reachable)
		}
		if ready && started.Load() == 32 {
			break
		}
		select {
		case <-deadline.C:
			t.Fatal("dead L4 probes starved local HTTP proof")
		case <-tick.C:
		}
	}
	if maximum.Load() > probeWorkers {
		t.Fatal("unbounded dial concurrency")
	}
	cancel()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("canceled batch leaked workers")
	}
	if active.Load() != 0 {
		t.Fatal("dial outlived joined worker batch")
	}
}

func TestHTTPDisabledProbeFailsClosed(t *testing.T) {
	cfg := validHTTPTarget(t)
	h := probeIngress(t, cfg)
	fw := probeForwarder(h, cfg)
	p := &prober{}
	p.loop(context.Background(), nil, fw, 0)
	if len(p.snapshot()) != 0 || healthCode(p, fw, "Running") != 503 {
		t.Fatal("disabled HTTP probing passed readiness")
	}
	if httpProbeInterval+probeTimeout > httpProofMaxAge || httpProofMaxAge > 30*time.Second {
		t.Fatal("HTTP cadence allows stale readiness")
	}
}
