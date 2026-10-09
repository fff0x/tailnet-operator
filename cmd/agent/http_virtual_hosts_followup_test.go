package main

import (
	"crypto/tls"
	"crypto/x509"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// Each backend has its own concrete name, leaf and CA, so neither request nor
// probe success can be obtained with a sibling's verifier/SNI selection.
func virtualTLSBackends(t *testing.T, targets []target, missingCA int) [][]byte {
	t.Helper()
	cas := make([][]byte, len(targets))
	for i := range targets {
		name := targets[i].Name + ".backend.test"
		frontendName := targets[i].DNSName
		cert, ca := backendCertificateFor(t, name, time.Now().Add(time.Hour))
		cas[i] = ca
		var pair atomic.Pointer[tls.Certificate]
		pair.Store(&cert)
		backend := backendTestServer(t, &pair, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.TLS.ServerName != name || !matchesHTTPHost(r.Host, frontendName) {
				t.Error("wrong route's backend TLS SNI or HTTP Host")
			}
			io.WriteString(w, "ok")
		}))
		targets[i].Address, targets[i].Port = "127.0.0.1", backend.Listener.Addr().(*net.TCPAddr).Port
		targets[i].BackendServerName = name
		targets[i].BackendCAFile = filepath.Join(t.TempDir(), "ca.crt")
		if i != missingCA {
			if err := os.WriteFile(targets[i].BackendCAFile, ca, 0600); err != nil {
				t.Fatal(err)
			}
		}
	}
	return cas
}

func TestVirtualHostBackendCAMissingAtStartup(t *testing.T) {
	for _, missing := range []int{0, 1} {
		t.Run([]string{"a", "b"}[missing], func(t *testing.T) {
			targets := virtualHostTargets(t)
			cas := virtualTLSBackends(t, targets, missing)
			fw, h, _ := virtualForwarder(t, targets)
			before := watcherRunning(fw)
			clients := []*http.Client{virtualClient(t, h, targets[0], true), virtualClient(t, h, targets[1], true)}
			for i, cfg := range targets {
				status := 200
				if i == missing {
					status = 502
				}
				virtualGET(t, clients[i], cfg, "/", status)
			}
			p := &prober{}
			p.probe(t.Context(), fw)
			if healthCode(p, fw, "Running") != 503 {
				t.Fatal("missing startup CA certified aggregate readiness")
			}
			for _, proof := range p.snapshotFor(fw) {
				bad := proof.Name == targets[missing].Name
				if proof.TLSReady == nil || !*proof.TLSReady || proof.BackendReachable == nil || proof.Reachable == bad || *proof.BackendReachable == bad {
					t.Fatalf("startup trust failure leaked across routes: %+v", proof)
				}
				if bad && (proof.BackendTLSReason != backendCAUnavailable || proof.BackendCAHash != "") {
					t.Fatalf("missing startup CA proof: %+v", proof)
				}
			}
			if err := os.WriteFile(targets[missing].BackendCAFile, cas[missing], 0600); err != nil {
				t.Fatal(err)
			}
			for i, cfg := range targets {
				virtualGET(t, clients[i], cfg, "/", 200)
				verifier, _, err := h.routes[cfg.DNSName].transport.proofConfig()
				if err != nil || verifier.ServerName != cfg.BackendServerName || verifier.InsecureSkipVerify || verifier.RootCAs == nil {
					t.Fatal("wrong per-route verifier after startup recovery", err)
				}
			}
			if healthCode(p, fw, "Running") != 503 {
				t.Fatal("CA appearance resurrected proof without a fresh probe")
			}
			p.probe(t.Context(), fw)
			if healthCode(p, fw, "Running") != 200 {
				t.Fatal("startup CA appearance did not recover both routes")
			}
			after := watcherRunning(fw)
			for name, r := range before {
				if after[name].ln != r.ln || after[name].generation != r.generation {
					t.Fatal("CA recovery required a group restart")
				}
			}
		})
	}
}

func TestVirtualHostServingCacheSANRemoval(t *testing.T) {
	for _, missing := range []string{baseDNS, testDNS, "b.example.test"} {
		t.Run(missing, func(t *testing.T) {
			targets := virtualHostTargets(t)
			_, h, _ := virtualForwarder(t, targets)
			handshake := func(cfg target, wantOK bool) {
				t.Helper()
				// Verify server-side policy, not client trust. No health/probe calls.
				c, err := tls.DialWithDialer(&net.Dialer{Timeout: time.Second}, "tcp", h.Addr().String(), &tls.Config{ServerName: cfg.DNSName, InsecureSkipVerify: true})
				if !wantOK {
					if err == nil {
						c.Close()
						t.Fatal("public handshake served a certificate missing a required SAN")
					}
					return
				}
				if err != nil {
					t.Fatal("cached valid pair unavailable", err)
				}
				defer c.Close()
				if c.ConnectionState().PeerCertificates[0].SerialNumber.Int64() != 1 {
					t.Fatal("handshake did not serve the cached valid pair")
				}
			}
			handshake(targets[0], true) // Populate cache through the public listener only.
			testCertificate(t, filepath.Dir(targets[0].CertFile), testDNS, time.Now().Add(-time.Hour), time.Now().Add(time.Hour), 2, func(c *x509.Certificate) {
				c.DNSNames = nil
				for _, name := range virtualNames(targets) {
					if name != missing {
						c.DNSNames = append(c.DNSNames, name)
					}
				}
			})
			for _, cfg := range targets {
				handshake(cfg, true) // A valid cached pair remains usable within the bound.
			}
			// Simulated cache age, NOT evidence of a minute-long wall-clock run.
			h.certs.mu.Lock()
			h.certs.checked = time.Now().Add(-time.Minute - time.Second)
			h.certs.mu.Unlock()
			for _, cfg := range targets {
				handshake(cfg, false)
			}
		})
	}
}

// Establishes a Go synchronization edge before any accepted connection can read
// the test-installed TLS callback. No production callback/clock seam is needed.
type agentAcceptGate struct {
	net.Listener
	ready <-chan struct{}
}

func (l *agentAcceptGate) Accept() (net.Conn, error) {
	<-l.ready
	return l.Listener.Accept()
}

func TestVirtualHostReloadFencesDelayedSNIMetrics(t *testing.T) {
	targets := virtualHostTargets(t)
	for i := range targets {
		virtualBackend(t, &targets[i], http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(204) }))
	}
	path := filepath.Join(t.TempDir(), "targets.json")
	writeV3Targets(t, path, targets, virtualNames(targets))
	ready := make(chan struct{})
	var readyOnce sync.Once
	openAccept := func() { readyOnce.Do(func() { close(ready) }) }
	fw := &forwarder{mode: "ingress", run: make(map[string]running), metrics: newAgentMetrics("ingress"), listenTailnet: func(_, _ string) (net.Listener, error) {
		ln, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			return nil, err
		}
		return &agentAcceptGate{Listener: ln, ready: ready}, nil
	}}
	t.Cleanup(fw.stopAll)
	t.Cleanup(openAccept) // Always release Accept before cleanup closes the server.
	if pending, err := fw.reload(t.Context(), path); err != nil || pending != 0 {
		t.Fatal(pending, err)
	}
	old := watcherRunning(fw)
	h := old["a"].ln.(*httpIngress)
	entered := make(chan *tls.ClientHelloInfo, 1)
	release, callbackDone := make(chan struct{}), make(chan struct{})
	var releaseOnce sync.Once
	unblock := func() { releaseOnce.Do(func() { close(release) }) }
	t.Cleanup(unblock)
	original := h.srv.TLSConfig.GetCertificate
	h.srv.TLSConfig.GetCertificate = func(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
		entered <- hello
		<-release // Deliberately let old accepted TLS work outlive group retirement.
		defer close(callbackDone)
		return original(hello)
	}
	openAccept()
	conn, err := net.DialTimeout("tcp", h.Addr().String(), time.Second)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { conn.Close() })
	conn.SetDeadline(time.Now().Add(5 * time.Second))
	client := tls.Client(conn, &tls.Config{ServerName: targets[1].DNSName, InsecureSkipVerify: true})
	handshakeDone := make(chan struct{})
	go func() {
		defer close(handshakeDone)
		_ = client.HandshakeContext(t.Context())
		client.Close()
	}()
	t.Cleanup(func() {
		unblock()
		conn.Close()
		awaitAgentSignal(t, handshakeDone, "old client cleanup")
	})
	var hello *tls.ClientHelloInfo
	select {
	case hello = <-entered:
	case <-time.After(3 * time.Second):
		t.Fatal("accepted TLS connection never reached pre-SNI gate")
	}
	t.Cleanup(func() {
		unblock()
		awaitAgentSignal(t, callbackDone, "old callback cleanup")
	})
	tracked, ok := hello.Conn.(*trackedConn)
	if !ok {
		t.Fatal("gate is not on a real accepted connection")
	}
	measured, ok := tracked.Conn.(*sniMeasuredConn)
	if !ok {
		t.Fatal("accepted connection lacks SNI metrics")
	}
	measured.mu.Lock()
	selected, closed := measured.selected, measured.closed
	measured.mu.Unlock()
	if selected || closed || metricValue(t, fw.metrics, "tailnet_agent_http_unattributed_connections_active", "", "") != 1 {
		t.Fatal("connection was not delayed before SNI attribution")
	}
	// Actual withdrawal and identical recreation, never manual metric deletion.
	writeV3Targets(t, path, []target{}, []string{})
	reloaded := make(chan struct{})
	var reloadErr error
	var pending int
	go func() {
		pending, reloadErr = fw.reload(t.Context(), path)
		close(reloaded)
	}()
	awaitAgentSignal(t, reloaded, "retirement while old TLS callback is gated")
	if reloadErr != nil || pending != 0 || len(watcherRunning(fw)) != 0 || h.active() {
		t.Fatal("group retirement failed", pending, reloadErr)
	}
	writeV3Targets(t, path, targets, virtualNames(targets))
	if pending, err := fw.reload(t.Context(), path); err != nil || pending != 0 {
		t.Fatal("group recreation failed", pending, err)
	}
	current := watcherRunning(fw)
	next := current["a"].ln.(*httpIngress)
	for _, cfg := range targets {
		if current[cfg.Name].generation <= old[cfg.Name].generation || next == h || next.routes[cfg.DNSName].metrics.active == h.routes[cfg.DNSName].metrics.active {
			t.Fatal("reload did not replace listener/metric generation")
		}
		client := virtualClient(t, next, cfg, false)
		virtualGET(t, client, cfg, "/", 204)
		// sniMeasuredConn counts bytes after Conn.Write returns, so the client can
		// finish reading before the server goroutine adds them. Close the keep-alive
		// connection and wait for its Close (which runs after the last Write) so the
		// snapshot below cannot race the new generation's own accounting.
		client.CloseIdleConnections()
		for deadline := time.Now().Add(3 * time.Second); metricValue(t, fw.metrics, "tailnet_agent_connections_active", "expose", cfg.Name) != 0; {
			if time.Now().After(deadline) {
				t.Fatalf("%s: new-generation connection did not close", cfg.Name)
			}
			time.Sleep(10 * time.Millisecond)
		}
	}
	// Snapshot all per-target connection, wire-byte directions and dial counts.
	snapshot := func() map[string]float64 {
		out := make(map[string]float64)
		families, err := fw.metrics.registry.Gather()
		if err != nil {
			t.Fatal(err)
		}
		for _, family := range families {
			for _, m := range family.Metric {
				key := family.GetName()
				for _, label := range m.Label {
					if strings.Contains(label.GetValue(), ".example.test") || strings.Contains(strings.ToLower(label.GetName()), "sni") || strings.Contains(strings.ToLower(label.GetName()), "host") {
						t.Fatal("raw SNI/Host metric label", label)
					}
					key += "/" + label.GetName() + "=" + label.GetValue()
				}
				if !strings.Contains(key, "/expose=") {
					continue
				}
				switch {
				case m.Gauge != nil:
					out[key] = m.Gauge.GetValue()
				case m.Counter != nil:
					out[key] = m.Counter.GetValue()
				case m.Histogram != nil:
					out[key] = float64(m.Histogram.GetSampleCount())
				}
			}
		}
		return out
	}
	before := snapshot()
	for _, cfg := range targets {
		if metricValue(t, fw.metrics, "tailnet_agent_bytes_total", "expose", cfg.Name) == 0 || metricValue(t, fw.metrics, "tailnet_agent_dial_duration_seconds", "expose", cfg.Name) != 1 {
			t.Fatal("new generation was not populated by its own request")
		}
	}
	unblock()
	awaitAgentSignal(t, callbackDone, "old GetCertificate return")
	awaitAgentSignal(t, handshakeDone, "old TLS handshake exit")
	// Idempotent delayed close of the actual old accepted connection.
	measured.Close()
	measured.mu.Lock()
	selected, closed = measured.selected, measured.closed
	measured.mu.Unlock()
	if selected || !closed {
		t.Fatal("retired connection admitted delayed SNI selection")
	}
	after := snapshot()
	if len(before) == 0 || len(before) != len(after) {
		t.Fatal("metric snapshot is empty or changed shape")
	}
	for key, value := range before {
		if after[key] != value {
			t.Fatalf("old TLS work contaminated new metric generation: %s: %v -> %v", key, value, after[key])
		}
	}
	if metricValue(t, fw.metrics, "tailnet_agent_http_unattributed_connections_active", "", "") != 0 {
		t.Fatal("old unattributed connection gauge leaked")
	}
}
