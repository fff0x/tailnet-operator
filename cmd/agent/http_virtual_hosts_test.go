package main

import (
	"bufio"
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

const baseDNS = "base.example.test"

func virtualHostTargets(t *testing.T) []target {
	t.Helper()
	a := testCertificate(t, t.TempDir(), testDNS, time.Now().Add(-time.Hour), time.Now().Add(time.Hour), 1, func(c *x509.Certificate) {
		c.DNSNames = []string{baseDNS, testDNS, "b.example.test"}
	})
	a.Name, a.ConfigID = "a", "revision-a"
	b := a
	b.Name, b.DNSName, b.ConfigID = "b", "b.example.test", "revision-b"
	return []target{a, b}
}

func virtualNames(targets []target) []string {
	names := []string{baseDNS}
	for _, t := range targets {
		if t.Mode == "http" {
			names = append(names, t.DNSName)
		}
	}
	return names
}

// Exercise production reload/listener/proxy/metrics ownership, replacing only tsnet's bind with
// an owned local socket. This is not a tailnet-connectivity or cluster acceptance fixture.
func virtualForwarder(t *testing.T, targets []target) (*forwarder, *httpIngress, string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "targets.json")
	writeV3Targets(t, path, targets, virtualNames(targets))
	fw := &forwarder{mode: "ingress", run: make(map[string]running), metrics: newAgentMetrics("ingress"), listenTailnet: func(_, _ string) (net.Listener, error) {
		return net.Listen("tcp", "127.0.0.1:0")
	}}
	t.Cleanup(fw.stopAll)
	if pending, err := fw.reload(t.Context(), path); err != nil || pending != 0 {
		t.Fatalf("reload: %d %v", pending, err)
	}
	h, ok := fw.run[targets[0].Name].ln.(*httpIngress)
	if !ok {
		t.Fatal("missing HTTP group")
	}
	return fw, h, path
}

func virtualClient(t *testing.T, h *httpIngress, cfg target, h2 bool) *http.Client {
	t.Helper()
	client := localHTTPClient(t, h, cfg, h2)
	client.Transport.(*http.Transport).TLSClientConfig.ServerName = strings.ToUpper(cfg.DNSName)
	return client
}

func virtualBackend(t *testing.T, cfg *target, handler http.Handler) {
	t.Helper()
	backend := httptest.NewServer(handler)
	t.Cleanup(backend.Close)
	cfg.Address, cfg.Port = "127.0.0.1", backend.Listener.Addr().(*net.TCPAddr).Port
}

func virtualGET(t *testing.T, client *http.Client, cfg target, path string, want int) {
	t.Helper()
	res, err := client.Get("https://" + cfg.DNSName + path)
	if err != nil {
		t.Fatal(err)
	}
	_, err = io.Copy(io.Discard, res.Body)
	res.Body.Close()
	if err != nil || res.StatusCode != want {
		t.Fatalf("%s status=%d want=%d err=%v", cfg.Name, res.StatusCode, want, err)
	}
}

func TestVirtualHostHTTPRoutingAndMetrics(t *testing.T) {
	targets := virtualHostTargets(t)
	for i := range targets {
		cfg := targets[i]
		virtualBackend(t, &targets[i], http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if !matchesHTTPHost(r.Host, cfg.DNSName) || r.URL.RequestURI() != "/path?q=keep" {
				t.Error("wrong virtual backend, Host, path or query")
			}
			if r.Header.Get("X-Forwarded-For") != "127.0.0.1" || r.Header.Get("X-Forwarded-Port") != "" || strings.Contains(r.Header.Get("Forwarded"), "spoof") {
				t.Error("forwarding headers not sanitized per route")
			}
			io.WriteString(w, cfg.Name)
		}))
	}
	fw, h, _ := virtualForwarder(t, targets)
	if fw.run["a"].ln != fw.run["b"].ln || h.transport != nil {
		t.Fatal("HTTP targets did not share one listener or retained ambiguous transport")
	}
	for _, h2 := range []bool{false, true} {
		for _, cfg := range targets {
			client := virtualClient(t, h, cfg, h2)
			req, _ := http.NewRequest("GET", "https://"+cfg.DNSName+"/path?q=keep", nil)
			req.Host = strings.ToUpper(cfg.DNSName) + ":443"
			req.Header.Set("Forwarded", "spoof")
			req.Header.Set("X-Forwarded-For", "spoof")
			req.Header.Set("X-Forwarded-Port", "spoof")
			res, err := client.Do(req)
			if err != nil {
				t.Fatal(err)
			}
			body, err := io.ReadAll(res.Body)
			res.Body.Close()
			if err != nil || string(body) != cfg.Name || res.StatusCode != 200 || (h2 && res.ProtoMajor != 2) || (!h2 && res.ProtoMajor != 1) {
				t.Fatalf("SNI dispatch: %s %s %q %v", cfg.Name, res.Proto, body, err)
			}
			// Reuse this SNI connection for a sibling SAN: Host must never switch routes.
			req.Host = targets[0].DNSName
			if req.Host == cfg.DNSName {
				req.Host = targets[1].DNSName
			}
			res, err = client.Do(req)
			if err != nil {
				t.Fatal(err)
			}
			io.Copy(io.Discard, res.Body)
			res.Body.Close()
			if res.StatusCode != 421 {
				t.Fatal("cross-SAN coalescing not rejected")
			}
		}
	}
	for _, cfg := range targets {
		if metricValue(t, fw.metrics, "tailnet_agent_dial_duration_seconds", "expose", cfg.Name) != 1 {
			t.Fatal("backend dial attributed to wrong target or 421 reached a backend")
		}
		if metricValue(t, fw.metrics, "tailnet_agent_bytes_total", "expose", cfg.Name) == 0 || metricValue(t, fw.metrics, "tailnet_agent_connections_active", "expose", cfg.Name) != 2 {
			t.Fatal("selected SNI wire traffic not attributed per target")
		}
	}
	for _, sni := range []string{baseDNS, "unknown.example.test", "", "a..example.test"} {
		conn, err := tls.DialWithDialer(&net.Dialer{Timeout: time.Second}, "tcp", h.Addr().String(), &tls.Config{ServerName: sni, InsecureSkipVerify: true}) // tests server rejection
		if err == nil {
			conn.Close()
			t.Fatalf("non-route SNI accepted: %q", sni)
		}
	}
	if metricValue(t, fw.metrics, "tailnet_agent_http_unattributed_bytes_total", "direction", "to_target") == 0 {
		t.Fatal("pre-SNI/unknown SNI bytes missing")
	}
	if _, err := h.probeTLS(context.Background()); !errors.Is(err, errLocalTLS) {
		t.Fatal("ambiguous frontend helper chose first route")
	}
	if _, _, reason := h.probeBackendTLS(context.Background()); reason != backendTLSProofStale || h.currentBackendProof("hash", time.Now().Add(time.Hour)) {
		t.Fatal("ambiguous backend helper chose first route")
	}
	h.Close()
	for _, cfg := range targets {
		if metricValue(t, fw.metrics, "tailnet_agent_connections_active", "expose", cfg.Name) != 0 {
			t.Fatal("group shutdown retained target connections")
		}
	}
	if metricValue(t, fw.metrics, "tailnet_agent_http_unattributed_connections_active", "", "") != 0 {
		t.Fatal("group shutdown retained unattributed connections")
	}
}

func TestVirtualHostSharedCertificateCoverage(t *testing.T) {
	for _, missing := range []string{baseDNS, testDNS, "b.example.test"} {
		t.Run(missing, func(t *testing.T) {
			targets := virtualHostTargets(t)
			fw, h, _ := virtualForwarder(t, targets)
			for _, cfg := range targets {
				if _, err := h.probeTLSFor(t.Context(), cfg.DNSName); err != nil {
					t.Fatal("initial shared certificate probe", err)
				}
			}
			testCertificate(t, filepath.Dir(targets[0].CertFile), testDNS, time.Now().Add(-time.Hour), time.Now().Add(time.Hour), 2, func(c *x509.Certificate) {
				c.DNSNames = nil
				for _, name := range virtualNames(targets) {
					if name != missing {
						c.DNSNames = append(c.DNSNames, name)
					}
				}
			})
			for _, cfg := range fw.desired {
				if _, err := h.probeTLSFor(t.Context(), cfg.DNSName); !errors.Is(err, errLocalTLS) {
					t.Fatal("partial SAN coverage certified a sibling")
				}
				conn, err := tls.DialWithDialer(&net.Dialer{Timeout: time.Second}, "tcp", h.Addr().String(), &tls.Config{ServerName: cfg.DNSName, InsecureSkipVerify: true})
				if err == nil {
					conn.Close()
					t.Fatal("shared invalid certificate served a sibling")
				}
			}
			// Wildcard SAN coverage remains supported, but creates no wildcard route.
			testCertificate(t, filepath.Dir(targets[0].CertFile), "*.example.test", time.Now().Add(-time.Hour), time.Now().Add(time.Hour), 3)
			for _, cfg := range targets {
				if _, err := h.probeTLSFor(t.Context(), cfg.DNSName); err != nil {
					t.Fatal("wildcard coverage rejected", err)
				}
			}
			if _, err := h.probeTLSFor(t.Context(), baseDNS); err == nil {
				t.Fatal("base SAN became a route")
			}
		})
	}
}

func TestVirtualHostBackendTLSIsolationAndProofs(t *testing.T) {
	targets := virtualHostTargets(t)
	cas := virtualTLSBackends(t, targets, -1)
	fw, h, _ := virtualForwarder(t, targets)
	// No traffic/probes exist yet. Observe each component probe's actual ClientHello.
	original := h.srv.TLSConfig.GetCertificate
	var mu sync.Mutex
	seen := make(map[string]int)
	h.srv.TLSConfig.GetCertificate = func(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
		mu.Lock()
		seen[strings.ToLower(hello.ServerName)]++
		mu.Unlock()
		return original(hello)
	}
	p := &prober{}
	p.probe(t.Context(), fw)
	if healthCode(p, fw, "Running") != 200 {
		t.Fatalf("initial aggregate readiness failed: %+v", p.snapshotFor(fw))
	}
	initial := p.snapshotFor(fw)
	if len(initial) != 2 || initial[0].BackendCAHash == initial[1].BackendCAHash || initial[0].TLSCertSHA256 != initial[1].TLSCertSHA256 {
		t.Fatal("backend proof not per target/shared leaf proof not consistent")
	}
	mu.Lock()
	for _, cfg := range targets {
		if seen[cfg.DNSName] != 1 {
			t.Error("probe did not handshake each explicit SNI")
		}
	}
	mu.Unlock()
	clients := []*http.Client{virtualClient(t, h, targets[0], true), virtualClient(t, h, targets[1], true)}
	for i, cfg := range targets {
		virtualGET(t, clients[i], cfg, "/", 200)
		if metricValue(t, fw.metrics, "tailnet_agent_dial_duration_seconds", "expose", cfg.Name) != 2 {
			t.Fatal("backend probe/serving dial selected wrong metric generation")
		}
	}
	for _, bad := range []string{"invalid", "missing", "sibling-ca"} {
		switch bad {
		case "invalid":
			if err := os.WriteFile(targets[0].BackendCAFile, []byte("private-sentinel"), 0600); err != nil {
				t.Fatal(err)
			}
		case "missing":
			if err := os.Remove(targets[0].BackendCAFile); err != nil {
				t.Fatal(err)
			}
		case "sibling-ca":
			if err := os.WriteFile(targets[0].BackendCAFile, cas[1], 0600); err != nil {
				t.Fatal(err)
			}
		}
		if healthCode(p, fw, "Running") != 503 {
			t.Fatal("stale per-host trust retained aggregate readiness")
		}
		virtualGET(t, clients[0], targets[0], "/", 502)
		virtualGET(t, clients[1], targets[1], "/", 200)
		p.probe(t.Context(), fw)
		for _, r := range p.snapshotFor(fw) {
			if !*r.TLSReady || (r.Name == "a" && (r.Reachable || *r.BackendReachable || r.BackendCAHash != "" || r.BackendTLSReason == "")) || (r.Name == "b" && (!r.Reachable || !*r.BackendReachable)) {
				t.Fatalf("backend isolation failed: %+v", r)
			}
		}
		if err := os.WriteFile(targets[0].BackendCAFile, cas[0], 0600); err != nil {
			t.Fatal(err)
		}
		if healthCode(p, fw, "Running") != 503 {
			t.Fatal("backend proof resurrected without handshake")
		}
		virtualGET(t, clients[0], targets[0], "/", 200)
		p.probe(t.Context(), fw)
		if healthCode(p, fw, "Running") != 200 {
			t.Fatal("restored CA did not recover")
		}
	}
	// Invalidate one saved proof's CA identity; its sibling's proof must remain valid.
	for _, proof := range initial {
		other := targets[0].DNSName
		if proof.Name == "a" {
			other = targets[1].DNSName
		}
		if h.currentBackendProofFor(other, proof.BackendCAHash, *proof.BackendTLSNotAfter) {
			t.Fatal("sibling CA proof accepted")
		}
	}
	p.mu.Lock()
	r := p.results["a"]
	r.LastProbe = time.Now().Add(-httpProofMaxAge - time.Second)
	p.results["a"] = r
	p.mu.Unlock()
	for _, r := range p.snapshotFor(fw) {
		if (r.Name == "a" && r.Reachable) || (r.Name == "b" && !r.Reachable) {
			t.Fatal("stale proof isolation failed")
		}
	}
}

func TestVirtualHostPerTargetTimeouts(t *testing.T) {
	for _, which := range []string{"request", "backend"} {
		t.Run(which, func(t *testing.T) {
			targets := virtualHostTargets(t)
			for i := range targets {
				virtualBackend(t, &targets[i], http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					select {
					case <-time.After(150 * time.Millisecond):
						io.WriteString(w, "complete")
					case <-r.Context().Done():
					}
				}))
				targets[i].RequestTimeout, targets[i].BackendRequestTimeout = "0s", "0s"
			}
			if which == "request" {
				targets[0].RequestTimeout = "40ms"
			} else {
				targets[0].BackendRequestTimeout = "40ms"
			}
			_, h, _ := virtualForwarder(t, targets)
			for _, h2 := range []bool{false, true} {
				virtualGET(t, virtualClient(t, h, targets[0], h2), targets[0], "/", 504)
				virtualGET(t, virtualClient(t, h, targets[1], h2), targets[1], "/", 200)
			}
		})
	}
}

func TestVirtualHostGroupReloadWithdrawalAndABA(t *testing.T) {
	targets := virtualHostTargets(t)
	for i := range targets {
		virtualBackend(t, &targets[i], http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { io.WriteString(w, "ok") }))
	}
	l4 := target{Name: "l4", Address: "127.0.0.1", Port: 80, ListenPort: 8443}
	targets = append(targets, l4)
	fw, h, path := virtualForwarder(t, targets)
	l4Running := fw.run[l4.Name]
	p := &prober{}
	p.probe(t.Context(), fw)
	oldProofs := p.snapshotFor(fw)
	oldA := fw.run["a"]
	// Reorder routes and SAN suffix: no restarts, no new metrics/probe generations.
	writeV3Targets(t, path, []target{targets[1], l4, targets[0]}, []string{baseDNS, targets[1].DNSName, targets[0].DNSName})
	if pending, err := fw.reload(t.Context(), path); err != nil || pending != 0 {
		t.Fatal(pending, err)
	}
	if fw.run["a"].ln != h || fw.run["a"].generation != oldA.generation || fw.run[l4.Name].ln != l4Running.ln {
		t.Fatal("reorder replaced ownership")
	}
	// A static change on b must replace a as well; old a proof must not certify the new group.
	targets[1].ConfigID = "new-b"
	writeV3Targets(t, path, targets, virtualNames(targets))
	if pending, err := fw.reload(t.Context(), path); err != nil || pending != 0 {
		t.Fatal(pending, err)
	}
	if h.active() || fw.run["a"].ln == h || fw.run["a"].generation == oldA.generation || fw.run[l4.Name].ln != l4Running.ln {
		t.Fatal("group change did not fence ownership")
	}
	for _, r := range oldProofs {
		p.publish(fw, r)
	}
	if healthCode(p, fw, "Running") != 503 {
		t.Fatal("old group proof certified replacement")
	}
	p.probe(t.Context(), fw)
	if healthCode(p, fw, "Running") != 200 {
		t.Fatal("replacement did not obtain new proofs")
	}
	current := fw.run["a"].ln.(*httpIngress)
	// Invalid whole config must never partially reconfigure the group.
	invalid := append([]target(nil), targets...)
	invalid[1].Name = invalid[0].Name
	writeV3Targets(t, path, invalid, virtualNames(targets))
	if _, err := fw.reload(t.Context(), path); err == nil || fw.run["a"].ln != current || !current.active() {
		t.Fatal("invalid reload touched accepted group")
	}
	// Explicit v3 frontend withdrawal keeps the independent L4 listener, not HTTP last-good.
	writeV3Targets(t, path, []target{l4}, []string{})
	if pending, err := fw.reload(t.Context(), path); err != nil || pending != 0 {
		t.Fatal(pending, err)
	}
	if current.active() || len(fw.run) != 1 || fw.run[l4.Name].ln != l4Running.ln || fw.run[l4.Name].generation != l4Running.generation {
		t.Fatal("withdrawal retained HTTP or restarted L4")
	}
	for _, runtime := range current.routes {
		runtime.transport.mu.Lock()
		closed := runtime.transport.closed
		runtime.transport.mu.Unlock()
		if !closed {
			t.Fatal("withdrawal retained backend resources")
		}
	}
	// Recreate identical a: no ABA observation or metric generation may return.
	writeV3Targets(t, path, targets, virtualNames(targets))
	if pending, err := fw.reload(t.Context(), path); err != nil || pending != 0 {
		t.Fatal(pending, err)
	}
	for _, r := range oldProofs {
		p.publish(fw, r)
	}
	if healthCode(p, fw, "Running") != 503 || fw.run["a"].generation <= oldA.generation {
		t.Fatal("ABA proof accepted")
	}
	// Removing and adding one member each replaces the complete group.
	before := fw.run["a"].ln.(*httpIngress)
	writeV3Targets(t, path, []target{targets[0], l4}, []string{baseDNS, targets[0].DNSName})
	if pending, err := fw.reload(t.Context(), path); err != nil || pending != 0 {
		t.Fatal(pending, err)
	}
	if before.active() || len(fw.run) != 2 || fw.run["a"].ln == before {
		t.Fatal("member removal did not replace group")
	}
	before = fw.run["a"].ln.(*httpIngress)
	writeV3Targets(t, path, targets, virtualNames(targets))
	if pending, err := fw.reload(t.Context(), path); err != nil || pending != 0 {
		t.Fatal(pending, err)
	}
	if before.active() || fw.run["a"].ln != fw.run["b"].ln {
		t.Fatal("member add did not replace complete group")
	}
	before = fw.run["a"].ln.(*httpIngress)
	writeV3Targets(t, path, []target{}, []string{})
	if pending, err := fw.reload(t.Context(), path); err != nil || pending != 0 || len(fw.run) != 0 || before.active() {
		t.Fatal("empty v3 withdrawal failed", pending, err)
	}
}

func TestVirtualHostFailedSharedBind(t *testing.T) {
	targets := virtualHostTargets(t)
	path := filepath.Join(t.TempDir(), "targets.json")
	writeV3Targets(t, path, targets, virtualNames(targets))
	var calls int
	fail := true
	fw := &forwarder{mode: "ingress", run: make(map[string]running), listenTailnet: func(network, address string) (net.Listener, error) {
		calls++
		if network != "tcp" || address != ":443" {
			t.Fatal("not one shared tailnet port")
		}
		if fail {
			return nil, errors.New("bind failure")
		}
		return net.Listen("tcp", "127.0.0.1:0")
	}}
	defer fw.stopAll()
	if pending, err := fw.reload(t.Context(), path); err != nil || pending != 2 || calls != 1 || len(fw.run) != 0 {
		t.Fatal("partial shared bind", pending, err)
	}
	p := &prober{}
	if healthCode(p, fw, "Running") != 503 || len(p.snapshotFor(fw)) != 2 {
		t.Fatal("missing group targets disappeared from readiness")
	}
	fail = false
	if pending, err := fw.reload(t.Context(), path); err != nil || pending != 0 || calls != 2 || len(fw.run) != 2 || fw.run["a"].ln != fw.run["b"].ln {
		t.Fatal("shared bind retry failed", pending, err)
	}
	old := fw.run["a"].ln.(*httpIngress)
	targets[1].ConfigID = "changed"
	writeV3Targets(t, path, targets, virtualNames(targets))
	fail = true
	if pending, err := fw.reload(t.Context(), path); err != nil || pending != 2 || calls != 3 || len(fw.run) != 0 || old.active() {
		t.Fatal("failed replacement retained partial group", pending, err)
	}
	if healthCode(p, fw, "Running") != 503 {
		t.Fatal("failed replacement ready")
	}
}

func TestVirtualHostMetricGenerationAndIncompleteShutdown(t *testing.T) {
	targets := virtualHostTargets(t)
	for i := range targets {
		virtualBackend(t, &targets[i], http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(204) }))
	}
	fw, h, _ := virtualForwarder(t, targets)
	staleRuntime := h.routes[strings.ToLower(targets[1].DNSName)]
	fw.metrics.remove("b")
	fw.metrics.connection("b")
	virtualGET(t, virtualClient(t, h, targets[1], false), targets[1], "/", 204)
	if metricValue(t, fw.metrics, "tailnet_agent_dial_duration_seconds", "expose", "b") != 0 || metricValue(t, fw.metrics, "tailnet_agent_connections_active", "expose", "b") != 0 || metricValue(t, fw.metrics, "tailnet_agent_bytes_total", "expose", "b") != 0 {
		t.Fatal("stale SNI runtime contaminated recreated metrics")
	}
	if staleRuntime.metrics.active == fw.metrics.connection("b").active {
		t.Fatal("metric generation not replaced")
	}
	conn, err := net.DialTimeout("tcp", h.Addr().String(), time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	deadline := time.Now().Add(time.Second)
	for metricValue(t, fw.metrics, "tailnet_agent_http_unattributed_connections_active", "", "") != 1 {
		if time.Now().After(deadline) {
			t.Fatal("incomplete TLS connection unaccounted")
		}
		time.Sleep(time.Millisecond)
	}
	h.Close()
	if metricValue(t, fw.metrics, "tailnet_agent_http_unattributed_connections_active", "", "") != 0 {
		t.Fatal("incomplete TLS connection leaked")
	}
	conn.SetReadDeadline(time.Now().Add(time.Second))
	if _, err := conn.Read(make([]byte, 1)); err == nil {
		t.Fatal("incomplete connection survived shutdown")
	} else if ne, ok := err.(net.Error); ok && ne.Timeout() {
		t.Fatal("incomplete connection leaked")
	}
}

func TestVirtualHostUpgradesAndShutdown(t *testing.T) {
	targets := virtualHostTargets(t)
	backendDone := make(chan struct{}, 2)
	for i := range targets {
		targets[i].RequestTimeout = "50ms"
		virtualBackend(t, &targets[i], http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			defer func() { backendDone <- struct{}{} }()
			conn, rw, err := http.NewResponseController(w).Hijack()
			if err != nil {
				t.Error(err)
				return
			}
			defer conn.Close()
			fmt.Fprint(rw, "HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: fixture\r\n\r\n")
			rw.Flush()
			for {
				line, err := rw.ReadString('\n')
				if err != nil {
					return
				}
				io.WriteString(rw, line)
				if err := rw.Flush(); err != nil {
					return
				}
			}
		}))
	}
	fw, h, _ := virtualForwarder(t, targets)
	var connections []net.Conn
	var readers []*bufio.Reader
	for _, cfg := range targets {
		conn, err := tls.DialWithDialer(&net.Dialer{Timeout: time.Second}, "tcp", h.Addr().String(), &tls.Config{ServerName: cfg.DNSName, InsecureSkipVerify: true})
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { conn.Close() })
		conn.SetDeadline(time.Now().Add(3 * time.Second))
		fmt.Fprintf(conn, "GET /socket HTTP/1.1\r\nHost: %s\r\nConnection: Upgrade\r\nUpgrade: fixture\r\n\r\n", cfg.DNSName)
		reader := bufio.NewReader(conn)
		res, err := http.ReadResponse(reader, &http.Request{Method: "GET"})
		if err != nil || res.StatusCode != 101 {
			t.Fatal("upgrade rejected", err)
		}
		connections = append(connections, conn)
		readers = append(readers, reader)
	}
	// HTTP budgets must not become tunnel lifetimes, for either virtual host.
	time.Sleep(120 * time.Millisecond)
	for i, conn := range connections {
		io.WriteString(conn, "still connected\n")
		line, err := readers[i].ReadString('\n')
		if err != nil || line != "still connected\n" {
			t.Fatal("upgrade expired at request timeout", err)
		}
		if metricValue(t, fw.metrics, "tailnet_agent_connections_active", "expose", targets[i].Name) != 1 {
			t.Fatal("hijacked connection lost selected metrics")
		}
	}
	closed := make(chan struct{})
	go func() { h.Close(); close(closed) }()
	select {
	case <-closed:
	case <-time.After(time.Second):
		t.Fatal("group did not join upgraded handlers")
	}
	for i, reader := range readers {
		select {
		case <-backendDone:
		case <-time.After(time.Second):
			t.Fatal("upgraded backend leaked")
		}
		if _, err := reader.ReadByte(); err == nil {
			t.Fatal("upgraded frontend leaked")
		}
		if metricValue(t, fw.metrics, "tailnet_agent_connections_active", "expose", targets[i].Name) != 0 {
			t.Fatal("upgrade gauge leaked")
		}
	}
}

func TestVirtualHostProbeShutdownJoinsEveryTarget(t *testing.T) {
	targets := virtualHostTargets(t)
	for i := range targets {
		_, ca := backendCertificate(t, time.Now().Add(time.Hour))
		targets[i].BackendServerName = backendDNS
		targets[i].BackendCAFile = filepath.Join(t.TempDir(), "ca.crt")
		if err := os.WriteFile(targets[i].BackendCAFile, ca, 0600); err != nil {
			t.Fatal(err)
		}
	}
	_, h, _ := virtualForwarder(t, targets)
	entered, exited := make(chan struct{}, 4), make(chan struct{}, 4)
	for _, runtime := range h.routes {
		runtime.transport.dial = func(ctx context.Context, _ target) (net.Conn, error) {
			entered <- struct{}{}
			<-ctx.Done()
			exited <- struct{}{}
			return nil, ctx.Err()
		}
	}
	h.srv.TLSConfig.GetCertificate = func(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
		entered <- struct{}{}
		<-hello.Context().Done()
		exited <- struct{}{}
		return nil, errLocalTLS
	}
	var probes sync.WaitGroup
	for _, cfg := range targets {
		probes.Go(func() { h.probeTLSFor(t.Context(), cfg.DNSName) })
		probes.Go(func() { h.probeBackendTLSFor(t.Context(), cfg.DNSName) })
	}
	for range 4 {
		select {
		case <-entered:
		case <-time.After(time.Second):
			t.Fatal("per-target probes did not start")
		}
	}
	closed := make(chan struct{})
	go func() { h.Close(); close(closed) }()
	select {
	case <-closed:
	case <-time.After(time.Second):
		t.Fatal("Close did not cancel and join all target probes")
	}
	probes.Wait()
	if len(exited) != 4 {
		t.Fatal("probe work outlived group closure")
	}
}

func TestVirtualHostNilMetrics(t *testing.T) {
	targets := virtualHostTargets(t)
	path := filepath.Join(t.TempDir(), "targets.json")
	for i := range targets {
		virtualBackend(t, &targets[i], http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { fmt.Fprint(w, "ok") }))
	}
	writeV3Targets(t, path, targets, virtualNames(targets))
	loaded, err := loadTargets(path)
	if err != nil {
		t.Fatal(err)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	fw := &forwarder{mode: "ingress"}
	h, err := serveHTTPIngressGroup(t.Context(), ln, loaded, fw.dial, nil)
	if err != nil {
		ln.Close()
		t.Fatal(err)
	}
	defer h.Close()
	for _, cfg := range targets {
		virtualGET(t, virtualClient(t, h, cfg, true), cfg, "/", 200)
	}
}
