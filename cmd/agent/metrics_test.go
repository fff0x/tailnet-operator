package main

import (
	"bufio"
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

func metricValue(t *testing.T, m *agentMetrics, family, label, value string) float64 {
	t.Helper()
	families, err := m.registry.Gather()
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range families {
		if f.GetName() != family {
			continue
		}
		for _, metric := range f.Metric {
			match := label == ""
			for _, l := range metric.Label {
				if l.GetName() == label && l.GetValue() == value {
					match = true
				}
			}
			if match {
				switch {
				case metric.Gauge != nil:
					return metric.Gauge.GetValue()
				case metric.Counter != nil:
					return metric.Counter.GetValue()
				case metric.Histogram != nil:
					return float64(metric.Histogram.GetSampleCount())
				}
			}
		}
	}
	t.Fatalf("metric %s missing", family)
	return 0
}

func TestConnectionMetricsPreserveHalfClose(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	m := newAgentMetrics("egress")
	measured := &measuredListener{Listener: ln, metrics: m.connection("database")}
	peer, err := net.DialTimeout("tcp", ln.Addr().String(), time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer peer.Close()
	conn, err := measured.Accept()
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	_ = peer.SetDeadline(time.Now().Add(3 * time.Second))
	_ = conn.SetDeadline(time.Now().Add(3 * time.Second))
	if _, err := io.WriteString(peer, "hello"); err != nil {
		t.Fatal(err)
	}
	if err := peer.(closeWriter).CloseWrite(); err != nil {
		t.Fatal(err)
	}
	if b, err := io.ReadAll(conn); err != nil || string(b) != "hello" {
		t.Fatal("measured read/EOF failed")
	}
	if _, err := io.WriteString(conn, "world"); err != nil {
		t.Fatal(err)
	}
	if err := conn.(closeWriter).CloseWrite(); err != nil {
		t.Fatal(err)
	}
	if b, err := io.ReadAll(peer); err != nil || string(b) != "world" {
		t.Fatal("measured half-close did not propagate EOF")
	}
	if metricValue(t, m, "tailnet_agent_connections_active", "", "") != 1 ||
		metricValue(t, m, "tailnet_agent_bytes_total", "direction", "to_target") != 5 ||
		metricValue(t, m, "tailnet_agent_bytes_total", "direction", "from_target") != 5 {
		t.Fatal("connection/byte accounting must update before close")
	}
	var wg sync.WaitGroup
	for range 8 {
		wg.Go(func() { _ = conn.Close() })
	}
	wg.Wait()
	if metricValue(t, m, "tailnet_agent_connections_active", "", "") != 0 {
		t.Fatal("concurrent Close decremented the active gauge more than once")
	}
}

func measuredHTTPIngress(t *testing.T, ctx context.Context, handler http.Handler) (*httpIngress, target, *agentMetrics) {
	t.Helper()
	backend := httptest.NewServer(handler)
	t.Cleanup(backend.Close)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	cfg := validHTTPTarget(t)
	cfg.Address, cfg.Port = "127.0.0.1", backend.Listener.Addr().(*net.TCPAddr).Port
	m := newAgentMetrics("ingress")
	fw := &forwarder{mode: "ingress", metrics: m}
	metrics := m.connection(cfg.Name)
	h, err := serveHTTPIngress(ctx, &measuredListener{Listener: ln, metrics: metrics}, cfg, metrics.wrapDial(fw.dial))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { h.Close() })
	return h, cfg, m
}

func TestHTTPTransportMetrics(t *testing.T) {
	h, cfg, m := measuredHTTPIngress(t, context.Background(), http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, "response")
	}))
	client := localHTTPClient(t, h, cfg, true)
	response, err := client.Get("https://" + testDNS + "/")
	if err != nil {
		t.Fatal(err)
	}
	_, err = io.Copy(io.Discard, response.Body)
	response.Body.Close()
	if err != nil || response.StatusCode != 200 || response.ProtoMajor != 2 {
		t.Fatal("metrics wrapper changed HTTP/2 proxy behavior")
	}
	if metricValue(t, m, "tailnet_agent_dial_duration_seconds", "", "") != 1 {
		t.Fatal("HTTP transport dial was not measured")
	}
	if metricValue(t, m, "tailnet_agent_bytes_total", "direction", "to_target") == 0 ||
		metricValue(t, m, "tailnet_agent_bytes_total", "direction", "from_target") <= float64(len("response")) {
		t.Fatal("HTTP metrics must include TLS wire bytes")
	}
	h.Close()
	if metricValue(t, m, "tailnet_agent_connections_active", "", "") != 0 {
		t.Fatal("HTTP shutdown left an active connection metric")
	}
}

func TestProbeSnapshotMetricsGeneration(t *testing.T) {
	backend, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer backend.Close()
	cfg := target{Name: "web", Address: "127.0.0.1", Port: backend.Addr().(*net.TCPAddr).Port}
	m := newAgentMetrics("ingress")
	m.connection(cfg.Name)
	fw := &forwarder{mode: "ingress", metrics: m, run: map[string]running{cfg.Name: {t: cfg}}}
	stale := fw.probeTargets()[0]
	if metricValue(t, m, "tailnet_agent_dial_duration_seconds", "", "") != 0 {
		t.Fatal("taking a snapshot must not observe a dial")
	}

	replacement, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer replacement.Close()
	cfg.Port = replacement.Addr().(*net.TCPAddr).Port
	// Match reload's remove/recreate critical section, before the old snapshot starts dialing.
	fw.mu.Lock()
	delete(fw.run, cfg.Name)
	m.remove(cfg.Name)
	m.connection(cfg.Name)
	fw.run[cfg.Name] = running{t: cfg}
	fw.mu.Unlock()
	current := fw.probeTargets()[0]
	if stale.t.Port == current.t.Port || fw.current()[cfg.Name] != cfg {
		t.Fatal("snapshot must retain its original target configuration")
	}
	dial := func(snapshot probeTarget) {
		t.Helper()
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		c, err := snapshot.dial(ctx, snapshot.t)
		if err != nil {
			t.Fatal(err)
		}
		c.Close()
	}
	dial(current)
	if metricValue(t, m, "tailnet_agent_dial_duration_seconds", "", "") != 1 {
		t.Fatal("current generation's dial was not measured")
	}
	dial(stale)
	if metricValue(t, m, "tailnet_agent_dial_duration_seconds", "", "") != 1 {
		t.Fatal("dial from a pre-removal snapshot contaminated the new generation")
	}
}

func TestHTTPTransportMetricsGeneration(t *testing.T) {
	h, cfg, m := measuredHTTPIngress(t, context.Background(), http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	// The old transport can start dialing after removal/recreation, just like a delayed probe.
	m.remove(cfg.Name)
	m.connection(cfg.Name)
	client := localHTTPClient(t, h, cfg, false)
	res, err := client.Get("https://" + testDNS + "/")
	if err != nil {
		t.Fatal(err)
	}
	res.Body.Close()
	if res.StatusCode != http.StatusNoContent {
		t.Fatalf("status = %d", res.StatusCode)
	}
	if metricValue(t, m, "tailnet_agent_dial_duration_seconds", "", "") != 0 {
		t.Fatal("old HTTP transport contaminated the new generation")
	}
}

func TestMeasuredHTTPIncompleteTLSShutdown(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	h, _, m := measuredHTTPIngress(t, ctx, http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		t.Error("incomplete TLS handshake reached backend")
	}))
	c, err := net.DialTimeout("tcp", h.Addr().String(), time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	// Wait until Accept accounts for this connection; do not let a pre-Accept close pass vacuously.
	deadline := time.Now().Add(3 * time.Second)
	for metricValue(t, m, "tailnet_agent_connections_active", "", "") != 1 {
		if time.Now().After(deadline) {
			t.Fatal("incomplete TLS handshake was not counted")
		}
		time.Sleep(time.Millisecond)
	}
	cancel()
	select {
	case <-h.done:
	case <-time.After(3 * time.Second):
		t.Fatal("canceled listener is still serving")
	}
	h.Close()
	if metricValue(t, m, "tailnet_agent_connections_active", "", "") != 0 {
		t.Fatal("incomplete TLS handshake left an active connection metric")
	}
	c.SetReadDeadline(time.Now().Add(time.Second))
	if _, err := c.Read(make([]byte, 1)); err == nil {
		t.Fatal("incomplete TLS handshake survived shutdown")
	} else if ne, ok := err.(net.Error); ok && ne.Timeout() {
		t.Fatal("incomplete TLS handshake leaked")
	}
}

func TestMeasuredHTTPWebSocketShutdown(t *testing.T) {
	backendDone := make(chan struct{})
	h, _, m := measuredHTTPIngress(t, context.Background(), http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
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
	c, err := tls.DialWithDialer(&net.Dialer{Timeout: time.Second}, "tcp", h.Addr().String(), &tls.Config{ServerName: testDNS, InsecureSkipVerify: true})
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
	if res.StatusCode != http.StatusSwitchingProtocols {
		t.Fatalf("upgrade status %d", res.StatusCode)
	}
	c.Write([]byte{0x81, 0x82, 1, 2, 3, 4, 'h' ^ 1, 'i' ^ 2})
	echo := make([]byte, 4)
	if _, err := io.ReadFull(br, echo); err != nil || string(echo) != string([]byte{0x81, 2, 'h', 'i'}) {
		t.Fatalf("echo=%v err=%v", echo, err)
	}
	if metricValue(t, m, "tailnet_agent_connections_active", "", "") != 1 {
		t.Fatal("WebSocket must remain counted after hijacking")
	}
	closed := make(chan struct{})
	go func() {
		running{ln: h, cancel: func() {}}.stop()
		close(closed)
	}()
	select {
	case <-closed:
	case <-time.After(3 * time.Second):
		t.Fatal("HTTP Close leaked upgraded handler")
	}
	if metricValue(t, m, "tailnet_agent_connections_active", "", "") != 0 {
		t.Fatal("WebSocket shutdown left an active connection metric")
	}
	select {
	case <-backendDone:
	case <-time.After(3 * time.Second):
		t.Fatal("upgraded upstream still open")
	}
	if _, err := br.ReadByte(); err == nil {
		t.Fatal("upgraded downstream still open")
	} else if ne, ok := err.(net.Error); ok && ne.Timeout() {
		t.Fatal("upgraded downstream leaked")
	}
}

func TestAgentMetricsLifecycle(t *testing.T) {
	for _, mode := range []string{"egress", "ingress"} {
		t.Run(mode, func(t *testing.T) {
			m := newAgentMetrics(mode)
			current := m.connection("web")
			current.startDial()()
			if metricValue(t, m, "tailnet_agent_dial_duration_seconds", "", "") != 1 {
				t.Fatal("dial observation missing")
			}
			rr := httptest.NewRecorder()
			m.handler().ServeHTTP(rr, httptest.NewRequest("GET", "/metrics", nil))
			labels := `expose="",target="web"`
			if mode == "ingress" {
				labels = `expose="web",target=""`
			}
			if rr.Code != 200 || !strings.Contains(rr.Body.String(), labels) || strings.Contains(rr.Body.String(), "go_gc_") {
				t.Fatal("private metrics handler did not expose the expected bounded labels")
			}
			late := current.startDial()
			m.remove("web")
			late()
			current.startDial()() // a stale snapshot cannot recreate removed series
			families, err := m.registry.Gather()
			if err != nil || len(families) != 0 {
				t.Fatal("removed target retained or recreated series")
			}
			m.connection("web")
			late()
			current.startDial()() // even when the stale dial starts after recreation
			if metricValue(t, m, "tailnet_agent_dial_duration_seconds", "", "") != 0 {
				t.Fatal("old observation contaminated a recreated target")
			}
		})
	}
}
