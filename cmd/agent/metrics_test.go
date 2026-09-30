package main

import (
	"context"
	"io"
	"net"
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
