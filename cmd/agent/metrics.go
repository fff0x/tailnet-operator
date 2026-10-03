package main

import (
	"context"
	"net"
	"net/http"
	"sync"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

// Agent metrics carry only configured target/expose names. Namespace and workload identity belong
// to scrape metadata, never peer identities or addresses. A private registry avoids tsnet/global
// collector collisions and does not accidentally expose unrelated process collectors.
type agentMetrics struct {
	mode         string
	registry     *prometheus.Registry
	active       *prometheus.GaugeVec
	bytes        *prometheus.CounterVec
	dial         *prometheus.HistogramVec
	mu           sync.Mutex
	targets      map[string]connectionMetrics
	unattributed connectionMetrics
}

type connectionMetrics struct {
	active               prometheus.Gauge
	toTarget, fromTarget prometheus.Counter
	dial                 prometheus.Observer
}

func newAgentMetrics(mode string) *agentMetrics {
	m := &agentMetrics{
		mode: mode, registry: prometheus.NewRegistry(), targets: make(map[string]connectionMetrics),
		active: prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Name: "tailnet_agent_connections_active", Help: "Open client TCP connections assigned to a target; HTTP assignment begins at recognized SNI.",
		}, []string{"target", "expose"}),
		bytes: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "tailnet_agent_bytes_total", Help: "Bytes on target-assigned client connections; HTTP counts after recognized SNI, including TLS wire overhead.",
		}, []string{"target", "expose", "direction"}),
		dial: prometheus.NewHistogramVec(prometheus.HistogramOpts{
			Name: "tailnet_agent_dial_duration_seconds", Help: "Upstream TCP dial duration, including failed dials and health probes.",
		}, []string{"target", "expose"}),
	}
	m.registry.MustRegister(m.active, m.bytes, m.dial)
	return m
}

// Dedicated families prevent collisions with arbitrary configured expose names. Created only
// for HTTP listeners; pre-SNI bytes stay here even after a route is selected.
func (m *agentMetrics) unattributedConnection() connectionMetrics {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.unattributed.active == nil {
		active := prometheus.NewGauge(prometheus.GaugeOpts{Name: "tailnet_agent_http_unattributed_connections_active", Help: "Open HTTP connections without a recognized SNI."})
		bytes := prometheus.NewCounterVec(prometheus.CounterOpts{Name: "tailnet_agent_http_unattributed_bytes_total", Help: "TLS wire bytes before recognized SNI, including rejected handshakes."}, []string{"direction"})
		m.registry.MustRegister(active, bytes)
		m.unattributed = connectionMetrics{active: active, toTarget: bytes.WithLabelValues("to_target"), fromTarget: bytes.WithLabelValues("from_target")}
	}
	return m.unattributed
}

func (m *agentMetrics) labels(name string) (target, expose string) {
	if m.mode == "ingress" {
		return "", name
	}
	return name, ""
}

func (m *agentMetrics) connection(name string) connectionMetrics {
	if m == nil {
		return connectionMetrics{}
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if current, ok := m.targets[name]; ok {
		return current
	}
	target, expose := m.labels(name)
	current := connectionMetrics{
		active:     m.active.WithLabelValues(target, expose),
		toTarget:   m.bytes.WithLabelValues(target, expose, "to_target"),
		fromTarget: m.bytes.WithLabelValues(target, expose, "from_target"),
		dial:       m.dial.WithLabelValues(target, expose),
	}
	m.targets[name] = current
	return current
}

func (m connectionMetrics) startDial() func() {
	if m.dial == nil {
		return func() {}
	}
	start := time.Now()
	return func() { m.dial.Observe(time.Since(start).Seconds()) }
}

type upstreamDial func(context.Context, target) (net.Conn, error)

// wrapDial retains the listener/probe snapshot's generation, but starts timing only when called.
// A stale caller must never resolve metrics by name after a same-name target has been recreated.
func (m connectionMetrics) wrapDial(dial upstreamDial) upstreamDial {
	return func(ctx context.Context, t target) (net.Conn, error) {
		defer m.startDial()()
		return dial(ctx, t)
	}
}

func (m *agentMetrics) remove(name string) {
	if m == nil {
		return
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.targets, name)
	target, expose := m.labels(name)
	m.active.DeleteLabelValues(target, expose)
	m.bytes.DeleteLabelValues(target, expose, "to_target")
	m.bytes.DeleteLabelValues(target, expose, "from_target")
	m.dial.DeleteLabelValues(target, expose)
}

func (m *agentMetrics) handler() http.Handler {
	return promhttp.HandlerFor(m.registry, promhttp.HandlerOpts{})
}

// Observe below TLS so HTTP/2 and WebSockets use the same accounting and shutdown path as L4.
// Read/Write count successful bytes immediately, not only when a long-lived connection closes.
type measuredListener struct {
	net.Listener
	metrics connectionMetrics
}

func (l *measuredListener) Accept() (net.Conn, error) {
	conn, err := l.Listener.Accept()
	if err != nil {
		return nil, err
	}
	l.metrics.active.Inc()
	return &measuredConn{Conn: conn, metrics: l.metrics}, nil
}

type measuredConn struct {
	net.Conn
	metrics connectionMetrics
	once    sync.Once
}

func (c *measuredConn) Read(p []byte) (int, error) {
	n, err := c.Conn.Read(p)
	c.metrics.toTarget.Add(float64(n))
	return n, err
}

func (c *measuredConn) Write(p []byte) (int, error) {
	n, err := c.Conn.Write(p)
	c.metrics.fromTarget.Add(float64(n))
	return n, err
}

func (c *measuredConn) Close() error {
	err := c.Conn.Close()
	c.once.Do(c.metrics.active.Dec)
	return err
}

// Embedding net.Conn would otherwise hide TCP's optional half-close operation and regress pipe.
func (c *measuredConn) CloseWrite() error {
	if conn, ok := c.Conn.(closeWriter); ok {
		return conn.CloseWrite()
	}
	return nil
}
