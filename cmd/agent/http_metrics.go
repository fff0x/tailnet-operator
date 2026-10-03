package main

import (
	"net"
	"sync"
)

// Selection happens once in GetCertificate, never from an HTTP Host header. Until then the
// connection and its bytes belong to bounded, dedicated unattributed metrics. All metric handles
// are captured at listener creation, so delayed TLS work cannot resolve a recreated generation.
type sniMeasuredListener struct {
	net.Listener
	unattributed connectionMetrics
}

func (l *sniMeasuredListener) Accept() (net.Conn, error) {
	conn, err := l.Listener.Accept()
	if err != nil {
		return nil, err
	}
	l.unattributed.active.Inc()
	return &sniMeasuredConn{Conn: conn, metrics: l.unattributed}, nil
}

type sniMeasuredConn struct {
	net.Conn
	mu               sync.Mutex
	metrics          connectionMetrics
	selected, closed bool
}

func (c *sniMeasuredConn) selectTarget(metrics connectionMetrics) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.selected || c.closed {
		return
	}
	c.metrics.active.Dec()
	c.metrics = metrics
	c.selected = true
	c.metrics.active.Inc()
}

func (c *sniMeasuredConn) Read(p []byte) (int, error) {
	n, err := c.Conn.Read(p)
	c.mu.Lock()
	c.metrics.toTarget.Add(float64(n))
	c.mu.Unlock()
	return n, err
}

func (c *sniMeasuredConn) Write(p []byte) (int, error) {
	n, err := c.Conn.Write(p)
	c.mu.Lock()
	c.metrics.fromTarget.Add(float64(n))
	c.mu.Unlock()
	return n, err
}

func (c *sniMeasuredConn) Close() error {
	err := c.Conn.Close()
	c.mu.Lock()
	defer c.mu.Unlock()
	if !c.closed {
		c.closed = true
		c.metrics.active.Dec()
	}
	return err
}
