package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httputil"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/net/http2"

	"tsunaro.io/tailnet-operator/internal/certificates"
	"tsunaro.io/tailnet-operator/internal/httpconfig"
)

func (t target) validateHTTP() error {
	switch t.Mode {
	case "", "l4":
		if t.BackendServerName != "" || t.BackendCAFile != "" || t.RequestTimeout != "" || t.BackendRequestTimeout != "" {
			return errors.New("HTTP settings require HTTP target mode")
		}
		return nil
	case "http":
		if t.ListenPort != 443 || !validDNSName(t.DNSName) || t.CertFile == "" || t.KeyFile == "" {
			return errors.New("HTTP target requires listener 443, DNS name and certificate/key files")
		}
		if (net.ParseIP(t.Address) == nil && !validDNSName(t.Address)) || t.Port < 1 || t.Port > 65535 {
			return errors.New("HTTP target requires a backend host and TCP port, not a URL")
		}
		if (t.BackendServerName == "") != (t.BackendCAFile == "") || (t.BackendServerName != "" && !validDNSName(t.BackendServerName)) {
			return errors.New("backend TLS requires DNS server name and CA file")
		}
		for _, value := range []string{t.RequestTimeout, t.BackendRequestTimeout} {
			if value != "" {
				if _, err := httpconfig.ParseDuration(value); err != nil {
					return errors.New("invalid HTTP timeout")
				}
			}
		}
		return nil
	default:
		return errors.New("unsupported target mode")
	}
}

func validDNSName(s string) bool {
	if len(s) == 0 || len(s) > 253 || net.ParseIP(s) != nil {
		return false
	}
	for _, label := range strings.Split(s, ".") {
		if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for _, c := range label {
			if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '-') {
				return false
			}
		}
	}
	return true
}

func matchesHTTPHost(host, dns string) bool {
	host = strings.TrimSuffix(host, ":443")
	return validDNSName(host) && strings.EqualFold(host, dns)
}

var errCertificate = certificates.ErrInvalid

// certificateSource reads projected Secret files without keeping descriptors to an old projection.
// A cached pair lives at most one minute, and never beyond the leaf's validity interval.
// No raw file, parser, path or x509 errors escape this boundary.
type certificateSource struct {
	mu sync.Mutex
	t  target
	// Immutable route set. Required SANs may include non-routable names.
	routes  map[string]*httpRuntime
	cert    *tls.Certificate
	checked time.Time
	now     func() time.Time
}

func (s *certificateSource) get(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
	return s.load(hello, false)
}

// fresh revalidates the current projection even within the serving cache interval. Health must
// not certify an old observation after rotation, invalidation or expiry.
func (s *certificateSource) fresh() (*tls.Certificate, error) {
	return s.load(nil, true)
}

func (s *certificateSource) load(hello *tls.ClientHelloInfo, fresh bool) (*tls.Certificate, error) {
	if hello != nil {
		known := strings.EqualFold(hello.ServerName, s.t.DNSName)
		if s.routes != nil {
			_, known = s.routes[strings.ToLower(hello.ServerName)]
		}
		if !validDNSName(hello.ServerName) || !known {
			return nil, errors.New("unrecognized TLS server name")
		}
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	now := time.Now()
	if s.now != nil {
		now = s.now()
	}
	if fresh || s.checked.IsZero() || now.Sub(s.checked) >= time.Minute || now.Before(s.checked) {
		s.checked = now
		s.cert = nil
		certPEM, keyPEM, err := readCertificateSnapshot(s.t.CertFile, s.t.KeyFile)
		if err == nil {
			s.cert, _ = certificates.ParseServingPair(certPEM, keyPEM, s.t.DNSName)
			if s.cert != nil {
				for _, name := range s.t.requiredCertificateNames {
					if name != "" && s.cert.Leaf.VerifyHostname(name) != nil {
						s.cert = nil
						break
					}
				}
			}
		}
	}
	if s.cert == nil || now.Before(s.cert.Leaf.NotBefore) || !now.Before(s.cert.Leaf.NotAfter) {
		return nil, errCertificate
	}
	return s.cert, nil
}

func readCertificateSnapshot(certFile, keyFile string) ([]byte, []byte, error) {
	certPath, err := filepath.EvalSymlinks(certFile)
	if err != nil {
		return nil, nil, errCertificate
	}
	keyPath, err := filepath.EvalSymlinks(keyFile)
	if err != nil {
		return nil, nil, errCertificate
	}
	// In a Kubernetes projection both siblings must resolve into the same generation.
	if filepath.Dir(certFile) == filepath.Dir(keyFile) && filepath.Dir(certPath) != filepath.Dir(keyPath) {
		return nil, nil, errCertificate
	}
	cert, err := os.ReadFile(certPath)
	if err != nil {
		return nil, nil, errCertificate
	}
	key, err := os.ReadFile(keyPath)
	if err != nil {
		return nil, nil, errCertificate
	}
	certAgain, err := os.ReadFile(certPath)
	if err != nil || !bytes.Equal(cert, certAgain) {
		return nil, nil, errCertificate
	}
	keyAgain, err := os.ReadFile(keyPath)
	if err != nil || !bytes.Equal(key, keyAgain) {
		return nil, nil, errCertificate
	}
	certEnd, err := filepath.EvalSymlinks(certFile)
	if err != nil || certEnd != certPath {
		return nil, nil, errCertificate
	}
	keyEnd, err := filepath.EvalSymlinks(keyFile)
	if err != nil || keyEnd != keyPath {
		return nil, nil, errCertificate
	}
	return cert, key, nil
}

// trackedListener tracks the raw connections BELOW TLS: http.Server still sees *tls.Conn (needed
// for HTTP/2), while Close also reaches hijacked WebSockets, which Server.Close does not own.
type trackedListener struct {
	net.Listener
	mu     sync.Mutex
	closed bool
	conns  map[*trackedConn]struct{}
}

type trackedConn struct {
	net.Conn
	owner *trackedListener
	once  sync.Once
}

func (c *trackedConn) Close() error {
	err := c.Conn.Close()
	c.once.Do(func() {
		c.owner.mu.Lock()
		delete(c.owner.conns, c)
		c.owner.mu.Unlock()
	})
	return err
}

func (l *trackedListener) Accept() (net.Conn, error) {
	c, err := l.Listener.Accept()
	if err != nil {
		return nil, err
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.closed {
		c.Close()
		return nil, net.ErrClosed
	}
	tc := &trackedConn{Conn: c, owner: l}
	l.conns[tc] = struct{}{}
	return tc, nil
}

func (l *trackedListener) Close() error {
	l.mu.Lock()
	l.closed = true
	conns := make([]*trackedConn, 0, len(l.conns))
	for c := range l.conns {
		conns = append(conns, c)
	}
	l.mu.Unlock()
	err := l.Listener.Close()
	for _, c := range conns {
		c.Close()
	}
	return err
}

// Each immutable SNI entry owns its backend trust, pool, proxy and timeout policy.
type httpRuntime struct {
	t               target
	transport       *backendSource
	proxy           *httputil.ReverseProxy
	requestDuration time.Duration
	metrics         connectionMetrics
}

type httpIngress struct {
	net.Listener
	srv    *http.Server
	routes map[string]*httpRuntime
	// Single-target compatibility only; deliberately nil for multi-host listeners.
	transport *backendSource
	cancel    context.CancelFunc
	once      sync.Once
	done      chan struct{}
	mu        sync.Mutex
	closing   bool
	handlers  sync.WaitGroup
	probes    sync.WaitGroup
	ctx       context.Context
	certs     *certificateSource
	tracked   *trackedListener
}

func (h *httpIngress) Close() error {
	h.once.Do(func() {
		h.mu.Lock()
		h.closing = true
		h.mu.Unlock()
		h.cancel()
		h.Listener.Close()
		h.srv.Close()
		<-h.done
		h.probes.Wait()   // cancellation closes raw probe pipes and joins both TLS handshakes
		h.handlers.Wait() // includes ReverseProxy's upgraded-connection copies
		for _, runtime := range h.routes {
			runtime.transport.Close()
		}
	})
	return nil
}

func newHTTPRuntime(t target, dial upstreamDial, metrics connectionMetrics) *httpRuntime {
	headerTimeout := 30 * time.Second
	if t.BackendRequestTimeout != "" {
		headerTimeout, _ = httpconfig.ParseDuration(t.BackendRequestTimeout) // validated above
	}
	var requestDuration time.Duration
	if t.RequestTimeout != "" {
		requestDuration, _ = httpconfig.ParseDuration(t.RequestTimeout)
	}
	transport := &backendSource{t: t, dial: dial, headerTimeout: headerTimeout}
	// net/http and ReverseProxy can log arbitrary transport errors and request material.
	// Suppress those logs; only bounded, fixed errors are sent to callers.
	quiet := log.New(io.Discard, "", 0)
	proxy := &httputil.ReverseProxy{
		Transport: transport,
		ErrorLog:  quiet,
		ErrorHandler: func(w http.ResponseWriter, _ *http.Request, err error) {
			var timeout net.Error
			if errors.Is(err, context.DeadlineExceeded) || (errors.As(err, &timeout) && timeout.Timeout()) {
				http.Error(w, "backend timeout", http.StatusGatewayTimeout)
				return
			}
			http.Error(w, "backend unavailable", http.StatusBadGateway)
		},
		Rewrite: func(r *httputil.ProxyRequest) {
			r.Out.URL.Scheme = "http"
			if t.BackendServerName != "" {
				r.Out.URL.Scheme = "https"
			}
			r.Out.URL.Host = net.JoinHostPort(t.Address, strconv.Itoa(t.Port))
			r.Out.URL.User = nil
			r.Out.Host = r.In.Host
			for k := range r.Out.Header {
				if strings.EqualFold(k, "Forwarded") || strings.HasPrefix(strings.ToLower(k), "x-forwarded-") {
					delete(r.Out.Header, k)
				}
			}
			r.SetXForwarded()
			// RemoteAddr comes from tsnet, never from an incoming forwarding header.
			if ip, _, err := net.SplitHostPort(r.In.RemoteAddr); err == nil {
				if strings.Contains(ip, ":") {
					ip = "[" + ip + "]"
				}
				r.Out.Header.Set("Forwarded", "for="+strconv.Quote(ip)+";proto=https;host="+strconv.Quote(r.In.Host))
			}
		},
	}
	return &httpRuntime{t: t, transport: transport, proxy: proxy, requestDuration: requestDuration, metrics: metrics}
}

// serveHTTPIngress is an unambiguous single-target compatibility helper.
func serveHTTPIngress(ctx context.Context, ln net.Listener, t target, dial upstreamDial) (*httpIngress, error) {
	return serveHTTPIngressGroup(ctx, ln, []target{t}, dial, nil)
}

// serveHTTPIngressGroup takes ownership of one already-bound tailnet listener. Tests may supply
// an owned local listener; production never binds a second (pod-network) TLS listener.
func serveHTTPIngressGroup(ctx context.Context, ln net.Listener, targets []target, dial upstreamDial, metrics *agentMetrics) (*httpIngress, error) {
	version := 2
	if len(targets) > 0 && targets[0].requiredCertificateNames[0] != "" {
		version = 3
	}
	if len(targets) == 0 || validateTargets(targets, version) != nil {
		return nil, errTargetsConfig
	}
	for _, t := range targets {
		if t.Mode != "http" {
			return nil, errTargetsConfig
		}
	}
	routes := make(map[string]*httpRuntime, len(targets))
	for _, t := range targets {
		m := metrics.connection(t.Name)
		rt := newHTTPRuntime(t, m.wrapDial(dial), m)
		routes[strings.ToLower(t.DNSName)] = rt
		for _, alias := range t.dnsAliases {
			if alias != "" {
				routes[alias] = rt
			}
		}
	}
	certs := &certificateSource{t: targets[0], routes: routes}
	ctx, cancel := context.WithCancel(ctx)
	if metrics != nil {
		ln = &sniMeasuredListener{Listener: ln, unattributed: metrics.unattributedConnection()}
	}
	tracked := &trackedListener{Listener: ln, conns: make(map[*trackedConn]struct{})}
	tlsConfig := &tls.Config{
		MinVersion: tls.VersionTLS12,
		GetCertificate: func(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
			// The raw accepted connection is below TLS so HTTP/2 and hijacks retain wire
			// accounting. Local net.Pipe component probes deliberately have no metrics.
			if runtime := routes[strings.ToLower(hello.ServerName)]; runtime != nil && validDNSName(hello.ServerName) {
				if tracked, ok := hello.Conn.(*trackedConn); ok {
					if measured, ok := tracked.Conn.(*sniMeasuredConn); ok {
						measured.selectTarget(runtime.metrics)
					}
				}
			}
			return certs.get(hello)
		},
		// Resumed sessions must not bypass SNI/certificate expiry/rotation checks.
		SessionTicketsDisabled: true,
	}
	h := &httpIngress{routes: routes, cancel: cancel, done: make(chan struct{}), ctx: ctx, certs: certs, tracked: tracked}
	if len(targets) == 1 {
		h.transport = routes[strings.ToLower(targets[0].DNSName)].transport
	}
	quiet := log.New(io.Discard, "", 0)
	h.srv = &http.Server{
		TLSConfig:         tlsConfig,
		ReadHeaderTimeout: 10 * time.Second,
		IdleTimeout:       90 * time.Second,
		ErrorLog:          quiet,
		BaseContext:       func(net.Listener) context.Context { return ctx },
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			h.mu.Lock()
			if h.closing {
				h.mu.Unlock()
				http.Error(w, "shutting down", http.StatusServiceUnavailable)
				return
			}
			h.handlers.Add(1)
			h.mu.Unlock()
			defer h.handlers.Done()
			var runtime *httpRuntime
			if r.TLS != nil {
				runtime = routes[strings.ToLower(r.TLS.ServerName)]
			}
			// Host must match the SNI that selected the route (same-origin). With aliases the
			// SNI may be an alias rather than the target's primary DNSName.
			if runtime == nil || r.TLS == nil || !matchesHTTPHost(r.Host, r.TLS.ServerName) {
				http.Error(w, "misdirected request", http.StatusMisdirectedRequest)
				return
			}
			if _, err := certs.get(nil); err != nil {
				http.Error(w, "TLS certificate unavailable", http.StatusServiceUnavailable)
				return
			}
			serveHTTPWithTimeout(w, r, runtime.proxy, runtime.requestDuration)
		}),
	}
	if err := http2.ConfigureServer(h.srv, &http2.Server{}); err != nil {
		cancel()
		for _, runtime := range routes {
			runtime.transport.Close()
		}
		return nil, errors.New("HTTP/2 configuration failed")
	}
	h.Listener = tls.NewListener(tracked, tlsConfig)
	go func() {
		defer close(h.done)
		if err := h.srv.Serve(h.Listener); err != nil && !errors.Is(err, http.ErrServerClosed) && !errors.Is(err, net.ErrClosed) {
			log.Printf("HTTP ingress listener stopped unexpectedly")
		}
	}()
	go func() {
		select {
		case <-ctx.Done():
		case <-h.done:
		}
		h.Close()
	}()
	return h, nil
}
