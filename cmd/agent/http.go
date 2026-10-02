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
	mu      sync.Mutex
	t       target
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
	if hello != nil && (!validDNSName(hello.ServerName) || !strings.EqualFold(hello.ServerName, s.t.DNSName)) {
		return nil, errors.New("unrecognized TLS server name")
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

type httpIngress struct {
	net.Listener
	srv       *http.Server
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
		h.transport.Close()
	})
	return nil
}

// serveHTTPIngress takes ownership of an already-bound tailnet listener. Tests supply a local
// owned listener and dial function; production never binds a second (pod-network) TLS listener.
func serveHTTPIngress(ctx context.Context, ln net.Listener, t target, dial func(context.Context, target) (net.Conn, error)) (*httpIngress, error) {
	if t.Mode != "http" {
		return nil, errors.New("HTTP listener requires HTTP target mode")
	}
	if err := t.validateHTTP(); err != nil {
		return nil, err
	}
	certs := &certificateSource{t: t}
	ctx, cancel := context.WithCancel(ctx)
	tracked := &trackedListener{Listener: ln, conns: make(map[*trackedConn]struct{})}
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
	tlsConfig := &tls.Config{
		MinVersion:     tls.VersionTLS12,
		GetCertificate: certs.get,
		// Resumed sessions must not bypass SNI/certificate expiry/rotation checks.
		SessionTicketsDisabled: true,
	}
	h := &httpIngress{transport: transport, cancel: cancel, done: make(chan struct{}), ctx: ctx, certs: certs, tracked: tracked}
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
			if r.TLS == nil || !strings.EqualFold(r.TLS.ServerName, t.DNSName) || !matchesHTTPHost(r.Host, t.DNSName) {
				http.Error(w, "misdirected request", http.StatusMisdirectedRequest)
				return
			}
			if _, err := certs.get(nil); err != nil {
				http.Error(w, "TLS certificate unavailable", http.StatusServiceUnavailable)
				return
			}
			serveHTTPWithTimeout(w, r, proxy, requestDuration)
		}),
	}
	if err := http2.ConfigureServer(h.srv, &http2.Server{}); err != nil {
		cancel()
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
