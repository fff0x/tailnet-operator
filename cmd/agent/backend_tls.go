package main

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"errors"
	"io"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"tsunaro.io/tailnet-operator/internal/certificates"
)

const (
	backendCAUnavailable = "BackendCAUnavailable"
	backendTLSFailed     = "BackendTLSFailed"
	backendTLSProofStale = "BackendTLSProofStale"
)

var errBackendTLS = errors.New("backend TLS unavailable")

// backendSource is the only RoundTripper exposed to the proxy. Each admission reads the
// projection; callers cannot retain an old transport and send later requests through it.
// Retirement closes idle connections, not established responses or upgraded streams.
// Retired transports live only as long as their admitted work, never in an accumulating list.
type backendSource struct {
	mu            sync.Mutex
	t             target
	dial          func(context.Context, target) (net.Conn, error)
	headerTimeout time.Duration
	current       *backendTransport
	closed        bool
}

type backendTransport struct {
	transport *http.Transport
	hash      string
	retired   bool // protected by backendSource.mu
}

func readBackendCA(path string) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, errBackendTLS
	}
	defer f.Close()
	b, err := io.ReadAll(io.LimitReader(f, certificates.MaxCABundleSize+1))
	if err != nil || len(b) > certificates.MaxCABundleSize {
		return nil, errBackendTLS
	}
	return b, nil
}

// refreshLocked fails closed rather than keeping invalid desired trust. Raw-byte digests
// deliberately include whitespace: a projection change is an explicit transport boundary.
func (s *backendSource) refreshLocked() error {
	if s.closed {
		return errBackendTLS
	}
	var cfg *tls.Config
	hash := ""
	if s.t.BackendServerName != "" {
		b, err := readBackendCA(s.t.BackendCAFile)
		if err != nil {
			s.retireLocked()
			return errBackendTLS
		}
		sum := sha256.Sum256(b)
		hash = hex.EncodeToString(sum[:])
		if s.current != nil && hash == s.current.hash {
			return nil
		}
		roots, err := certificates.ParseCABundle(b)
		if err != nil {
			s.retireLocked()
			return errBackendTLS
		}
		cfg = &tls.Config{MinVersion: tls.VersionTLS12, ServerName: s.t.BackendServerName, RootCAs: roots}
	} else if s.current != nil {
		return nil
	}
	s.retireLocked()
	next := &backendTransport{hash: hash}
	next.transport = &http.Transport{
		// Preserve response bytes/metadata (including stored S3 gzip objects).
		// Forward client Accept-Encoding unchanged; never negotiate or decode for it.
		DisableCompression: true,
		// No ambient proxy, system-root fallback, session cache, or plaintext retry.
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			// A pre-rotation admission that has not begun dialing may not establish
			// another connection with retired trust. Established streams are untouched.
			s.mu.Lock()
			retired := next.retired || s.closed
			s.mu.Unlock()
			if retired {
				return nil, errBackendTLS
			}
			ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
			defer cancel()
			return s.dial(ctx, s.t)
		},
		TLSClientConfig:       cfg,
		TLSHandshakeTimeout:   10 * time.Second,
		IdleConnTimeout:       90 * time.Second,
		ResponseHeaderTimeout: s.headerTimeout,
		MaxIdleConnsPerHost:   16,
	}
	s.current = next
	return nil
}

func (s *backendSource) retireLocked() {
	if s.current != nil {
		s.current.retired = true
		s.current.transport.CloseIdleConnections()
		s.current = nil
	}
}

func (s *backendSource) Close() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.closed = true
	s.retireLocked()
}

func (s *backendSource) RoundTrip(r *http.Request) (*http.Response, error) {
	s.mu.Lock()
	if err := s.refreshLocked(); err != nil {
		s.mu.Unlock()
		return nil, err
	}
	// Selection is request admission. Only already-admitted work can finish on retirement.
	current := s.current
	s.mu.Unlock()
	response, err := current.transport.RoundTrip(r)
	if err != nil {
		s.release(current)
		return nil, err
	}
	body := &backendBody{ReadCloser: response.Body, release: func() { s.release(current) }}
	// ReverseProxy relies on io.ReadWriteCloser for WebSocket/101 tunnelling.
	if writer, ok := response.Body.(io.Writer); ok {
		response.Body = &backendUpgradeBody{backendBody: body, Writer: writer}
	} else {
		response.Body = body
	}
	return response, nil
}

func (s *backendSource) release(t *backendTransport) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if t.retired {
		t.transport.CloseIdleConnections()
	}
}

type backendBody struct {
	io.ReadCloser
	once    sync.Once
	release func()
}

func (b *backendBody) Close() error {
	err := b.ReadCloser.Close()
	b.once.Do(b.release)
	return err
}

type backendUpgradeBody struct {
	*backendBody
	io.Writer
}

// proofConfig supplies the same verification configuration as serving, but probes always
// dial a fresh connection and perform a new handshake; pooled success is not evidence.
func (s *backendSource) proofConfig() (*tls.Config, string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.refreshLocked(); err != nil {
		return nil, "", err
	}
	if s.current.transport.TLSClientConfig == nil {
		return nil, "", errBackendTLS
	}
	return s.current.transport.TLSClientConfig.Clone(), s.current.hash, nil
}

func (h *httpIngress) currentBackendProof(hash string, notAfter time.Time) bool {
	return len(h.routes) == 1 && h.currentBackendProofFor(h.certs.t.DNSName, hash, notAfter)
}

func (h *httpIngress) currentBackendProofFor(dnsName, hash string, notAfter time.Time) bool {
	runtime := h.routes[strings.ToLower(dnsName)]
	if runtime == nil || hash == "" || !h.active() || !time.Now().Before(notAfter) {
		return false
	}
	_, currentHash, err := runtime.transport.proofConfig()
	return err == nil && currentHash == hash && h.active()
}

func (h *httpIngress) probeBackendTLS(ctx context.Context) (string, time.Time, string) {
	if len(h.routes) != 1 {
		return "", time.Time{}, backendTLSProofStale
	}
	return h.probeBackendTLSFor(ctx, h.certs.t.DNSName)
}

func (h *httpIngress) probeBackendTLSFor(ctx context.Context, dnsName string) (string, time.Time, string) {
	runtime := h.routes[strings.ToLower(dnsName)]
	if runtime == nil {
		return "", time.Time{}, backendTLSProofStale
	}
	h.mu.Lock()
	if h.closing {
		h.mu.Unlock()
		return "", time.Time{}, backendTLSProofStale
	}
	h.probes.Add(1)
	h.mu.Unlock()
	defer h.probes.Done()
	ctx, cancel := context.WithTimeout(ctx, probeTimeout)
	defer cancel()
	stop := context.AfterFunc(h.ctx, cancel)
	defer stop()
	cfg, hash, err := runtime.transport.proofConfig()
	if err != nil {
		return "", time.Time{}, backendCAUnavailable
	}
	raw, err := runtime.transport.dial(ctx, runtime.t)
	if err != nil {
		return "", time.Time{}, backendTLSFailed
	}
	defer raw.Close()
	stopConn := context.AfterFunc(ctx, func() { raw.Close() })
	defer stopConn()
	c := tls.Client(raw, cfg)
	if err := c.HandshakeContext(ctx); err != nil {
		return "", time.Time{}, backendTLSFailed
	}
	state := c.ConnectionState()
	if len(state.VerifiedChains) == 0 {
		return "", time.Time{}, backendTLSFailed
	}
	// The whole verified chain must remain valid, not just the presented leaf.
	notAfter := state.PeerCertificates[0].NotAfter
	for _, cert := range state.VerifiedChains[0] {
		if cert.NotAfter.Before(notAfter) {
			notAfter = cert.NotAfter
		}
	}
	if ctx.Err() != nil || !h.currentBackendProofFor(dnsName, hash, notAfter) {
		return "", time.Time{}, backendTLSProofStale
	}
	return hash, notAfter, ""
}
