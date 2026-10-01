package main

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"net"
	"time"
)

var errLocalTLS = errors.New("local TLS component probe failed")

type tlsObservation struct {
	sha256   string
	notAfter time.Time
}

func leafSHA256(leaf *x509.Certificate) string {
	sum := sha256.Sum256(leaf.Raw)
	return hex.EncodeToString(sum[:])
}

// active checks the owned listener/server lifecycle, not tsnet Accept or tailnet connectivity.
func (h *httpIngress) active() bool {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.closing || h.ctx.Err() != nil {
		return false
	}
	select {
	case <-h.done:
		return false
	default:
	}
	h.tracked.mu.Lock()
	defer h.tracked.mu.Unlock()
	return !h.tracked.closed
}

// currentProof revalidates the projected pair even inside the serving cache/probe intervals.
// Only public leaf identity is compared; no key hash or parser diagnostics leave the source.
func (h *httpIngress) currentProof(proof tlsObservation) bool {
	if proof.sha256 == "" || !h.active() || !time.Now().Before(proof.notAfter) {
		return false
	}
	cert, err := h.certs.fresh()
	return err == nil && leafSHA256(cert.Leaf) == proof.sha256 && cert.Leaf.NotAfter.Equal(proof.notAfter) && h.active()
}

// probeTLS checks LOCAL TLS components using the exact public server TLSConfig/GetCertificate.
// It intentionally does NOT exercise tsnet Accept, ACLs, DERP, routing or DNS. Real peer TLS/HTTP
// acceptance is separate. net.Pipe does not expose another pod/network listener.
func (h *httpIngress) probeTLS(ctx context.Context) (tlsObservation, error) {
	h.mu.Lock()
	if h.closing {
		h.mu.Unlock()
		return tlsObservation{}, errLocalTLS
	}
	h.probes.Add(1)
	h.mu.Unlock()
	defer h.probes.Done()
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	stop := context.AfterFunc(h.ctx, cancel)
	defer stop()
	if !h.active() {
		return tlsObservation{}, errLocalTLS
	}
	selected, err := h.certs.fresh()
	if err != nil {
		return tlsObservation{}, errLocalTLS
	}
	proof, err := localTLSHandshake(ctx, h.srv.TLSConfig, selected.Leaf, h.certs.t.DNSName)
	if err != nil || ctx.Err() != nil || !h.currentProof(proof) {
		return tlsObservation{}, errLocalTLS
	}
	return proof, nil
}

// localTLSHandshake independently verifies hostname, validity and the selected public leaf.
// Both sides are bounded, canceled and joined. Close raw pipes, never tls.Conn.Close: a TLS
// close_notify write on an in-memory pipe can otherwise wait forever for the other side to read.
func localTLSHandshake(ctx context.Context, serverConfig *tls.Config, selected *x509.Certificate, dnsName string) (tlsObservation, error) {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	serverRaw, clientRaw := net.Pipe()
	closeRaw := func() {
		serverRaw.Close()
		clientRaw.Close()
	}
	defer closeRaw()
	stop := context.AfterFunc(ctx, closeRaw)
	defer stop()
	deadline, _ := ctx.Deadline()
	serverRaw.SetDeadline(deadline)
	clientRaw.SetDeadline(deadline)
	roots := x509.NewCertPool()
	roots.AddCert(selected)
	pin := leafSHA256(selected)
	client := tls.Client(clientRaw, &tls.Config{
		MinVersion: tls.VersionTLS12,
		ServerName: dnsName,
		RootCAs:    roots,
		VerifyConnection: func(state tls.ConnectionState) error {
			if len(state.PeerCertificates) == 0 || leafSHA256(state.PeerCertificates[0]) != pin {
				return errLocalTLS
			}
			return nil
		},
	})
	server := tls.Server(serverRaw, serverConfig)
	done := make(chan error, 2)
	go func() { done <- server.HandshakeContext(ctx) }()
	go func() { done <- client.HandshakeContext(ctx) }()
	ok := true
	for range 2 {
		if err := <-done; err != nil {
			ok = false
			closeRaw()
		}
	}
	if !ok || ctx.Err() != nil {
		return tlsObservation{}, errLocalTLS
	}
	// Report the ACTUALLY PRESENTED leaf, not an identity inferred from files.
	leaf := client.ConnectionState().PeerCertificates[0]
	return tlsObservation{sha256: leafSHA256(leaf), notAfter: leaf.NotAfter}, nil
}
