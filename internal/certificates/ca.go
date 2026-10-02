package certificates

import (
	"bytes"
	"crypto/x509"
	"encoding/pem"
)

// MaxCABundleSize bounds both projected file reads and API bundle validation.
const MaxCABundleSize = 1 << 20

// ParseCABundle accepts only a nonempty sequence of certificate PEM blocks.
// It never supplements explicit trust with system roots, or returns parser diagnostics.
func ParseCABundle(data []byte) (*x509.CertPool, error) {
	if len(data) == 0 || len(data) > MaxCABundleSize {
		return nil, ErrInvalid
	}
	roots := x509.NewCertPool()
	count := 0
	for data = bytes.TrimSpace(data); len(data) != 0; data = bytes.TrimSpace(data) {
		// pem.Decode otherwise silently skips leading garbage (including malformed blocks).
		if !bytes.HasPrefix(data, []byte("-----BEGIN CERTIFICATE-----")) {
			return nil, ErrInvalid
		}
		block, rest := pem.Decode(data)
		if block == nil || block.Type != "CERTIFICATE" || len(block.Headers) != 0 {
			return nil, ErrInvalid
		}
		// Ensure Decode did not skip a malformed certificate to find a later valid one.
		encoded := data[:len(data)-len(rest)]
		if bytes.Count(encoded, []byte("-----BEGIN ")) != 1 {
			return nil, ErrInvalid
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, ErrInvalid
		}
		roots.AddCert(cert)
		count++
		data = rest
	}
	if count == 0 {
		return nil, ErrInvalid
	}
	return roots, nil
}
