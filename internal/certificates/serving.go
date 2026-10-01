// Package certificates defines the certificate policy shared by the controller and HTTP agent.
package certificates

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"net"
)

// ErrInvalid contains no key material, PEM content, parser diagnostics or certificate names.
var ErrInvalid = errors.New("TLS certificate unavailable or invalid")

// ParseServingPair checks key matching, the DNS SAN and server-leaf constraints, not chain trust.
// Callers supply a validated concrete DNS name and enforce the validity interval at every use,
// including uses of cached pairs.
func ParseServingPair(certPEM, keyPEM []byte, dnsName string) (*tls.Certificate, error) {
	if dnsName == "" || net.ParseIP(dnsName) != nil {
		return nil, ErrInvalid
	}
	pair, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil || len(pair.Certificate) == 0 {
		return nil, ErrInvalid
	}
	leaf, err := x509.ParseCertificate(pair.Certificate[0])
	if err != nil || leaf.VerifyHostname(dnsName) != nil || leaf.IsCA || len(leaf.UnhandledCriticalExtensions) != 0 {
		return nil, ErrInvalid
	}
	server := len(leaf.ExtKeyUsage) == 0 && len(leaf.UnknownExtKeyUsage) == 0
	for _, usage := range leaf.ExtKeyUsage {
		server = server || usage == x509.ExtKeyUsageServerAuth || usage == x509.ExtKeyUsageAny
	}
	if !server {
		return nil, ErrInvalid
	}
	pair.Leaf = leaf
	return &pair, nil
}
