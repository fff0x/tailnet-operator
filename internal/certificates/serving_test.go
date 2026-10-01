package certificates

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"math/big"
	"testing"
	"time"
)

func TestParseServingPair(t *testing.T) {
	const dns = "app.tailnet.invalid"
	for _, tt := range []struct {
		name   string
		mutate func(*x509.Certificate)
		valid  bool
	}{
		{name: "server", valid: true},
		{name: "wildcard-san", valid: true, mutate: func(c *x509.Certificate) { c.DNSNames = []string{"*.tailnet.invalid"} }},
		{name: "unrestricted", valid: true, mutate: func(c *x509.Certificate) { c.ExtKeyUsage = nil }},
		{name: "any-purpose", valid: true, mutate: func(c *x509.Certificate) { c.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageAny} }},
		// Time checks belong to callers: a cached pair must expire without needing another parse.
		{name: "time-is-checked-by-caller", valid: true, mutate: func(c *x509.Certificate) {
			c.NotBefore, c.NotAfter = time.Unix(1, 0), time.Unix(2, 0)
		}},
		{name: "ca", mutate: func(c *x509.Certificate) { c.IsCA = true }},
		{name: "unknown-critical", mutate: func(c *x509.Certificate) {
			c.ExtraExtensions = []pkix.Extension{{Id: asn1.ObjectIdentifier{1, 2, 3, 4}, Critical: true, Value: []byte{5, 0}}}
		}},
		{name: "client-only", mutate: func(c *x509.Certificate) { c.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth} }},
		{name: "unknown-purpose-only", mutate: func(c *x509.Certificate) {
			c.ExtKeyUsage = nil
			c.UnknownExtKeyUsage = []asn1.ObjectIdentifier{{1, 2, 3, 4}}
		}},
		{name: "wrong-san", mutate: func(c *x509.Certificate) { c.DNSNames = []string{"different.invalid"} }},
		{name: "cn-is-not-san", mutate: func(c *x509.Certificate) { c.Subject.CommonName = dns; c.DNSNames = nil }},
	} {
		t.Run(tt.name, func(t *testing.T) {
			key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
			if err != nil {
				t.Fatal("fixture key generation failed")
			}
			leaf := &x509.Certificate{SerialNumber: big.NewInt(1), DNSNames: []string{dns},
				NotBefore: time.Unix(1800000000, 0), NotAfter: time.Unix(1800003600, 0),
				KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
				BasicConstraintsValid: true}
			if tt.mutate != nil {
				tt.mutate(leaf)
			}
			der, err := x509.CreateCertificate(rand.Reader, leaf, leaf, &key.PublicKey, key)
			if err != nil {
				t.Fatal("fixture certificate generation failed")
			}
			keyDER, err := x509.MarshalPKCS8PrivateKey(key)
			if err != nil {
				t.Fatal("fixture key encoding failed")
			}
			certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
			keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})
			pair, err := ParseServingPair(certPEM, keyPEM, dns)
			if !tt.valid {
				if pair != nil || err != ErrInvalid {
					t.Fatal("invalid leaf accepted or error was not bounded")
				}
				return
			}
			if err != nil || pair == nil || pair.Leaf == nil || !bytes.Equal(pair.Leaf.Raw, der) || !bytes.Equal(pair.Certificate[0], der) {
				t.Fatal("valid pair did not retain its parsed public leaf")
			}
			for _, badName := range []string{"", "100.64.0.1", "different.invalid"} {
				if p, err := ParseServingPair(certPEM, keyPEM, badName); p != nil || err != ErrInvalid {
					t.Fatal("bad desired name accepted or error was not bounded")
				}
			}
			if p, err := ParseServingPair(certPEM, []byte("credential-parser-sentinel"), dns); p != nil || err != ErrInvalid {
				t.Fatal("invalid key accepted or parser diagnostics escaped")
			}
		})
	}
}
