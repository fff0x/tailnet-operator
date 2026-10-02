package certificates

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"math/big"
	"testing"
	"time"
)

func TestParseCABundle(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	ca := &x509.Certificate{SerialNumber: big.NewInt(1), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour)}
	der, err := x509.CreateCertificate(rand.Reader, ca, ca, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	private := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: []byte("secret")})
	for name, data := range map[string][]byte{
		"empty": nil, "space": []byte(" \n"), "garbage": []byte("secret"),
		"prefix": append([]byte("unexpected\n"), cert...), "suffix": append(append([]byte{}, cert...), 'x'),
		"private": private, "mixed": append(append([]byte{}, cert...), private...),
		"mixed-reverse":          append(append([]byte{}, private...), cert...),
		"malformed":              pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: []byte("bad DER")}),
		"malformed-before-valid": append([]byte("-----BEGIN CERTIFICATE-----\nbad\n"), cert...),
		"headers":                pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Headers: map[string]string{"Extra": "unexpected"}, Bytes: der}),
		"oversize":               bytes.Repeat([]byte(" "), MaxCABundleSize+1),
	} {
		t.Run(name, func(t *testing.T) {
			if pool, err := ParseCABundle(data); pool != nil || err != ErrInvalid {
				t.Fatalf("accepted invalid bundle or unbounded error: %v", err)
			}
		})
	}
	for _, data := range [][]byte{cert, append(append([]byte{}, cert...), cert...), append(append([]byte("\n \t"), cert...), '\n')} {
		pool, err := ParseCABundle(data)
		if err != nil || pool == nil {
			t.Fatalf("valid bundle: %v", err)
		}
		parsed, _ := x509.ParseCertificate(der)
		if _, err := parsed.Verify(x509.VerifyOptions{Roots: pool, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageAny}}); err != nil {
			t.Fatal(err)
		}
	}
}
