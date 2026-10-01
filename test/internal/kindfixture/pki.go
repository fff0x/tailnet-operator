package kindfixture

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"math/big"
	"time"

	"k8s.io/apimachinery/pkg/util/validation"
)

// Authority is ephemeral test PKI. Its private key is never serialized by this
// API. It is not a production trust store or an external issuer integration.
type Authority struct {
	cert   *x509.Certificate
	key    *ecdsa.PrivateKey
	public []byte
}

func NewAuthority(now time.Time) (*Authority, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, ErrWebhook
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, ErrWebhook
	}
	t := &x509.Certificate{SerialNumber: serial, Subject: pkix.Name{CommonName: "owned-kind-fixture"}, NotBefore: now.Add(-time.Minute), NotAfter: now.Add(time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign}
	der, err := x509.CreateCertificate(rand.Reader, t, t, &key.PublicKey, key)
	if err != nil {
		return nil, ErrWebhook
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, ErrWebhook
	}
	return &Authority{cert: cert, key: key, public: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})}, nil
}

func (a *Authority) PublicPEM() []byte { return append([]byte(nil), a.public...) }

// Issue returns fixture leaf/key PEM and a public leaf fingerprint. Callers must
// keep keys in memory or in the owned cluster's Secret, never in test output.
func (a *Authority) Issue(dns string, now, expires time.Time) (certPEM, keyPEM []byte, fingerprint string, err error) {
	if a == nil || a.cert == nil || len(validation.IsDNS1123Subdomain(dns)) != 0 || !now.Before(expires) || expires.After(a.cert.NotAfter) {
		return nil, nil, "", ErrWebhook
	}
	key, e := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if e != nil {
		return nil, nil, "", ErrWebhook
	}
	serial, e := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if e != nil {
		return nil, nil, "", ErrWebhook
	}
	t := &x509.Certificate{SerialNumber: serial, DNSNames: []string{dns}, NotBefore: now.Add(-time.Minute), NotAfter: expires, KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, BasicConstraintsValid: true}
	der, e := x509.CreateCertificate(rand.Reader, t, a.cert, &key.PublicKey, a.key)
	if e != nil {
		return nil, nil, "", ErrWebhook
	}
	raw, e := x509.MarshalPKCS8PrivateKey(key)
	if e != nil {
		return nil, nil, "", ErrWebhook
	}
	sum := sha256.Sum256(der)
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: raw}), hex.EncodeToString(sum[:]), nil
}
