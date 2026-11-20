package controller

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// chainFixture builds a CA (optionally name-constrained) and a leaf signed by it, returning a
// kubernetes.io/tls Secret with tls.crt, tls.key and ca.crt (the issuing CA, as cert-manager writes
// it). selfSignedLeaf ignores the CA for the leaf signature, modelling a foreign issuer.
func chainFixture(t *testing.T, leafDNS string, permitted []string, selfSignedLeaf bool) *corev1.Secret {
	t.Helper()
	now := time.Unix(1800000000, 0)
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	caTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "Test CA"},
		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign,
	}
	if len(permitted) > 0 {
		caTmpl.PermittedDNSDomains = permitted
		caTmpl.PermittedDNSDomainsCritical = true
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	caCert, err := x509.ParseCertificate(caDER)
	if err != nil {
		t.Fatal(err)
	}

	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	leafTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(2), DNSNames: []string{leafDNS},
		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	parent, signKey := caCert, caKey
	if selfSignedLeaf {
		parent, signKey = leafTmpl, leafKey
	}
	leafDER, err := x509.CreateCertificate(rand.Reader, leafTmpl, parent, &leafKey.PublicKey, signKey)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(leafKey)
	if err != nil {
		t.Fatal(err)
	}
	return &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: "app-tls", Namespace: "tenant"},
		Type:       corev1.SecretTypeTLS,
		Data: map[string][]byte{
			corev1.TLSCertKey:       pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leafDER}),
			corev1.TLSPrivateKeyKey: pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}),
			"ca.crt":                pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER}),
		},
	}
}

func TestInspectIngressCertificateChain(t *testing.T) {
	now := time.Unix(1800000000, 0)
	const dns = "app.tenant.example.internal"
	cases := []struct {
		name         string
		secret       *corev1.Secret
		chainInvalid bool
		reason       string
	}{
		{name: "verifies against ca.crt", secret: chainFixture(t, dns, nil, false)},
		{name: "within name constraints", secret: chainFixture(t, dns, []string{"tenant.example.internal"}, false)},
		{name: "outside name constraints", secret: chainFixture(t, "app.other.internal", []string{"tenant.example.internal"}, false), chainInvalid: true},
		{name: "foreign issuer", secret: chainFixture(t, dns, nil, true), chainInvalid: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			want := dns
			if tc.name == "outside name constraints" {
				want = "app.other.internal"
			}
			leaf, reason, _ := inspectIngressCertificateNames(tc.secret, []string{want}, now)
			if reason != tc.reason {
				t.Fatalf("reason = %q, want %q (listener must stay, chain is status-only)", reason, tc.reason)
			}
			if leaf.chainInvalid != tc.chainInvalid {
				t.Fatalf("chainInvalid = %v, want %v", leaf.chainInvalid, tc.chainInvalid)
			}
		})
	}

	// No ca.crt: nothing to check, never reported invalid.
	noCA := chainFixture(t, dns, nil, false)
	delete(noCA.Data, "ca.crt")
	if leaf, reason, _ := inspectIngressCertificateNames(noCA, []string{dns}, now); reason != "" || leaf.chainInvalid {
		t.Fatalf("no ca.crt: reason=%q chainInvalid=%v, want empty/false", reason, leaf.chainInvalid)
	}
}

// A leaf that otherwise verifies but fails the chain surfaces as TLSReady=False/TLSChainInvalid,
// while every other local signal is green — the listener keeps serving.
func TestChainInvalidSurfacesInStatus(t *testing.T) {
	r, in, state, probes, now := ingressTLSStatusFixture(t)
	state.leaf.chainInvalid = true
	r.computeIngressStatus(in, state, probes, nil, now)
	c := meta.FindStatusCondition(in.Status.Conditions, "TLSReady")
	if c == nil || c.Status != metav1.ConditionFalse || c.Reason != "TLSChainInvalid" {
		t.Fatalf("TLSReady = %+v, want False/TLSChainInvalid", c)
	}
	if condReason(in.Status.Conditions, "Ready") != "TLSChainInvalid" {
		t.Fatalf("Ready reason = %s, want TLSChainInvalid", condReason(in.Status.Conditions, "Ready"))
	}
}
