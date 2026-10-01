package controller

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/hex"
	"encoding/pem"
	"math/big"
	"reflect"
	"strings"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	tnv1 "tsunaro.io/tailnet-operator/api/v1alpha1"
)

func tlsIngress() *tnv1.TailnetIngress {
	in := ingress("app", "tenant", tnv1.Expose{Name: "web", Mode: "http", Port: 443,
		Backend: tnv1.Backend{Service: "app", Port: 8080}})
	in.Status.DNSName = "app.tenant.tailnet.invalid"
	return in
}

func TestResolveIngressTLS(t *testing.T) {
	defaultIssuer := &tnv1.TLSIssuerReference{Name: "default-ca", Kind: "ClusterIssuer", Group: "cert-manager.io"}
	localIssuer := &tnv1.TLSIssuerReference{Name: "local-ca"}
	for _, tt := range []struct {
		name   string
		local  *tnv1.IngressTLS
		global *tnv1.TLSIssuerReference
		secret string
		issuer *tnv1.TLSIssuerReference
		reason string
	}{
		{name: "missing", reason: "TLSConfigurationMissing"},
		{name: "empty", local: &tnv1.IngressTLS{}, reason: "TLSConfigurationMissing"},
		{name: "inherit", global: defaultIssuer, secret: "app-tls", issuer: defaultIssuer},
		{name: "empty-inherits", local: &tnv1.IngressTLS{}, global: defaultIssuer, secret: "app-tls", issuer: defaultIssuer},
		{name: "explicit-issuer", local: &tnv1.IngressTLS{IssuerRef: localIssuer}, global: defaultIssuer,
			secret: "app-tls", issuer: &tnv1.TLSIssuerReference{Name: "local-ca", Kind: "Issuer", Group: "cert-manager.io"}},
		{name: "explicit-secret", local: &tnv1.IngressTLS{SecretName: "external.tls"}, global: defaultIssuer, secret: "external.tls"},
		{name: "secret-suppresses-invalid-default", local: &tnv1.IngressTLS{SecretName: "external.tls"},
			global: &tnv1.TLSIssuerReference{Name: "invalid", Group: "external.invalid"}, secret: "external.tls"},
		{name: "issuer-suppresses-invalid-default", local: &tnv1.IngressTLS{IssuerRef: localIssuer},
			global: &tnv1.TLSIssuerReference{Name: "invalid", Group: "external.invalid"}, secret: "app-tls",
			issuer: &tnv1.TLSIssuerReference{Name: "local-ca", Kind: "Issuer", Group: "cert-manager.io"}},
		{name: "mutually-exclusive", local: &tnv1.IngressTLS{SecretName: "external", IssuerRef: localIssuer}, reason: "TLSConfigurationInvalid"},
		{name: "invalid-local-does-not-fallback", local: &tnv1.IngressTLS{IssuerRef: &tnv1.TLSIssuerReference{Name: "../invalid"}},
			global: defaultIssuer, reason: "TLSConfigurationInvalid"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			in := tlsIngress()
			in.Spec.TLS = tt.local
			tn := &tnv1.Tailnet{Spec: tnv1.TailnetSpec{Defaults: tnv1.TailnetDefaults{TLS: &tnv1.TLSDefaults{IssuerRef: tt.global}}}}
			beforeIn, beforeTN := in.DeepCopy(), tn.DeepCopy()
			plan, reason := resolveIngressTLS(in, tn)
			if reason != tt.reason || !plan.http || plan.secretName != tt.secret || !reflect.DeepEqual(plan.issuer, tt.issuer) {
				t.Fatalf("plan=%+v issuer=%+v reason=%q", plan, plan.issuer, reason)
			}
			if !reflect.DeepEqual(in, beforeIn) || !reflect.DeepEqual(tn, beforeTN) {
				t.Fatal("mutated informer-owned input")
			}
			if plan.issuer != nil {
				plan.issuer.Name = "mutated-result"
				if !reflect.DeepEqual(in, beforeIn) || !reflect.DeepEqual(tn, beforeTN) {
					t.Fatal("result aliases informer-owned issuer")
				}
			}
		})
	}
}

func TestResolveIngressTLSAdmissionBypass(t *testing.T) {
	for _, tt := range []struct {
		name   string
		mutate func(*tnv1.TailnetIngress)
		reason string
	}{
		{"port", func(in *tnv1.TailnetIngress) { in.Spec.Exposes[0].Port = 8443 }, "TLSConfigurationInvalid"},
		{"mode", func(in *tnv1.TailnetIngress) { in.Spec.Exposes[0].Mode = "HTTP" }, "TLSConfigurationInvalid"},
		{"multiple-http", func(in *tnv1.TailnetIngress) { in.Spec.Exposes = append(in.Spec.Exposes, in.Spec.Exposes[0]) }, "TLSConfigurationInvalid"},
		{"l4-port-collision", func(in *tnv1.TailnetIngress) {
			in.Spec.Exposes = append(in.Spec.Exposes, tnv1.Expose{Name: "legacy", Mode: "l4", Port: 443})
		}, "TLSConfigurationInvalid"},
		{"duplicate-name", func(in *tnv1.TailnetIngress) {
			in.Spec.Exposes = append(in.Spec.Exposes, tnv1.Expose{Name: "web", Mode: "l4", Port: 8443})
		}, "TLSConfigurationInvalid"},
		{"missing-dns", func(in *tnv1.TailnetIngress) { in.Status.DNSName = "" }, "TLSInvalidDNSName"},
		{"ip-not-dns", func(in *tnv1.TailnetIngress) { in.Status.DNSName = "100.64.0.1" }, "TLSInvalidDNSName"},
		{"wildcard", func(in *tnv1.TailnetIngress) { in.Status.DNSName = "*.tailnet.invalid" }, "TLSInvalidDNSName"},
		{"long-dns-label", func(in *tnv1.TailnetIngress) { in.Status.DNSName = strings.Repeat("a", 64) + ".invalid" }, "TLSInvalidDNSName"},
		{"secret-path", func(in *tnv1.TailnetIngress) { in.Spec.TLS = &tnv1.IngressTLS{SecretName: "other/secret"} }, "TLSConfigurationInvalid"},
		{"issuer-empty", func(in *tnv1.TailnetIngress) { in.Spec.TLS.IssuerRef.Name = "" }, "TLSConfigurationInvalid"},
		{"issuer-long", func(in *tnv1.TailnetIngress) { in.Spec.TLS.IssuerRef.Name = strings.Repeat("a", 254) }, "TLSConfigurationInvalid"},
		{"issuer-path", func(in *tnv1.TailnetIngress) { in.Spec.TLS.IssuerRef.Name = "other/issuer" }, "TLSConfigurationInvalid"},
		{"issuer-kind", func(in *tnv1.TailnetIngress) { in.Spec.TLS.IssuerRef.Kind = "ExternalIssuer" }, "TLSConfigurationInvalid"},
		{"issuer-group", func(in *tnv1.TailnetIngress) { in.Spec.TLS.IssuerRef.Group = "external.invalid" }, "TLSConfigurationInvalid"},
		{"tls-with-l4", func(in *tnv1.TailnetIngress) { in.Spec.Exposes[0].Mode = "l4" }, "TLSConfigurationInvalid"},
		{"multiple-http-distinct-ports", func(in *tnv1.TailnetIngress) {
			in.Spec.Exposes = append(in.Spec.Exposes, tnv1.Expose{Name: "second", Mode: "http", Port: 8443})
		}, "TLSConfigurationInvalid"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			in := tlsIngress()
			in.Spec.TLS = &tnv1.IngressTLS{IssuerRef: &tnv1.TLSIssuerReference{Name: "ca"}}
			tt.mutate(in)
			_, reason := resolveIngressTLS(in, &tnv1.Tailnet{})
			if reason != tt.reason {
				t.Fatalf("reason=%q, want %q", reason, tt.reason)
			}
		})
	}
	// A global HTTP default does not change either omitted-mode or explicit L4 listeners.
	for _, mode := range []string{"", "l4"} {
		in := ingress("legacy", "tenant", tnv1.Expose{Name: "tcp", Mode: mode, Port: 6443})
		tn := &tnv1.Tailnet{Spec: tnv1.TailnetSpec{Defaults: tnv1.TailnetDefaults{TLS: &tnv1.TLSDefaults{
			IssuerRef: &tnv1.TLSIssuerReference{Name: "invalid-default", Group: "unsupported"},
		}}}}
		plan, reason := resolveIngressTLS(in, tn)
		if reason != "" || plan.http || plan.secretName != "" || plan.issuer != nil {
			t.Fatalf("L4 changed: plan=%+v reason=%q", plan, reason)
		}
	}
}

func ingressTestCertificate(t *testing.T, leaf *x509.Certificate) (*corev1.Secret, []byte) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal("generate fixture key")
	}
	der, err := x509.CreateCertificate(rand.Reader, leaf, leaf, &key.PublicKey, key)
	if err != nil {
		t.Fatal("generate fixture certificate")
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal("encode fixture key")
	}
	return &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: "app-tls", Namespace: "tenant"},
		Type:       corev1.SecretTypeTLS,
		Data: map[string][]byte{
			corev1.TLSCertKey:       pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
			corev1.TLSPrivateKeyKey: pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}),
		},
	}, der
}

func TestInspectIngressCertificate(t *testing.T) {
	now := time.Unix(1800000000, 0)
	dns := "app.tenant.tailnet.invalid"
	for _, tt := range []struct {
		name   string
		mutate func(*x509.Certificate)
		secret func(*corev1.Secret)
		reason string
	}{
		{name: "valid"},
		{name: "valid-wildcard", mutate: func(c *x509.Certificate) { c.DNSNames = []string{"*.tenant.tailnet.invalid"} }},
		{name: "any-purpose", mutate: func(c *x509.Certificate) { c.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageAny} }},
		{name: "unrestricted-purpose", mutate: func(c *x509.Certificate) { c.ExtKeyUsage = nil }},
		{name: "exact-not-before", mutate: func(c *x509.Certificate) { c.NotBefore = now }},
		{name: "expired", mutate: func(c *x509.Certificate) { c.NotAfter = now.Add(-time.Second) }, reason: "TLSCertificateExpired"},
		{name: "exact-not-after", mutate: func(c *x509.Certificate) { c.NotAfter = now }, reason: "TLSCertificateExpired"},
		{name: "future", mutate: func(c *x509.Certificate) { c.NotBefore = now.Add(time.Second) }, reason: "TLSCertificateNotYetValid"},
		{name: "wrong-san", mutate: func(c *x509.Certificate) { c.DNSNames = []string{"different.invalid"} }, reason: "TLSCertificateInvalid"},
		{name: "common-name-is-not-san", mutate: func(c *x509.Certificate) { c.DNSNames = nil; c.Subject.CommonName = dns }, reason: "TLSCertificateInvalid"},
		{name: "client-only", mutate: func(c *x509.Certificate) { c.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth} }, reason: "TLSCertificateInvalid"},
		{name: "unknown-purpose-only", mutate: func(c *x509.Certificate) {
			c.ExtKeyUsage = nil
			c.UnknownExtKeyUsage = []asn1.ObjectIdentifier{{1, 2, 3, 4}}
		}, reason: "TLSCertificateInvalid"},
		{name: "ca-not-leaf", mutate: func(c *x509.Certificate) { c.IsCA = true }, reason: "TLSCertificateInvalid"},
		{name: "unknown-critical-extension", mutate: func(c *x509.Certificate) {
			c.ExtraExtensions = []pkix.Extension{{Id: asn1.ObjectIdentifier{1, 2, 3, 4}, Critical: true, Value: []byte{5, 0}}}
		}, reason: "TLSCertificateInvalid"},
		{name: "wrong-type", secret: func(s *corev1.Secret) { s.Type = corev1.SecretTypeOpaque }, reason: "TLSSecretInvalid"},
		{name: "missing-cert", secret: func(s *corev1.Secret) { delete(s.Data, corev1.TLSCertKey) }, reason: "TLSCertificateInvalid"},
		{name: "missing-key", secret: func(s *corev1.Secret) { delete(s.Data, corev1.TLSPrivateKeyKey) }, reason: "TLSCertificateInvalid"},
		{name: "malformed-credential", secret: func(s *corev1.Secret) {
			s.Data[corev1.TLSPrivateKeyKey] = []byte("sensitive-fixture-parser-sentinel")
		}, reason: "TLSCertificateInvalid"},
		{name: "mismatched-key", secret: func(s *corev1.Secret) {
			other, _ := ingressTestCertificate(t, &x509.Certificate{SerialNumber: big.NewInt(2), NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour)})
			s.Data[corev1.TLSPrivateKeyKey] = other.Data[corev1.TLSPrivateKeyKey]
		}, reason: "TLSCertificateInvalid"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			leaf := &x509.Certificate{SerialNumber: big.NewInt(1), DNSNames: []string{dns},
				NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour),
				KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
				BasicConstraintsValid: true}
			if tt.mutate != nil {
				tt.mutate(leaf)
			}
			secret, der := ingressTestCertificate(t, leaf)
			if tt.secret != nil {
				tt.secret(secret)
			}
			before := secret.DeepCopy()
			got, reason := inspectIngressCertificate(secret, dns, now)
			if reason != tt.reason {
				t.Fatalf("reason=%q, want %q", reason, tt.reason)
			}
			if !reflect.DeepEqual(secret, before) {
				t.Fatal("mutated input Secret")
			}
			if reason == "" || reason == "TLSCertificateExpired" || reason == "TLSCertificateNotYetValid" {
				hash := sha256.Sum256(der)
				if !got.notAfter.Time.Equal(leaf.NotAfter) || got.sha256 != hex.EncodeToString(hash[:]) {
					t.Fatal("wrong public leaf identity/expiry")
				}
			} else if got.sha256 != "" || !got.notAfter.IsZero() {
				t.Fatal("invalid material returned usable leaf identity")
			}
		})
	}
	if _, reason := inspectIngressCertificate(nil, dns, now); reason != "TLSSecretMissing" {
		t.Fatalf("missing secret reason=%q", reason)
	}
}
