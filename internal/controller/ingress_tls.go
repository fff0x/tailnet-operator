package controller

import (
	"crypto/sha256"
	"encoding/hex"
	"net"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/validation"

	tnv1 "tsunaro.io/tailnet-operator/api/v1alpha1"
	"tsunaro.io/tailnet-operator/internal/certificates"
	"tsunaro.io/tailnet-operator/internal/naming"
)

// ingressTLSPlan contains references only. Certificate/key bytes never enter workload metadata.
// Empty issuer means an externally managed, namespace-local Secret.
type ingressTLSPlan struct {
	http       bool
	secretName string
	issuer     *tnv1.TLSIssuerReference
}

// resolveIngressTLS repeats the HTTP safety checks for objects that bypass admission.
// It does not read Secrets or certify that the agent has mounted or served a certificate.
func resolveIngressTLS(in *tnv1.TailnetIngress, tn *tnv1.Tailnet) (ingressTLSPlan, string) {
	var plan ingressTLSPlan
	names, ports := make(map[string]bool), make(map[int32]bool)
	for _, expose := range in.Spec.Exposes {
		if names[expose.Name] || ports[expose.Port] {
			return ingressTLSPlan{http: true}, "TLSConfigurationInvalid"
		}
		names[expose.Name], ports[expose.Port] = true, true
		switch expose.Mode {
		case "", "l4":
		case "http":
			if plan.http || expose.Port != 443 {
				return ingressTLSPlan{http: true}, "TLSConfigurationInvalid"
			}
			plan.http = true
		default:
			return ingressTLSPlan{http: true}, "TLSConfigurationInvalid"
		}
	}
	if !plan.http {
		if in.Spec.TLS != nil {
			return plan, "TLSConfigurationInvalid"
		}
		return plan, ""
	}
	if naming.ValidateDNSName(in.Status.DNSName) != nil || net.ParseIP(in.Status.DNSName) != nil {
		return plan, "TLSInvalidDNSName"
	}
	var ref *tnv1.TLSIssuerReference
	if local := in.Spec.TLS; local != nil {
		if local.SecretName != "" && local.IssuerRef != nil {
			return plan, "TLSConfigurationInvalid"
		}
		if local.SecretName != "" {
			if len(validation.IsDNS1123Subdomain(local.SecretName)) != 0 {
				return plan, "TLSConfigurationInvalid"
			}
			plan.secretName = local.SecretName
			return plan, "" // An explicit Secret suppresses even an invalid Tailnet issuer default.
		}
		ref = local.IssuerRef
	}
	if ref == nil && tn.Spec.Defaults.TLS != nil {
		ref = tn.Spec.Defaults.TLS.IssuerRef
	}
	if ref == nil {
		return plan, "TLSConfigurationMissing"
	}
	issuer := *ref // Default locally; never mutate objects owned by the informer cache.
	if issuer.Kind == "" {
		issuer.Kind = "Issuer"
	}
	if issuer.Group == "" {
		issuer.Group = "cert-manager.io"
	}
	if len(validation.IsDNS1123Subdomain(issuer.Name)) != 0 || issuer.Group != "cert-manager.io" ||
		(issuer.Kind != "Issuer" && issuer.Kind != "ClusterIssuer") {
		return plan, "TLSConfigurationInvalid"
	}
	plan.secretName = in.Name + "-tls"
	if len(validation.IsDNS1123Subdomain(plan.secretName)) != 0 {
		return plan, "TLSConfigurationInvalid"
	}
	plan.issuer = &issuer
	return plan, ""
}

// servingCertificate identifies the selected public leaf, not the private key or Secret resource
// version. A later agent observation can match this digest without restarting on Secret rotation.
type servingCertificate struct {
	notAfter metav1.Time
	sha256   string
}

// inspectIngressCertificate validates namespace-local material without leaking parser or SAN
// diagnostics. It does not assert client CA trust, mounted projection freshness, or TLS readiness.
func inspectIngressCertificate(secret *corev1.Secret, dnsName string, now time.Time) (servingCertificate, string) {
	var result servingCertificate
	if secret == nil {
		return result, "TLSSecretMissing"
	}
	if secret.Type != corev1.SecretTypeTLS {
		return result, "TLSSecretInvalid"
	}
	if naming.ValidateDNSName(dnsName) != nil || net.ParseIP(dnsName) != nil {
		return result, "TLSInvalidDNSName"
	}
	pair, err := certificates.ParseServingPair(secret.Data[corev1.TLSCertKey], secret.Data[corev1.TLSPrivateKeyKey], dnsName)
	if err != nil {
		return result, "TLSCertificateInvalid"
	}
	leaf := pair.Leaf
	digest := sha256.Sum256(pair.Certificate[0])
	result = servingCertificate{notAfter: metav1.NewTime(leaf.NotAfter), sha256: hex.EncodeToString(digest[:])}
	if now.Before(leaf.NotBefore) {
		return result, "TLSCertificateNotYetValid"
	}
	if !now.Before(leaf.NotAfter) {
		return result, "TLSCertificateExpired"
	}
	return result, ""
}
