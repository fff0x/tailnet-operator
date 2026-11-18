package controller

import (
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"net"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/validation"

	tnv1 "tsunaro.io/tailnet-operator/api/v1alpha1"
	"tsunaro.io/tailnet-operator/internal/naming"
)

// ingressTLSPlan contains references only. Certificate/key bytes never enter workload metadata.
// Empty issuer means an externally managed, namespace-local Secret.
type ingressTLSPlan struct {
	http            bool
	secretName      string
	issuer          *tnv1.TLSIssuerReference
	names           ingressDNSPlan
	controlIdentity string
}

// resolveIngressTLS repeats the HTTP safety checks for objects that bypass admission.
// It does not read Secrets or certify that the agent has mounted or served a certificate.
func resolveIngressTLS(in *tnv1.TailnetIngress, tn *tnv1.Tailnet) (ingressTLSPlan, string) {
	plan := ingressTLSPlan{http: ingressHTTPProtocol(in), controlIdentity: ingressResolvedControlDigest(in, tn)}
	if !safeIngressExposes(in.Spec.Exposes) {
		return plan, "TLSConfigurationInvalid"
	}
	names, reason := resolveIngressDNSNames(in, tn)
	if reason != "" {
		return plan, reason
	}
	plan.names = names
	if !plan.http {
		if in.Spec.TLS != nil {
			return plan, "TLSConfigurationInvalid"
		}
		return plan, ""
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
	leaf, reason, _ := inspectIngressCertificateNames(secret, []string{dnsName}, now)
	return leaf, reason
}

// maxIngressCertificateNames bounds the SAN list: the base name plus, per HTTP expose (≤ 50), its
// name, one alias and up to maxBridgeNamesPerExpose bridge names.
const maxIngressCertificateNames = 1 + 50*(2+maxBridgeNamesPerExpose)

// Return only the first uncovered configured name, never names or parser errors from the Secret.
// Keep the server-leaf policy aligned with certificates.ParseServingPair; time is checked at use.
func inspectIngressCertificateNames(secret *corev1.Secret, names []string, now time.Time) (servingCertificate, string, string) {
	var result servingCertificate
	if secret == nil {
		return result, "TLSSecretMissing", ""
	}
	if secret.Type != corev1.SecretTypeTLS {
		return result, "TLSSecretInvalid", ""
	}
	if len(names) == 0 || len(names) > maxIngressCertificateNames {
		return result, "TLSInvalidDNSName", ""
	}
	for _, name := range names {
		if naming.ValidateDNSName(name) != nil || net.ParseIP(name) != nil {
			return result, "TLSInvalidDNSName", ""
		}
	}
	pair, err := tls.X509KeyPair(secret.Data[corev1.TLSCertKey], secret.Data[corev1.TLSPrivateKeyKey])
	if err != nil || len(pair.Certificate) == 0 {
		return result, "TLSCertificateInvalid", ""
	}
	leaf, err := x509.ParseCertificate(pair.Certificate[0])
	if err != nil || leaf.IsCA || len(leaf.UnhandledCriticalExtensions) != 0 {
		return result, "TLSCertificateInvalid", ""
	}
	server := len(leaf.ExtKeyUsage) == 0 && len(leaf.UnknownExtKeyUsage) == 0
	for _, usage := range leaf.ExtKeyUsage {
		server = server || usage == x509.ExtKeyUsageServerAuth || usage == x509.ExtKeyUsageAny
	}
	if !server {
		return result, "TLSCertificateInvalid", ""
	}
	for _, name := range names {
		if leaf.VerifyHostname(name) != nil {
			return result, "TLSNameMismatch", name
		}
	}
	digest := sha256.Sum256(pair.Certificate[0])
	result = servingCertificate{notAfter: metav1.NewTime(leaf.NotAfter), sha256: hex.EncodeToString(digest[:])}
	if now.Before(leaf.NotBefore) {
		return result, "TLSCertificateNotYetValid", ""
	}
	if !now.Before(leaf.NotAfter) {
		return result, "TLSCertificateExpired", ""
	}
	return result, "", ""
}
