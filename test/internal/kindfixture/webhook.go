package kindfixture

import (
	"bytes"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"time"

	admissionregv1 "k8s.io/api/admissionregistration/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/validation"
)

const OwnerLabel = "fixture.tsunaro.io/owner"

var ErrWebhook = errors.New("kind fixture: public CA or webhook configuration rejected")

// PublicCAConfigMap accepts one public, self-signed fixture root, never a key or
// a chain with trailing material. The namespace must already exist and carry
// the fixture's ownership label. The caller verifies its UID against the API.
func PublicCAConfigMap(ns *corev1.Namespace, name string, ca []byte, now time.Time) (*corev1.ConfigMap, error) {
	if !ownedNamespace(ns) || len(validation.IsDNS1123Subdomain(name)) != 0 || !publicRoot(ca, now) {
		return nil, ErrWebhook
	}
	yes := true
	return &corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: ns.Name, Labels: map[string]string{OwnerLabel: string(ns.UID)}}, Immutable: &yes, Data: map[string]string{controlCAKey: string(ca)}}, nil
}

// AgentCAWebhook applies only to matching ingress Pods in the one owned
// namespace. This is test wiring, not an authorization boundary against writers
// who can change namespace or Pod labels. The caller waits for the HTTPS server
// before installing it, and removes it before deleting that server.
func AgentCAWebhook(ns *corev1.Namespace, name string, ca []byte, now time.Time) (*admissionregv1.MutatingWebhookConfiguration, error) {
	if !ownedNamespace(ns) || len(validation.IsDNS1123Subdomain(name)) != 0 || !publicRoot(ca, now) {
		return nil, ErrWebhook
	}
	fail, exact, none, never := admissionregv1.Fail, admissionregv1.Exact, admissionregv1.SideEffectClassNone, admissionregv1.NeverReinvocationPolicy
	scope := admissionregv1.NamespacedScope
	seconds, port := int32(3), int32(443)
	path := "/mutate-agent"
	return &admissionregv1.MutatingWebhookConfiguration{ObjectMeta: metav1.ObjectMeta{Name: name, Labels: map[string]string{OwnerLabel: string(ns.UID)}}, Webhooks: []admissionregv1.MutatingWebhook{{
		Name: "agent-ca.fixture.tsunaro.io", AdmissionReviewVersions: []string{"v1"}, FailurePolicy: &fail, MatchPolicy: &exact, SideEffects: &none, ReinvocationPolicy: &never, TimeoutSeconds: &seconds,
		NamespaceSelector: &metav1.LabelSelector{MatchLabels: map[string]string{"kubernetes.io/metadata.name": ns.Name, OwnerLabel: string(ns.UID)}},
		ObjectSelector:    &metav1.LabelSelector{MatchLabels: map[string]string{"app.kubernetes.io/name": "tailnet-ingress", "app.kubernetes.io/managed-by": "tailnet-operator"}},
		Rules:             []admissionregv1.RuleWithOperations{{Operations: []admissionregv1.OperationType{admissionregv1.Create}, Rule: admissionregv1.Rule{APIGroups: []string{""}, APIVersions: []string{"v1"}, Resources: []string{"pods"}, Scope: &scope}}},
		ClientConfig:      admissionregv1.WebhookClientConfig{CABundle: append([]byte(nil), ca...), Service: &admissionregv1.ServiceReference{Namespace: ns.Name, Name: "fixture-admission", Path: &path, Port: &port}},
	}}}, nil
}

func ownedNamespace(ns *corev1.Namespace) bool {
	return ns != nil && ns.UID != "" && ns.DeletionTimestamp == nil && len(validation.IsDNS1123Label(ns.Name)) == 0 && ns.Labels[OwnerLabel] == string(ns.UID)
}

func publicRoot(b []byte, now time.Time) bool {
	if len(b) == 0 || len(b) > 64<<10 {
		return false
	}
	// pem.Decode otherwise skips leading non-PEM content.
	b = bytes.TrimSpace(b)
	if !bytes.HasPrefix(b, []byte("-----BEGIN CERTIFICATE-----")) {
		return false
	}
	p, rest := pem.Decode(b)
	if p == nil || p.Type != "CERTIFICATE" || len(p.Headers) != 0 || len(bytes.TrimSpace(rest)) != 0 {
		return false
	}
	// Decode also skips malformed BEGIN blocks, not only ordinary prefixes.
	// Require one canonical fixture PEM so discarded bytes cannot contain key
	// material that callers would otherwise store in the public ConfigMap.
	canonical := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: p.Bytes})
	if !bytes.Equal(b, bytes.TrimSpace(canonical)) {
		return false
	}
	c, err := x509.ParseCertificate(p.Bytes)
	return err == nil && c.IsCA && c.BasicConstraintsValid && c.KeyUsage&x509.KeyUsageCertSign != 0 && len(c.UnhandledCriticalExtensions) == 0 && !now.Before(c.NotBefore) && now.Before(c.NotAfter) && bytes.Equal(c.RawIssuer, c.RawSubject) && c.CheckSignatureFrom(c) == nil
}
