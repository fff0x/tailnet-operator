package kindfixture

import (
	"bytes"
	"encoding/base64"
	"testing"
	"time"

	admissionregv1 "k8s.io/api/admissionregistration/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func TestPublicCARejectsSkippedPEM(t *testing.T) {
	now := time.Now()
	ca, err := NewAuthority(now)
	if err != nil {
		t.Fatal("fixture PKI failed")
	}
	_, privateKey, _, err := ca.Issue("fixture.invalid", now, now.Add(time.Minute))
	if err != nil {
		t.Fatal("fixture leaf failed")
	}
	// pem.Decode can skip an unmatched BEGIN block and find a later valid
	// root. The skipped material must never enter the public ConfigMap.
	malformed := append([]byte("-----BEGIN CERTIFICATE-----\n"+base64.StdEncoding.EncodeToString(privateKey)+"\n"), ca.PublicPEM()...)
	ns := &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "owned-test", UID: "fixture-uid", Labels: map[string]string{OwnerLabel: "fixture-uid"}}}
	if _, err := PublicCAConfigMap(ns, "control-ca", malformed, now); err != ErrWebhook {
		t.Fatal("skipped private material accepted for public ConfigMap")
	}
	if _, err := AgentCAWebhook(ns, "owned-hook", malformed, now); err != ErrWebhook {
		t.Fatal("skipped private material accepted for public trust bundle")
	}
}

func TestOwnedPublicCAAndWebhook(t *testing.T) {
	now := time.Now()
	ca, err := NewAuthority(now)
	if err != nil {
		t.Fatal("fixture PKI failed")
	}
	ns := &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "owned-test", UID: "fixture-uid", Labels: map[string]string{OwnerLabel: "fixture-uid"}}}
	cm, err := PublicCAConfigMap(ns, "control-ca", ca.PublicPEM(), now)
	if err != nil || cm.Immutable == nil || !*cm.Immutable || len(cm.Data) != 1 || len(cm.BinaryData) != 0 || cm.Namespace != ns.Name {
		t.Fatal("public immutable CA rejected")
	}
	hook, err := AgentCAWebhook(ns, "owned-hook", ca.PublicPEM(), now)
	if err != nil || len(hook.Webhooks) != 1 {
		t.Fatal("owned webhook rejected")
	}
	h := hook.Webhooks[0]
	if *h.FailurePolicy != admissionregv1.Fail || *h.SideEffects != admissionregv1.SideEffectClassNone || *h.ReinvocationPolicy != admissionregv1.NeverReinvocationPolicy || *h.TimeoutSeconds != 3 || *h.MatchPolicy != admissionregv1.Exact || h.ClientConfig.URL != nil || h.ClientConfig.Service.Namespace != ns.Name || *h.ClientConfig.Service.Path != "/mutate-agent" || h.NamespaceSelector.MatchLabels[OwnerLabel] != string(ns.UID) || h.NamespaceSelector.MatchLabels["kubernetes.io/metadata.name"] != ns.Name || !bytes.Equal(h.ClientConfig.CABundle, ca.PublicPEM()) {
		t.Fatal("webhook scope/TLS/failure policy changed")
	}
	if len(h.Rules) != 1 || len(h.Rules[0].Operations) != 1 || h.Rules[0].Operations[0] != admissionregv1.Create || len(h.Rules[0].Resources) != 1 || h.Rules[0].Resources[0] != "pods" || *h.Rules[0].Scope != admissionregv1.NamespacedScope {
		t.Fatal("webhook rules expanded")
	}
	leaf, key, _, err := ca.Issue("fixture.invalid", now, now.Add(time.Minute))
	if err != nil {
		t.Fatal("leaf creation failed")
	}
	for _, bad := range [][]byte{nil, leaf, key, append(ca.PublicPEM(), key...), append(ca.PublicPEM(), ca.PublicPEM()...), append([]byte("ignored-prefix"), ca.PublicPEM()...), bytes.Repeat([]byte("x"), 65537)} {
		if _, err := PublicCAConfigMap(ns, "control-ca", bad, now); err != ErrWebhook {
			t.Fatal("non-public-root input accepted")
		}
		if _, err := AgentCAWebhook(ns, "owned-hook", bad, now); err != ErrWebhook {
			t.Fatal("unsafe webhook CA accepted")
		}
	}
	for _, bad := range []*corev1.Namespace{nil, {}, {ObjectMeta: metav1.ObjectMeta{Name: ns.Name, UID: ns.UID}}, {ObjectMeta: metav1.ObjectMeta{Name: ns.Name, UID: ns.UID, Labels: map[string]string{OwnerLabel: "different"}}}} {
		if _, err := AgentCAWebhook(bad, "owned-hook", ca.PublicPEM(), now); err != ErrWebhook {
			t.Fatal("unowned namespace accepted")
		}
	}
	if _, err := PublicCAConfigMap(ns, "control-ca", ca.PublicPEM(), now.Add(2*time.Hour)); err != ErrWebhook {
		t.Fatal("expired CA accepted")
	}
}
