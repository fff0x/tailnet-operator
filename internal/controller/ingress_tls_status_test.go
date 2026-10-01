package controller

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"errors"
	"math/big"
	"strings"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	dynamicfake "k8s.io/client-go/dynamic/fake"
	ktesting "k8s.io/client-go/testing"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	tnv1 "tsunaro.io/tailnet-operator/api/v1alpha1"
)

func ingressTLSFakeClient(t *testing.T, objs ...client.Object) client.Client {
	t.Helper()
	scheme := runtime.NewScheme()
	if err := corev1.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	if err := tnv1.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	return fake.NewClientBuilder().WithScheme(scheme).
		WithStatusSubresource(&tnv1.TailnetIngress{}, &tnv1.Tailnet{}).
		WithObjects(objs...).Build()
}

func ingressTLSStatusFixture(t *testing.T) (*TailnetIngressReconciler, *tnv1.TailnetIngress, ingressTLSState, map[string]ingressProbe, time.Time) {
	t.Helper()
	now := time.Unix(1800000000, 0)
	in := tlsResourceIngress()
	in.Spec.TLS = &tnv1.IngressTLS{SecretName: "external-tls"}
	in.Status.NodeID = "node"
	secret, _ := ingressTestCertificate(t, &x509.Certificate{
		SerialNumber: big.NewInt(1), DNSNames: []string{in.Status.DNSName},
		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	})
	secret.Name = in.Spec.TLS.SecretName
	r := &TailnetIngressReconciler{Client: ingressTLSFakeClient(t, secret)}
	state := r.prepareIngressTLS(context.Background(), in, &tnv1.Tailnet{}, now)
	if state.reason != "" || in.Status.TLSNotAfter == nil || in.Status.TLSSecretName != secret.Name {
		t.Fatalf("external Secret preparation failed: %s", state.reason)
	}
	yes := true
	expiry := state.leaf.notAfter.Time
	target := renderedIngressTargets(t, in, in.Namespace, state.plan)[0]
	probes := map[string]ingressProbe{
		"web": {Name: "web", Reachable: true, BackendReachable: &yes, TLSReady: &yes,
			ConfigID: target.ConfigID, TLSCertSHA256: state.leaf.sha256, TLSNotAfter: &expiry, LastProbe: now},
		"ssh": {Name: "ssh", Reachable: true, LastProbe: now},
	}
	return r, in, state, probes, now
}

func TestIngressTLSStatusProof(t *testing.T) {
	for _, tc := range []struct {
		name   string
		change func(*tnv1.TailnetIngress, *ingressTLSState, *ingressProbe)
		reason string
	}{
		{"valid", func(*tnv1.TailnetIngress, *ingressTLSState, *ingressProbe) {}, "TLSReady"},
		{"old-agent", func(_ *tnv1.TailnetIngress, _ *ingressTLSState, p *ingressProbe) {
			*p = ingressProbe{Name: "web", Reachable: true}
		}, "TLSProbePending"},
		{"changed-config", func(_ *tnv1.TailnetIngress, _ *ingressTLSState, p *ingressProbe) { p.ConfigID = "old" }, "TLSConfigMismatch"},
		{"new-generation", func(in *tnv1.TailnetIngress, _ *ingressTLSState, _ *ingressProbe) { in.Generation++ }, "TLSConfigMismatch"},
		{"recreated-ingress", func(in *tnv1.TailnetIngress, _ *ingressTLSState, _ *ingressProbe) { in.UID = "replacement" }, "TLSConfigMismatch"},
		{"stale", func(_ *tnv1.TailnetIngress, _ *ingressTLSState, p *ingressProbe) {
			p.LastProbe = p.LastProbe.Add(-3 * time.Minute)
		}, "TLSProbeStale"},
		{"future", func(_ *tnv1.TailnetIngress, _ *ingressTLSState, p *ingressProbe) {
			p.LastProbe = p.LastProbe.Add(time.Minute)
		}, "TLSProbeStale"},
		{"old-leaf", func(_ *tnv1.TailnetIngress, _ *ingressTLSState, p *ingressProbe) { p.TLSCertSHA256 = "old-leaf" }, "TLSCertificateMismatch"},
		{"no-expiry", func(_ *tnv1.TailnetIngress, _ *ingressTLSState, p *ingressProbe) { p.TLSNotAfter = nil }, "TLSCertificateMismatch"},
		{"wrong-expiry", func(_ *tnv1.TailnetIngress, _ *ingressTLSState, p *ingressProbe) {
			expiry := p.TLSNotAfter.Add(time.Second)
			p.TLSNotAfter = &expiry
		}, "TLSCertificateMismatch"},
		{"invalid-secret", func(_ *tnv1.TailnetIngress, s *ingressTLSState, _ *ingressProbe) { s.reason = "TLSSecretInvalid" }, "TLSSecretInvalid"},
		{"missing-cert-manager", func(_ *tnv1.TailnetIngress, s *ingressTLSState, _ *ingressProbe) { s.reason = "CertManagerMissing" }, "CertManagerMissing"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r, in, state, probes, now := ingressTLSStatusFixture(t)
			p := probes["web"]
			tc.change(in, &state, &p)
			probes["web"] = p
			r.computeIngressStatus(in, state, probes, nil, now)
			cond := meta.FindStatusCondition(in.Status.Conditions, "TLSReady")
			wantReady := tc.reason == "TLSReady"
			if cond == nil || cond.Reason != tc.reason || (cond.Status == metav1.ConditionTrue) != wantReady ||
				in.Status.Exposes[0].TLSReady == nil || *in.Status.Exposes[0].TLSReady != wantReady ||
				(condStatus(in.Status.Conditions, "Ready") == metav1.ConditionTrue) != wantReady {
				t.Fatalf("unexpected local TLS verdict for %s", tc.name)
			}
			if in.Status.Exposes[1].TLSReady != nil || !in.Status.Exposes[1].Reachable {
				t.Fatal("L4 inherited HTTP readiness")
			}
			if tc.reason == "TLSConfigMismatch" || tc.reason == "TLSProbeStale" {
				if in.Status.Exposes[0].Reachable {
					t.Fatal("stale generation reported the new backend reachable")
				}
			}
		})
	}
}

func TestIngressTLSAndBackendAreIndependent(t *testing.T) {
	r, in, state, probes, now := ingressTLSStatusFixture(t)
	no := false
	p := probes["web"]
	p.Reachable, p.BackendReachable = false, &no
	probes["web"] = p
	r.computeIngressStatus(in, state, probes, nil, now)
	if condStatus(in.Status.Conditions, "TLSReady") != metav1.ConditionTrue ||
		condStatus(in.Status.Conditions, "BackendsReachable") != metav1.ConditionFalse ||
		condStatus(in.Status.Conditions, "Ready") != metav1.ConditionFalse {
		t.Fatal("local TLS proof must not hide a failed backend")
	}
	r.computeIngressStatus(in, state, probes, errors.New("secret-sentinel"), now)
	encoded, _ := json.Marshal(in.Status)
	if strings.Contains(string(encoded), "secret-sentinel") || condStatus(in.Status.Conditions, "TLSReady") != metav1.ConditionFalse {
		t.Fatal("scrape error leaked or retained TLS readiness")
	}
}

func TestIngressTLSCleanupRetrySurvivesSourceChange(t *testing.T) {
	in, _, cert := certificateClientFixture()
	in.Spec.TLS = &tnv1.IngressTLS{SecretName: "new-external"}
	in.Status.TLSSecretName = in.Name + "-tls"
	c := dynamicfake.NewSimpleDynamicClient(runtime.NewScheme(), cert)
	forbidden := true
	c.PrependReactor("delete", "certificates", func(ktesting.Action) (bool, runtime.Object, error) {
		if forbidden {
			return true, nil, apierrors.NewForbidden(schema.GroupResource{Group: "cert-manager.io", Resource: "certificates"}, cert.GetName(), errors.New("secret-sentinel"))
		}
		return false, nil, nil
	})
	r := &TailnetIngressReconciler{Client: ingressTLSFakeClient(t), Certificates: c}
	r.prepareIngressTLS(context.Background(), in, &tnv1.Tailnet{}, time.Now())
	if in.Status.TLSSecretName != "new-external" || meta.FindStatusCondition(in.Status.Conditions, "TLSCleanup") == nil {
		t.Fatal("source change lost cleanup retry marker")
	}
	forbidden = false
	r.prepareIngressTLS(context.Background(), in, &tnv1.Tailnet{}, time.Now())
	if meta.FindStatusCondition(in.Status.Conditions, "TLSCleanup") == nil {
		t.Fatal("accepted deletion was treated as completed deletion")
	}
	r.prepareIngressTLS(context.Background(), in, &tnv1.Tailnet{}, time.Now())
	if meta.FindStatusCondition(in.Status.Conditions, "TLSCleanup") != nil {
		t.Fatal("confirmed cleanup retained retry marker")
	}
}

func TestIngressExternalSecretWatchNamespace(t *testing.T) {
	a, b, c := tlsResourceIngress(), tlsResourceIngress(), tlsResourceIngress()
	a.Spec.TLS = &tnv1.IngressTLS{SecretName: "external"}
	b.Name, b.UID = "second", "second"
	b.Spec.TLS = &tnv1.IngressTLS{SecretName: "external"}
	c.Namespace, c.UID = "foreign", "foreign"
	c.Spec.TLS = &tnv1.IngressTLS{SecretName: "external"}
	generated := tlsResourceIngress()
	generated.Name, generated.UID = "generated", "generated"
	r := &TailnetIngressReconciler{Client: ingressTLSFakeClient(t, a, b, c, generated)}
	keys := r.ingressesForTLSSecret(context.Background(), &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: "external", Namespace: "tenant"}})
	if len(keys) != 2 {
		t.Fatal("external Secret must enqueue both namespace-local referents")
	}
	for _, key := range keys {
		if key.Namespace != "tenant" || (key.Name != "app" && key.Name != "second") {
			t.Fatal("watch escaped namespace or selected unrelated ingress")
		}
	}
	keys = r.ingressesForTLSSecret(context.Background(), &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: "generated-tls", Namespace: "tenant"}})
	if len(keys) != 1 || keys[0] != (types.NamespacedName{Namespace: "tenant", Name: "generated"}) {
		t.Fatal("generated Secret rotation requires a watch before initial status persistence")
	}
}
