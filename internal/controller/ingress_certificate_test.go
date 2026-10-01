package controller

import (
	"reflect"
	"testing"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"

	tnv1 "tsunaro.io/tailnet-operator/api/v1alpha1"
)

func TestDesiredIngressCertificate(t *testing.T) {
	for _, kind := range []string{"Issuer", "ClusterIssuer"} {
		t.Run(kind, func(t *testing.T) {
			in := tlsIngress()
			in.UID = "fixture-ingress-uid"
			// A cross-namespace backend must not move the certificate, Secret or Issuer lookup.
			in.Spec.Exposes[0].Backend.Namespace = "different-backend-namespace"
			tn := &tnv1.Tailnet{Spec: tnv1.TailnetSpec{Defaults: tnv1.TailnetDefaults{TLS: &tnv1.TLSDefaults{
				IssuerRef: &tnv1.TLSIssuerReference{Name: "internal", Kind: kind},
			}}}}
			plan, reason := resolveIngressTLS(in, tn)
			if reason != "" {
				t.Fatalf("resolve reason=%s", reason)
			}
			cert := desiredIngressCertificate(in, plan)
			if cert == nil || cert.GetAPIVersion() != "cert-manager.io/v1" || cert.GetKind() != "Certificate" ||
				cert.GetNamespace() != in.Namespace || cert.GetName() != "app-tls" {
				t.Fatal("incorrect certificate identity or namespace")
			}
			wantSpec := map[string]any{
				"secretName": "app-tls",
				"dnsNames":   []any{in.Status.DNSName},
				"issuerRef":  map[string]any{"name": "internal", "kind": kind, "group": "cert-manager.io"},
			}
			if !reflect.DeepEqual(cert.Object["spec"], wantSpec) {
				t.Fatal("certificate spec differs from resolved source/DNS name")
			}
			owner := metav1.GetControllerOf(cert)
			if owner == nil || owner.UID != in.UID || owner.Name != in.Name || owner.Kind != "TailnetIngress" ||
				owner.APIVersion != tnv1.GroupVersion.String() || owner.BlockOwnerDeletion == nil || !*owner.BlockOwnerDeletion {
				t.Fatal("incorrect controller ownership")
			}
			if _, ok := cert.Object["status"]; ok {
				t.Fatal("desired object must not manufacture certificate status")
			}
			// Mutable unstructured slices/maps must not alias either the input or another result.
			copy := cert.DeepCopy()
			if err := unstructured.SetNestedSlice(copy.Object, []any{"changed.invalid"}, "spec", "dnsNames"); err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(cert.Object["spec"], wantSpec) || !reflect.DeepEqual(cert, desiredIngressCertificate(in, plan)) {
				t.Fatal("certificate construction aliases mutable state")
			}
			plan.issuer.Name = "changed"
			if !reflect.DeepEqual(cert.Object["spec"], wantSpec) || tn.Spec.Defaults.TLS.IssuerRef.Name != "internal" {
				t.Fatal("constructed certificate or Tailnet aliases the resolved issuer")
			}
		})
	}
	if got := desiredIngressCertificate(tlsIngress(), ingressTLSPlan{http: true, secretName: "external"}); got != nil {
		t.Fatal("an external Secret must not create a Certificate")
	}
	if got := desiredIngressCertificate(tlsIngress(), ingressTLSPlan{}); got != nil {
		t.Fatal("L4 must not create a Certificate")
	}
}
