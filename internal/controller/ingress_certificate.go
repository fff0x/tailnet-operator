package controller

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"

	tnv1 "tsunaro.io/tailnet-operator/api/v1alpha1"
)

// desiredIngressCertificate takes a successfully resolved plan. An external Secret never creates
// a Certificate. The unstructured object needs neither a cert-manager scheme nor an informer:
// cert-manager must remain an optional runtime API, not a manager startup dependency.
func desiredIngressCertificate(in *tnv1.TailnetIngress, plan ingressTLSPlan) *unstructured.Unstructured {
	if !plan.http || plan.issuer == nil {
		return nil
	}
	names := make([]any, len(plan.names.certificateNames))
	for i, name := range plan.names.certificateNames {
		names[i] = name
	}
	cert := &unstructured.Unstructured{Object: map[string]any{
		"apiVersion": "cert-manager.io/v1",
		"kind":       "Certificate",
		"spec": map[string]any{
			"secretName": plan.secretName,
			"dnsNames":   names,
			"issuerRef": map[string]any{
				"name": plan.issuer.Name, "kind": plan.issuer.Kind, "group": plan.issuer.Group,
			},
		},
	}}
	cert.SetName(in.Name + "-tls")
	cert.SetNamespace(in.Namespace)
	cert.SetLabels(ingressObjLabels(in.Name))
	cert.SetOwnerReferences([]metav1.OwnerReference{*metav1.NewControllerRef(in, tnv1.GroupVersion.WithKind("TailnetIngress"))})
	return cert
}
