//go:build e2e_kind

package e2ekind

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"testing"
)

func TestCertificateRequestIdentityUsesAnnotationAndOwner(t *testing.T) {
	cert := cmObject("Certificate", cmNamespace, "fixture-ca", nil)
	cert.SetUID("certificate-uid")
	request := cmObject("CertificateRequest", cmNamespace, "fixture-ca-1", map[string]any{"username": "system:serviceaccount:cert-manager:controller"})
	request.SetAnnotations(map[string]string{"cert-manager.io/certificate-name": cert.GetName()})
	request.SetOwnerReferences([]metav1.OwnerReference{*metav1.NewControllerRef(cert, cert.GroupVersionKind())})
	user := "system:serviceaccount:cert-manager:controller"
	if !cmRequestIdentity(request, cert, user) {
		t.Fatal("annotation-bound request rejected")
	}
	if cmRequestIdentity(request, cert, "system:admin") {
		t.Fatal("foreign creator accepted")
	}
	labelsOnly := request.DeepCopy()
	labelsOnly.SetAnnotations(nil)
	labelsOnly.SetLabels(map[string]string{"cert-manager.io/certificate-name": cert.GetName()})
	if cmRequestIdentity(labelsOnly, cert, user) {
		t.Fatal("label substituted for association annotation")
	}
	foreign := request.DeepCopy()
	refs := foreign.GetOwnerReferences()
	refs[0].UID = "foreign"
	foreign.SetOwnerReferences(refs)
	if cmRequestIdentity(foreign, cert, user) {
		t.Fatal("foreign certificate owner accepted")
	}
	if cmRequestIdentity(nil, cert, user) || cmRequestIdentity(request, nil, user) {
		t.Fatal("missing identity accepted")
	}
}
