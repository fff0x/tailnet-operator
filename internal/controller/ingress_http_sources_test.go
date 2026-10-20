package controller

import (
	"testing"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	tnv1 "tsunaro.io/tailnet-operator/api/v1alpha1"
)

// apiUrl is operator-only; agents dial Server. Changing apiUrl must not change the control
// identity (and so must not re-roll HTTP agents), changing Server must.
func TestIngressControlDigestIgnoresAPIURL(t *testing.T) {
	in := &tnv1.TailnetIngress{ObjectMeta: metav1.ObjectMeta{Name: "web", Namespace: "apps"}}
	base := func() *tnv1.Tailnet {
		return &tnv1.Tailnet{
			ObjectMeta: metav1.ObjectMeta{Name: "corp", UID: "tn-uid"},
			Spec: tnv1.TailnetSpec{
				Server:                  "https://ts.example.test",
				APIURL:                  "http://headscale.tailnet-system.svc:8080",
				IngressTagTemplate:      "tag:ingress-{name}",
				IngressHostnameTemplate: "ingress-{name}",
			},
		}
	}
	ref := ingressResolvedControlDigest(in, base())

	https := base()
	https.Spec.APIURL = "https://headscale.tailnet-system.svc:8080"
	if got := ingressResolvedControlDigest(in, https); got != ref {
		t.Fatalf("apiUrl change altered the control digest: %s != %s", got, ref)
	}
	empty := base()
	empty.Spec.APIURL = ""
	if got := ingressResolvedControlDigest(in, empty); got != ref {
		t.Fatalf("unset apiUrl altered the control digest")
	}

	server := base()
	server.Spec.Server = "https://ts2.example.test"
	if got := ingressResolvedControlDigest(in, server); got == ref {
		t.Fatalf("server change must alter the control digest")
	}
}
