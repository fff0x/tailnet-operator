package controller

import (
	"context"
	"testing"
	"time"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	"k8s.io/apimachinery/pkg/runtime"
	dynamicfake "k8s.io/client-go/dynamic/fake"

	tnv1 "this-is-fine.io/tailnet-operator/api/v1alpha1"
)

func TestIngressCleanupSurvivesMissingInheritedSource(t *testing.T) {
	for _, next := range []string{"l4", "external"} {
		t.Run(next, func(t *testing.T) {
			in, _, cert := certificateClientFixture()
			in.Status.TLSSecretName = in.Name + "-tls"
			certificates := dynamicfake.NewSimpleDynamicClient(runtime.NewScheme(), cert)
			r := &TailnetIngressReconciler{Client: ingressTLSFakeClient(t), Certificates: certificates}
			// The previously inherited issuer has been removed from the Tailnet. The CR
			// remains admission-valid; resolution now fails before source inspection.
			tn := &tnv1.Tailnet{}
			state := r.prepareIngressTLS(context.Background(), in, tn, time.Now())
			if state.reason != "TLSConfigurationMissing" || len(certificates.Actions()) != 0 {
				t.Fatal("rejected source must not operate on the previous Certificate yet")
			}
			if next == "l4" {
				in.Spec.Exposes[0].Mode = "l4"
			} else {
				in.Spec.TLS = &tnv1.IngressTLS{SecretName: "external"}
			}
			r.prepareIngressTLS(context.Background(), in, tn, time.Now())
			if _, err := certificates.Tracker().Get(ingressCertificateResource, in.Namespace, cert.GetName()); !apierrors.IsNotFound(err) {
				t.Fatal("resolution failure lost cleanup tracking; obsolete owned Certificate survived")
			}
			if meta.FindStatusCondition(in.Status.Conditions, "TLSCleanup") == nil {
				t.Fatal("accepted delete must remain tracked until absence is confirmed")
			}
			r.prepareIngressTLS(context.Background(), in, tn, time.Now())
			if meta.FindStatusCondition(in.Status.Conditions, "TLSCleanup") != nil {
				t.Fatal("confirmed cleanup retained a stale retry marker")
			}
		})
	}
}
