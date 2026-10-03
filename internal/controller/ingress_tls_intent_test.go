package controller

import (
	"context"
	"testing"
	"time"

	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	dynamicfake "k8s.io/client-go/dynamic/fake"
	k8stesting "k8s.io/client-go/testing"
	"sigs.k8s.io/controller-runtime/pkg/client"

	tnv1 "tsunaro.io/tailnet-operator/api/v1alpha1"
)

func TestIngressCertificateCreationRequiresPersistedIntent(t *testing.T) {
	for _, stored := range []bool{false, true} {
		t.Run(map[bool]string{false: "failed-status-write", true: "persist-before-create"}[stored], func(t *testing.T) {
			ctx := context.Background()
			in, plan, _ := certificateClientFixture()
			in.Spec.TLS = &tnv1.IngressTLS{IssuerRef: plan.issuer}
			var objects []client.Object
			if stored {
				objects = append(objects, in)
			}
			kube := ingressTLSFakeClient(t, objects...)
			if stored {
				if err := kube.Get(ctx, client.ObjectKeyFromObject(in), in); err != nil {
					t.Fatal(err)
				}
			}
			persistedDNS := in.Status.DNSName
			in.Status.DNSName = "new.tenant.invalid" // desired, not yet a validated node observation
			certificates := dynamicfake.NewSimpleDynamicClient(runtime.NewScheme())
			created := false
			certificates.PrependReactor("create", "certificates", func(action k8stesting.Action) (bool, runtime.Object, error) {
				var saved tnv1.TailnetIngress
				if err := kube.Get(ctx, client.ObjectKeyFromObject(in), &saved); err != nil || saved.Status.TLSSecretName != plan.secretName {
					t.Fatal("Certificate creation preceded durable cleanup tracking")
				}
				if saved.Status.DNSName != persistedDNS {
					t.Fatal("intent write published an unvalidated DNS/node observation")
				}
				obj := action.(k8stesting.CreateAction).GetObject().(*unstructured.Unstructured)
				names, _, _ := unstructured.NestedStringSlice(obj.Object, "spec", "dnsNames")
				if len(names) != 1 || names[0] != "web.tenant.tailnet.invalid" {
					t.Fatal("intent patch response overwrote the desired Certificate DNS name")
				}
				for _, kind := range []string{"TLSReady", "Ready"} {
					cond := meta.FindStatusCondition(saved.Status.Conditions, kind)
					if cond == nil || cond.Status != metav1.ConditionFalse {
						t.Fatal("pending source retained a green readiness condition")
					}
				}
				created = true
				return false, nil, nil
			})
			r := &TailnetIngressReconciler{Client: kube, Certificates: certificates}
			state := r.prepareIngressTLS(ctx, in, tlsTestTailnet(), time.Now())
			if stored {
				if !created || state.reason != "TLSCertificatePending" {
					t.Fatal("persisted source did not reach Certificate creation")
				}
			} else if state.reason != "TLSCertificateUnavailable" || len(certificates.Actions()) != 0 {
				t.Fatal("failed intent persistence allowed Certificate API side effects")
			}
		})
	}
}
