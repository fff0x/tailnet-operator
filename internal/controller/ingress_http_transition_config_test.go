package controller

import (
	"context"
	"reflect"
	"testing"
	"time"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"

	tnv1 "tsunaro.io/tailnet-operator/api/v1alpha1"
)

func TestIngressHTTPTransitionMatchingConfigIsStable(t *testing.T) {
	ctx := context.Background()
	r, in, dep, cm, pod := transitionFixture(t, true)
	dep.Spec.Template.Annotations = ingressProtocolAnnotations(in)
	if err := r.Update(ctx, dep); err != nil {
		t.Fatal(err)
	}
	before := transitionDeployment(t, r, in)
	ca := backendCAFixture(t, in.Namespace, time.Now())
	if err := r.Create(ctx, ca); err != nil {
		t.Fatal(err)
	}
	// Generation/status and non-HTTP changes must not be rollout boundaries.
	in.Generation++
	in.Status.DNSName = "changed-status.example"
	in.Spec.Image = "different:image"
	in.Spec.AllowFrom = []string{"group:new"}
	if err := r.Update(ctx, in); err != nil {
		t.Fatal(err)
	}
	for _, rotation := range []string{"original", "new-ca-bytes", "deleted"} {
		if rotation == "new-ca-bytes" {
			ca.Data["root.pem"] += "\n"
			if err := r.Update(ctx, ca); err != nil {
				t.Fatal(err)
			}
		} else if rotation == "deleted" {
			if err := r.Delete(ctx, ca); err != nil {
				t.Fatal(err)
			}
		}
		if _, reason := transitionReconcile(t, r, in); reason != "NoTailnet" {
			t.Fatalf("unchanged config paused on %s: %s", rotation, reason)
		}
		if !reflect.DeepEqual(before, transitionDeployment(t, r, in)) {
			t.Fatalf("unchanged config changed the Deployment on %s", rotation)
		}
	}
	var gotCM corev1.ConfigMap
	var gotPod corev1.Pod
	if err := r.Get(ctx, client.ObjectKeyFromObject(cm), &gotCM); err != nil {
		t.Fatal(err)
	}
	if err := r.Get(ctx, client.ObjectKeyFromObject(pod), &gotPod); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(cm.Data, gotCM.Data) || !reflect.DeepEqual(pod, &gotPod) {
		t.Fatal("matching-marker barrier changed config or Pod")
	}
}

func TestIngressDesiredHTTPConfigDigest(t *testing.T) {
	in := tlsResourceIngress()
	in.Spec.TLS = &tnv1.IngressTLS{SecretName: "frontend"}
	in.Spec.Exposes[0].Backend.TLS = backendTLSFixture()
	original := ingressDesiredHTTPConfigDigest(in)
	for _, tc := range []struct {
		name   string
		mutate func(*tnv1.TailnetIngress)
	}{
		{"backend-name", func(in *tnv1.TailnetIngress) { in.Spec.Exposes[0].Backend.Service = "new-service" }},
		{"tls-name", func(in *tnv1.TailnetIngress) { in.Spec.Exposes[0].Backend.TLS.ServerName = "new.example" }},
		{"ca-name", func(in *tnv1.TailnetIngress) { in.Spec.Exposes[0].Backend.TLS.CAConfigMapRef.Name = "new-ca" }},
		{"ca-key", func(in *tnv1.TailnetIngress) { in.Spec.Exposes[0].Backend.TLS.CAConfigMapRef.Key = "new.pem" }},
		{"tls-removed", func(in *tnv1.TailnetIngress) { in.Spec.Exposes[0].Backend.TLS = nil }},
		{"empty-timeouts", func(in *tnv1.TailnetIngress) { in.Spec.Exposes[0].Timeouts = &tnv1.HTTPTimeouts{} }},
		{"frontend-reference", func(in *tnv1.TailnetIngress) { in.Spec.TLS.SecretName = "new-secret" }},
		{"tailnet-reference", func(in *tnv1.TailnetIngress) { in.Spec.TailnetRef.Name = "new-tailnet" }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			changed := in.DeepCopy()
			tc.mutate(changed)
			if ingressDesiredHTTPConfigDigest(changed) == original {
				t.Fatal("changed HTTP reference configuration reused its process marker")
			}
		})
	}
}

func TestIngressHTTPTransitionUsesPresenceBeforeValidation(t *testing.T) {
	for _, tc := range []struct {
		name   string
		mutate func(*tnv1.TailnetIngress)
	}{
		{"empty-tls", func(in *tnv1.TailnetIngress) { in.Spec.Exposes[0].Backend.TLS = &tnv1.BackendTLS{} }},
		{"empty-timeouts", func(in *tnv1.TailnetIngress) {
			in.Spec.Exposes[0].Backend.TLS = nil
			in.Spec.Exposes[0].Timeouts = &tnv1.HTTPTimeouts{}
		}},
		{"invalid-timeout", func(in *tnv1.TailnetIngress) {
			in.Spec.Exposes[0].Timeouts = &tnv1.HTTPTimeouts{Request: extensionString("-1s")}
		}},
		{"l4-with-tls", func(in *tnv1.TailnetIngress) { in.Spec.Exposes[0].Mode = "l4" }},
		{"duplicate-port", func(in *tnv1.TailnetIngress) { in.Spec.Exposes[1].Port = 443 }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r, in, _, _, _ := transitionFixture(t, false)
			tc.mutate(in)
			if err := r.Update(context.Background(), in); err != nil {
				t.Fatal(err)
			}
			if _, reason := transitionReconcile(t, r, in); reason != "HTTPTransitionPending" || *transitionDeployment(t, r, in).Spec.Replicas != 0 {
				t.Fatalf("new fields escaped predecessor retirement: %s", reason)
			}
		})
	}
}

func TestIngressHTTPTransitionLegacyAndInitialCreate(t *testing.T) {
	t.Run("legacy-unchanged", func(t *testing.T) {
		r, in, _, _, _ := transitionFixture(t, false)
		in.Spec.Exposes[0].Backend.TLS = nil
		if err := r.Update(context.Background(), in); err != nil {
			t.Fatal(err)
		}
		before := transitionDeployment(t, r, in)
		if _, reason := transitionReconcile(t, r, in); reason != "NoTailnet" || !reflect.DeepEqual(before, transitionDeployment(t, r, in)) {
			t.Fatal("legacy ingress behavior changed")
		}
	})
	t.Run("no-predecessor", func(t *testing.T) {
		r, in, dep, _, pod := transitionFixture(t, false)
		if err := r.Delete(context.Background(), dep); err != nil {
			t.Fatal(err)
		}
		if _, reason := transitionReconcile(t, r, in); reason != "HTTPTransitionPending" {
			t.Fatal("deleted Deployment bypassed a surviving predecessor Pod")
		}
		if err := r.Delete(context.Background(), pod); err != nil {
			t.Fatal(err)
		}
		transition, waiting, err := r.retireIngressHTTPPredecessor(context.Background(), in)
		if err != nil || transition || waiting {
			t.Fatalf("initial creation blocked: %v %v %v", transition, waiting, err)
		}
	})
	t.Run("v2-without-digest", func(t *testing.T) {
		r, in, dep, _, _ := transitionFixture(t, true)
		delete(dep.Spec.Template.Annotations, ingressHTTPConfigAnnotation)
		if err := r.Update(context.Background(), dep); err != nil {
			t.Fatal(err)
		}
		if _, reason := transitionReconcile(t, r, in); reason != "HTTPTransitionPending" || *transitionDeployment(t, r, in).Spec.Replicas != 0 {
			t.Fatal("unmarked v2 agent escaped retirement")
		}
	})
}

func TestIngressHTTPTransitionWaitsForScaleObservation(t *testing.T) {
	r, in, _, _, pod := transitionFixture(t, false)
	transitionReconcile(t, r, in)
	if err := r.Delete(context.Background(), pod); err != nil {
		t.Fatal(err)
	}
	dep := transitionDeployment(t, r, in)
	dep.Status.Replicas = 0
	dep.Status.ObservedGeneration = dep.Generation - 1
	if err := r.Status().Update(context.Background(), dep); err != nil {
		t.Fatal(err)
	}
	if _, reason := transitionReconcile(t, r, in); reason != "HTTPTransitionPending" {
		t.Fatal("empty Pod list bypassed unobserved scale-down")
	}
	transitionAcknowledgeScale(t, r, in)
	if _, reason := transitionReconcile(t, r, in); reason != "NoTailnet" {
		t.Fatal(reason)
	}
}

func TestIngressExtendedDeploymentApplyOwnershipFence(t *testing.T) {
	ctx := context.Background()
	r, in, dep, _, pod := transitionFixture(t, false)
	desired := ingressAgentDeployment(in, &tnv1.Tailnet{}, in.Namespace, "new", nil, corev1.ResourceRequirements{})
	if err := controllerutil.SetControllerReference(in, desired, r.Scheme); err != nil {
		t.Fatal(err)
	}
	dep.OwnerReferences[0].UID = "replacement-owner"
	if err := r.Update(ctx, dep); err != nil {
		t.Fatal(err)
	}
	if err := r.applyExtendedIngressDeployment(ctx, in, desired); err != errIngressTransitionOwnership {
		t.Fatalf("adopted Deployment replaced during dependency lookups: %v", err)
	}
	if err := r.Delete(ctx, dep); err != nil {
		t.Fatal(err)
	}
	if err := r.Delete(ctx, pod); err != nil {
		t.Fatal(err)
	}
	// Simulate another writer creating a foreign Deployment after Get=NotFound.
	r.Client = interceptor.NewClient(r.Client.(client.WithWatch), interceptor.Funcs{
		Create: func(ctx context.Context, c client.WithWatch, obj client.Object, opts ...client.CreateOption) error {
			foreign := dep.DeepCopy()
			foreign.ResourceVersion = ""
			if err := c.Create(ctx, foreign); err != nil {
				t.Fatal(err)
			}
			return c.Create(ctx, obj, opts...)
		},
	})
	if err := r.applyExtendedIngressDeployment(ctx, in, desired); err == nil {
		t.Fatal("creation adopted a concurrent foreign Deployment")
	}
	if got := transitionDeployment(t, r, in); metav1.IsControlledBy(got, in) || got.Spec.Template.Spec.Containers[0].Image != "old:agent" || got.Spec.Strategy.Type != appsv1.RecreateDeploymentStrategyType {
		t.Fatal("foreign Deployment was overwritten")
	}
}
