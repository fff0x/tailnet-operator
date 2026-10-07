package controller

import (
	"context"
	"testing"
	"time"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"

	tnv1 "tsunaro.io/tailnet-operator/api/v1alpha1"
)

func legacyFixture(t *testing.T, owned bool) (*TailnetIngressReconciler, *tnv1.TailnetIngress, *corev1.Pod) {
	t.Helper()
	in := tlsResourceIngress()
	in.UID = "cr-uid"
	one := int32(1)
	dep := &appsv1.Deployment{ObjectMeta: metav1.ObjectMeta{Name: in.Name, Namespace: in.Namespace, UID: "dep-uid", Generation: 1},
		Spec: appsv1.DeploymentSpec{Replicas: &one}, Status: appsv1.DeploymentStatus{ObservedGeneration: 1, Replicas: 1}}
	np := &networkingv1.NetworkPolicy{ObjectMeta: metav1.ObjectMeta{Name: in.Name, Namespace: in.Namespace, UID: "np-uid"}}
	pod := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "old", Namespace: in.Namespace, Labels: ingressSelectorLabels(in.Name)}}
	c := transitionClient(t)
	if owned {
		for _, o := range []client.Object{dep, np} {
			if err := controllerutil.SetControllerReference(in, o, c.Scheme()); err != nil {
				t.Fatal(err)
			}
		}
	}
	c = transitionClient(t, in, dep, np, pod)
	return &TailnetIngressReconciler{Client: c, Scheme: c.Scheme()}, in, pod
}

func TestLegacyIngressWorkloadIsDrainedThenDeleted(t *testing.T) {
	ctx := context.Background()
	r, in, pod := legacyFixture(t, true)
	key := client.ObjectKeyFromObject(in)
	step := func(want bool) {
		t.Helper()
		if got, err := r.retireLegacyIngressWorkload(ctx, in); err != nil || got != want {
			t.Fatalf("waiting=%v err=%v, want %v", got, err, want)
		}
	}
	step(true) // scales to zero
	var dep appsv1.Deployment
	if err := r.Get(ctx, key, &dep); err != nil || *dep.Spec.Replicas != 0 {
		t.Fatalf("not scaled down: %v", err)
	}
	dep.Status.ObservedGeneration, dep.Status.Replicas = dep.Generation, 0
	if err := r.Status().Update(ctx, &dep); err != nil {
		t.Fatal(err)
	}
	step(true) // pod still terminating
	if err := r.Get(ctx, key, &dep); err != nil {
		t.Fatalf("deleted while a pod remained: %v", err)
	}
	if err := r.Delete(ctx, pod); err != nil {
		t.Fatal(err)
	}
	step(true) // deletes Deployment and NetworkPolicy
	if err := r.Get(ctx, key, &dep); !apierrors.IsNotFound(err) {
		t.Fatalf("legacy Deployment survived: %v", err)
	}
	if err := r.Get(ctx, key, &networkingv1.NetworkPolicy{}); !apierrors.IsNotFound(err) {
		t.Fatalf("legacy NetworkPolicy survived: %v", err)
	}
	step(false)
}

func TestLegacyIngressWorkloadIgnoresForeignDeployment(t *testing.T) {
	ctx := context.Background()
	r, in, _ := legacyFixture(t, false)
	if waiting, err := r.retireLegacyIngressWorkload(ctx, in); err != nil || waiting {
		t.Fatalf("waiting=%v err=%v", waiting, err)
	}
	var dep appsv1.Deployment
	if err := r.Get(ctx, client.ObjectKeyFromObject(in), &dep); err != nil || *dep.Spec.Replicas != 1 {
		t.Fatalf("foreign Deployment touched: %v", err)
	}
	if err := r.Get(ctx, client.ObjectKeyFromObject(in), &networkingv1.NetworkPolicy{}); err != nil {
		t.Fatalf("foreign NetworkPolicy touched: %v", err)
	}
}

func TestIngressStatusHostsL4FallsBackToNodeName(t *testing.T) {
	in := tlsResourceIngress()
	in.Spec.Exposes = in.Spec.Exposes[1:] // L4 only
	in.Status.DNSName = "app.tenant.example"
	r := &TailnetIngressReconciler{}
	r.computeIngressStatus(in, ingressTLSState{}, nil, nil, time.Now())
	if len(in.Status.Hosts) != 1 || in.Status.Hosts[0] != "app.tenant.example" {
		t.Fatalf("hosts=%v", in.Status.Hosts)
	}
}
