package controller

import (
	"context"
	"testing"

	"github.com/prometheus/client_golang/prometheus"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	tnv1 "this-is-fine.io/tailnet-operator/api/v1alpha1"
	operatormetrics "this-is-fine.io/tailnet-operator/internal/metrics"
)

func TestPolicyReplayCounterBaseline(t *testing.T) {
	scheme := runtime.NewScheme()
	_ = tnv1.AddToScheme(scheme)
	_ = corev1.AddToScheme(scheme)
	tn := &tnv1.Tailnet{ObjectMeta: metav1.ObjectMeta{Name: "fixture", Generation: 1}}
	tn.Spec.Policy.BaseConfigMap = "missing-base"
	c := fake.NewClientBuilder().WithScheme(scheme).WithStatusSubresource(tn).WithObjects(tn).Build()
	reg := prometheus.NewPedanticRegistry()
	m, err := operatormetrics.Register(reg)
	if err != nil {
		t.Fatal(err)
	}
	r := TailnetPolicyReconciler{Client: c, Metrics: m, OperatorNamespace: "ns"}
	if _, err := r.Reconcile(context.Background(), ctrl.Request{NamespacedName: client.ObjectKey{Name: tn.Name}}); err != nil {
		t.Fatal(err)
	}
	if v, n := gatheredValue(t, reg, "tailnet_route_approvals_replayed_total"); v != 0 || n != 1 {
		t.Fatal("idle policy reconciliation did not establish a replay counter baseline")
	}
	m.Approved(tn.Name, 4)
	if v, n := gatheredValue(t, reg, "tailnet_route_approvals_replayed_total"); v != 4 || n != 1 {
		t.Fatal("first approval batch did not increment the established counter")
	}
}
