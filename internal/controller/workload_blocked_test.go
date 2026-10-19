package controller

import (
	"context"
	"testing"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

// TestWorkloadBlocked reads the admission reason off the agent Deployment's ReplicaFailure
// condition, and stays silent when there is none or no Deployment.
func TestWorkloadBlocked(t *testing.T) {
	const reason = `pods "ingress-shop" is forbidden: minimum cpu usage per Container is 100m, but request is 10m`
	s := runtime.NewScheme()
	_ = clientgoscheme.AddToScheme(s)
	key := types.NamespacedName{Namespace: "apps", Name: "ingress-shop"}
	dep := func(conds ...appsv1.DeploymentCondition) *appsv1.Deployment {
		return &appsv1.Deployment{
			ObjectMeta: metav1.ObjectMeta{Namespace: key.Namespace, Name: key.Name},
			Status:     appsv1.DeploymentStatus{Conditions: conds},
		}
	}
	for _, tc := range []struct {
		name string
		objs []*appsv1.Deployment
		want string
	}{
		{"blocked", []*appsv1.Deployment{dep(appsv1.DeploymentCondition{Type: appsv1.DeploymentReplicaFailure, Status: corev1.ConditionTrue, Message: reason})}, reason},
		{"progressing-ok", []*appsv1.Deployment{dep(appsv1.DeploymentCondition{Type: appsv1.DeploymentProgressing, Status: corev1.ConditionTrue, Message: "ok"})}, ""},
		{"failure-cleared", []*appsv1.Deployment{dep(appsv1.DeploymentCondition{Type: appsv1.DeploymentReplicaFailure, Status: corev1.ConditionFalse, Message: reason})}, ""},
		{"no-deployment", nil, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			b := fake.NewClientBuilder().WithScheme(s)
			for _, o := range tc.objs {
				b = b.WithObjects(o)
			}
			if got := workloadBlocked(context.Background(), b.Build(), key); got != tc.want {
				t.Fatalf("workloadBlocked = %q, want %q", got, tc.want)
			}
		})
	}
}
