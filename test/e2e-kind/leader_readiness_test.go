//go:build e2e_kind

package e2ekind

import (
	"testing"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

func TestLeaderMappingDoesNotWaitForReplacement(t *testing.T) {
	scheme := runtime.NewScheme()
	_ = corev1.AddToScheme(scheme)
	_ = appsv1.AddToScheme(scheme)
	deployment := &appsv1.Deployment{
		ObjectMeta: metav1.ObjectMeta{Name: "tailnet-operator", Namespace: namespace, Generation: 1},
		Status:     appsv1.DeploymentStatus{ObservedGeneration: 1, ReadyReplicas: 1},
	}
	survivor := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: "operator-survivor", Namespace: namespace, UID: "survivor", Labels: map[string]string{"app.kubernetes.io/name": "tailnet-operator"}},
		Status:     corev1.PodStatus{Conditions: []corev1.PodCondition{{Type: corev1.PodReady, Status: corev1.ConditionTrue}}},
	}
	pending := survivor.DeepCopy()
	pending.Name, pending.UID = "operator-replacement", "replacement"
	pending.Status = corev1.PodStatus{Phase: corev1.PodPending}
	f := &fixture{kube: fake.NewClientBuilder().WithScheme(scheme).WithObjects(deployment, survivor, pending).Build()}
	if _, ready := f.readyOperators(t.Context()); ready {
		t.Fatal("two-replica readiness incorrectly passed")
	}
	pods := f.readyOperatorPods(t.Context())
	if got, ok := holderPod(survivor.Name+"_12345678-1234-1234-1234-123456789abc", pods); !ok || got.UID != survivor.UID {
		t.Fatal("surviving leader could not be mapped while replacement remained pending")
	}
}
