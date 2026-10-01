package controller

import (
	"context"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"

	tnv1 "tsunaro.io/tailnet-operator/api/v1alpha1"
)

func TestIngressEarlyFailureClearsTLSProof(t *testing.T) {
	for _, tailnetExists := range []bool{false, true} {
		t.Run(map[bool]string{false: "missing-tailnet", true: "missing-working-key"}[tailnetExists], func(t *testing.T) {
			r, in, state, probes, now := ingressTLSStatusFixture(t)
			in.Spec.TailnetRef.Name = "corp"
			r.computeIngressStatus(in, state, probes, nil, now)
			objects := []client.Object{in}
			if tailnetExists {
				objects = append(objects, &tnv1.Tailnet{ObjectMeta: metav1.ObjectMeta{Name: "corp"}})
			}
			r.Client = ingressTLSFakeClient(t, objects...)
			r.OperatorNamespace = "operator"
			key := client.ObjectKeyFromObject(in)
			if _, err := r.Reconcile(context.Background(), ctrl.Request{NamespacedName: key}); err != nil {
				t.Fatal(err)
			}
			var got tnv1.TailnetIngress
			if err := r.Get(context.Background(), key, &got); err != nil {
				t.Fatal(err)
			}
			if condStatus(got.Status.Conditions, "Ready") != metav1.ConditionFalse ||
				condStatus(got.Status.Conditions, "TLSReady") != metav1.ConditionFalse ||
				got.Status.Exposes[0].TLSReady == nil || *got.Status.Exposes[0].TLSReady {
				t.Fatal("early control-plane failure preserved a green TLS proof")
			}
			if got.Status.TLSSecretName != in.Status.TLSSecretName {
				t.Fatal("failure lost the selected Secret name needed for cleanup")
			}
		})
	}
}

func TestIngressMissingOnlineNodeClearsIdentity(t *testing.T) {
	r, in, state, probes, now := ingressTLSStatusFixture(t)
	in.Status.TailnetIPs = []string{"100.64.0.1"}
	r.associateNode(context.Background(), in, nil, nil, "tag:ingress-app", "app")
	if in.Status.NodeID != "" || len(in.Status.TailnetIPs) != 0 {
		t.Fatal("offline or absent node retained an active identity/DNS address")
	}
	r.computeIngressStatus(in, state, probes, nil, now)
	if condStatus(in.Status.Conditions, "Ready") != metav1.ConditionFalse {
		t.Fatal("healthy local components made an unregistered ingress ready")
	}
}

func TestIngressProbeIgnoresTerminatingPod(t *testing.T) {
	now := metav1.NewTime(time.Now())
	old := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: "a-old", Namespace: "tenant", Labels: ingressSelectorLabels("app"),
			DeletionTimestamp: &now, Finalizers: []string{"fixture.example/hold"}},
		Status: corev1.PodStatus{Phase: corev1.PodRunning, PodIP: "192.0.2.1"},
	}
	r := &TailnetIngressReconciler{Client: ingressTLSFakeClient(t, old)}
	if got := r.agentPodIP(context.Background(), "tenant", "app"); got != "" {
		t.Fatal("terminating Pod was treated as the active agent")
	}
	current := old.DeepCopy()
	current.Name, current.ResourceVersion, current.UID = "z-current", "", types.UID("")
	current.DeletionTimestamp, current.Finalizers = nil, nil
	current.Status.PodIP = "192.0.2.2"
	if err := r.Create(context.Background(), current); err != nil {
		t.Fatal(err)
	}
	if got := r.agentPodIP(context.Background(), "tenant", "app"); got != current.Status.PodIP {
		t.Fatal("did not select the current agent")
	}
}
