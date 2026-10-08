//go:build e2e_kind

package e2ekind

import (
	"context"
	"strings"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"

	tnv1 "tsunaro.io/tailnet-operator/api/v1alpha1"
)

// peerTailnetIPv4 reads the fixture peer's address from the control plane's node inventory, the
// only place that knows it: the peer reports readiness over the Pod network, not its tailnet
// identity. Registration is asynchronous, so this converges rather than reading once.
func peerTailnetIPv4(t *testing.T, x *httpPeerFixture) string {
	t.Helper()
	var address string
	eventually(t, "fixture peer online with a tailnet IPv4", func() bool {
		nodes, ok := decodeGatewayCLINodes(x.cli("nodes", "list", "--output", "json"))
		if !ok {
			return false
		}
		address = ""
		for _, n := range nodes {
			if n.GivenName == "http-peer" && n.Online {
				address = tailnetIPv4(n.IPAddresses)
			}
		}
		return address != ""
	})
	return address
}

// TestEgressReach is the P1.4 egress gate: a TailnetEgress must turn a host that exists only on the
// tailnet into an ordinary ClusterIP Service. The target is the fixture peer, which serves the same
// bounded nonce/digest exchange on its tsnet listener as on its Pod-network one. The consumer has
// to be an in-cluster Pod rather than the peer itself, because a ClusterIP is not dialable from
// outside the cluster network — which is exactly the gap the egress proxy closes.
func TestEgressReach(t *testing.T) {
	x := newPeerFixture(t, nil, "egress-reach")
	f := x.f
	base := setupTailnetFixture(t, x)
	address := peerTailnetIPv4(t, x)
	egress := &tnv1.TailnetEgress{ObjectMeta: metav1.ObjectMeta{Name: "peer-egress", Namespace: namespace}, Spec: tnv1.TailnetEgressSpec{
		TailnetRef: tnv1.TailnetRef{Name: base.tn.Name}, ConsumerNamespaces: []string{namespace},
		Targets: []tnv1.Target{{Name: "peer", Address: address, Port: 8081}},
	}}
	x.create(egress)
	base.track(egress, "failed-egress.private.json")
	var agent corev1.Pod
	eventually(t, "generated egress agent held at real startup gate", func() bool {
		var pods corev1.PodList
		if f.kube.List(t.Context(), &pods, client.InNamespace(namespace), client.MatchingLabels{"app.kubernetes.io/name": "tailnet-egress", "app.kubernetes.io/instance": egress.Name}) != nil || len(pods.Items) != 1 {
			return false
		}
		agent = pods.Items[0]
		return agent.DeletionTimestamp == nil && len(agent.Status.InitContainerStatuses) == 1 && agent.Status.InitContainerStatuses[0].State.Running != nil
	})
	// The gate held, which also proves the widened fixture admission reaches egress Pods: an
	// unmatched Pod would have started straight away and without the control CA.
	releaseFixturePod(t, f, &agent)
	eventually(t, "egress Ready with the target routed and reachable", func() bool {
		if f.kube.Get(t.Context(), client.ObjectKeyFromObject(egress), egress) != nil || egress.Status.ObservedGeneration != egress.Generation {
			return false
		}
		if !meta.IsStatusConditionTrue(egress.Status.Conditions, "RoutesGranted") || !meta.IsStatusConditionTrue(egress.Status.Conditions, "TargetsReachable") || !meta.IsStatusConditionTrue(egress.Status.Conditions, "Ready") {
			return false
		}
		target := egress.Status.Targets
		return len(target) == 1 && target[0].Name == "peer" && target[0].Route == address+"/32" && target[0].Present && target[0].Reachable && target[0].Reason == ""
	})
	// The Service is the product: a consumer dials <target>.<namespace>.svc on the target's own
	// port and never learns that the far end lives on a tailnet.
	var service corev1.Service
	if f.kube.Get(t.Context(), client.ObjectKey{Namespace: namespace, Name: "peer"}, &service) != nil ||
		len(service.Spec.Ports) != 1 || service.Spec.Ports[0].Port != 8081 || service.Spec.ClusterIP == "" {
		t.Fatal("egress target Service missing or not on the target port")
	}
	consumer := httpFixturePod("egress-consumer", x.image)
	consumer.Spec.Containers[0].Command = []string{"/egressprobe"}
	consumer.Spec.Containers[0].Args = []string{"--fixture=p1.8-egress"}
	// OnFailure, because the agent's local listener can lag its Reachable status by a moment. A
	// genuinely broken path never succeeds and the wait below times out with the Pod kept for
	// evidence; a single early dial does not decide the gate.
	consumer.Spec.RestartPolicy = corev1.RestartPolicyOnFailure
	x.create(consumer)
	consumerLogs := func(ctx context.Context, limit string) []byte {
		out, _ := f.command(ctx, "", "kubectl", "--kubeconfig", f.config, "--context", f.context, "--request-timeout=5s", "--namespace", namespace, "logs", consumer.Name, "--limit-bytes="+limit)
		return out
	}
	t.Cleanup(func() {
		if !t.Failed() {
			return
		}
		ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
		defer cancel()
		var current corev1.Pod
		if f.kube.Get(ctx, client.ObjectKeyFromObject(consumer), &current) == nil && current.UID == consumer.UID {
			x.save("failed-consumer.private.json", map[string]any{"status": current.Status, "logs": string(consumerLogs(ctx, "4096"))})
		}
	})
	eventually(t, "consumer completed the exchange through the egress Service", func() bool {
		return f.kube.Get(t.Context(), client.ObjectKeyFromObject(consumer), consumer) == nil && consumer.Status.Phase == corev1.PodSucceeded
	})
	ctx, cancel := context.WithTimeout(t.Context(), 15*time.Second)
	defer cancel()
	out := strings.TrimSpace(string(consumerLogs(ctx, "1024")))
	if out != `{"egressExchange":true}` {
		t.Fatal("consumer exited successfully without reporting the exchange")
	}
	x.save("result.json", map[string]any{
		"peerAddress": address, "target": egress.Status.Targets[0], "servicePort": service.Spec.Ports[0].Port,
		"consumerRestarts": consumer.Status.ContainerStatuses[0].RestartCount, "consumerOutput": out,
	})
	t.Log("gate: the generated egress agent passed the real startup gate, the peer's /32 is routed and probed reachable, and an ordinary in-cluster consumer completed the bounded exchange through the target's ClusterIP Service without knowing the far end is on a tailnet")
}
