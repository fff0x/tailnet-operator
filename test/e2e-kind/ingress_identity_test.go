//go:build e2e_kind

package e2ekind

import (
	"testing"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

// TestIngressIdentityPersists: an ingress agent that loses its Pod comes back as the same tailnet
// node. The node key lives in the CR's state Secret, written by the agent through its own
// ServiceAccount, so status.nodeID and the tailnet address survive the restart and a peer keeps
// dialling the address it already knows. This is the ingress counterpart of the gateway's retained
// identity; egress agents stay ephemeral.
func TestIngressIdentityPersists(t *testing.T) {
	x := newPeerFixture(t, nil, "ingress-identity")
	f := x.f
	l4 := setupL4Ingress(t, x, "http-agent")
	before := probeL4Exchange(t, x, "before-restart", l4.target)
	nodeID, target := l4.ingress.Status.NodeID, l4.target
	if nodeID == "" || target == "" {
		t.Fatal("ingress has no tailnet identity to keep")
	}

	// The registered node left its state behind: exactly one labelled Secret, owned by the CR,
	// with content the agent wrote.
	var secrets corev1.SecretList
	if f.kube.List(t.Context(), &secrets, client.InNamespace(namespace), client.MatchingLabels{"app.kubernetes.io/name": "tailnet-ingress", "app.kubernetes.io/instance": l4.ingress.Name, "tsunaro.io/state": "true"}) != nil || len(secrets.Items) != 1 {
		t.Fatalf("expected exactly one ingress state Secret, got %d", len(secrets.Items))
	}
	state := secrets.Items[0]
	if !metav1.IsControlledBy(&state, l4.ingress) || len(state.Data) == 0 {
		t.Fatal("state Secret is not owned by the ingress or still empty after registration")
	}

	retired := l4.agent.DeepCopy()
	uid := retired.UID
	if f.kube.Delete(t.Context(), retired, client.Preconditions{UID: &uid}) != nil {
		t.Fatal("agent pod delete rejected")
	}
	agent := &corev1.Pod{}
	eventually(t, "replacement agent waits alone in the startup gate", func() bool {
		var pods corev1.PodList
		if f.kube.List(t.Context(), &pods, client.InNamespace(namespace), client.MatchingLabels{"app.kubernetes.io/name": "tailnet-ingress", "app.kubernetes.io/instance": l4.ingress.Name}) != nil || len(pods.Items) != 1 {
			return false
		}
		p := pods.Items[0]
		if p.UID == retired.UID || p.DeletionTimestamp != nil || len(p.Status.InitContainerStatuses) != 1 || p.Status.InitContainerStatuses[0].State.Running == nil {
			return false
		}
		*agent = p
		return true
	})
	releaseFixturePod(t, f, agent)
	eventually(t, "restarted ingress Ready on the same node", func() bool {
		return l4.ready() && l4.ingress.Status.NodeID == nodeID && tailnetIPv4(l4.ingress.Status.TailnetIPs) == target
	})
	after := probeL4Exchange(t, x, "after-restart-same-ipv4", target)

	nodes, ok := decodeGatewayCLINodes(x.cli("nodes", "list", "--output", "json"))
	if !ok {
		t.Fatal("private node inventory unreadable")
	}
	var named, online int
	for _, n := range nodes {
		if n.GivenName == "http-agent" {
			named++
			if n.Online {
				online++
				if n.ID != nodeID {
					t.Fatal("the online node is not the one the ingress had before the restart")
				}
			}
		}
	}
	x.save("result.json", map[string]any{
		"realChartAndReconciler": true, "restartVector": "pod delete", "agentPodReplaced": agent.UID != retired.UID,
		"nodeKept": l4.ingress.Status.NodeID == nodeID, "addressKept": tailnetIPv4(l4.ingress.Status.TailnetIPs) == target,
		"nodesWithName": named, "onlineNodesWithName": online, "stateSecret": state.Name,
		"exchangeBefore": before, "exchangeAfterSameIPv4": after,
	})
	if named != 1 || online != 1 {
		t.Fatalf("expected exactly one node under the name and it online, got %d/%d", named, online)
	}
}
