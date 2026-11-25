//go:build e2e_kind

package e2ekind

import (
	"encoding/json"
	"testing"

	corev1 "k8s.io/api/core/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"

	tnv1 "tsunaro.io/tailnet-operator/api/v1alpha1"
)

// probeL4Gone converges on the opposite of probeL4Exchange: the name no longer reaches the service.
// Connected is the discriminator, not TimedOut — a withdrawn MagicDNS record fails in the lookup,
// a record still pointing at the retired node fails in the dial, and demanding one of the two would
// pin a Headscale timing detail rather than the behaviour under test.
func probeL4Gone(t *testing.T, x *httpPeerFixture, label, address string) l4Observation {
	t.Helper()
	var got l4Observation
	eventually(t, "retired name stops reaching the service ("+label+")", func() bool {
		input, _ := json.Marshal(map[string]string{"target": address})
		b, err := x.proxy(x.peer.Name, 9081, "probe-l4", string(input))
		var raw struct {
			OK        *bool `json:"ok"`
			Connected *bool `json:"connected"`
			TimedOut  *bool `json:"timedOut"`
		}
		if err != nil || len(b) > 1024 || json.Unmarshal(b, &raw) != nil || raw.OK == nil || raw.Connected == nil || raw.TimedOut == nil {
			return false
		}
		got = l4Observation{OK: *raw.OK, Connected: *raw.Connected, TimedOut: *raw.TimedOut}
		return !got.OK && !got.Connected
	})
	return got
}

// TestMagicDNSRename renames the tailnet node of a Ready ingress. spec.hostname is the only rename
// vector a CR has, because its name is immutable in Kubernetes, and it renames the node: a peer
// resolves <givenName>.<base_domain>, the fixture control plane serves fixture.test, and the
// operator writes no records of its own (DNSSpec only renders a cluster hosts file for a gateway's
// CoreDNS). associateNode matches candidates by GivenName, so the old node is never found again —
// the agent rolls and re-registers as a new node with a new address and a new MagicDNS name.
//
// The gate pins the status contract: status.dnsName and status.hosts are the gateway-zone names
// rendered from the CR name (served by the gateway's CoreDNS, not by MagicDNS) and therefore do not
// move with spec.hostname; status.hostname is the MagicDNS identity and follows the rename. The
// fixture zone fixture.test doubles as the MagicDNS base_domain because kind has no other resolver,
// which is exactly the configuration the docs forbid — so here the unchanged dnsName is a name
// MagicDNS no longer serves. That is a property of the fixture, not of the operator.
func TestMagicDNSRename(t *testing.T) {
	x := newPeerFixture(t, nil, "magicdns-rename")
	f := x.f
	l4 := setupL4Ingress(t, x, "http-agent")
	const oldName, newName = "http-agent.fixture.test", "renamed-agent.fixture.test"
	if l4.ingress.Status.DNSName != oldName || l4.ingress.Status.Hostname != "http-agent" {
		t.Fatal("ingress did not start with the expected record and node name")
	}
	beforeByName := probeL4Exchange(t, x, "before-rename-old-magicdns", oldName)
	retired := l4.agent.DeepCopy()
	retiredNode, retiredTarget := l4.ingress.Status.NodeID, l4.target
	if retiredNode == "" || retiredTarget == "" {
		t.Fatal("ingress has no tailnet identity to rename away from")
	}

	before := l4.ingress.DeepCopy()
	l4.ingress.Spec.Hostname = "renamed-agent"
	if f.kube.Patch(t.Context(), l4.ingress, client.MergeFromWithOptions(before, client.MergeFromWithOptimisticLock{})) != nil {
		t.Fatal("hostname change rejected")
	}
	// TS_HOSTNAME sits in the Deployment's Pod template, so the change rolls the agent, and the
	// fixture holds every new Pod in the network gate until the test releases it.
	agent := &corev1.Pod{}
	eventually(t, "renamed agent waits alone in the unchanged startup gate", func() bool {
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
	eventually(t, "renamed ingress Ready again on a new node", func() bool {
		return l4.ready() && l4.ingress.Status.Hostname == "renamed-agent" && l4.ingress.Status.NodeID != retiredNode
	})
	// The replacement is a different tailnet node, so the address read before the roll is dead.
	target := tailnetIPv4(l4.ingress.Status.TailnetIPs)
	if target == "" {
		t.Fatal("renamed agent has no tailnet IPv4")
	}
	if target == retiredTarget {
		t.Fatal("replacement node kept the retired address, so the rename proves nothing about names")
	}

	afterByIP := probeL4Exchange(t, x, "after-rename-new-ipv4", target)
	afterByName := probeL4Exchange(t, x, "after-rename-new-magicdns", newName)
	goneByName := probeL4Gone(t, x, "old-magicdns", oldName)

	var current tnv1.TailnetIngress
	if f.kube.Get(t.Context(), client.ObjectKeyFromObject(l4.ingress), &current) != nil {
		t.Fatal("ingress unreadable after the rename")
	}
	nodes, ok := decodeGatewayCLINodes(x.cli("nodes", "list", "--output", "json"))
	if !ok {
		t.Fatal("private node inventory unreadable")
	}
	var onlineNew, onlineOld int
	for _, n := range nodes {
		switch {
		case n.GivenName == "renamed-agent" && n.Online:
			onlineNew++
			if n.ID != current.Status.NodeID {
				t.Fatal("status points at a different node than the online renamed one")
			}
		case n.GivenName == "http-agent" && n.Online:
			onlineOld++
		}
	}
	x.save("result.json", map[string]any{
		"realChartAndReconciler": true, "renameVector": "spec.hostname", "renamedSubject": "tailnet node",
		"oldMagicDNS": oldName, "newMagicDNS": newName, "nodeName": current.Status.Hostname,
		"nodeReplaced": current.Status.NodeID != retiredNode, "addressReplaced": target != retiredTarget,
		"agentPodReplaced":       agent.UID != retired.UID,
		"onlineNodesWithNewName": onlineNew, "onlineNodesWithOldName": onlineOld,
		"statusDNSName": current.Status.DNSName, "statusHosts": current.Status.Hosts,
		"statusDNSNameHostnameIndependent": current.Status.DNSName == oldName,
		"exchangeBeforeByOldName":          beforeByName, "exchangeAfterByNewName": afterByName,
		"exchangeAfterByNewIPv4": afterByIP, "oldNameObservation": goneByName,
		"recordTemplateRenameTested": false, "operatorOwnedZoneTested": false,
	})
	if onlineNew != 1 || onlineOld != 0 {
		t.Fatalf("expected exactly one online node under the new name and none under the old: %d/%d", onlineNew, onlineOld)
	}
	if len(current.Status.Exposes) != 1 || !current.Status.Exposes[0].Reachable {
		t.Fatal("renamed ingress does not report its L4 expose as reachable")
	}
	if current.Status.DNSName != oldName || current.Status.Hostname != "renamed-agent" {
		t.Fatalf("status.dnsName must stay the zone name rendered from the CR name and status.hostname must follow the rename: dnsName=%q hostname=%q", current.Status.DNSName, current.Status.Hostname)
	}
	// Pinned divergence, see the doc comment: a fix has to replace this expectation.
	if current.Status.DNSName != oldName || len(current.Status.Hosts) != 1 || current.Status.Hosts[0] != oldName {
		t.Fatalf("status no longer advertises the retired name (dnsName %q hosts %v): the divergence was fixed, rewrite this gate", current.Status.DNSName, current.Status.Hosts)
	}
	t.Log("gate: spec.hostname change rolled the agent and re-registered it as a new node with a new address; the new MagicDNS name completes the L4 exchange, the old one reaches nothing, no online node keeps the old name — while status.dnsName/hosts still advertise it, the tracked divergence")
}
