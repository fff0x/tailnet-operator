//go:build e2e_kind

package e2ekind

import (
	"context"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	"sigs.k8s.io/controller-runtime/pkg/client"

	tnv1 "tsunaro.io/tailnet-operator/api/v1alpha1"
)

// exposeBridgePhase continues TestEgressReach on the same Ready egress: a second target named by
// MagicDNS (the peer again) must be served without any subnet route, and spec.expose must publish
// the target Services on the LAN only once the Tailnet admin lists the client prefixes. kind has no
// LoadBalancer implementation, so address assignment is simulated through the Service status —
// the contract under test is the operator's rendering and gating, not a vendor's IPAM.
func exposeBridgePhase(t *testing.T, x *httpPeerFixture, base *tailnetFixture, egress *tnv1.TailnetEgress) {
	t.Helper()
	f := x.f
	condReason := func(typ string) string {
		if c := meta.FindStatusCondition(egress.Status.Conditions, typ); c != nil {
			return c.Reason
		}
		return ""
	}
	current := func() bool {
		return f.kube.Get(t.Context(), client.ObjectKeyFromObject(egress), egress) == nil && egress.Status.ObservedGeneration == egress.Generation
	}
	t.Cleanup(func() {
		if !t.Failed() {
			return
		}
		ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
		defer cancel()
		logs, _ := f.command(ctx, "", "kubectl", "--kubeconfig", f.config, "--context", f.context, "--request-timeout=5s", "--namespace", namespace, "logs", "deployment/"+egress.Name, "--all-containers=true", "--tail=200", "--limit-bytes=65536")
		x.save("failed-egress-agent.private.json", map[string]string{"logs": string(logs)})
		var services corev1.ServiceList
		var policies networkingv1.NetworkPolicyList
		_ = f.kube.List(ctx, &services, client.InNamespace(namespace), client.MatchingLabels{"app.kubernetes.io/instance": egress.Name})
		_ = f.kube.List(ctx, &policies, client.InNamespace(namespace), client.MatchingLabels{"app.kubernetes.io/instance": egress.Name})
		x.save("failed-expose-children.private.json", map[string]any{"services": services.Items, "networkPolicies": policies.Items})
	})
	exposeRule := func() *networkingv1.NetworkPolicyIngressRule {
		var np networkingv1.NetworkPolicy
		if err := f.kube.Get(t.Context(), client.ObjectKey{Namespace: namespace, Name: egress.Name}, &np); err != nil {
			if !apierrors.IsNotFound(err) {
				t.Fatalf("egress NetworkPolicy lookup: %v", err)
			}
			return nil
		}
		for i := range np.Spec.Ingress {
			if len(np.Spec.Ingress[i].From) > 0 && np.Spec.Ingress[i].From[0].IPBlock != nil {
				return &np.Spec.Ingress[i]
			}
		}
		return nil
	}

	// 1. Tenant asks for a DNS-named target and an expose; the admin allowlist is still empty.
	before := egress.DeepCopy()
	egress.Spec.Targets = append(egress.Spec.Targets, tnv1.Target{Name: "peer-name", Address: "http-peer.fixture.test", Port: 8081})
	egress.Spec.Expose = &tnv1.EgressExpose{AllowFrom: []tnv1.SourcePrefix{"192.0.2.0/24"}}
	if f.kube.Patch(t.Context(), egress, client.MergeFrom(before)) != nil {
		t.Fatal("egress expose patch rejected")
	}
	// The new target reaches the agent through its ConfigMap mount (kubelet sync, up to ~90 s) plus
	// the agent's 10 s poll; the generic 90 s budget is too tight for that path alone.
	eventuallyWithin(t, 4*time.Minute, "DNS-named target served without a route; expose denied by the empty allowlist", func() bool {
		if !current() || len(egress.Status.Targets) != 2 {
			return false
		}
		var byName *tnv1.TargetStatus
		for i := range egress.Status.Targets {
			if egress.Status.Targets[i].Name == "peer-name" {
				byName = &egress.Status.Targets[i]
			}
		}
		if byName == nil || byName.Route != "" || !byName.Present || !byName.Reachable || byName.Reason != "" {
			return false
		}
		return condReason("Exposed") == "Denied" && condReason("Ready") == "Denied" && !meta.IsStatusConditionTrue(egress.Status.Conditions, "Ready")
	})
	var service corev1.Service
	if f.kube.Get(t.Context(), client.ObjectKey{Namespace: namespace, Name: "peer"}, &service) != nil || service.Spec.Type != corev1.ServiceTypeClusterIP || exposeRule() != nil {
		t.Fatal("a denied expose must leave the Service ClusterIP and render no ipBlock rule")
	}

	// 2. The admin lists the client prefixes: the Services become LoadBalancers with the source
	// filter, and the egress waits for an address.
	tnBefore := base.tn.DeepCopy()
	base.tn.Spec.ExposeSourceAllowlist = []tnv1.GatewayPrefix{"192.0.2.0/24"}
	if f.kube.Patch(t.Context(), base.tn, client.MergeFrom(tnBefore)) != nil {
		t.Fatal("tailnet allowlist patch rejected")
	}
	eventually(t, "expose rendered and pending an address", func() bool {
		if !current() || condReason("Exposed") != "PendingAddress" || condReason("Ready") != "PendingAddress" {
			return false
		}
		if f.kube.Get(t.Context(), client.ObjectKey{Namespace: namespace, Name: "peer"}, &service) != nil {
			return false
		}
		rule := exposeRule()
		return service.Spec.Type == corev1.ServiceTypeLoadBalancer && service.Spec.ExternalTrafficPolicy == corev1.ServiceExternalTrafficPolicyLocal &&
			service.Spec.AllocateLoadBalancerNodePorts != nil && !*service.Spec.AllocateLoadBalancerNodePorts &&
			rule != nil && len(rule.From) == 1 && rule.From[0].IPBlock.CIDR == "192.0.2.0/24" && len(rule.Ports) == 2
	})

	// 3. The cluster's LB implementation assigns addresses (simulated): Exposed and Ready follow.
	for _, name := range []string{"peer", "peer-name"} {
		var svc corev1.Service
		if f.kube.Get(t.Context(), client.ObjectKey{Namespace: namespace, Name: name}, &svc) != nil {
			t.Fatalf("exposed Service %s missing", name)
		}
		svcBefore := svc.DeepCopy()
		svc.Status.LoadBalancer.Ingress = []corev1.LoadBalancerIngress{{IP: "192.0.2.200"}}
		if f.kube.Status().Patch(t.Context(), &svc, client.MergeFrom(svcBefore)) != nil {
			t.Fatalf("simulated LB address on %s rejected", name)
		}
	}
	eventually(t, "egress Exposed and Ready with the LAN address reported", func() bool {
		return current() && condReason("Exposed") == "AddressAssigned" && meta.IsStatusConditionTrue(egress.Status.Conditions, "Ready") &&
			egress.Status.Expose != nil && len(egress.Status.Expose.Addresses) == 1 && egress.Status.Expose.Addresses[0] == "192.0.2.200"
	})
	x.save("expose-result.json", map[string]any{
		"dnsTarget": egress.Status.Targets, "exposeAddresses": egress.Status.Expose.Addresses, "serviceType": service.Spec.Type,
		"externalTrafficPolicy": service.Spec.ExternalTrafficPolicy, "ipBlockRule": exposeRule(),
	})
	t.Log("gate: a MagicDNS-named target is served with no subnet route; spec.expose stays ClusterIP until the Tailnet allowlist admits the prefixes, then renders a Local LoadBalancer plus an ipBlock rule on the listen ports and reports the assigned address")
}

// eventuallyWithin is eventually with an explicit budget for the few waits that include a kubelet
// ConfigMap propagation.
func eventuallyWithin(t *testing.T, budget time.Duration, label string, check func() bool) {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), budget)
	defer cancel()
	for {
		if check() {
			return
		}
		select {
		case <-ctx.Done():
			t.Fatalf("timed out waiting for %s", label)
		case <-time.After(time.Second):
		}
	}
}
