package controller

import (
	"context"
	"testing"

	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	tnv1 "tsunaro.io/tailnet-operator/api/v1alpha1"
)

func exposeFixture() (*tnv1.TailnetEgress, tnv1.Target, map[string]int32) {
	eg := &tnv1.TailnetEgress{ObjectMeta: metav1.ObjectMeta{Name: "bridge", Namespace: "agents", UID: "u"}}
	eg.Spec.ConsumerNamespaces = []string{"shop"}
	eg.Spec.Targets = []tnv1.Target{{Name: "shop", Address: "shop.prod.tailnet.example.internal", Port: 443}}
	eg.Spec.Expose = &tnv1.EgressExpose{
		AllowFrom: []tnv1.SourcePrefix{"192.0.2.77/32", "198.51.100.0/24"},
		LoadBalancer: tnv1.EgressExposeLoadBalancer{
			Class:       "example.com/bgp",
			Annotations: map[string]string{"example.com/pool": "legacy"},
			Labels:      map[string]string{"lb-pool": "legacy", "app.kubernetes.io/instance": "hijack"},
		},
	}
	return eg, eg.Spec.Targets[0], map[string]int32{"shop": 10000}
}

// Without expose the Service and NetworkPolicy are exactly what every existing egress gets: a
// ClusterIP and namespace peers, no LB fields, no ipBlock.
func TestTargetServiceWithoutExposeIsClusterIP(t *testing.T) {
	eg, target, listen := exposeFixture()
	eg.Spec.Expose = nil
	svc := targetService(eg, "agents", target, listen["shop"], nil)
	if svc.Spec.Type != corev1.ServiceTypeClusterIP || svc.Spec.ExternalTrafficPolicy != "" || svc.Spec.LoadBalancerClass != nil || svc.Spec.AllocateLoadBalancerNodePorts != nil || svc.Annotations != nil {
		t.Fatalf("non-exposed Service carries LB settings: %+v", svc.Spec)
	}
	np := egressNetworkPolicy(eg, "agents", "operator", nil, nil, listen)
	for _, rule := range np.Spec.Ingress {
		for _, p := range rule.From {
			if p.IPBlock != nil {
				t.Fatal("non-exposed NetworkPolicy must not carry an ipBlock peer")
			}
		}
	}
}

func TestTargetServiceExposeRendersLoadBalancer(t *testing.T) {
	eg, target, listen := exposeFixture()
	svc := targetService(eg, "agents", target, listen["shop"], eg.Spec.Expose)
	if svc.Spec.Type != corev1.ServiceTypeLoadBalancer {
		t.Fatalf("type = %s, want LoadBalancer", svc.Spec.Type)
	}
	if svc.Spec.ExternalTrafficPolicy != corev1.ServiceExternalTrafficPolicyLocal {
		t.Fatalf("externalTrafficPolicy = %q, want Local (client address must survive for the ipBlock filter)", svc.Spec.ExternalTrafficPolicy)
	}
	if svc.Spec.AllocateLoadBalancerNodePorts == nil || *svc.Spec.AllocateLoadBalancerNodePorts {
		t.Fatal("exposed Service must not allocate NodePorts")
	}
	if svc.Spec.LoadBalancerClass == nil || *svc.Spec.LoadBalancerClass != "example.com/bgp" {
		t.Fatalf("loadBalancerClass = %v", svc.Spec.LoadBalancerClass)
	}
	if svc.Annotations["example.com/pool"] != "legacy" {
		t.Fatalf("annotations not passed through: %v", svc.Annotations)
	}
	if svc.Labels["lb-pool"] != "legacy" {
		t.Fatalf("user labels not passed through: %v", svc.Labels)
	}
	if svc.Labels["app.kubernetes.io/instance"] != "bridge" {
		t.Fatalf("identity label overridden by user label: %v", svc.Labels)
	}
	if svc.Spec.Ports[0].Port != 443 || svc.Spec.Ports[0].TargetPort.IntVal != 10000 {
		t.Fatalf("ports changed by expose: %+v", svc.Spec.Ports[0])
	}
}

// The ipBlock rule is the whole source filter: exactly allowFrom, exactly the listen ports.
func TestEgressNetworkPolicyExposeRule(t *testing.T) {
	eg, _, listen := exposeFixture()
	np := egressNetworkPolicy(eg, "agents", "operator", nil, eg.Spec.Expose, listen)
	var rule *networkingv1.NetworkPolicyIngressRule
	for i := range np.Spec.Ingress {
		if len(np.Spec.Ingress[i].From) > 0 && np.Spec.Ingress[i].From[0].IPBlock != nil {
			rule = &np.Spec.Ingress[i]
		}
	}
	if rule == nil {
		t.Fatal("no ipBlock rule rendered")
	}
	if len(rule.From) != 2 || rule.From[0].IPBlock.CIDR != "192.0.2.77/32" || rule.From[1].IPBlock.CIDR != "198.51.100.0/24" {
		t.Fatalf("ipBlock peers = %+v", rule.From)
	}
	if len(rule.Ports) != 1 || rule.Ports[0].Port.IntVal != 10000 {
		t.Fatalf("ipBlock ports = %+v, want listen port only", rule.Ports)
	}
}

func TestExposeDenied(t *testing.T) {
	expose := &tnv1.EgressExpose{AllowFrom: []tnv1.SourcePrefix{"192.0.2.77/32", "198.51.100.0/24"}}
	cases := []struct {
		name      string
		allowlist []tnv1.GatewayPrefix
		want      string
	}{
		{"empty allowlist denies", nil, "192.0.2.77/32"},
		{"all inside", []tnv1.GatewayPrefix{"192.0.2.0/24", "198.51.100.0/24"}, ""},
		{"one outside", []tnv1.GatewayPrefix{"192.0.2.0/24"}, "198.51.100.0/24"},
		{"wider request than allowlist", []tnv1.GatewayPrefix{"192.0.2.77/32", "198.51.100.0/25"}, "198.51.100.0/24"},
		{"family mismatch", []tnv1.GatewayPrefix{"::/0"}, "192.0.2.77/32"},
	}
	for _, c := range cases {
		if got := exposeDenied(expose, c.allowlist); got != c.want {
			t.Errorf("%s: exposeDenied = %q, want %q", c.name, got, c.want)
		}
	}
}

func TestObserveExposeAddresses(t *testing.T) {
	eg, _, _ := exposeFixture()
	eg.Spec.Targets = append(eg.Spec.Targets, tnv1.Target{Name: "api", Address: "api.prod.tailnet.example.internal", Port: 443})
	owned := func(name string, ingress ...corev1.LoadBalancerIngress) *corev1.Service {
		svc := &corev1.Service{ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: "agents",
			OwnerReferences: []metav1.OwnerReference{{UID: eg.UID, Controller: boolPtr(true)}}}}
		svc.Status.LoadBalancer.Ingress = ingress
		return svc
	}
	r := &TailnetEgressReconciler{Client: transitionClient(t, owned("shop", corev1.LoadBalancerIngress{IP: "192.0.2.200"}), owned("api"))}
	r.observeExpose(context.Background(), eg, "agents")
	if got := condReason(eg.Status.Conditions, "Exposed"); got != "PendingAddress" {
		t.Fatalf("Exposed reason = %s, want PendingAddress while one Service has no address", got)
	}
	if eg.Status.Expose == nil || len(eg.Status.Expose.Addresses) != 1 || eg.Status.Expose.Addresses[0] != "192.0.2.200" {
		t.Fatalf("status.expose = %+v", eg.Status.Expose)
	}

	r = &TailnetEgressReconciler{Client: transitionClient(t, owned("shop", corev1.LoadBalancerIngress{IP: "192.0.2.200"}), owned("api", corev1.LoadBalancerIngress{Hostname: "lb.example.internal"}))}
	r.observeExpose(context.Background(), eg, "agents")
	if !meta.IsStatusConditionTrue(eg.Status.Conditions, "Exposed") || condReason(eg.Status.Conditions, "Exposed") != "AddressAssigned" {
		t.Fatalf("Exposed = %+v, want True/AddressAssigned", meta.FindStatusCondition(eg.Status.Conditions, "Exposed"))
	}
	if len(eg.Status.Expose.Addresses) != 2 {
		t.Fatalf("addresses = %v", eg.Status.Expose.Addresses)
	}
}

// A DNS-named target has no subnet route to wait for: present, Ready hinges on reachability only;
// and a False Exposed blocks Ready.
func TestComputeTargetStatusDNSTargetAndExposed(t *testing.T) {
	r := &TailnetEgressReconciler{}
	eg, _, listen := exposeFixture()
	eg.Status.NodeID = "1"
	r.computeTargetStatus(eg, listen, map[string]bool{}, map[string]bool{}, map[string]bool{}, map[string]bool{"shop": true}, nil)
	ts := eg.Status.Targets[0]
	if ts.Route != "" || !ts.Present || ts.Reason != "" || !ts.Reachable {
		t.Fatalf("DNS target status = %+v, want route-less present reachable", ts)
	}
	if !meta.IsStatusConditionTrue(eg.Status.Conditions, "Ready") {
		t.Fatalf("Ready = %+v", meta.FindStatusCondition(eg.Status.Conditions, "Ready"))
	}
	setCond(&eg.Status.Conditions, eg.Generation, "Exposed", metav1.ConditionFalse, "Denied", "outside allowlist")
	r.computeTargetStatus(eg, listen, map[string]bool{}, map[string]bool{}, map[string]bool{}, map[string]bool{"shop": true}, nil)
	if meta.IsStatusConditionTrue(eg.Status.Conditions, "Ready") || condReason(eg.Status.Conditions, "Ready") != "Denied" {
		t.Fatalf("Ready = %+v, want False/Denied", meta.FindStatusCondition(eg.Status.Conditions, "Ready"))
	}
	// Unreachable DNS target: not a route problem.
	eg.Status.Conditions = nil
	r.computeTargetStatus(eg, listen, map[string]bool{}, map[string]bool{}, map[string]bool{}, map[string]bool{}, nil)
	if condReason(eg.Status.Conditions, "RoutesGranted") != "AllGranted" || condReason(eg.Status.Conditions, "TargetsReachable") != "Unreachable" {
		t.Fatalf("conditions = %+v", eg.Status.Conditions)
	}
}

func boolPtr(b bool) *bool { return &b }
