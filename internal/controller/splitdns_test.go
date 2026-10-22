package controller

import (
	"context"
	"strings"
	"testing"

	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	tnv1 "tsunaro.io/tailnet-operator/api/v1alpha1"
)

func TestEvaluateSplitDNS(t *testing.T) {
	want := []string{"10.0.0.17"}
	for _, tc := range []struct {
		name   string
		zone   string
		routes map[string][]string
		status metav1.ConditionStatus
		reason string
	}{
		{"configured", "prod-1.tailnet.example", map[string][]string{"prod-1.tailnet.example": {"10.0.0.17"}}, metav1.ConditionTrue, "Configured"},
		{"trailing dot and case", "Prod-1.Tailnet.Example.", map[string][]string{"prod-1.tailnet.example": {"10.0.0.17"}}, metav1.ConditionTrue, "Configured"},
		{"missing", "prod-1.tailnet.example", map[string][]string{"other.example": {"10.0.0.17"}}, metav1.ConditionFalse, "Missing"},
		{"mismatch", "prod-1.tailnet.example", map[string][]string{"prod-1.tailnet.example": {"10.0.0.99"}}, metav1.ConditionFalse, "Mismatch"},
		{"extra resolver", "prod-1.tailnet.example", map[string][]string{"prod-1.tailnet.example": {"10.0.0.17", "10.0.0.99"}}, metav1.ConditionFalse, "Mismatch"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			status, reason, msg := evaluateSplitDNS(tc.zone, want, tc.routes)
			if status != tc.status || reason != tc.reason || !strings.Contains(msg, "dns.nameservers.split.prod-1.tailnet.example") {
				t.Fatalf("got %s/%s %q", status, reason, msg)
			}
		})
	}
}

func TestSplitDNSConditionWithoutGatewayOrAgent(t *testing.T) {
	s := runtime.NewScheme()
	_ = tnv1.AddToScheme(s)
	tn := &tnv1.Tailnet{ObjectMeta: metav1.ObjectMeta{Name: "corp", Generation: 3}, Spec: tnv1.TailnetSpec{
		DNS: tnv1.DNSSpec{IngressNameTemplate: "{name}-{namespace}.prod-1.tailnet.example"},
	}}
	c := fake.NewClientBuilder().WithScheme(s).Build()
	if splitDNSCondition(context.Background(), c, tn) {
		t.Fatal("no gateway must not be True")
	}
	dns := meta.FindStatusCondition(tn.Status.Conditions, "SplitDNS")
	if dns == nil || dns.Status != metav1.ConditionUnknown || dns.Reason != "CannotVerify" || dns.ObservedGeneration != 3 ||
		!strings.Contains(dns.Message, "no TailnetGateway") || !strings.Contains(dns.Message, "dns.nameservers.split.prod-1.tailnet.example") {
		t.Fatalf("SplitDNS=%+v", dns)
	}

	// A bound gateway but no running agent: still Unknown, now naming the expected address.
	gw := &tnv1.TailnetGateway{ObjectMeta: metav1.ObjectMeta{Name: "gw", Namespace: "tailscale-system"}, Spec: tnv1.TailnetGatewaySpec{
		TailnetRef: tnv1.GatewayLocalReference{Name: "corp"},
		Service:    tnv1.GatewayService{LoadBalancerIP: "10.0.0.17"},
	}}
	c = fake.NewClientBuilder().WithScheme(s).WithObjects(gw).Build()
	if splitDNSCondition(context.Background(), c, tn) {
		t.Fatal("no agent must not be True")
	}
	dns = meta.FindStatusCondition(tn.Status.Conditions, "SplitDNS")
	if dns == nil || dns.Reason != "CannotVerify" || !strings.Contains(dns.Message, "no online agent") || !strings.Contains(dns.Message, "10.0.0.17") {
		t.Fatalf("SplitDNS=%+v", dns)
	}

	// Turning DNS off removes the condition.
	tn.Spec.DNS.IngressNameTemplate = ""
	if !splitDNSCondition(context.Background(), c, tn) || meta.FindStatusCondition(tn.Status.Conditions, "SplitDNS") != nil {
		t.Fatal("stale SplitDNS condition survived DNS removal")
	}
}
