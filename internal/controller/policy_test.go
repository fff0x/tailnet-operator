package controller

import (
	"context"
	"slices"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	"k8s.io/utils/ptr"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	tnv1 "tsunaro.io/tailnet-operator/api/v1alpha1"
)

// collect must see egress CRs of the operator namespace and ingress CRs of any namespace, only those
// bound to the Tailnet, with tags resolved exactly like the egress/ingress reconcilers do, and must
// skip name-addressed targets (no route to grant).
func TestPolicyCollect(t *testing.T) {
	s := runtime.NewScheme()
	_ = clientgoscheme.AddToScheme(s)
	_ = tnv1.AddToScheme(s)
	tn := &tnv1.Tailnet{
		ObjectMeta: metav1.ObjectMeta{Name: "corp"},
		Spec: tnv1.TailnetSpec{TagTemplate: "tag:egress-{name}", IngressTagTemplate: "tag:ingress-{name}",
			Policy: tnv1.PolicySpec{BaseConfigMap: "policy", TagOwners: []string{"group:operator"}, RouteApprovers: []string{"tag:fabric"}}},
	}
	ref := tnv1.TailnetRef{Name: "corp"}
	objs := []runtime.Object{
		&tnv1.TailnetEgress{ObjectMeta: metav1.ObjectMeta{Name: "billing-dev", Namespace: "tailnet-system"},
			Spec: tnv1.TailnetEgressSpec{TailnetRef: ref, Targets: []tnv1.Target{
				{Name: "db-1", Address: "10.0.10.20", Port: 1521},
				{Name: "db-2", Address: "10.0.10.21", Port: 1521},
				{Name: "by-name", Address: "db.magic.example", Port: 5432},
			}}},
		&tnv1.TailnetEgress{ObjectMeta: metav1.ObjectMeta{Name: "explicit", Namespace: "tailnet-system"},
			Spec: tnv1.TailnetEgressSpec{TailnetRef: ref, Tag: "tag:ns-explicit", Targets: []tnv1.Target{{Name: "x", Address: "fd00::1", Port: 80}}}},
		&tnv1.TailnetEgress{ObjectMeta: metav1.ObjectMeta{Name: "other-tailnet", Namespace: "tailnet-system"},
			Spec: tnv1.TailnetEgressSpec{TailnetRef: tnv1.TailnetRef{Name: "lab"}, Targets: []tnv1.Target{{Name: "y", Address: "10.9.9.9", Port: 1}}}},
		&tnv1.TailnetEgress{ObjectMeta: metav1.ObjectMeta{Name: "wrong-ns", Namespace: "tenant"},
			Spec: tnv1.TailnetEgressSpec{TailnetRef: ref, Targets: []tnv1.Target{{Name: "z", Address: "10.8.8.8", Port: 1}}}},
		&tnv1.TailnetIngress{ObjectMeta: metav1.ObjectMeta{Name: "shop", Namespace: "shop-dev"},
			Spec: tnv1.TailnetIngressSpec{TailnetRef: ref, AllowFrom: []string{"group:shop"},
				Exposes: []tnv1.Expose{{Name: "https", Port: 443}, {Name: "pg", Port: 5432}}}},
		&corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Name: "policy", Namespace: "tailnet-system"}},
		gatewayFixture("site", "corp", "10.0.0.0/24", "198.51.100.0/24", nil),
		gatewayFixture("noadv", "corp", "10.1.0.0/24", "198.51.100.0/24", ptr.To(false)),
		gatewayFixture("foreign", "lab", "10.2.0.0/24", "198.51.100.0/24", nil),
		gatewayFixture("broken", "corp", "not-a-cidr", "198.51.100.0/24", nil),
	}
	r := &TailnetPolicyReconciler{Client: fake.NewClientBuilder().WithScheme(s).WithRuntimeObjects(objs...).Build(), Scheme: s, OperatorNamespace: "tailnet-system"}

	in, skipped, _, err := r.collect(context.Background(), tn)
	if err != nil {
		t.Fatal(err)
	}
	if len(in.Egresses) != 2 || in.Egresses[0].Tag != "tag:egress-billing-dev" || in.Egresses[1].Tag != "tag:ns-explicit" {
		t.Fatalf("egresses = %+v", in.Egresses)
	}
	if got := in.Egresses[0].Targets; len(got) != 2 || got[0].CIDR != "10.0.10.20/32" || got[1].Port != 1521 {
		t.Fatalf("billing targets = %+v", got)
	}
	if got := in.Egresses[1].Targets; len(got) != 1 || got[0].CIDR != "fd00::1/128" {
		t.Fatalf("v6 target = %+v", got)
	}
	if len(skipped) != 2 || skipped[0] != "billing-dev/by-name" {
		t.Fatalf("skipped = %v", skipped)
	}
	if len(in.Ingresses) != 1 || in.Ingresses[0].Tag != "tag:ingress-shop" || len(in.Ingresses[0].Ports) != 2 || in.Ingresses[0].AllowFrom[0] != "group:shop" {
		t.Fatalf("ingresses = %+v", in.Ingresses)
	}
	// Gateways: only this Tailnet's, routes exactly as RenderFresh plans them (LAN + LB CIDR + the
	// egress /32 and /128 targets unless advertiseEgressTargets is off; DNS names are skipped).
	if len(in.Gateways) != 2 || len(skipped) != 2 || skipped[1] != "gateway/broken" {
		t.Fatalf("gateways = %+v, skipped = %v", in.Gateways, skipped)
	}
	want := []string{"10.0.0.0/24", "10.0.10.20/32", "10.0.10.21/32", "198.51.100.0/24", "fd00::1/128"}
	if got := in.Gateways[1].Routes; !slices.Equal(got, want) || !slices.Equal(in.Gateways[1].Tags, []string{"tag:site"}) {
		t.Fatalf("site gateway = %+v", in.Gateways[1])
	}
	if got := in.Gateways[0].Routes; !slices.Equal(got, []string{"10.1.0.0/24", "198.51.100.0/24"}) {
		t.Fatalf("noadv gateway advertised egress targets: %v", got)
	}
	if in.TagOwners[0] != "group:operator" || in.RouteApprovers[0] != "tag:fabric" {
		t.Fatalf("spec passthrough = %+v", in)
	}
}

func gatewayFixture(name, tailnet, lan, lb string, advertise *bool) *tnv1.TailnetGateway {
	return &tnv1.TailnetGateway{ObjectMeta: metav1.ObjectMeta{Name: name}, Spec: tnv1.TailnetGatewaySpec{
		TailnetRef: tnv1.GatewayLocalReference{Name: tnv1.GatewayName(tailnet)}, Tags: []string{"tag:" + name},
		Routes:  tnv1.GatewayRoutes{LAN: []tnv1.GatewayPrefix{tnv1.GatewayPrefix(lan)}, AdvertiseEgressTargets: advertise},
		Service: tnv1.GatewayService{TailnetLBCIDR: tnv1.GatewayPrefix(lb)}}}
}

func TestPolicyOwned(t *testing.T) {
	tn := &tnv1.Tailnet{}
	if policyOwned(tn) {
		t.Fatal("off must not be owned")
	}
	tn.Spec.Policy = tnv1.PolicySpec{BaseConfigMap: "p", Mode: "DryRun"}
	if policyOwned(tn) {
		t.Fatal("DryRun must not be owned")
	}
	tn.Spec.Policy.Mode = "Apply"
	if !policyOwned(tn) {
		t.Fatal("Apply must be owned")
	}
}

// A failed write is retried at 15s doubling up to the caller's limit: 1 min for a rejected policy
// (the blocker clears on the Headscale side without a Kubernetes event), the regular 5-min cadence
// for transport failures. Success resets the backoff and each Tailnet counts on its own.
func TestPolicyRetryBackoff(t *testing.T) {
	r := &TailnetPolicyReconciler{}
	want := []time.Duration{15 * time.Second, 30 * time.Second, time.Minute, 2 * time.Minute, 4 * time.Minute, policyRequeue, policyRequeue}
	for i, w := range want {
		if got := r.retryAfter("a", policyRequeue); got != w {
			t.Fatalf("attempt %d: got %s, want %s", i, got, w)
		}
	}
	if got := r.retryAfter("b", policyRequeue); got != policyRetry {
		t.Fatalf("other tailnet: got %s, want %s", got, policyRetry)
	}
	r.clearRetry("a")
	if got := r.retryAfter("a", policyRequeue); got != policyRetry {
		t.Fatalf("after clear: got %s, want %s", got, policyRetry)
	}
	r.clearRetry("a")
	for i, w := range []time.Duration{15 * time.Second, 30 * time.Second, time.Minute, time.Minute, time.Minute} {
		if got := r.retryAfter("a", policyRejectedMax); got != w {
			t.Fatalf("rejected attempt %d: got %s, want %s", i, got, w)
		}
	}
}
