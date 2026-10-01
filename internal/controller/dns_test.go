package controller

import (
	"context"
	"strings"
	"testing"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	tnv1 "tsunaro.io/tailnet-operator/api/v1alpha1"
)

// renderHosts must be deterministic (sorted), keep both address families of one source, drop a
// name a second source also claims (first source wins), and reduce to the header when empty.
func TestRenderHosts(t *testing.T) {
	var warned []string
	warn := func(msg string, kv ...any) { warned = append(warned, msg) }

	got := renderHosts("corp", []hostEntry{
		{Name: "shop-webshop.prod-1.tailnet.example.internal", IP: "fd7a::1", Source: "tailnetingress/webshop/shop"},
		{Name: "api.corp.example", IP: "10.43.0.9", Source: "tailnetegress/tailscale-system/billing-dev"},
		{Name: "shop-webshop.prod-1.tailnet.example.internal", IP: "100.64.0.42", Source: "tailnetingress/webshop/shop"},
		{Name: "api.corp.example", IP: "10.43.0.77", Source: "tailnetegress/tailscale-system/zzz"}, // loser
	}, warn)

	want := "# managed by tailnet-operator (Tailnet corp) — do not edit\n" +
		"10.43.0.9\tapi.corp.example\n" +
		"100.64.0.42\tshop-webshop.prod-1.tailnet.example.internal\n" +
		"fd7a::1\tshop-webshop.prod-1.tailnet.example.internal\n"
	if got != want {
		t.Fatalf("hosts =\n%s\nwant\n%s", got, want)
	}
	if len(warned) != 1 {
		t.Fatalf("want 1 duplicate warning, got %d", len(warned))
	}

	empty := renderHosts("corp", nil, warn)
	if strings.Count(empty, "\n") != 1 || !strings.HasPrefix(empty, "# managed by") {
		t.Fatalf("empty render = %q", empty)
	}
}

// Ingress names publish IPv4 only: an AAAA would be preferred by clients and time out (see collect).
func TestCollectIngressIPv4Only(t *testing.T) {
	s := runtime.NewScheme()
	_ = clientgoscheme.AddToScheme(s)
	_ = tnv1.AddToScheme(s)
	in := &tnv1.TailnetIngress{ObjectMeta: metav1.ObjectMeta{Name: "shop", Namespace: "shop-dev"},
		Spec: tnv1.TailnetIngressSpec{TailnetRef: tnv1.TailnetRef{Name: "corp"}}}
	in.Status.DNSName = "shop-shop-dev.prod-1.tailnet.example.internal"
	in.Status.TailnetIPs = []string{"100.64.0.42", "fd7a:115c:a1e0::2a"}
	r := &TailnetDNSReconciler{Client: fake.NewClientBuilder().WithScheme(s).WithRuntimeObjects(in).WithStatusSubresource(in).Build(), Scheme: s, OperatorNamespace: "tailnet-system"}

	got, err := r.collect(context.Background(), "corp")
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0].IP != "100.64.0.42" {
		t.Fatalf("entries = %+v, want only the IPv4 one", got)
	}
}
