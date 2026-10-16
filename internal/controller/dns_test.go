package controller

import (
	"context"
	"strings"
	"testing"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	"sigs.k8s.io/controller-runtime/pkg/client"
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

func dnsTailnet() *tnv1.Tailnet {
	tn := &tnv1.Tailnet{ObjectMeta: metav1.ObjectMeta{Name: "corp", UID: "tn-uid"}}
	tn.Spec.DNS.HostsConfigMap = "tailnet-dns-hosts"
	tn.Spec.DNS.IngressNameTemplate = "{name}.{namespace}.prod-1.tailnet.example.internal"
	tn.Spec.DNS.IngressAliasTemplate = "{name}.prod-1.tailnet.example.internal"
	return tn
}

func dnsCollectReconciler(t *testing.T, objs ...client.Object) *TailnetDNSReconciler {
	t.Helper()
	s := runtime.NewScheme()
	_ = clientgoscheme.AddToScheme(s)
	_ = tnv1.AddToScheme(s)
	b := fake.NewClientBuilder().WithScheme(s)
	for _, o := range objs {
		b = b.WithObjects(o).WithStatusSubresource(o)
	}
	return &TailnetDNSReconciler{Client: b.Build(), Scheme: s, OperatorNamespace: "tailnet-system"}
}

// Ingress names publish IPv4 only: an AAAA would be preferred by clients and time out (see collect).
func TestCollectIngressIPv4Only(t *testing.T) {
	tn := dnsTailnet()
	in := &tnv1.TailnetIngress{ObjectMeta: metav1.ObjectMeta{
		Name: "shop", Namespace: "shop-dev", UID: "in-uid", CreationTimestamp: metav1.Now()}}
	in.Spec.TailnetRef = tnv1.TailnetRef{Name: "corp"}
	in.Spec.Exposes = []tnv1.Expose{{Name: "web", Mode: "http", Port: 443, Backend: tnv1.Backend{Service: "shop", Port: 8080}}}
	in.Status.TailnetIPs = []string{"100.64.0.42", "fd7a:115c:a1e0::2a"}
	r := dnsCollectReconciler(t, in)

	got, err := r.collect(context.Background(), tn)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0].IP != "100.64.0.42" || got[0].Name != "shop.shop-dev.prod-1.tailnet.example.internal" {
		t.Fatalf("entries = %+v, want only the IPv4 base name", got)
	}
}

// A multi-HTTP ingress with a labeled expose and an alias publishes every won name to the node IPs.
func TestCollectVirtualHostsAndAliases(t *testing.T) {
	tn := dnsTailnet()
	in := &tnv1.TailnetIngress{ObjectMeta: metav1.ObjectMeta{
		Name: "apps", Namespace: "ns1", UID: "apps-uid", CreationTimestamp: metav1.Now()}}
	in.Spec.TailnetRef = tnv1.TailnetRef{Name: "corp"}
	in.Spec.Exposes = []tnv1.Expose{
		{Name: "web", Mode: "http", Port: 443, Alias: true, Backend: tnv1.Backend{Service: "web", Port: 80}},
		{Name: "graf", Mode: "http", Port: 443, DNSLabel: "grafana", Backend: tnv1.Backend{Service: "graf", Port: 80}},
	}
	in.Status.TailnetIPs = []string{"100.64.0.5"}
	r := dnsCollectReconciler(t, in)

	got, err := r.collect(context.Background(), tn)
	if err != nil {
		t.Fatal(err)
	}
	names := map[string]bool{}
	for _, e := range got {
		if e.IP != "100.64.0.5" {
			t.Fatalf("unexpected IP in %+v", e)
		}
		names[e.Name] = true
	}
	want := []string{"apps.ns1.prod-1.tailnet.example.internal", "grafana.ns1.prod-1.tailnet.example.internal", "apps.prod-1.tailnet.example.internal"}
	for _, n := range want {
		if !names[n] {
			t.Fatalf("missing %q in %+v", n, got)
		}
	}
	if len(names) != len(want) {
		t.Fatalf("entries = %+v, want exactly %v", got, want)
	}
}

// The younger owner of a conflicting alias must not be published; the older one still is.
func TestCollectConflictLoserNotPublished(t *testing.T) {
	tn := dnsTailnet()
	older := &tnv1.TailnetIngress{ObjectMeta: metav1.ObjectMeta{
		Name: "web", Namespace: "a", UID: "older", CreationTimestamp: metav1.NewTime(time.Unix(1000, 0))}}
	older.Spec.TailnetRef = tnv1.TailnetRef{Name: "corp"}
	older.Spec.Exposes = []tnv1.Expose{{Name: "web", Mode: "http", Port: 443, Alias: true, Backend: tnv1.Backend{Service: "web", Port: 80}}}
	older.Status.TailnetIPs = []string{"100.64.0.1"}
	// Different namespace, but the SAME alias web.prod-1.tailnet.example.internal.
	younger := &tnv1.TailnetIngress{ObjectMeta: metav1.ObjectMeta{
		Name: "web", Namespace: "b", UID: "younger", CreationTimestamp: metav1.NewTime(time.Unix(2000, 0))}}
	younger.Spec.TailnetRef = tnv1.TailnetRef{Name: "corp"}
	younger.Spec.Exposes = []tnv1.Expose{{Name: "web", Mode: "http", Port: 443, Alias: true, Backend: tnv1.Backend{Service: "web", Port: 80}}}
	younger.Status.TailnetIPs = []string{"100.64.0.2"}
	r := dnsCollectReconciler(t, older, younger)

	got, err := r.collect(context.Background(), tn)
	if err != nil {
		t.Fatal(err)
	}
	alias := "web.prod-1.tailnet.example.internal"
	var ips []string
	for _, e := range got {
		if e.Name == alias {
			ips = append(ips, e.IP)
		}
	}
	if len(ips) != 1 || ips[0] != "100.64.0.1" {
		t.Fatalf("alias %q resolved to %v, want only the older owner's IP", alias, ips)
	}
}
