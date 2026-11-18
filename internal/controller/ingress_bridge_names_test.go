package controller

import (
	"context"
	"reflect"
	"testing"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	tnv1 "tsunaro.io/tailnet-operator/api/v1alpha1"
)

func bridgeIngress(bridges ...string) (*tnv1.TailnetIngress, *tnv1.Tailnet) {
	in, tn := virtualIngress()
	in.Spec.Exposes[2].Alias = true
	in.Spec.Exposes[2].BridgeNames = bridges
	tn.Spec.DNS.IngressAliasTemplate = "{name}.tailnet.invalid"
	tn.Spec.BridgeNameAllowlist = []string{"site.example", "other.example"}
	return in, tn
}

func TestResolveIngressDNSNamesBridge(t *testing.T) {
	in, tn := bridgeIngress("shop.site.example", "api.other.example")
	plan, reason := resolveIngressDNSNames(in, tn)
	if reason != "" {
		t.Fatal(reason)
	}
	want := []string{"app.tenant.tailnet.invalid", "alpha.tailnet.invalid", "alpha.tenant.tailnet.invalid", "api.other.example", "shop.site.example", "zeta.tenant.tailnet.invalid"}
	if !reflect.DeepEqual(plan.certificateNames, want) || !reflect.DeepEqual(plan.bridgeNames, map[string][]string{"second": {"shop.site.example", "api.other.example"}}) {
		t.Fatalf("plan=%+v", plan)
	}
	// Agent wire: bridge names ride alongside the alias and are all covered by the SAN list.
	targets := renderedIngressTargets(t, in, in.Namespace, ingressTLSPlan{http: true, secretName: "frontend", names: plan})
	for _, target := range targets {
		if target.Name != "second" {
			continue
		}
		if !reflect.DeepEqual(target.DNSAliases, []string{"alpha.tailnet.invalid", "shop.site.example", "api.other.example"}) {
			t.Fatalf("target=%+v", target)
		}
	}
	// Bridge names change the resolved config, nothing else about the CR does.
	withoutBridges, _ := bridgeIngress()
	if ingressResolvedSourceDigest(in, tn) == ingressResolvedSourceDigest(withoutBridges, tn) {
		t.Fatal("bridge names must change the resolved source digest")
	}
	if ingressDesiredHTTPConfigDigest(withoutBridges) != ingressDesiredHTTPConfigDigest(func() *tnv1.TailnetIngress {
		i, _ := virtualIngress()
		i.Spec.Exposes[2].Alias = true
		return i
	}()) {
		t.Fatal("an absent bridgeNames field must not change the desired config digest")
	}
}

func TestResolveIngressDNSNamesBridgeDenied(t *testing.T) {
	for _, tt := range []struct {
		name   string
		mutate func(*tnv1.TailnetIngress, *tnv1.Tailnet)
		reason string
	}{
		{"empty-allowlist", func(_ *tnv1.TailnetIngress, tn *tnv1.Tailnet) { tn.Spec.BridgeNameAllowlist = nil }, "BridgeNameDenied"},
		{"zone-itself", func(in *tnv1.TailnetIngress, _ *tnv1.Tailnet) {
			in.Spec.Exposes[2].BridgeNames = []string{"site.example"}
		}, "BridgeNameDenied"},
		{"foreign-zone", func(in *tnv1.TailnetIngress, _ *tnv1.Tailnet) {
			in.Spec.Exposes[2].BridgeNames = []string{"shop.evil.example"}
		}, "BridgeNameDenied"},
		{"suffix-not-label", func(in *tnv1.TailnetIngress, _ *tnv1.Tailnet) {
			in.Spec.Exposes[2].BridgeNames = []string{"shop.notsite.example"}
		}, "BridgeNameDenied"},
		{"tailnet-name-zone", func(in *tnv1.TailnetIngress, tn *tnv1.Tailnet) {
			tn.Spec.BridgeNameAllowlist = append(tn.Spec.BridgeNameAllowlist, "tailnet.invalid")
			in.Spec.Exposes[2].BridgeNames = []string{"foreign.tenant.tailnet.invalid"}
		}, "BridgeNameDenied"},
		{"tailnet-alias-zone", func(in *tnv1.TailnetIngress, tn *tnv1.Tailnet) {
			tn.Spec.BridgeNameAllowlist = append(tn.Spec.BridgeNameAllowlist, "invalid")
			in.Spec.Exposes[2].BridgeNames = []string{"foreign.tailnet.invalid"}
		}, "BridgeNameDenied"},
		{"ip-literal", func(in *tnv1.TailnetIngress, _ *tnv1.Tailnet) {
			in.Spec.Exposes[2].BridgeNames = []string{"192.0.2.10"}
		}, "TLSInvalidDNSName"},
		{"uppercase", func(in *tnv1.TailnetIngress, _ *tnv1.Tailnet) {
			in.Spec.Exposes[2].BridgeNames = []string{"SHOP.site.example"}
		}, "TLSInvalidDNSName"},
		{"duplicate-in-expose", func(in *tnv1.TailnetIngress, _ *tnv1.Tailnet) {
			in.Spec.Exposes[2].BridgeNames = []string{"shop.site.example", "shop.site.example"}
		}, "TLSInvalidDNSName"},
		{"duplicate-across-exposes", func(in *tnv1.TailnetIngress, _ *tnv1.Tailnet) {
			in.Spec.Exposes[0].BridgeNames = []string{"shop.site.example"}
		}, "TLSInvalidDNSName"},
		{"too-many", func(in *tnv1.TailnetIngress, _ *tnv1.Tailnet) {
			in.Spec.Exposes[2].BridgeNames = []string{"a.site.example", "b.site.example", "c.site.example", "d.site.example", "e.site.example"}
		}, "TLSConfigurationInvalid"},
		{"l4-expose", func(in *tnv1.TailnetIngress, _ *tnv1.Tailnet) {
			in.Spec.Exposes = append(in.Spec.Exposes, tnv1.Expose{Name: "tcp", Port: 5432, BridgeNames: []string{"db.site.example"}, Backend: tnv1.Backend{Service: "db", Port: 5432}})
		}, "TLSConfigurationInvalid"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			in, tn := bridgeIngress("shop.site.example")
			tt.mutate(in, tn)
			if plan, reason := resolveIngressDNSNames(in, tn); reason != tt.reason || !reflect.DeepEqual(plan, ingressDNSPlan{}) {
				t.Fatalf("plan=%+v reason=%q; want empty plan, %q", plan, reason, tt.reason)
			}
		})
	}
}

// Bridge names are the site's records, never the operator's: no hosts entry, no claim.
func TestCollectSkipsBridgeNames(t *testing.T) {
	tn := dnsTailnet()
	tn.Spec.BridgeNameAllowlist = []string{"site.example"}
	in := &tnv1.TailnetIngress{ObjectMeta: metav1.ObjectMeta{
		Name: "apps", Namespace: "ns1", UID: "apps-uid", CreationTimestamp: metav1.Now()}}
	in.Spec.TailnetRef = tnv1.TailnetRef{Name: "corp"}
	in.Spec.Exposes = []tnv1.Expose{
		{Name: "web", Mode: "http", Port: 443, Alias: true, BridgeNames: []string{"apps.site.example"}, Backend: tnv1.Backend{Service: "web", Port: 80}},
	}
	in.Status.TailnetIPs = []string{"100.64.0.5"}
	r := dnsCollectReconciler(t, in)
	got, err := r.collect(context.Background(), tn)
	if err != nil {
		t.Fatal(err)
	}
	names := map[string]bool{}
	for _, e := range got {
		names[e.Name] = true
	}
	if names["apps.site.example"] || !names["apps.prod-1.tailnet.example.internal"] || len(names) != 2 {
		t.Fatalf("entries = %+v", got)
	}
	set, reason := desiredIngressDNSClaims(in, tn, "tailscale-system")
	if reason != "" || set == nil {
		t.Fatal(reason)
	}
	for _, c := range set.Claims {
		if c.Name == "apps.site.example" {
			t.Fatalf("bridge name claimed: %+v", set.Claims)
		}
	}
}
