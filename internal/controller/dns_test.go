package controller

import (
	"strings"
	"testing"
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
