package gateway

import (
	"errors"
	"reflect"
	"slices"
	"strings"
	"testing"
)

func TestRoutesDualStackOrderAndDedup(t *testing.T) {
	in := RouteInputs{
		LAN:                    []string{"fd12::/64", "10.0.0.0/8", "10.0.0.0/24", "10.0.0.0/8"},
		LoadBalancerCIDR:       "10.96.0.0/16",
		AdvertiseEgressTargets: true,
		EgressTargets:          []string{"fd12::2", "10.0.0.2", "::ffff:10.0.0.2", "2001:DB8:0::1", "10.0.0.0"},
	}
	want := []string{"10.0.0.0/8", "10.0.0.0/24", "10.0.0.0/32", "10.0.0.2/32", "10.96.0.0/16", "2001:db8::1/128", "fd12::/64", "fd12::2/128"}
	for range 3 {
		plan, err := PlanRoutes(in)
		if err != nil || !slices.Equal(plan.Routes, want) || len(plan.SkippedDNS) != 0 {
			t.Fatalf("PlanRoutes = %+v, %v; want %v", plan, err, want)
		}
		slices.Reverse(in.LAN)
		slices.Reverse(in.EgressTargets)
	}
}

func TestRoutesLBSurvivesToggles(t *testing.T) {
	for _, enabled := range []bool{false, true} {
		for _, targets := range [][]string{nil, {}, {"db.example"}, {"192.0.2.1"}} {
			in := RouteInputs{LAN: []string{"10.0.0.0/8"}, LoadBalancerCIDR: "fd12::/64", AdvertiseEgressTargets: enabled, EgressTargets: targets}
			plan, err := PlanRoutes(in)
			if err != nil || !slices.Contains(plan.Routes, "fd12::/64") {
				t.Fatalf("enabled=%v targets=%v: %+v, %v", enabled, targets, plan, err)
			}
			if !enabled && (len(plan.Routes) != 2 || len(plan.SkippedDNS) != 0) {
				t.Fatalf("disabled automatic routes: %+v", plan)
			}
		}
	}
	in := RouteInputs{LAN: []string{"10.0.0.0/8"}, LoadBalancerCIDR: "10.0.0.0/8", EgressTargets: []string{"invalid/ignored", "::1", ""}}
	plan, err := PlanRoutes(in)
	if err != nil || !slices.Equal(plan.Routes, []string{"10.0.0.0/8"}) {
		t.Fatalf("ignored targets / identical LB: %+v, %v", plan, err)
	}
	// No built-in CGNAT/Tailscale exclusion; custom Headscale deployments decide.
	in.LAN, in.LoadBalancerCIDR = []string{"100.64.0.0/10"}, "fd7a:115c:a1e0::/48"
	if _, err := PlanRoutes(in); err != nil {
		t.Fatal(err)
	}
}

func TestRoutesDNSSkipped(t *testing.T) {
	in := RouteInputs{
		LAN: []string{"10.0.0.0/8"}, LoadBalancerCIDR: "192.0.2.0/24", AdvertiseEgressTargets: true,
		EgressTargets: []string{"z.example", "a.example", "z.example", "db", "123.example", "xn--bcher-kva.example", "db.123", "0x7f000001", "0x7f.0.0.1", "1.2.3.0x4"},
	}
	plan, err := PlanRoutes(in)
	// These are valid DNS strings in Target.address. They must never become
	// routes through legacy numeric-address interpretation or DNS resolution.
	want := []string{"0x7f.0.0.1", "0x7f000001", "1.2.3.0x4", "123.example", "a.example", "db", "db.123", "xn--bcher-kva.example", "z.example"}
	if err != nil || !slices.Equal(plan.SkippedDNS, want) || len(plan.Routes) != 2 {
		t.Fatalf("PlanRoutes = %+v, %v", plan, err)
	}
}

func TestRoutesInvalidPrefixes(t *testing.T) {
	bad := []string{
		"", "sensitive-value", "10.1.2.3", "10.0.0.1/24", "fd12::1/64",
		"FD12::/64", "fd12:0:0:0::/64", "10.0.0.0/08", "010.0.0.0/8", "10.0.0.0/33", "fd12::/129",
		" 10.0.0.0/8", "10.0.0.0/8 ", "fe80::%secret-zone/64", "::ffff:192.0.2.0/120",
		"::ffff:c000:200/120", "0.0.0.0/0", "::/0", "0.0.0.0/32", "0.0.0.0/8", "::/128",
		"127.0.0.1/32", "127.0.0.0/8", "126.0.0.0/7", "::1/128", "::/127",
		"224.0.0.1/32", "224.0.0.0/4", "192.0.0.0/2", "ff02::/16", "ff00::/8", "fe00::/7",
	}
	for _, value := range bad {
		for _, field := range []string{"LAN[1]", "LoadBalancerCIDR"} {
			t.Run(field+"/"+value, func(t *testing.T) {
				in := RouteInputs{LAN: []string{"10.0.0.0/8"}, LoadBalancerCIDR: "192.0.2.0/24"}
				if field == "LAN[1]" {
					in.LAN = append(in.LAN, value)
				} else {
					in.LoadBalancerCIDR = value
				}
				plan, err := PlanRoutes(in)
				if !errors.Is(err, ErrInvalidRoutes) || !reflect.DeepEqual(plan, RoutePlan{}) {
					t.Fatalf("expected redacted error and zero plan: %+v, %v", plan, err)
				}
				if want := "invalid gateway routes: " + field; err.Error() != want {
					t.Fatalf("error = %q, want %q", err, want)
				}
			})
		}
	}
	if plan, err := PlanRoutes(RouteInputs{LoadBalancerCIDR: "10.0.0.0/8"}); !errors.Is(err, ErrInvalidRoutes) || !reflect.DeepEqual(plan, RoutePlan{}) {
		t.Fatalf("missing LAN: %+v, %v", plan, err)
	}
	// Nearby non-reserved ranges remain valid; explicit link-local is caller policy.
	for _, value := range []string{"0.0.0.1/32", "126.0.0.0/8", "128.0.0.0/8", "223.0.0.0/8", "::2/127", "fe00::/8", "169.254.0.0/16", "fe80::/64"} {
		if _, err := PlanRoutes(RouteInputs{LAN: []string{value}, LoadBalancerCIDR: "192.0.2.0/24"}); err != nil {
			t.Errorf("valid prefix %s: %v", value, err)
		}
	}
}

func TestRoutesInvalidTargets(t *testing.T) {
	bad := []string{
		"", "127.0.0.1", "127.9.8.7", "::1", "0.0.0.0", "::", "224.0.0.1", "ff02::1",
		"169.254.1.2", "fe80::1", "fd12::1%secret-zone", "fe80::1%eth0", "255.255.255.255",
		"::ffff:127.0.0.1", "::ffff:0.0.0.0", "::ffff:224.0.0.1", "::ffff:169.254.1.2", "::ffff:192.0.2.1%eth0",
		"999.1.2.3", "192.168.1", "012.0.0.1", "2130706433",
		"1.2.3.4.5", "2001:db8:::1", "https://secret.example/path", "192.0.2.0/24",
		"host:443", "192.0.2.1:443", "[2001:db8::1]:443", "[2001:db8::1]", "user@host",
		"Upper.example", "a..b", "-a.example", "a-.example", "a_b.example", "*.example", "bücher.example", "host.example.",
		" host.example", "host.example\n", strings.Repeat("a", 64) + ".example", strings.Repeat("a.", 127) + "a",
	}
	for _, value := range bad {
		t.Run(value, func(t *testing.T) {
			in := RouteInputs{LAN: []string{"10.0.0.0/8"}, LoadBalancerCIDR: "192.0.2.0/24", AdvertiseEgressTargets: true, EgressTargets: []string{"valid.example", "192.0.2.1", value}}
			plan, err := PlanRoutes(in)
			if !errors.Is(err, ErrInvalidRoutes) || !reflect.DeepEqual(plan, RoutePlan{}) {
				t.Fatalf("expected error and zero plan: %+v, %v", plan, err)
			}
			if err.Error() != "invalid gateway routes: EgressTargets[2]" {
				t.Fatalf("error leaks input: %v", err)
			}
		})
	}
}

func TestRoutesNoMutation(t *testing.T) {
	in := RouteInputs{LAN: []string{"fd12::/64", "10.0.0.0/8"}, LoadBalancerCIDR: "192.0.2.0/24", AdvertiseEgressTargets: true, EgressTargets: []string{"z.example", "a.example", "10.0.0.1"}}
	before := in
	before.LAN, before.EgressTargets = slices.Clone(in.LAN), slices.Clone(in.EgressTargets)
	plan, err := PlanRoutes(in)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(in, before) {
		t.Fatal("input mutated")
	}
	plan.Routes[0], plan.SkippedDNS[0] = "changed", "changed"
	if !reflect.DeepEqual(in, before) {
		t.Fatal("output aliases input")
	}
	in.EgressTargets = append(in.EgressTargets, "invalid/target")
	before.EgressTargets = slices.Clone(in.EgressTargets)
	if _, err := PlanRoutes(in); err == nil || !reflect.DeepEqual(in, before) {
		t.Fatal("error path accepted invalid target or mutated input")
	}
}
