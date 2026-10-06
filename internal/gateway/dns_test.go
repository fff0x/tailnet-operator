package gateway

import (
	"errors"
	"fmt"
	"net/netip"
	"reflect"
	"strings"
	"testing"

	tnv1 "tsunaro.io/tailnet-operator/api/v1alpha1"
)

func dnsFixture() DNSInputs {
	return DNSInputs{
		Config: tnv1.GatewayDNS{Zone: "tail.example",
			StaticRecords:   []tnv1.GatewayStaticRecord{{Name: "api", Address: "192.0.2.10"}, {Name: "v6", Address: "2001:db8::10"}},
			WildcardAddress: "192.0.2.80",
		},
		ServerIP: "192.0.2.1", Serial: 7, BindAddresses: []netip.Addr{netip.IPv4Unspecified(), netip.IPv6Unspecified()},
	}
}

func TestRenderDNS(t *testing.T) {
	in := dnsFixture()
	before := in.Config.DeepCopy()
	got, err := RenderDNS(in)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(before, &in.Config) {
		t.Fatal("renderer modified input")
	}
	for _, want := range []string{"bind 0.0.0.0 ::", "file zone.db tail.example", "reload 1s", "prometheus :9153", "\n    reload\n"} {
		if !strings.Contains(got.Corefile, want) {
			t.Fatalf("missing directive %s", want)
		}
	}
	for _, forbidden := range []string{"template", "hosts ", "forward", "resolv.conf", "$ORIGIN", "$TTL"} {
		if strings.Contains(got.Corefile+got.ZoneFile, forbidden) {
			t.Fatal("unsafe or externally expanded directive")
		}
	}
	for _, want := range []string{"tail.example. 30 IN SOA tail.example. hostmaster.invalid. 7 ", "tail.example. 30 IN A 192.0.2.1", "api.tail.example. 30 IN A 192.0.2.10", "v6.tail.example. 30 IN AAAA 2001:db8::10", "*.tail.example. 30 IN A 192.0.2.80"} {
		if !strings.Contains(got.ZoneFile, want) {
			t.Fatal("missing zone record")
		}
	}
	in.Config.StaticRecords[0], in.Config.StaticRecords[1] = in.Config.StaticRecords[1], in.Config.StaticRecords[0]
	in.BindAddresses[0], in.BindAddresses[1] = in.BindAddresses[1], in.BindAddresses[0]
	again, err := RenderDNS(in)
	if err != nil || again != got {
		t.Fatal("set order changed rendering")
	}
	in.Config.WildcardAddress = ""
	in.ServerIP = "2001:db8::1"
	in.Serial++
	without, err := RenderDNS(in)
	if err != nil || strings.Contains(without.ZoneFile, "*.") || !strings.Contains(without.ZoneFile, "tail.example. 30 IN AAAA 2001:db8::1") || !strings.Contains(without.ZoneFile, "hostmaster.invalid. 8 ") {
		t.Fatal("IPv6 apex or optional wildcard failed")
	}
}

func TestRenderDNSCNAME(t *testing.T) {
	in := dnsFixture()
	in.Config.StaticRecords = []tnv1.GatewayStaticRecord{
		{Name: "api", Address: "192.0.2.10"},
		{Name: "k8s", Target: "ingress.tail.example"},               // bare label resolved from hosts
		{Name: "talos", Target: "ingress-talos.other.tail.example"}, // nested in-zone FQDN
		{Name: "apex", Target: "tail.example"},                      // target equals the zone apex
	}
	in.Hosts = "192.0.2.42 ingress.tail.example\n"
	got, err := RenderDNS(in)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"api.tail.example. 30 IN A 192.0.2.10",
		"k8s.tail.example. 30 IN CNAME ingress.tail.example.",
		"talos.tail.example. 30 IN CNAME ingress-talos.other.tail.example.",
		"apex.tail.example. 30 IN CNAME tail.example.",
		"ingress.tail.example. 30 IN A 192.0.2.42",
	} {
		if !strings.Contains(got.ZoneFile, want) {
			t.Fatalf("missing record %q", want)
		}
	}
	// A hosts record for the same name shadows the configured CNAME.
	with := in
	with.Hosts = "192.0.2.42 ingress.tail.example\n203.0.113.5 k8s.tail.example\n"
	shadowed, err := RenderDNS(with)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(shadowed.ZoneFile, "k8s.tail.example. 30 IN CNAME") {
		t.Fatal("hosts A did not shadow configured CNAME")
	}
	if !strings.Contains(shadowed.ZoneFile, "k8s.tail.example. 30 IN A 203.0.113.5") {
		t.Fatal("hosts A missing after shadowing")
	}
}

func TestRenderDNSCNAMERejectsOutOfZone(t *testing.T) {
	for name, change := range map[string]func(*tnv1.GatewayStaticRecord){
		"out of zone":   func(r *tnv1.GatewayStaticRecord) { r.Target = "ingress.other.example" },
		"empty target":  func(r *tnv1.GatewayStaticRecord) { r.Target = "" },
		"both set":      func(r *tnv1.GatewayStaticRecord) { r.Target, r.Address = "ingress.tail.example", "192.0.2.1" },
		"self loop":     func(r *tnv1.GatewayStaticRecord) { r.Target = "x.tail.example" },
		"invalid label": func(r *tnv1.GatewayStaticRecord) { r.Target = "a..tail.example" },
	} {
		t.Run(name, func(t *testing.T) {
			in := dnsFixture()
			in.Config.StaticRecords = []tnv1.GatewayStaticRecord{{Name: "x"}}
			change(&in.Config.StaticRecords[0])
			if got, err := RenderDNS(in); !errors.Is(err, ErrDNSConfiguration) || got != (DNSPlan{}) {
				t.Fatal("unsafe CNAME was accepted")
			}
		})
	}
}

func TestRenderDNSHostsSnapshot(t *testing.T) {
	in := dnsFixture()
	in.Hosts = "# source snapshot\n192.0.2.7 v6.tail.example alias.tail.example # comment\n2001:db8::7 alias.tail.example\n192.0.2.7 alias.tail.example\n192.0.2.8 outside.example\n"
	got, err := RenderDNS(in)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"v6.tail.example. 30 IN A 192.0.2.7", "alias.tail.example. 30 IN A 192.0.2.7", "alias.tail.example. 30 IN AAAA 2001:db8::7"} {
		if strings.Count(got.ZoneFile, want) != 1 {
			t.Fatal("dynamic records were not merged and deduplicated")
		}
	}
	if strings.Contains(got.ZoneFile, "2001:db8::10") || strings.Contains(got.ZoneFile, "outside.example") {
		t.Fatal("static family leaked or an unserved zone was included")
	}
	in.Hosts = "2001:db8::7 alias.tail.example\n192.0.2.7 alias.tail.example v6.tail.example\n"
	again, err := RenderDNS(in)
	if err != nil || again != got {
		t.Fatal("hosts order, comments or duplicates changed rendering")
	}
}

func TestRenderDNSRejectsUnsafeInput(t *testing.T) {
	for name, change := range map[string]func(*DNSInputs){
		"empty zone":         func(i *DNSInputs) { i.Config.Zone = "" },
		"corefile injection": func(i *DNSInputs) { i.Config.Zone = "x\n}\n.:53 { forward . private.invalid" },
		"empty label":        func(i *DNSInputs) { i.Config.Zone = "x..example" },
		"long label":         func(i *DNSInputs) { i.Config.Zone = tnv1.GatewayName(strings.Repeat("x", 64) + ".example") },
		"mapped server":      func(i *DNSInputs) { i.ServerIP = "::ffff:192.0.2.1" },
		"loopback server":    func(i *DNSInputs) { i.ServerIP = "127.0.0.1" },
		"serial zero":        func(i *DNSInputs) { i.Serial = 0 },
		"implicit bind":      func(i *DNSInputs) { i.BindAddresses = nil },
		"invalid bind":       func(i *DNSInputs) { i.BindAddresses = []netip.Addr{{}} },
		"multicast bind":     func(i *DNSInputs) { i.BindAddresses = []netip.Addr{netip.MustParseAddr("ff02::1")} },
		"zoned bind":         func(i *DNSInputs) { i.BindAddresses = []netip.Addr{netip.MustParseAddr("fe80::1%eth0")} },
		"record injection":   func(i *DNSInputs) { i.Config.StaticRecords[0].Name = "bad\n*.example." },
		"duplicate record":   func(i *DNSInputs) { i.Config.StaticRecords = append(i.Config.StaticRecords, i.Config.StaticRecords[0]) },
		"address injection":  func(i *DNSInputs) { i.Config.StaticRecords[0].Address = "192.0.2.1\n*.example. IN A 192.0.2.2" },
		"invalid wildcard":   func(i *DNSInputs) { i.Config.WildcardAddress = "invalid" },
		"hosts apex":         func(i *DNSInputs) { i.Hosts = "192.0.2.5 tail.example" },
		"hosts missing name": func(i *DNSInputs) { i.Hosts = "192.0.2.5" },
		"hosts bad address":  func(i *DNSInputs) { i.Hosts = "not-an-address app.tail.example" },
		"hosts bad owner":    func(i *DNSInputs) { i.Hosts = "192.0.2.5 *.tail.example" },
		"hosts oversize":     func(i *DNSInputs) { i.Hosts = strings.Repeat("#", maxDNSHostsBytes+1) },
		"too many names": func(i *DNSInputs) {
			var b strings.Builder
			for n := 0; n <= maxDNSHostNames; n++ {
				fmt.Fprintf(&b, "192.0.2.1 h%d.tail.example\n", n)
			}
			i.Hosts = b.String()
		},
	} {
		t.Run(name, func(t *testing.T) {
			in := dnsFixture()
			change(&in)
			got, err := RenderDNS(in)
			if !errors.Is(err, ErrDNSConfiguration) || err.Error() != ErrDNSConfiguration.Error() || got != (DNSPlan{}) {
				t.Fatal("unsafe input did not return a redacted error and empty plan")
			}
		})
	}
}

func TestRenderDNSForwardingIsBlocked(t *testing.T) {
	for _, name := range []tnv1.GatewayName{"site.example", "injected\nprivate-value"} {
		in := dnsFixture()
		in.Config.ExtraZones = []tnv1.GatewayExtraZone{{Zone: name, Upstreams: []tnv1.GatewayIP{"192.0.2.53"}}}
		got, err := RenderDNS(in)
		if !errors.Is(err, ErrDNSForwardingUnsupported) || err.Error() != ErrDNSForwardingUnsupported.Error() || got != (DNSPlan{}) {
			t.Fatal("forwarding was not rejected without partial output")
		}
	}
}

func TestRenderDNSConfigMapSizeLimit(t *testing.T) {
	in := dnsFixture()
	var hosts strings.Builder
	for n := 0; n < 16000; n++ {
		fmt.Fprintf(&hosts, "192.0.2.1 h%05d-%s.tail.example\n", n, strings.Repeat("x", 30))
	}
	in.Hosts = hosts.String()
	if len(in.Hosts) > maxDNSHostsBytes {
		t.Fatal("fixture exceeds the input limit")
	}
	got, err := RenderDNS(in)
	if !errors.Is(err, ErrDNSConfiguration) || got != (DNSPlan{}) {
		t.Fatal("oversized ConfigMap output was accepted")
	}
}

func TestRenderDNSWireLimits(t *testing.T) {
	in := dnsFixture()
	in.Config.StaticRecords, in.Config.WildcardAddress = nil, ""
	in.Config.Zone = tnv1.GatewayName(strings.Repeat("a", 63) + "." + strings.Repeat("b", 63) + "." + strings.Repeat("c", 63) + "." + strings.Repeat("d", 61))
	if len(in.Config.Zone) != 253 {
		t.Fatal("invalid test fixture")
	}
	if _, err := RenderDNS(in); err != nil {
		t.Fatal("maximum zone rejected")
	}
	in.Config.WildcardAddress = "192.0.2.80"
	if _, err := RenderDNS(in); err == nil {
		t.Fatal("oversized wildcard owner accepted")
	}
	in.Config.WildcardAddress = ""
	in.Config.StaticRecords = []tnv1.GatewayStaticRecord{{Name: "x", Address: "192.0.2.10"}}
	if _, err := RenderDNS(in); err == nil {
		t.Fatal("oversized static owner accepted")
	}
}
