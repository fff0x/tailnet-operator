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

// The renderer output for a Gateway without extra zones is frozen: every
// pre-v0.15 gateway must keep its content hash (CAS annotation)
// and ConfigMap keys byte for byte, or the next reconcile would bump serials
// and rewrite running DNS for a no-op upgrade.
func TestRenderDNSGoldenWithoutExtraZones(t *testing.T) {
	in := dnsFixture()
	in.Hosts = "192.0.2.7 alias.tail.example\n10.0.0.5 proxy.corp.example\n"
	got, err := RenderDNS(in)
	if err != nil {
		t.Fatal(err)
	}
	const goldenCorefile = "tail.example {\n    bind 0.0.0.0 ::\n    errors\n    prometheus :9153\n    file zone.db tail.example {\n        reload 1s\n    }\n    reload\n}\n"
	const goldenHash = "b71fe9035e2e3887789631c3784e24b1f2287a478ee4cce8f9c80f248eb4d669" // v0.14.2 renderer
	if got.Corefile != goldenCorefile || got.HostsFile != "" || dnsContentHash(got.Corefile, got.ZoneFile, got.HostsFile) != goldenHash {
		t.Fatalf("pre-extraZones rendering drifted: hash %s corefile %q hosts %q", dnsContentHash(got.Corefile, got.ZoneFile, got.HostsFile), got.Corefile, got.HostsFile)
	}
	if len(dnsPayload(got)) != 2 {
		t.Fatal("hosts key rendered without extra zones")
	}
}

func TestRenderDNSExtraZones(t *testing.T) {
	in := dnsFixture()
	in.Config.ExtraZones = []tnv1.GatewayExtraZone{
		{Zone: "corp.example", Upstreams: []tnv1.GatewayIP{"10.0.0.2", "10.0.0.1"}},
		{Zone: "partner.example", Upstreams: []tnv1.GatewayIP{"2001:db8::53"}},
	}
	in.Hosts = "192.0.2.7 alias.tail.example\n10.0.0.5 proxy.corp.example zulu.corp.example\n10.0.0.6 proxy.corp.example\n10.0.0.9 corp.example\n10.0.0.7 ipam.partner.example\n10.0.0.8 other.example\n"
	got, err := RenderDNS(in)
	if err != nil {
		t.Fatal(err)
	}
	wantHosts := dnsHostsHeader + "10.0.0.9 corp.example\n10.0.0.7 ipam.partner.example\n10.0.0.5 proxy.corp.example\n10.0.0.6 proxy.corp.example\n10.0.0.5 zulu.corp.example\n"
	if got.HostsFile != wantHosts {
		t.Fatalf("hosts file %q", got.HostsFile)
	}
	wantBlock := "corp.example {\n    bind 0.0.0.0 ::\n    errors\n    prometheus :9153\n    hosts hosts corp.example {\n        fallthrough\n    }\n    cache 30\n    forward . 10.0.0.2 10.0.0.1 {\n        max_concurrent 1000\n    }\n    reload\n}\n"
	if !strings.HasPrefix(got.Corefile, "tail.example {\n") || !strings.Contains(got.Corefile, wantBlock) || !strings.Contains(got.Corefile, "partner.example {\n") || !strings.Contains(got.Corefile, "forward . 2001:db8::53 {") {
		t.Fatalf("corefile %q", got.Corefile)
	}
	for _, leaked := range []string{"corp.example", "partner", "other.example"} {
		if strings.Contains(got.ZoneFile, leaked) {
			t.Fatal("extra-zone or foreign name leaked into the primary zone")
		}
	}
	if len(dnsPayload(got)) != 3 || dnsPayload(got)[DNSHostsFile] != wantHosts {
		t.Fatal("hosts key missing from payload")
	}
	// Hosts changes inside an extra zone are semantic: they advance the serial.
	base, err := PlanDNSRevision(in, nil)
	if err != nil {
		t.Fatal(err)
	}
	in.Hosts += "10.0.0.10 new.corp.example\n"
	next, err := PlanDNSRevision(in, &DNSRevision{Serial: 1, ContentHash: base.ContentHash, ResourceVersion: "rv"})
	if err != nil || !next.Changed || next.Serial != 2 {
		t.Fatal("extra-zone hosts change did not advance the serial")
	}
	for name, mutate := range map[string]func(*DNSInputs){
		"no upstream":     func(i *DNSInputs) { i.Config.ExtraZones[0].Upstreams = nil },
		"nine upstreams":  func(i *DNSInputs) { i.Config.ExtraZones[0].Upstreams = make([]tnv1.GatewayIP, 9) },
		"bad upstream":    func(i *DNSInputs) { i.Config.ExtraZones[0].Upstreams = []tnv1.GatewayIP{"10.0.0.1 10.0.0.2"} },
		"loopback":        func(i *DNSInputs) { i.Config.ExtraZones[0].Upstreams = []tnv1.GatewayIP{"127.0.0.1"} },
		"self upstream":   func(i *DNSInputs) { i.Config.ExtraZones[0].Upstreams = []tnv1.GatewayIP{"192.0.2.1"} },
		"dup upstream":    func(i *DNSInputs) { i.Config.ExtraZones[0].Upstreams = []tnv1.GatewayIP{"10.0.0.1", "10.0.0.1"} },
		"injected zone":   func(i *DNSInputs) { i.Config.ExtraZones[0].Zone = "injected\nprivate-value" },
		"primary zone":    func(i *DNSInputs) { i.Config.ExtraZones[0].Zone = "tail.example" },
		"under primary":   func(i *DNSInputs) { i.Config.ExtraZones[0].Zone = "sub.tail.example" },
		"over primary":    func(i *DNSInputs) { i.Config.ExtraZones[0].Zone = "example" },
		"duplicate zone":  func(i *DNSInputs) { i.Config.ExtraZones[1].Zone = "corp.example" },
		"nested extra":    func(i *DNSInputs) { i.Config.ExtraZones[1].Zone = "it.corp.example" },
		"too many zones":  func(i *DNSInputs) { i.Config.ExtraZones = make([]tnv1.GatewayExtraZone, 17) },
		"hosts host apex": func(i *DNSInputs) { i.Hosts = "10.0.0.1 tail.example\n" },
	} {
		t.Run(name, func(t *testing.T) {
			in := dnsFixture()
			in.Config.ExtraZones = []tnv1.GatewayExtraZone{
				{Zone: "corp.example", Upstreams: []tnv1.GatewayIP{"10.0.0.1"}},
				{Zone: "partner.example", Upstreams: []tnv1.GatewayIP{"10.0.0.2"}},
			}
			mutate(&in)
			if got, err := RenderDNS(in); !errors.Is(err, ErrDNSConfiguration) || got != (DNSPlan{}) {
				t.Fatal("invalid extra zone accepted or partial output returned")
			}
		})
	}
}

func TestRenderDNSAliasZones(t *testing.T) {
	in := dnsFixture()
	in.Config.ExtraZones = []tnv1.GatewayExtraZone{{Zone: "corp.example", Upstreams: []tnv1.GatewayIP{"10.0.0.1"}}}
	in.Config.AliasZones = []tnv1.GatewayName{"prod-2.example", "empty.example"}
	in.Hosts = "192.0.2.7 alias.tail.example\n10.96.0.9 talos.prod-2.example\n10.96.0.8 k8s.prod-2.example\n2001:db8::8 k8s.prod-2.example\n10.0.0.5 proxy.corp.example\n10.0.0.8 other.example\n"
	got, err := RenderDNS(in)
	if err != nil {
		t.Fatal(err)
	}
	wantAlias := "prod-2.example {\n    bind 0.0.0.0 ::\n    errors\n    prometheus :9153\n    hosts /dev/null prod-2.example {\n        10.96.0.8 k8s.prod-2.example\n        2001:db8::8 k8s.prod-2.example\n        10.96.0.9 talos.prod-2.example\n    }\n    reload\n}\n"
	wantEmpty := "empty.example {\n    bind 0.0.0.0 ::\n    errors\n    prometheus :9153\n    hosts /dev/null empty.example {\n    }\n    reload\n}\n"
	if !strings.HasSuffix(got.Corefile, wantEmpty+wantAlias) || strings.Index(got.Corefile, "corp.example {") > strings.Index(got.Corefile, wantEmpty) {
		t.Fatalf("corefile %q", got.Corefile)
	}
	if strings.Contains(got.ZoneFile, "prod-2") || strings.Contains(got.HostsFile, "prod-2") || strings.Contains(got.Corefile, "other.example") {
		t.Fatal("alias name leaked into the zone or hosts file, or a foreign name was served")
	}
	// Alias zones alone keep the two-key payload, so the Pod template is unchanged.
	aliasOnly := dnsFixture()
	aliasOnly.Config.AliasZones = []tnv1.GatewayName{"prod-2.example"}
	aliasOnly.Hosts = in.Hosts
	plain, err := RenderDNS(aliasOnly)
	if err != nil || len(dnsPayload(plain)) != 2 || plain.HostsFile != "" {
		t.Fatal("alias zones added a hosts key")
	}
	base, err := PlanDNSRevision(aliasOnly, nil)
	if err != nil {
		t.Fatal(err)
	}
	aliasOnly.Hosts += "10.96.0.10 new.prod-2.example\n"
	next, err := PlanDNSRevision(aliasOnly, &DNSRevision{Serial: 1, ContentHash: base.ContentHash, ResourceVersion: "rv"})
	if err != nil || !next.Changed || next.Serial != 2 {
		t.Fatal("alias hosts change did not advance the serial")
	}
	for name, mutate := range map[string]func(*DNSInputs){
		"primary zone":   func(i *DNSInputs) { i.Config.AliasZones[0] = "tail.example" },
		"under primary":  func(i *DNSInputs) { i.Config.AliasZones[0] = "sub.tail.example" },
		"over primary":   func(i *DNSInputs) { i.Config.AliasZones[0] = "example" },
		"extra zone":     func(i *DNSInputs) { i.Config.AliasZones[0] = "corp.example" },
		"under extra":    func(i *DNSInputs) { i.Config.AliasZones[0] = "it.corp.example" },
		"nested alias":   func(i *DNSInputs) { i.Config.AliasZones[1] = "a.prod-2.example" },
		"duplicate":      func(i *DNSInputs) { i.Config.AliasZones[1] = "prod-2.example" },
		"injected zone":  func(i *DNSInputs) { i.Config.AliasZones[0] = "injected\n}\nevil.example" },
		"too many zones": func(i *DNSInputs) { i.Config.AliasZones = make([]tnv1.GatewayName, 17) },
	} {
		t.Run(name, func(t *testing.T) {
			in := dnsFixture()
			in.Config.ExtraZones = []tnv1.GatewayExtraZone{{Zone: "corp.example", Upstreams: []tnv1.GatewayIP{"10.0.0.1"}}}
			in.Config.AliasZones = []tnv1.GatewayName{"prod-2.example", "prod-3.example"}
			mutate(&in)
			if got, err := RenderDNS(in); !errors.Is(err, ErrDNSConfiguration) || got != (DNSPlan{}) {
				t.Fatal("invalid alias zone accepted or partial output returned")
			}
		})
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
