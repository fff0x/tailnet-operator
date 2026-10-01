package netproof

import (
	"bytes"
	"encoding/json"
	"net/netip"
	"strings"
	"testing"
)

func prefix(s string) netip.Prefix { return netip.MustParsePrefix(s) }
func ip(s string) netip.Addr       { return netip.MustParseAddr(s) }
func standardFixtureRules() []Rule {
	var out []Rule
	for _, f := range []int{4, 6} {
		for _, table := range []uint32{255, 254, 253} {
			if f == 6 && table == 253 {
				continue
			}
			priority := uint32(0)
			if table == 254 {
				priority = 32766
			}
			if table == 253 {
				priority = 32767
			}
			out = append(out, Rule{Family: f, Table: table, Priority: priority, Action: 1, Protocol: 2, SuppressPrefix: ^uint32(0)})
		}
	}
	return out
}
func route(dst string, link int, table uint32, kind, scope, proto uint8) Route {
	p := prefix(dst)
	f := 6
	if p.Addr().Is4() {
		f = 4
	}
	return Route{Family: f, Destination: p, LinkIndex: link, Table: table, Type: kind, Scope: scope, Protocol: proto}
}
func addLocal(s *Snapshot) {
	s.Routes = append(s.Routes,
		route("127.0.0.0/8", 1, 255, 2, 254, 2), route("127.0.0.1/32", 1, 255, 2, 254, 2),
		route("127.255.255.255/32", 1, 255, 3, 253, 2), route("::1/128", 1, 255, 2, 0, 2))
	for _, l := range s.Links {
		if l.Loopback {
			continue
		}
		for _, p := range l.Addresses {
			if p.Addr().Is4() {
				s.Routes = append(s.Routes, route(host(p.Addr()).String(), l.Index, 255, 2, 254, 2))
			} else {
				s.Routes = append(s.Routes, route(p.Masked().String(), l.Index, 254, 1, 0, 2), route(host(p.Addr()).String(), l.Index, 255, 2, 0, 2), route("ff00::/8", l.Index, 255, 5, 0, 3))
			}
		}
	}
}
func fixture() (Snapshot, Snapshot, NodeBinding, PodBinding) {
	lo := Link{Index: 1, PeerIndex: 1, Kind: "loopback", Up: true, Loopback: true, Addresses: []netip.Prefix{prefix("127.0.0.1/8"), prefix("::1/128")}}
	n := Snapshot{Version: Version, UID: 65534, Rules: standardFixtureRules(), Dials: Dials{NetworkUnreachable, NetworkUnreachable}, Links: []Link{lo,
		{Index: 2, PeerIndex: 90, Kind: "veth", Up: true, Addresses: []netip.Prefix{prefix("192.168.76.2/24"), prefix("fe80::a2/64")}},
		{Index: 7, PeerIndex: 2, Kind: "veth", Up: true, Addresses: []netip.Prefix{prefix("10.77.4.1/32"), prefix("fe80::a7/64")}},
	}, Routes: []Route{route("192.168.76.0/24", 2, 254, 1, 253, 2), route("10.77.4.19/32", 7, 254, 1, 254, 3), route("192.168.76.255/32", 2, 255, 3, 253, 2)}}
	p := Snapshot{Version: Version, UID: 65532, Rules: standardFixtureRules(), Dials: Dials{NetworkUnreachable, NetworkUnreachable}, Links: []Link{lo,
		{Index: 2, PeerIndex: 7, Kind: "veth", Up: true, Addresses: []netip.Prefix{prefix("10.77.4.19/24"), prefix("fe80::b2/64")}},
	}, Routes: []Route{route("0.0.0.0/0", 2, 254, 1, 0, 3), route("10.77.4.0/24", 2, 254, 1, 0, 3), route("10.77.4.1/32", 2, 254, 1, 253, 3), route("10.77.4.255/32", 2, 255, 3, 253, 2)}}
	p.Routes[0].Gateway = ip("10.77.4.1")
	p.Routes[1].Gateway = ip("10.77.4.1")
	addLocal(&n)
	addLocal(&p)
	return n, p, NodeBinding{prefix("192.168.76.0/24"), ip("192.168.76.2"), prefix("10.77.4.0/24")}, PodBinding{ip("10.77.4.19")}
}
func TestRoutedVeth(t *testing.T) {
	n, p, nb, pb := fixture()
	proof, err := VerifyNode(n, nb)
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifyPod(p, pb, proof); err != nil {
		t.Fatal(err)
	}
	// Mutations to the caller's slices must not mutate the already issued proof.
	n.Links[2].Addresses[0] = prefix("10.77.4.200/32")
	n.Routes[1].Destination = prefix("10.77.4.200/32")
	if err := VerifyPod(p, pb, proof); err != nil {
		t.Fatal("proof retained mutable caller state")
	}
	if VerifyPod(p, pb, NodeProof{}) == nil {
		t.Fatal("zero proof accepted")
	}
	// Policy-dropped ICMP: the Pod's IPv4 SYN times out while the node proof holds.
	p.Dials.IPv4 = TimedOut
	if err := VerifyPod(p, pb, proof); err != nil {
		t.Fatal("IPv4 timeout under node proof rejected")
	}
}
func TestRejectNode(t *testing.T) {
	cases := map[string]func(*Snapshot, *NodeBinding){
		"default":      func(s *Snapshot, _ *NodeBinding) { s.Routes = append(s.Routes, route("0.0.0.0/0", 2, 254, 1, 0, 3)) },
		"gateway":      func(s *Snapshot, _ *NodeBinding) { s.Routes[0].Gateway = ip("192.168.76.1") },
		"hidden table": func(s *Snapshot, _ *NodeBinding) { s.Routes[0].Table = 100 },
		"flags":        func(s *Snapshot, _ *NodeBinding) { s.Routes[0].Flags = 1 },
		"global IPv6 address": func(s *Snapshot, _ *NodeBinding) {
			s.Links[1].Addresses = append(s.Links[1].Addresses, prefix("2001:db8::2/64"))
		},
		"global IPv6 route": func(s *Snapshot, _ *NodeBinding) {
			s.Routes = append(s.Routes, route("2001:db8::/64", 2, 254, 1, 0, 2))
		},
		"foreign link-local prefix": func(s *Snapshot, _ *NodeBinding) {
			s.Routes = append(s.Routes, route("fe80:0:0:1::/64", 2, 254, 1, 0, 2))
		},
		"unknown interface":         func(s *Snapshot, _ *NodeBinding) { s.Links[2].Kind = "wireguard" },
		"extra external link":       func(s *Snapshot, _ *NodeBinding) { s.Links[2].Addresses[0] = prefix("192.168.80.2/24") },
		"CNI bridge":                func(s *Snapshot, _ *NodeBinding) { s.Links[2].Addresses[0] = prefix("10.77.4.1/24") },
		"wrong outer address":       func(s *Snapshot, _ *NodeBinding) { s.Links[1].Addresses[0] = prefix("192.168.76.8/24") },
		"wrong actual prefix":       func(s *Snapshot, _ *NodeBinding) { s.Links[1].Addresses[0] = prefix("192.168.76.2/16") },
		"down":                      func(s *Snapshot, _ *NodeBinding) { s.Links[1].Up = false },
		"unknown rule":              func(s *Snapshot, _ *NodeBinding) { s.Rules = append(s.Rules, Rule{Family: 4, Table: 100}) },
		"rule priority":             func(s *Snapshot, _ *NodeBinding) { s.Rules[1].Priority = 10 },
		"rule action":               func(s *Snapshot, _ *NodeBinding) { s.Rules[1].Action = 6 },
		"rule suppress":             func(s *Snapshot, _ *NodeBinding) { s.Rules[1].SuppressPrefix = 0 },
		"rule protocol":             func(s *Snapshot, _ *NodeBinding) { s.Rules[1].Protocol = 3 },
		"refusal":                   func(s *Snapshot, _ *NodeBinding) { s.Dials.IPv4 = Refused },
		"timeout":                   func(s *Snapshot, _ *NodeBinding) { s.Dials.IPv6 = TimedOut },
		"IPv4 timeout":              func(s *Snapshot, _ *NodeBinding) { s.Dials.IPv4 = TimedOut },
		"unsupported IPv6 unproven": func(s *Snapshot, _ *NodeBinding) { s.Dials.IPv6 = AddressFamilyUnsupported },
		"no dial":                   func(s *Snapshot, _ *NodeBinding) { s.Dials = Dials{} },
		"wrong uid":                 func(s *Snapshot, _ *NodeBinding) { s.UID = 1000 },
		"overlapping binding":       func(_ *Snapshot, b *NodeBinding) { b.PodCIDR = b.OuterCIDR },
		"broad private binding":     func(_ *Snapshot, b *NodeBinding) { b.PodCIDR = prefix("10.0.0.0/8") },
		"public binding":            func(_ *Snapshot, b *NodeBinding) { b.PodCIDR = prefix("192.0.2.0/24") },
		"noncanonical binding":      func(_ *Snapshot, b *NodeBinding) { b.PodCIDR = prefix("10.77.4.2/24") },
		"broadcast node":            func(_ *Snapshot, b *NodeBinding) { b.NodeIP = ip("192.168.76.255") },
		"unknown source":            func(s *Snapshot, _ *NodeBinding) { s.Routes[0].Source = ip("192.168.76.8") },
		"return outside pod CIDR":   func(s *Snapshot, _ *NodeBinding) { s.Routes[1].Destination = prefix("10.77.5.19/32") },
		"missing connected route":   func(s *Snapshot, _ *NodeBinding) { s.Routes = s.Routes[1:] },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			n, _, b, _ := fixture()
			mutate(&n, &b)
			if _, err := VerifyNode(n, b); err != ErrInvalid {
				t.Fatal("invalid node accepted")
			}
		})
	}
}
func TestRejectPod(t *testing.T) {
	cases := map[string]func(*Snapshot, *Snapshot, *PodBinding){
		"bad pod peer":         func(_ *Snapshot, p *Snapshot, _ *PodBinding) { p.Links[1].PeerIndex = 8 },
		"bad node peer":        func(n *Snapshot, _ *Snapshot, _ *PodBinding) { n.Links[2].PeerIndex = 8 },
		"missing return route": func(n *Snapshot, _ *Snapshot, _ *PodBinding) { n.Routes = append(n.Routes[:1], n.Routes[2:]...) },
		"wrong return route":   func(n *Snapshot, _ *Snapshot, _ *PodBinding) { n.Routes[1].Destination = prefix("10.77.4.20/32") },
		"wrong actual PodIP":   func(_ *Snapshot, p *Snapshot, _ *PodBinding) { p.Links[1].Addresses[0] = prefix("10.77.4.20/24") },
		"wrong live PodIP":     func(_ *Snapshot, _ *Snapshot, b *PodBinding) { b.PodIP = ip("10.77.4.20") },
		"two defaults":         func(_ *Snapshot, p *Snapshot, _ *PodBinding) { p.Routes = append(p.Routes, p.Routes[0]) },
		"no default":           func(_ *Snapshot, p *Snapshot, _ *PodBinding) { p.Routes = p.Routes[1:] },
		"foreign gateway":      func(_ *Snapshot, p *Snapshot, _ *PodBinding) { p.Routes[0].Gateway = ip("10.77.4.2") },
		"missing gateway link": func(_ *Snapshot, p *Snapshot, _ *PodBinding) { p.Routes = append(p.Routes[:2], p.Routes[3:]...) },
		"extra IPv4 route": func(_ *Snapshot, p *Snapshot, _ *PodBinding) {
			p.Routes = append(p.Routes, route("192.168.80.0/24", 2, 254, 1, 253, 3))
		},
		"IPv6 default": func(_ *Snapshot, p *Snapshot, _ *PodBinding) {
			p.Routes = append(p.Routes, route("::/0", 2, 254, 1, 0, 3))
		},
		"second interface": func(_ *Snapshot, p *Snapshot, _ *PodBinding) {
			l := p.Links[1]
			l.Index = 4
			p.Links = append(p.Links, l)
		},
		"refusal":      func(_ *Snapshot, p *Snapshot, _ *PodBinding) { p.Dials.IPv4 = Refused },
		"connected":    func(_ *Snapshot, p *Snapshot, _ *PodBinding) { p.Dials.IPv4 = Connected },
		"other":        func(_ *Snapshot, p *Snapshot, _ *PodBinding) { p.Dials.IPv4 = OtherFailure },
		"IPv6 timeout": func(_ *Snapshot, p *Snapshot, _ *PodBinding) { p.Dials.IPv6 = TimedOut },
		"no dial":      func(_ *Snapshot, p *Snapshot, _ *PodBinding) { p.Dials = Dials{} },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			n, p, nb, pb := fixture()
			mutate(&n, &p, &pb)
			proof, err := VerifyNode(n, nb)
			if err != nil {
				t.Fatal("node fixture invalid")
			}
			if VerifyPod(p, pb, proof) == nil {
				t.Fatal("invalid pod accepted")
			}
		})
	}
}
func TestSnapshotJSONBounds(t *testing.T) {
	n, _, _, _ := fixture()
	b, err := json.Marshal(n)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = DecodeSnapshot(bytes.NewReader(b)); err != nil {
		t.Fatal(err)
	}
	for _, b := range []string{`{"version":1,"unknown":true}`, string(b) + ` {}`, strings.Repeat(" ", MaxJSON+1)} {
		if _, err := DecodeSnapshot(strings.NewReader(b)); err != ErrInvalid {
			t.Fatal("bad JSON accepted")
		}
	}
}
