package main

import (
	"bytes"
	"encoding/json"
	"io"
	"net/netip"
	"strings"
	"testing"

	"tsunaro.io/tailnet-operator/test/internal/netproof"
)

const validBinding = `{"OuterCIDR":"10.89.0.0/24","NodeIP":"10.89.0.2","PodCIDR":"10.244.0.0/24","PodIP":"10.244.0.5"}`

func TestBinding(t *testing.T) {
	if _, _, err := binding(strings.NewReader(validBinding)); err != nil {
		t.Fatal("valid binding rejected")
	}
	bad := []string{"", "null", "[]", "{}", validBinding + `{}`, validBinding + strings.Repeat(" ", 1025),
		strings.Replace(validBinding, `"PodIP":`, `"extra":"x","PodIP":`, 1),
		strings.Replace(validBinding, `"PodIP":`, `"PodIP":"10.244.0.6","PodIP":`, 1),
		strings.Replace(validBinding, "OuterCIDR", "outercidr", 1),
	}
	for _, key := range []string{"OuterCIDR", "NodeIP", "PodCIDR", "PodIP"} {
		for _, value := range []any{nil, 12, true, "", "invalid", "::ffff:10.89.0.2", "fe80::1%eth0", "1.1.1.1", "10.89.0.2/24", "10.89.0.0/16", "10.89.0.0", "10.89.0.255"} {
			var fields map[string]any
			_ = json.Unmarshal([]byte(validBinding), &fields)
			fields[key] = value
			raw, _ := json.Marshal(fields)
			bad = append(bad, string(raw))
		}
		var fields map[string]any
		_ = json.Unmarshal([]byte(validBinding), &fields)
		delete(fields, key)
		raw, _ := json.Marshal(fields)
		bad = append(bad, string(raw))
	}
	bad = append(bad, strings.Replace(validBinding, "10.244.0.0/24", "10.89.0.0/24", 1))
	for i, raw := range bad {
		if _, _, err := binding(strings.NewReader(raw)); err != errBinding {
			t.Fatalf("case %d not rejected with fixed category", i)
		}
	}
}

// Synthetic snapshots only: these tests never capture or dial on the host.
func snapshots(t *testing.T) (netproof.Snapshot, netproof.Snapshot) {
	t.Helper()
	prefix := func(s string) netip.Prefix {
		p, err := netip.ParsePrefix(s)
		if err != nil {
			t.Fatal("invalid synthetic prefix")
		}
		return p
	}
	addr := func(s string) netip.Addr {
		p, err := netip.ParseAddr(s)
		if err != nil {
			t.Fatal("invalid synthetic address")
		}
		return p
	}
	route := func(s string, link int, table uint32, kind, scope, proto uint8) netproof.Route {
		p := prefix(s)
		family := 4
		if p.Addr().Is6() {
			family = 6
		}
		return netproof.Route{Family: family, Destination: p, LinkIndex: link, Table: table, Type: kind, Scope: scope, Protocol: proto}
	}
	var rules []netproof.Rule
	for _, family := range []int{4, 6} {
		for _, table := range []uint32{255, 254, 253} {
			if family == 6 && table == 253 {
				continue
			}
			priority := uint32(0)
			if table == 254 {
				priority = 32766
			}
			if table == 253 {
				priority = 32767
			}
			rules = append(rules, netproof.Rule{Family: family, Table: table, Priority: priority, Action: 1, Protocol: 2, SuppressPrefix: ^uint32(0)})
		}
	}
	lo := netproof.Link{Index: 1, PeerIndex: 1, Kind: "loopback", Up: true, Loopback: true, Addresses: []netip.Prefix{prefix("127.0.0.1/8"), prefix("::1/128")}}
	node := netproof.Snapshot{Version: 1, UID: 65534, Rules: rules, Dials: netproof.Dials{IPv4: netproof.NetworkUnreachable, IPv6: netproof.NetworkUnreachable}, Links: []netproof.Link{lo,
		{Index: 2, PeerIndex: 90, Kind: "veth", Up: true, Addresses: []netip.Prefix{prefix("10.89.0.2/24"), prefix("fe80::a2/64")}},
		{Index: 7, PeerIndex: 2, Kind: "veth", Up: true, Addresses: []netip.Prefix{prefix("10.244.0.1/32"), prefix("fe80::a7/64")}},
	}, Routes: []netproof.Route{route("10.89.0.0/24", 2, 254, 1, 253, 2), route("10.244.0.5/32", 7, 254, 1, 254, 3), route("10.89.0.255/32", 2, 255, 3, 253, 2)}}
	pod := netproof.Snapshot{Version: 1, UID: 65532, Rules: rules, Dials: node.Dials, Links: []netproof.Link{lo,
		{Index: 2, PeerIndex: 7, Kind: "veth", Up: true, Addresses: []netip.Prefix{prefix("10.244.0.5/24"), prefix("fe80::b2/64")}},
	}, Routes: []netproof.Route{route("0.0.0.0/0", 2, 254, 1, 0, 3), route("10.244.0.0/24", 2, 254, 1, 0, 3), route("10.244.0.1/32", 2, 254, 1, 253, 3), route("10.244.0.255/32", 2, 255, 3, 253, 2)}}
	pod.Routes[0].Gateway = addr("10.244.0.1")
	pod.Routes[1].Gateway = addr("10.244.0.1")
	for _, s := range []*netproof.Snapshot{&node, &pod} {
		s.Routes = append(s.Routes, route("127.0.0.0/8", 1, 255, 2, 254, 2), route("127.0.0.1/32", 1, 255, 2, 254, 2), route("127.255.255.255/32", 1, 255, 3, 253, 2), route("::1/128", 1, 255, 2, 0, 2))
		for _, l := range s.Links[1:] {
			for _, p := range l.Addresses {
				host := netip.PrefixFrom(p.Addr(), p.Addr().BitLen()).String()
				if p.Addr().Is4() {
					s.Routes = append(s.Routes, route(host, l.Index, 255, 2, 254, 2))
				} else {
					s.Routes = append(s.Routes, route(p.Masked().String(), l.Index, 254, 1, 0, 2), route(host, l.Index, 255, 2, 0, 2), route("ff00::/8", l.Index, 255, 5, 0, 3))
				}
			}
		}
	}
	return node, pod
}

func TestVerifyBoundSnapshots(t *testing.T) {
	for _, mode := range []string{"valid", "node-uid", "pod-uid", "node-dial", "pod-dial", "control-timeout", "peer"} {
		t.Run(mode, func(t *testing.T) {
			n, p := snapshots(t)
			want := ""
			switch mode {
			case "node-uid":
				n.UID = 0
				want = "node-classifier-rejected"
			case "pod-uid":
				p.UID = 0
				want = "pod-classifier-rejected"
			case "node-dial":
				n.Dials.IPv6 = netproof.AddressFamilyUnsupported
				want = "node-classifier-rejected"
			case "pod-dial":
				p.Dials.IPv4 = netproof.Refused
				want = "pod-classifier-rejected"
			case "control-timeout":
				p.Dials.IPv4 = netproof.TimedOut
				want = "pod-classifier-rejected"
			case "peer":
				p.Links[1].PeerIndex = 8
				want = "pod-classifier-rejected"
			}
			nb, _ := json.Marshal(n)
			pb, _ := json.Marshal(p)
			var out bytes.Buffer
			err := verify(strings.NewReader(validBinding), bytes.NewReader(nb), bytes.NewReader(pb), &out)
			if want != "" {
				if err == nil || err.Error() != want || out.Len() != 0 {
					t.Fatal("negative snapshot verification failed")
				}
			} else {
				if err != nil {
					t.Fatal("valid snapshots rejected")
				}
				if out.String() != "{\"nodeClassifierPassed\":true,\"podClassifierPassed\":true,\"exactENETUNREACHCount\":4}\n" {
					t.Fatal("unexpected result")
				}
			}
		})
	}
}

func TestFixedFailures(t *testing.T) {
	for _, tc := range []struct{ binding, node, pod, want string }{
		{"invalid-private-input", "", "", "binding-rejected"},
		{validBinding, "private-parser-input", "", "snapshot-decode-rejected"},
		{validBinding, "{}", "{}", "node-classifier-rejected"},
	} {
		var out bytes.Buffer
		err := verify(strings.NewReader(tc.binding), strings.NewReader(tc.node), strings.NewReader(tc.pod), &out)
		if err == nil || err.Error() != tc.want || out.Len() != 0 {
			t.Fatal("failure category/output mismatch")
		}
	}
	if err := run(nil, io.Discard); err == nil || err.Error() != "arguments-rejected" {
		t.Fatal("arguments accepted")
	}
}
