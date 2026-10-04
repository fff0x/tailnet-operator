//go:build e2e_kind

package e2ekind

import (
	"encoding/json"
	"net/netip"
	"testing"

	tnv1 "tsunaro.io/tailnet-operator/api/v1alpha1"
)

// A fresh TLS-verified HTTP/1.1 upgrade, server greeting and nonce/hash exchange
// must succeed on each address. This is not an HTTP/2 extended-CONNECT test or
// proof of one long-lived connection surviving rotation/retirement.
func checkIngressWebSocket(t *testing.T, x *httpPeerFixture, ingress *tnv1.TailnetIngress, leaf, phase string) {
	t.Helper()
	var target string
	for _, raw := range ingress.Status.TailnetIPs {
		ip, err := netip.ParseAddr(raw)
		if err == nil && ip.Is4() && netip.MustParsePrefix("100.64.0.0/10").Contains(ip) {
			target = raw
		}
	}
	if target == "" || ingress.Status.DNSName != "http-agent.fixture.test" {
		t.Fatal("WebSocket ingress identity missing")
	}
	type observation struct {
		AddressKind string `json:"addressKind"`
		Valid       bool   `json:"valid"`
		OK          bool   `json:"ok"`
		Upgraded    bool   `json:"upgraded"`
		Leaf        string `json:"leafSHA256"`
		Exchanged   bool   `json:"exchanged"`
	}
	var results []observation
	defer func() { x.save("websocket-"+phase+".json", results) }()
	for _, address := range []struct{ kind, target string }{{"ipv4", target}, {"magicDNS", ingress.Status.DNSName}} {
		eventually(t, "verified WebSocket upgrade and bidirectional exchange", func() bool {
			raw, _ := json.Marshal(map[string]string{"target": address.target})
			b, err := x.proxy(x.peer.Name, 9081, "probe-websocket", string(raw))
			got := observation{AddressKind: address.kind}
			got.Valid = err == nil && len(b) <= 1024 && json.Unmarshal(b, &got) == nil
			results = append(results, got)
			return got.Valid && got.OK && got.Upgraded && got.Exchanged && got.Leaf == leaf
		})
	}
}
