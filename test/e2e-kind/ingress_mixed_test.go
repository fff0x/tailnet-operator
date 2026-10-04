//go:build e2e_kind

package e2ekind

import (
	"encoding/json"
	"net/netip"
	"testing"

	"sigs.k8s.io/controller-runtime/pkg/client"

	tnv1 "tsunaro.io/tailnet-operator/api/v1alpha1"
)

// The HTTP test calls this around its HTTPS checks on the same CR/agent. Every
// probe opens a fresh TCP/8443 connection and requires a nonce/hash exchange,
// not merely a successful dial. This proves both listeners work in each stable
// phase, not uninterrupted traffic during an intentional protocol retirement.
func checkIngressL4Coexistence(t *testing.T, x *httpPeerFixture, ingress *tnv1.TailnetIngress, phase string) {
	t.Helper()
	if x.f.kube.Get(t.Context(), client.ObjectKeyFromObject(ingress), ingress) != nil {
		t.Fatal("mixed ingress status unavailable")
	}
	var target string
	for _, raw := range ingress.Status.TailnetIPs {
		ip, err := netip.ParseAddr(raw)
		if err == nil && ip.Is4() && netip.MustParsePrefix("100.64.0.0/10").Contains(ip) {
			target = raw
		}
	}
	if target == "" || ingress.Status.DNSName != "http-agent.fixture.test" {
		t.Fatal("mixed ingress tailnet identity missing")
	}
	type observation struct {
		AddressKind string `json:"addressKind"`
		Valid       bool   `json:"valid"`
		l4Observation
	}
	var observations []observation
	defer func() { x.save("l4-coexistence-"+phase+".json", observations) }()
	for _, address := range []struct{ kind, target string }{{"ipv4", target}, {"magicDNS", ingress.Status.DNSName}} {
		eventually(t, "mixed HTTP/L4 ingress completes TCP byte exchange", func() bool {
			input, _ := json.Marshal(map[string]string{"target": address.target})
			b, err := x.proxy(x.peer.Name, 9081, "probe-l4", string(input))
			var raw struct {
				OK        *bool `json:"ok"`
				Connected *bool `json:"connected"`
				TimedOut  *bool `json:"timedOut"`
			}
			valid := err == nil && len(b) <= 1024 && json.Unmarshal(b, &raw) == nil && raw.OK != nil && raw.Connected != nil && raw.TimedOut != nil
			got := observation{AddressKind: address.kind, Valid: valid}
			if valid {
				got.l4Observation = l4Observation{OK: *raw.OK, Connected: *raw.Connected, TimedOut: *raw.TimedOut}
			}
			observations = append(observations, got)
			return valid && got.OK && got.Connected && !got.TimedOut
		})
	}
}
