package gateway

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"tailscale.com/types/key"

	"tsunaro.io/tailnet-operator/internal/headscale"
)

func stateBindingFixture(t *testing.T) (*corev1.Secret, []headscale.Node) {
	t.Helper()
	machine, node := key.NewMachine(), key.NewNode()
	machineText, err := machine.MarshalText()
	if err != nil {
		t.Fatal("synthetic machine key unavailable")
	}
	nodeText, err := node.MarshalText()
	if err != nil {
		t.Fatal("synthetic node key unavailable")
	}
	profile, err := json.Marshal(map[string]any{"ControlURL": "https://headscale.example", "Config": map[string]string{"PrivateNodeKey": string(nodeText)}})
	if err != nil {
		t.Fatal("synthetic profile unavailable")
	}
	secret := &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: "router-state", Namespace: "operator", UID: "state-uid", ResourceVersion: "22"}, Type: corev1.SecretTypeOpaque, Data: map[string][]byte{
		"_machinekey": machineText, "_current-profile": []byte("profile-abc123"), "profile-abc123": profile,
	}}
	nodes := []headscale.Node{{ID: "17", MachineKey: machine.Public().String(), NodeKey: node.Public().String(), GivenName: "router", Online: true,
		Tags: []string{"tag:fabric", "tag:mesh"}, IPAddresses: []string{"100.64.0.17", "fd7a:115c:a1e0::17"}, PreAuthKey: &headscale.NodeAuthKey{ID: "9"}}}
	return secret, nodes
}

func TestGatewayStateBindingMatchesPublicKeysOnly(t *testing.T) {
	in := freshInspectionFixture(t)
	state, nodes := stateBindingFixture(t)
	got, err := VerifyGatewayState(in.Fresh.Gateway, in.Fresh.Tailnet, state, "operator", state.UID, nodes, "9")
	if err != nil || got.NodeID != "17" || got.IPv4 != "100.64.0.17" || got.StateUID != state.UID || got.StateVersion != state.ResourceVersion {
		t.Fatal("persistent machine/node identity was not bound")
	}
	machine := string(state.Data["_machinekey"])
	if strings.Contains(got.NodeID+got.IPv4, machine) {
		t.Fatal("private state leaked into receipt")
	}
	for name, change := range map[string]func(*corev1.Secret, []headscale.Node){
		"missing machine": func(s *corev1.Secret, _ []headscale.Node) { delete(s.Data, "_machinekey") },
		"invalid machine": func(s *corev1.Secret, _ []headscale.Node) {
			s.Data["_machinekey"] = []byte("private-canary-do-not-log")
		},
		"missing profile":       func(s *corev1.Secret, _ []headscale.Node) { delete(s.Data, "profile-abc123") },
		"wrong profile pointer": func(s *corev1.Secret, _ []headscale.Node) { s.Data["_current-profile"] = []byte("../foreign") },
		"wrong server": func(s *corev1.Secret, _ []headscale.Node) {
			s.Data["profile-abc123"] = []byte(`{"ControlURL":"https://foreign.example","Config":{}}`)
		},
		"foreign machine":   func(_ *corev1.Secret, n []headscale.Node) { n[0].MachineKey = "mkey:foreign" },
		"foreign node":      func(_ *corev1.Secret, n []headscale.Node) { n[0].NodeKey = "nodekey:foreign" },
		"renamed":           func(_ *corev1.Secret, n []headscale.Node) { n[0].GivenName = "router-1" },
		"offline":           func(_ *corev1.Secret, n []headscale.Node) { n[0].Online = false },
		"wrong tags":        func(_ *corev1.Secret, n []headscale.Node) { n[0].Tags = []string{"tag:fabric"} },
		"ephemeral key":     func(_ *corev1.Secret, n []headscale.Node) { n[0].PreAuthKey.Ephemeral = true },
		"wrong auth ID":     func(_ *corev1.Secret, n []headscale.Node) { n[0].PreAuthKey.ID = "10" },
		"duplicate IPv4":    func(_ *corev1.Secret, n []headscale.Node) { n[0].IPAddresses = append(n[0].IPAddresses, "100.64.0.18") },
		"no state revision": func(s *corev1.Secret, _ []headscale.Node) { s.ResourceVersion = "" },
	} {
		t.Run(name, func(t *testing.T) {
			state, nodes := stateBindingFixture(t)
			change(state, nodes)
			receipt, err := VerifyGatewayState(in.Fresh.Gateway, in.Fresh.Tailnet, state, "operator", state.UID, nodes, "9")
			if !errors.Is(err, ErrGatewayStateBinding) || receipt != (GatewayStateBinding{}) || strings.Contains(err.Error(), "private-canary") || len(state.Data["_machinekey"]) != 0 && strings.Contains(err.Error(), string(state.Data["_machinekey"])) {
				t.Fatal("unsafe state or Headscale identity accepted or exposed")
			}
		})
	}
}

func TestGatewayStateBindingRejectsAmbiguousNodes(t *testing.T) {
	in := freshInspectionFixture(t)
	state, nodes := stateBindingFixture(t)
	dup := nodes[0]
	dup.ID = "18"
	nodes = append(nodes, dup)
	if _, err := VerifyGatewayState(in.Fresh.Gateway, in.Fresh.Tailnet, state, "operator", state.UID, nodes, "9"); !errors.Is(err, ErrGatewayStateBinding) {
		t.Fatal("duplicate machine key accepted")
	}
	if _, err := VerifyGatewayState(in.Fresh.Gateway, in.Fresh.Tailnet, state, "foreign", state.UID, nodes[:1], "9"); !errors.Is(err, ErrGatewayStateBinding) {
		t.Fatal("cross-namespace state accepted")
	}
	if _, err := VerifyGatewayState(in.Fresh.Gateway, in.Fresh.Tailnet, state, "operator", "recreated-uid", nodes[:1], "9"); !errors.Is(err, ErrGatewayStateBinding) {
		t.Fatal("recreated state Secret accepted")
	}
	foreign := nodes[0]
	foreign.MachineKey = "mkey:foreign"
	if _, err := VerifyGatewayState(in.Fresh.Gateway, in.Fresh.Tailnet, state, "operator", state.UID, []headscale.Node{nodes[0], foreign}, "9"); !errors.Is(err, ErrGatewayStateBinding) {
		t.Fatal("foreign node owning the hostname accepted")
	}
}
