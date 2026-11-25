//go:build e2e_kind

package e2ekind

import (
	_ "embed"
	"testing"

	"sigs.k8s.io/yaml"
)

//go:embed kind-http.yaml
var httpKindConfig []byte

func TestHTTPKindConfig(t *testing.T) {
	var cfg struct {
		Kind       string `json:"kind"`
		APIVersion string `json:"apiVersion"`
		Networking struct {
			APIServerAddress string `json:"apiServerAddress"`
		} `json:"networking"`
		Nodes []struct {
			Role  string `json:"role"`
			Image string `json:"image"`
		} `json:"nodes"`
		Patches []string `json:"kubeadmConfigPatches"`
	}
	if yaml.UnmarshalStrict(httpKindConfig, &cfg) != nil || cfg.Kind != "Cluster" || cfg.APIVersion != "kind.x-k8s.io/v1alpha4" || cfg.Networking.APIServerAddress != "127.0.0.1" || len(cfg.Nodes) != 1 || len(cfg.Patches) != 2 {
		t.Fatal("unexpected owned HTTP kind configuration")
	}
	if cfg.Nodes[0].Role != "control-plane" || cfg.Nodes[0].Image != "kindest/node:v1.37.0@sha256:a1ed56cfb0e7b93589bdf97c8cd566405a265939e3620fc4f5de89adff580ae5" {
		t.Fatal("unexpected HTTP fixture node pin")
	}
	var patch struct {
		Kind      string `json:"kind"`
		APIServer struct {
			ExtraArgs []struct{ Name, Value string } `json:"extraArgs"`
		} `json:"apiServer"`
	}
	if yaml.UnmarshalStrict([]byte(cfg.Patches[0]), &patch) != nil || patch.Kind != "ClusterConfiguration" || len(patch.APIServer.ExtraArgs) != 1 || patch.APIServer.ExtraArgs[0].Name != "enable-aggregator-routing" || patch.APIServer.ExtraArgs[0].Value != "true" {
		t.Fatal("unexpected endpoint resolver patch")
	}
	var kubelet struct {
		Kind                 string   `json:"kind"`
		AllowedUnsafeSysctls []string `json:"allowedUnsafeSysctls"`
		SyncFrequency        string   `json:"syncFrequency"`
	}
	if yaml.UnmarshalStrict([]byte(cfg.Patches[1]), &kubelet) != nil || kubelet.Kind != "KubeletConfiguration" || len(kubelet.AllowedUnsafeSysctls) != 1 || kubelet.AllowedUnsafeSysctls[0] != "net.ipv4.ip_forward" || kubelet.SyncFrequency != "10s" {
		t.Fatal("unexpected kubelet patch")
	}
}
