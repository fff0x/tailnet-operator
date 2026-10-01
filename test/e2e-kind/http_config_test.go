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
	if yaml.UnmarshalStrict(httpKindConfig, &cfg) != nil || cfg.Kind != "Cluster" || cfg.APIVersion != "kind.x-k8s.io/v1alpha4" || cfg.Networking.APIServerAddress != "127.0.0.1" || len(cfg.Nodes) != 1 || len(cfg.Patches) != 1 {
		t.Fatal("unexpected owned HTTP kind configuration")
	}
	if cfg.Nodes[0].Role != "control-plane" || cfg.Nodes[0].Image != "kindest/node:v1.36.1@sha256:3489c7674813ba5d8b1a9977baea8a6e553784dab7b84759d1014dbd78f7ebd5" {
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
}
