//go:build e2e_kind

package e2ekind

import (
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
)

func TestGatewayRuntimeImageAliases(t *testing.T) {
	p, images := gatewayStartupFixture(t)
	ref := images["tailscale"]
	alias := "ghcr.io/tailscale/tailscale@sha256:" + strings.Repeat("3", 64)
	ids, ok := verifiedGatewayImageIDs(ref, "expected-config", "expected-config", []string{alias, ref})
	if !ok {
		t.Fatal("verified archive-index alias rejected")
	}
	g, err := newGatewayStartup(p, gatewayTestNode, gatewayTestGate, images)
	if err != nil {
		t.Fatal(err)
	}
	g.imageIDs["tailscale"] = ids
	p.Status = gatewayStartedStatus(images)
	p.Status.InitContainerStatuses[1].ImageID = alias
	p.Status.ContainerStatuses[0].ImageID = alias
	if !g.started(p, "containerd://gate", []string{gatewayTestGateDigest}) {
		t.Fatal("config-bound runtime alias rejected")
	}
	for _, digests := range [][]string{{alias}, {ref, ref}, {ref, "foreign@sha256:" + strings.Repeat("3", 64)}, {ref, "malformed"}, nil} {
		if _, ok := verifiedGatewayImageIDs(ref, "expected-config", "expected-config", digests); ok {
			t.Fatal("unbound alias accepted")
		}
	}
	if _, ok := verifiedGatewayImageIDs(ref, "expected-config", "foreign-config", []string{ref}); ok {
		t.Fatal("foreign image configuration accepted")
	}
}

func TestGatewayCLIIdentityDecoder(t *testing.T) {
	// Exact encoding/json protobuf shape from Headscale 0.29.3 CLI, not REST.
	b := []byte(`[{"id":12,"machine_key":"mkey:public","node_key":"nodekey:public","given_name":"router","online":true,"ip_addresses":["100.64.0.1"],"tags":["tag:fabric"],"available_routes":["192.0.2.0/24"],"approved_routes":["192.0.2.0/24"],"pre_auth_key":{"id":7}}]`)
	nodes, ok := decodeGatewayCLINodes(b)
	if !ok || len(nodes) != 1 || nodes[0].ID != "12" || nodes[0].MachineKey != "mkey:public" || nodes[0].NodeKey != "nodekey:public" || nodes[0].GivenName != "router" || !nodes[0].Online || nodes[0].PreAuthKey == nil || nodes[0].PreAuthKey.ID != "7" || nodes[0].PreAuthKey.Ephemeral || !reflect.DeepEqual(nodes[0].IPAddresses, []string{"100.64.0.1"}) || !reflect.DeepEqual(nodes[0].AvailableRoutes, []string{"192.0.2.0/24"}) || !reflect.DeepEqual(nodes[0].ApprovedRoutes, []string{"192.0.2.0/24"}) {
		t.Fatal("CLI public identity conversion failed")
	}
	for _, bad := range []string{`[{"id":"12"}]`, `[{"id":0}]`, `[{"id":12,"pre_auth_key":{}}]`, `{"nodes":[]}`, `[{"id":12}] trailing`, strings.Repeat("x", (1<<20)+1)} {
		if _, ok := decodeGatewayCLINodes([]byte(bad)); ok {
			t.Fatal("invalid CLI shape accepted")
		}
	}
	nodes, ok = decodeGatewayCLINodes([]byte(`[{"id":12}]`))
	if !ok || nodes[0].PreAuthKey != nil || nodes[0].Online {
		t.Fatal("absent CLI fields fabricated")
	}
	var key gatewayCLIKey
	if json.Unmarshal([]byte(`{"id":7,"key":"synthetic","reusable":true,"acl_tags":["tag:fabric"],"expiration":{"seconds":1900000000,"nanos":123}}`), &key) != nil || key.ID != 7 || !key.Reusable || key.Ephemeral || key.Expiration.Seconds != 1900000000 || key.Expiration.Nanos != 123 {
		t.Fatal("CLI key shape mismatch")
	}
}

func TestGatewayProcessContinuity(t *testing.T) {
	p, images := gatewayStartupFixture(t)
	p.Status = gatewayStartedStatus(images)
	if !gatewayProcessesStable(p, p.DeepCopy()) {
		t.Fatal("unchanged gateway rejected")
	}
	for name, change := range map[string]func(*corev1.Pod){
		"uid":          func(p *corev1.Pod) { p.UID = "recreated" },
		"image":        func(p *corev1.Pod) { p.Status.ContainerStatuses[0].ImageID = "foreign" },
		"process":      func(p *corev1.Pod) { p.Status.ContainerStatuses[1].ContainerID = "new" },
		"init process": func(p *corev1.Pod) { p.Status.InitContainerStatuses[1].ContainerID = "new" },
		"restart":      func(p *corev1.Pod) { p.Status.ContainerStatuses[0].RestartCount = 1 },
		"duplicate":    func(p *corev1.Pod) { p.Status.ContainerStatuses[1] = p.Status.ContainerStatuses[0] },
		"terminated": func(p *corev1.Pod) {
			p.Status.ContainerStatuses[1].State = corev1.ContainerState{Terminated: &corev1.ContainerStateTerminated{}}
		},
		"spec": func(p *corev1.Pod) { p.Spec.Containers[0].Args = []string{"different"} },
	} {
		t.Run(name, func(t *testing.T) {
			current := p.DeepCopy()
			change(current)
			if gatewayProcessesStable(p, current) {
				t.Fatal("unproved process change accepted")
			}
		})
	}
}

func TestGatewayFreshRunnerSelection(t *testing.T) {
	path, err := filepath.Abs("../../hack/e2e-kind-projection.sh")
	if err != nil {
		t.Fatal("runner path unavailable")
	}
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal("runner source unavailable")
	}
	for _, required := range []string{
		"elif [[ $# == 1 && $1 == --gateway-fresh-only ]]; then\n    test_pattern='^TestGatewayFreshPod$'\n    test_timeout=10m\n    gateway_only=true",
		"gateway-images.json test/e2e-kind/gateway-assets*.py",
		`cmp "$out/gateway-cache.json" "$out/gateway-assets.json"`,
		`"$fixture/gateway-assets.py" --check-import`,
		`crictl inspecti "$ref" > "$out/gateway-$component-cri-image.json"`,
		"httppeer,kernelcheck,gatewayprobe}/*.go",
		"kindfixture,kernelcheck,gatewayprobe}/*.go",
		"httppeer kernelcheck gatewayprobe; do",
		"httppeer,kernelcheck,gatewayprobe}",
		`len(s.splitlines())==12 and s.count("statically linked")==12`,
	} {
		if !strings.Contains(string(b), required) {
			t.Fatal("gateway runner bound selection/provenance missing")
		}
	}
	for _, args := range [][]string{{"--gateway-fresh-only", "--repair"}, {"--gateway-fresh-only", "--http-only"}, {"--gateway-fresh-only", "--image=foreign"}} {
		ctx, cancel := context.WithTimeout(t.Context(), 3*time.Second)
		cmd := exec.CommandContext(ctx, "bash", append([]string{path}, args...)...)
		cmd.Env = []string{"PATH=" + os.Getenv("PATH")}
		out, err := cmd.CombinedOutput()
		cancel()
		if e, ok := err.(*exec.ExitError); !ok || e.ExitCode() != 2 || string(out) != "projection: stage=preflight result=rejected\n" {
			t.Fatal("unsupported gateway invocation reached runtime lookup")
		}
	}
}
