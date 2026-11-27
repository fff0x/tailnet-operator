//go:build e2e_kind

package e2ekind

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestGatewayPrerequisiteRunner(t *testing.T) {
	path, err := filepath.Abs("../../hack/e2e-kind-projection.sh")
	if err != nil {
		t.Fatal("resolve runner")
	}
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal("read runner")
	}
	s := string(b)
	for _, required := range []string{
		"test_pattern='^Test(FixtureCAProjection|PodNetworkGate|HeadscaleHTTPS|AgentHTTPSPeer|IngressHTTP|IngressL4)$'\ntest_timeout=35m",
		"test_pattern='^TestIngressHTTP$'\n", "    test_timeout=22m\nelif",
		"test_pattern='^Test(EgressReach|RestartNoFlap|MagicDNSRename|IngressIdentityPersists)$'\n    test_timeout=26m",
		"test_pattern='^TestIngressL4$'\n", "    test_timeout=18m\nelif",
		"elif [[ $# == 1 && $1 == --gateway-preflight-only ]]; then\n    test_pattern='^TestGatewayKernelPrerequisites$'\n    test_timeout=10m\n    kernel_only=true",
		"[[ $kernel_only != true ]] || modes+=(kernel)",
		"kernel) action=(exec --user 65534:65534 \"$node\" /tmp/owned-source-kernelcheck --capture=node --fixture=p2.1-kernel-prerequisites)",
		"test/internal/{netproof,kindfixture,kernelcheck,gatewayprobe}/*.go",
		"httppeer,kernelcheck,gatewayprobe,egressprobe}/*.go",
	} {
		if !strings.Contains(s, required) {
			t.Fatal("fixed selection, budget or provenance contract changed")
		}
	}
	// Invalid selections must exit before state creation or tool/runtime lookup.
	for _, args := range [][]string{{"--gateway-preflight-only", "--repair"}, {"--gateway-only"}, {"--gateway-preflight-only", "--http-only"}, {"--run=TestGatewayKernelPrerequisites"}} {
		ctx, cancel := context.WithTimeout(t.Context(), 3*time.Second)
		cmd := exec.CommandContext(ctx, "bash", append([]string{path}, args...)...)
		cmd.Env = []string{"PATH=" + os.Getenv("PATH")}
		out, err := cmd.CombinedOutput()
		cancel()
		if e, ok := err.(*exec.ExitError); !ok || e.ExitCode() != 2 || string(out) != "projection: stage=preflight result=rejected\n" {
			t.Fatal("unsupported invocation was not rejected before runtime use")
		}
	}
}
