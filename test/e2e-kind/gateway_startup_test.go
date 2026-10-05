//go:build e2e_kind

package e2ekind

import (
	"errors"
	"os"
	"reflect"
	"regexp"
	"slices"
	"testing"

	corev1 "k8s.io/api/core/v1"

	"tsunaro.io/tailnet-operator/test/internal/kindfixture"
)

var errGatewayStartup = errors.New("gateway fixture startup binding rejected")

// gatewayStartup binds only the full fresh gateway shape, never an arbitrary
// multi-container workload. Image references must be verified by the runner's
// immutable archive/import gate before they are passed here.
type gatewayStartup struct {
	pod      *corev1.Pod
	imageIDs map[string][]string
}

func newGatewayStartup(pod *corev1.Pod, node, gateImage string, images map[string]string) (*gatewayStartup, error) {
	if kindfixture.ValidateGatewayNetworkGate(pod, gateImage) != nil || pod.UID == "" || pod.Namespace != namespace || pod.DeletionTimestamp != nil ||
		!regexp.MustCompile(`^tn-kind-[a-z0-9]{10}-control-plane$`).MatchString(node) ||
		pod.Spec.NodeName != "" && pod.Spec.NodeName != node || len(images) != 2 {
		return nil, errGatewayStartup
	}
	// Deliberately fixed repositories: no caller-provided image override mode.
	for role, repo := range map[string]string{"tailscale": "ghcr.io/tailscale/tailscale", "coredns": "docker.io/coredns/coredns"} {
		if !regexp.MustCompile(`^` + regexp.QuoteMeta(repo) + `@sha256:[0-9a-f]{64}$`).MatchString(images[role]) {
			return nil, errGatewayStartup
		}
	}
	for _, c := range pod.Spec.Containers {
		if c.Image != images[c.Name] || c.ImagePullPolicy != corev1.PullNever {
			return nil, errGatewayStartup
		}
	}
	if pod.Spec.InitContainers[1].Image != images["tailscale"] || pod.Spec.InitContainers[1].ImagePullPolicy != corev1.PullNever {
		return nil, errGatewayStartup
	}
	bound := pod.DeepCopy()
	bound.Spec.NodeName = node
	return &gatewayStartup{pod: bound,
		imageIDs: map[string][]string{"tailscale": {images["tailscale"]}, "coredns": {images["coredns"]}}}, nil
}

func (g *gatewayStartup) samePod(p *corev1.Pod) bool {
	return p != nil && p.UID == g.pod.UID && p.Name == g.pod.Name && p.Namespace == g.pod.Namespace && p.DeletionTimestamp == nil &&
		reflect.DeepEqual(p.Spec, g.pod.Spec)
}

func freshWaiting(s corev1.ContainerStatus) bool {
	return s.ContainerID == "" && s.RestartCount == 0 && !s.Ready && s.State.Running == nil && s.State.Terminated == nil &&
		s.LastTerminationState == (corev1.ContainerState{})
}

// statusByName rejects unknown/duplicate entries instead of trusting API list
// order. Pending containers may have no status yet; running containers may not.
func statusByName(statuses []corev1.ContainerStatus, names ...string) (map[string]corev1.ContainerStatus, bool) {
	out := make(map[string]corev1.ContainerStatus, len(statuses))
	for _, s := range statuses {
		if _, exists := out[s.Name]; exists || !slices.Contains(names, s.Name) {
			return nil, false
		}
		out[s.Name] = s
	}
	return out, true
}

func (g *gatewayStartup) blocked(p *corev1.Pod, gateDigests []string) bool {
	if !g.samePod(p) {
		return false
	}
	inits, ok := statusByName(p.Status.InitContainerStatuses, kindfixture.NetworkGateContainer, "kernel-preflight")
	if !ok {
		return false
	}
	gate, exists := inits[kindfixture.NetworkGateContainer]
	if !exists || gate.ContainerID == "" || gate.RestartCount != 0 || gate.State.Running == nil || gate.State.Terminated != nil || gate.State.Waiting != nil ||
		gate.LastTerminationState != (corev1.ContainerState{}) || !slices.Contains(gateDigests, gate.ImageID) || gate.ImageID == "" {
		return false
	}
	if preflight, exists := inits["kernel-preflight"]; exists && !freshWaiting(preflight) {
		return false
	}
	apps, ok := statusByName(p.Status.ContainerStatuses, "tailscale", "coredns")
	if !ok {
		return false
	}
	for _, s := range apps {
		if !freshWaiting(s) {
			return false
		}
	}
	return true
}

func (g *gatewayStartup) started(p *corev1.Pod, gateID string, gateDigests []string) bool {
	if !g.samePod(p) || gateID == "" {
		return false
	}
	inits, ok := statusByName(p.Status.InitContainerStatuses, kindfixture.NetworkGateContainer, "kernel-preflight")
	if !ok || len(inits) != 2 {
		return false
	}
	gate, preflight := inits[kindfixture.NetworkGateContainer], inits["kernel-preflight"]
	if gate.ContainerID != gateID || gate.ImageID == "" || !slices.Contains(gateDigests, gate.ImageID) || !slices.Contains(g.imageIDs["tailscale"], preflight.ImageID) {
		return false
	}
	ids := make(map[string]bool)
	for _, s := range inits {
		if s.ContainerID == "" || ids[s.ContainerID] || s.RestartCount != 0 || s.State.Terminated == nil || s.State.Terminated.ExitCode != 0 ||
			s.State.Running != nil || s.State.Waiting != nil || s.LastTerminationState != (corev1.ContainerState{}) {
			return false
		}
		ids[s.ContainerID] = true
	}
	apps, ok := statusByName(p.Status.ContainerStatuses, "tailscale", "coredns")
	if !ok || len(apps) != 2 {
		return false
	}
	for name, s := range apps {
		if s.ContainerID == "" || ids[s.ContainerID] || !slices.Contains(g.imageIDs[name], s.ImageID) || s.RestartCount != 0 || s.State.Running == nil ||
			s.State.Waiting != nil || s.State.Terminated != nil || s.LastTerminationState != (corev1.ContainerState{}) {
			return false
		}
		ids[s.ContainerID] = true
	}
	return true
}

func releaseGatewayFixturePod(t *testing.T, f *fixture, pod *corev1.Pod, images map[string]string) {
	t.Helper()
	image := os.Getenv("E2E_KIND_FIXTURE_IMAGE")
	if image != "localhost/tn-source-netprobe:"+f.cluster {
		t.Fatal("owned gateway gate image required")
	}
	startup, err := newGatewayStartup(pod, f.cluster+"-control-plane", image, images)
	if err != nil {
		t.Fatal("gateway startup contract rejected")
	}
	// Containerd can report an archive-index digest instead of the platform
	// manifest. Accept only aliases from the independently config-bound import.
	startup.imageIDs = gatewayFixtureImageIDs(t, images)
	releaseBoundFixturePod(t, f, pod, startup.blocked, startup.started)
}
