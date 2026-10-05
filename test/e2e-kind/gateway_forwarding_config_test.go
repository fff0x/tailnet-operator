//go:build e2e_kind

package e2ekind

import (
	"reflect"
	"testing"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	probe "tsunaro.io/tailnet-operator/test/internal/gatewayprobe"
	"tsunaro.io/tailnet-operator/test/internal/kindfixture"
)

func TestGatewayForwardingRejectsShortcuts(t *testing.T) {
	good := probe.Result{Mode: "forward", Connected: true, TargetVerified: true, SourceIPv4: "10.244.0.4", RouteSelected: true}
	if !forwardedByGateway(good, "10.244.0.4") {
		t.Fatal("bound forwarding result rejected")
	}
	for name, mutate := range map[string]func(*probe.Result){
		"native peer":       func(r *probe.Result) { r.SourceIPv4 = "10.244.0.5" },
		"target loopback":   func(r *probe.Result) { r.SourceIPv4 = "127.0.0.1" },
		"native mode":       func(r *probe.Result) { r.Mode = "underlay" },
		"no route":          func(r *probe.Result) { r.RouteSelected = false },
		"connection only":   func(r *probe.Result) { r.TargetVerified = false },
		"no connection":     func(r *probe.Result) { r.Connected = false },
		"error":             func(r *probe.Result) { r.Error = "dial" },
		"DNS mixed":         func(r *probe.Result) { r.DNSVerified = true },
		"DNS address mixed": func(r *probe.Result) { r.AnswerIPv4 = "198.51.100.8" },
	} {
		t.Run(name, func(t *testing.T) {
			bad := good
			mutate(&bad)
			if forwardedByGateway(bad, "10.244.0.4") {
				t.Fatal("shortcut or unverified transport accepted")
			}
		})
	}
	for _, ip := range []string{"", "127.0.0.1", "100.64.0.1", "::ffff:10.244.0.4"} {
		bad := good
		bad.SourceIPv4 = ip
		if forwardedByGateway(bad, ip) {
			t.Fatal("invalid gateway Pod address accepted")
		}
	}
}

func TestGatewayProbePodsKeepUnprivilegedGate(t *testing.T) {
	for _, role := range []string{"peer", "target"} {
		p := gatewayProbePod("gateway-proof-"+role, role, gatewayTestGate)
		before := p.Spec.Containers[0].DeepCopy()
		if kindfixture.AddNetworkGate(p, gatewayTestGate) != nil || !reflect.DeepEqual(*before, p.Spec.Containers[0]) {
			t.Fatal("probe changed unprivileged application contract")
		}
		if p.Spec.HostNetwork || p.Spec.HostPID || p.Spec.HostIPC || p.Spec.SecurityContext.RunAsUser == nil || *p.Spec.SecurityContext.RunAsUser != 65532 || *p.Spec.AutomountServiceAccountToken || len(before.SecurityContext.Capabilities.Add) != 0 || len(p.Spec.InitContainers) != 1 {
			t.Fatal("probe gained host access, token or privileges")
		}
		p.UID = "owned-probe"
		p.Status.PodIP = "10.244.0.5"
		p.Status.InitContainerStatuses = []corev1.ContainerStatus{{Name: kindfixture.NetworkGateContainer, ContainerID: "containerd://gate", ImageID: gatewayTestGateDigest, State: corev1.ContainerState{Terminated: &corev1.ContainerStateTerminated{ExitCode: 0}}}}
		p.Status.ContainerStatuses = []corev1.ContainerStatus{{Name: "application", ContainerID: "containerd://probe", ImageID: gatewayTestGateDigest, State: corev1.ContainerState{Running: &corev1.ContainerStateRunning{StartedAt: metav1.Now()}}}}
		if !singleGatewayProbeStable(p, p.DeepCopy()) {
			t.Fatal("unchanged probe process rejected")
		}
		for _, change := range []string{"uid", "ip", "spec", "restart", "container", "gate", "duplicate"} {
			changed := p.DeepCopy()
			switch change {
			case "uid":
				changed.UID = "replacement"
			case "ip":
				changed.Status.PodIP = "10.244.0.6"
			case "spec":
				changed.Spec.Containers[0].Args = nil
			case "restart":
				changed.Status.ContainerStatuses[0].RestartCount++
			case "container":
				changed.Status.ContainerStatuses[0].ContainerID = "replacement"
			case "gate":
				changed.Status.InitContainerStatuses[0].ImageID = "foreign"
			case "duplicate":
				changed.Status.ContainerStatuses = append(changed.Status.ContainerStatuses, changed.Status.ContainerStatuses[0])
			}
			if singleGatewayProbeStable(p, changed) {
				t.Fatalf("unverified %s accepted", change)
			}
		}
	}
}
