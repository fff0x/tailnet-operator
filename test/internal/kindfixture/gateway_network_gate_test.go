package kindfixture

import (
	"reflect"
	"testing"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/utils/ptr"
)

func gatewayFixturePod() *corev1.Pod {
	security := func(uid int64, cap corev1.Capability) *corev1.SecurityContext {
		return &corev1.SecurityContext{RunAsUser: ptr.To(uid), RunAsGroup: ptr.To(uid), RunAsNonRoot: ptr.To(uid != 0), Privileged: ptr.To(false), AllowPrivilegeEscalation: ptr.To(false), ReadOnlyRootFilesystem: ptr.To(true), Capabilities: &corev1.Capabilities{Drop: []corev1.Capability{"ALL"}, Add: []corev1.Capability{cap}}}
	}
	return &corev1.Pod{Spec: corev1.PodSpec{
		AutomountServiceAccountToken: ptr.To(false),
		SecurityContext:              &corev1.PodSecurityContext{SeccompProfile: &corev1.SeccompProfile{Type: corev1.SeccompProfileTypeRuntimeDefault}, Sysctls: []corev1.Sysctl{{Name: "net.ipv4.ip_forward", Value: "1"}}},
		Volumes:                      []corev1.Volume{{Name: "tun", VolumeSource: corev1.VolumeSource{HostPath: &corev1.HostPathVolumeSource{Path: "/dev/net/tun", Type: ptr.To(corev1.HostPathCharDev)}}}},
		Containers: []corev1.Container{
			{Name: "tailscale", SecurityContext: security(0, "NET_ADMIN"), VolumeMounts: []corev1.VolumeMount{{Name: "tun", MountPath: "/dev/net/tun"}}},
			{Name: "coredns", SecurityContext: security(65532, "NET_BIND_SERVICE")},
		},
	}}
}

func TestGatewayNetworkGatePreservesApplications(t *testing.T) {
	original := gatewayFixturePod()
	p := original.DeepCopy()
	if err := AddGatewayNetworkGate(p, ownedGateImage); err != nil {
		t.Fatal(err)
	}
	if len(p.Spec.InitContainers) != 1 || len(p.Spec.Volumes) != 2 || p.Spec.InitContainers[0].Name != NetworkGateContainer || p.Spec.InitContainers[0].Image != ownedGateImage || p.Spec.InitContainers[0].SecurityContext.Capabilities.Add != nil || p.Spec.InitContainers[0].VolumeMounts[0].Name != networkGateVolume {
		t.Fatal("gate changed privilege or storage boundary")
	}
	p.Spec.InitContainers = nil
	p.Spec.Volumes = p.Spec.Volumes[:1]
	if !reflect.DeepEqual(p, original) {
		t.Fatal("gate changed application")
	}
	// The old contract must not accept this privileged kernel form.
	if AddNetworkGate(original, ownedGateImage) != ErrAgentCA {
		t.Fatal("unprivileged gate was relaxed")
	}
}

func TestGatewayNetworkGateRejectsMutationsWithoutChangingPod(t *testing.T) {
	mutations := map[string]func(*corev1.Pod){
		"init":            func(p *corev1.Pod) { p.Spec.InitContainers = []corev1.Container{{Name: "foreign"}} },
		"ephemeral":       func(p *corev1.Pod) { p.Spec.EphemeralContainers = []corev1.EphemeralContainer{{}} },
		"extra container": func(p *corev1.Pod) { p.Spec.Containers = append(p.Spec.Containers, corev1.Container{Name: "foreign"}) },
		"host network":    func(p *corev1.Pod) { p.Spec.HostNetwork = true },
		"host pid":        func(p *corev1.Pod) { p.Spec.HostPID = true },
		"token":           func(p *corev1.Pod) { p.Spec.AutomountServiceAccountToken = ptr.To(true) },
		"extra sysctl": func(p *corev1.Pod) {
			p.Spec.SecurityContext.Sysctls = append(p.Spec.SecurityContext.Sysctls, corev1.Sysctl{Name: "net.ipv6.conf.all.forwarding", Value: "1"})
		},
		"unconfined pod": func(p *corev1.Pod) { p.Spec.SecurityContext.SeccompProfile.Type = corev1.SeccompProfileTypeUnconfined },
		"unconfined container": func(p *corev1.Pod) {
			p.Spec.Containers[0].SecurityContext.SeccompProfile = &corev1.SeccompProfile{Type: corev1.SeccompProfileTypeUnconfined}
		},
		"windows":      func(p *corev1.Pod) { p.Spec.OS = &corev1.PodOS{Name: corev1.Windows} },
		"missing tun":  func(p *corev1.Pod) { p.Spec.Volumes = nil },
		"block device": func(p *corev1.Pod) { *p.Spec.Volumes[0].HostPath.Type = corev1.HostPathBlockDev },
		"directory":    func(p *corev1.Pod) { p.Spec.Volumes[0].HostPath.Path = "/dev" },
		"second hostpath": func(p *corev1.Pod) {
			p.Spec.Volumes = append(p.Spec.Volumes, corev1.Volume{Name: "host", VolumeSource: corev1.VolumeSource{HostPath: &corev1.HostPathVolumeSource{Path: "/"}}})
		},
		"duplicate tun":         func(p *corev1.Pod) { p.Spec.Volumes = append(p.Spec.Volumes, p.Spec.Volumes[0]) },
		"gate volume collision": func(p *corev1.Pod) { p.Spec.Volumes = append(p.Spec.Volumes, corev1.Volume{Name: networkGateVolume}) },
		"root coredns":          func(p *corev1.Pod) { p.Spec.Containers[1].SecurityContext.RunAsUser = ptr.To(int64(0)) },
		"nonroot tailscale":     func(p *corev1.Pod) { p.Spec.Containers[0].SecurityContext.RunAsUser = ptr.To(int64(65532)) },
		"extra capability": func(p *corev1.Pod) {
			p.Spec.Containers[0].SecurityContext.Capabilities.Add = append(p.Spec.Containers[0].SecurityContext.Capabilities.Add, "SYS_ADMIN")
		},
		"privileged":        func(p *corev1.Pod) { p.Spec.Containers[0].SecurityContext.Privileged = ptr.To(true) },
		"escalation":        func(p *corev1.Pod) { p.Spec.Containers[0].SecurityContext.AllowPrivilegeEscalation = ptr.To(true) },
		"writable root":     func(p *corev1.Pod) { p.Spec.Containers[0].SecurityContext.ReadOnlyRootFilesystem = ptr.To(false) },
		"wrong coredns cap": func(p *corev1.Pod) { p.Spec.Containers[1].SecurityContext.Capabilities.Add[0] = "NET_ADMIN" },
		"tun in coredns": func(p *corev1.Pod) {
			p.Spec.Containers[1].VolumeMounts = append(p.Spec.Containers[1].VolumeMounts, corev1.VolumeMount{Name: "tun", MountPath: "/dev/net/tun"})
		},
		"tun subpath": func(p *corev1.Pod) { p.Spec.Containers[0].VolumeMounts[0].SubPath = "tun" },
		"tun shadow": func(p *corev1.Pod) {
			p.Spec.Containers[0].VolumeMounts = append(p.Spec.Containers[0].VolumeMounts, corev1.VolumeMount{Name: "other", MountPath: "/dev/net/tun"})
		},
		"gate mount": func(p *corev1.Pod) {
			p.Spec.Containers[0].VolumeMounts = append(p.Spec.Containers[0].VolumeMounts, corev1.VolumeMount{Name: networkGateVolume, MountPath: "/other"})
		},
	}
	for name, mutate := range mutations {
		t.Run(name, func(t *testing.T) {
			p := gatewayFixturePod()
			mutate(p)
			before := p.DeepCopy()
			if AddGatewayNetworkGate(p, ownedGateImage) != ErrAgentCA || !reflect.DeepEqual(p, before) {
				t.Fatal("unsafe pod accepted or changed on rejection")
			}
		})
	}
	for _, image := range []string{"", "registry.example/fixture:tag", ownedGateImage + "-foreign"} {
		if AddGatewayNetworkGate(gatewayFixturePod(), image) != ErrAgentCA {
			t.Fatal("foreign gate image accepted")
		}
	}
	if AddGatewayNetworkGate(nil, ownedGateImage) != ErrAgentCA {
		t.Fatal("nil pod accepted")
	}
}
