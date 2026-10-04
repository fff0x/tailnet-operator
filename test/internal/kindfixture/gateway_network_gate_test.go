package kindfixture

import (
	"reflect"
	"testing"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/utils/ptr"

	tnv1 "tsunaro.io/tailnet-operator/api/v1alpha1"
	"tsunaro.io/tailnet-operator/internal/gateway"
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

func TestGatewayNetworkGateAcceptsFreshPodPreflightFirst(t *testing.T) {
	in := gateway.FreshInputs{Namespace: "operator", DNSSerial: 1,
		Gateway: &tnv1.TailnetGateway{ObjectMeta: metav1.ObjectMeta{Name: "router", UID: "fixture-uid"}, Spec: tnv1.TailnetGatewaySpec{
			TailnetRef: tnv1.GatewayLocalReference{Name: "tailnet"}, Hostname: "router", Replicas: 1, DeletionPolicy: "Retain",
			StateSecretRef: tnv1.GatewayLocalReference{Name: "router-state"}, AuthKeySecretRef: &tnv1.GatewayAuthKeyReference{Name: "router-auth", Key: "TS_AUTHKEY"},
			Image: "ghcr.io/tailscale/tailscale:v1.102.4", Tags: []string{"tag:fabric"},
			Routes:  tnv1.GatewayRoutes{LAN: []tnv1.GatewayPrefix{"192.0.2.0/24"}},
			Service: tnv1.GatewayService{LoadBalancerIP: "198.51.100.1", TailnetLBCIDR: "198.51.100.0/24"},
			DNS:     tnv1.GatewayDNS{Zone: "tail.example", ServiceName: "router-dns", ServiceClusterIP: "10.96.0.53", Image: "coredns/coredns:1.14.6"},
		}}, Tailnet: &tnv1.Tailnet{ObjectMeta: metav1.ObjectMeta{Name: "tailnet"}, Spec: tnv1.TailnetSpec{Server: "https://headscale.example"}}}
	plan, err := gateway.RenderFresh(in)
	if err != nil {
		t.Fatal(err)
	}
	for _, obj := range plan.Objects {
		sts, ok := obj.(*appsv1.StatefulSet)
		if !ok {
			continue
		}
		p := &corev1.Pod{Spec: *sts.Spec.Template.Spec.DeepCopy()}
		before := p.DeepCopy()
		if err := AddGatewayNetworkGate(p, ownedGateImage); err != nil || len(p.Spec.InitContainers) != 2 || p.Spec.InitContainers[0].Name != NetworkGateContainer || p.Spec.InitContainers[1].Name != "kernel-preflight" {
			t.Fatal("fresh pod preflight cannot run after fixture gate")
		}
		p.Spec.InitContainers = p.Spec.InitContainers[1:]
		p.Spec.Volumes = p.Spec.Volumes[:len(p.Spec.Volumes)-1]
		if !reflect.DeepEqual(p, before) {
			t.Fatal("gate changed the fresh pod or its preflight")
		}
		return
	}
	t.Fatal("fresh plan has no StatefulSet")
}

func TestGatewayNetworkGateRejectsUnsafePreflight(t *testing.T) {
	baseline := func() *corev1.Pod {
		p := gatewayFixturePod()
		p.Spec.Containers[0].Image = "pinned-kernel-image"
		p.Spec.InitContainers = []corev1.Container{{Name: "kernel-preflight", Image: "pinned-kernel-image",
			SecurityContext: &corev1.SecurityContext{RunAsUser: ptr.To(int64(65532)), RunAsGroup: ptr.To(int64(65532)), RunAsNonRoot: ptr.To(true), Privileged: ptr.To(false), AllowPrivilegeEscalation: ptr.To(false), ReadOnlyRootFilesystem: ptr.To(true), Capabilities: &corev1.Capabilities{Drop: []corev1.Capability{"ALL"}}},
			VolumeMounts:    []corev1.VolumeMount{{Name: "tun", MountPath: "/dev/net/tun", ReadOnly: true}},
		}}
		return p
	}
	for name, mutate := range map[string]func(*corev1.Pod){
		"root": func(p *corev1.Pod) { p.Spec.InitContainers[0].SecurityContext.RunAsUser = ptr.To(int64(0)) },
		"extra cap": func(p *corev1.Pod) {
			p.Spec.InitContainers[0].SecurityContext.Capabilities.Add = []corev1.Capability{"NET_ADMIN"}
		},
		"writable tun": func(p *corev1.Pod) { p.Spec.InitContainers[0].VolumeMounts[0].ReadOnly = false },
		"token mount": func(p *corev1.Pod) {
			p.Spec.InitContainers[0].VolumeMounts = append(p.Spec.InitContainers[0].VolumeMounts, corev1.VolumeMount{Name: "token", MountPath: "/token"})
		},
		"foreign image": func(p *corev1.Pod) { p.Spec.InitContainers[0].Image = "foreign-image" },
	} {
		t.Run(name, func(t *testing.T) {
			p := baseline()
			mutate(p)
			before := p.DeepCopy()
			if AddGatewayNetworkGate(p, ownedGateImage) != ErrAgentCA || !reflect.DeepEqual(p, before) {
				t.Fatal("unsafe preflight accepted or changed")
			}
		})
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
