package kindfixture

import (
	"reflect"
	"testing"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	"k8s.io/utils/ptr"
)

func gatedGatewayValidationPod(t *testing.T) *corev1.Pod {
	t.Helper()
	p := gatewayFixturePod()
	p.Spec.Containers[0].Image = "pinned-kernel-image"
	p.Spec.InitContainers = []corev1.Container{{
		Name: "kernel-preflight", Image: "pinned-kernel-image",
		SecurityContext: &corev1.SecurityContext{
			RunAsUser: ptr.To(int64(65532)), RunAsGroup: ptr.To(int64(65532)), RunAsNonRoot: ptr.To(true),
			Privileged: ptr.To(false), AllowPrivilegeEscalation: ptr.To(false), ReadOnlyRootFilesystem: ptr.To(true),
			Capabilities: &corev1.Capabilities{Drop: []corev1.Capability{"ALL"}},
		},
		VolumeMounts: []corev1.VolumeMount{{Name: "tun", MountPath: "/dev/net/tun", ReadOnly: true}},
	}}
	if err := AddGatewayNetworkGate(p, ownedGateImage); err != nil {
		t.Fatalf("build gated gateway fixture: %v", err)
	}
	return p
}

func TestValidateGatewayNetworkGateAcceptsWithoutMutation(t *testing.T) {
	for name, defaults := range map[string]func(*corev1.Container){
		"exact": func(*corev1.Container) {},
		"termination path default": func(c *corev1.Container) {
			c.TerminationMessagePath = "/dev/termination-log"
		},
		"termination policy default": func(c *corev1.Container) {
			c.TerminationMessagePolicy = corev1.TerminationMessageReadFile
		},
		"both termination defaults": func(c *corev1.Container) {
			c.TerminationMessagePath = "/dev/termination-log"
			c.TerminationMessagePolicy = corev1.TerminationMessageReadFile
		},
	} {
		t.Run(name, func(t *testing.T) {
			p := gatedGatewayValidationPod(t)
			defaults(&p.Spec.InitContainers[0])
			before := p.DeepCopy()
			if err := ValidateGatewayNetworkGate(p, ownedGateImage); err != nil {
				t.Errorf("valid gate rejected: %v", err)
			}
			if !reflect.DeepEqual(p, before) {
				t.Fatal("validation mutated the gated Pod")
			}
		})
	}
}

func TestValidateGatewayNetworkGateRejectsWithoutMutation(t *testing.T) {
	for name, mutate := range map[string]func(*corev1.Pod){
		"gate command": func(p *corev1.Pod) { p.Spec.InitContainers[0].Command = []string{"/bin/true"} },
		"gate args":    func(p *corev1.Pod) { p.Spec.InitContainers[0].Args = []string{"--action=release"} },
		"gate image":   func(p *corev1.Pod) { p.Spec.InitContainers[0].Image = "foreign-image" },
		"gate pull policy": func(p *corev1.Pod) {
			p.Spec.InitContainers[0].ImagePullPolicy = corev1.PullAlways
		},
		"gate env value": func(p *corev1.Pod) {
			p.Spec.InitContainers[0].Env[0] = corev1.EnvVar{Name: "POD_UID", Value: "foreign-uid"}
		},
		"gate env field": func(p *corev1.Pod) {
			p.Spec.InitContainers[0].Env[0].ValueFrom.FieldRef.FieldPath = "metadata.name"
		},
		"extra gate env": func(p *corev1.Pod) {
			p.Spec.InitContainers[0].Env = append(p.Spec.InitContainers[0].Env, corev1.EnvVar{Name: "EXTRA", Value: "1"})
		},
		"gate security missing": func(p *corev1.Pod) { p.Spec.InitContainers[0].SecurityContext = nil },
		"gate root": func(p *corev1.Pod) {
			p.Spec.InitContainers[0].SecurityContext.RunAsUser = ptr.To(int64(0))
		},
		"gate capability": func(p *corev1.Pod) {
			p.Spec.InitContainers[0].SecurityContext.Capabilities.Add = []corev1.Capability{"NET_ADMIN"}
		},
		"gate writable root": func(p *corev1.Pod) {
			p.Spec.InitContainers[0].SecurityContext.ReadOnlyRootFilesystem = ptr.To(false)
		},
		"gate mount": func(p *corev1.Pod) { p.Spec.InitContainers[0].VolumeMounts[0].MountPath = "/other" },
		"gate resources": func(p *corev1.Pod) {
			p.Spec.InitContainers[0].Resources.Limits[corev1.ResourceMemory] = resource.MustParse("1Gi")
		},
		"nonstandard termination path": func(p *corev1.Pod) {
			p.Spec.InitContainers[0].TerminationMessagePath = "/other"
		},
		"nonstandard termination policy": func(p *corev1.Pod) {
			p.Spec.InitContainers[0].TerminationMessagePolicy = corev1.TerminationMessageFallbackToLogsOnError
		},
		"gate store type": func(p *corev1.Pod) {
			p.Spec.Volumes[1].VolumeSource = corev1.VolumeSource{HostPath: &corev1.HostPathVolumeSource{Path: "/tmp"}}
		},
		"gate store disk": func(p *corev1.Pod) { p.Spec.Volumes[1].EmptyDir.Medium = corev1.StorageMediumDefault },
		"gate store size": func(p *corev1.Pod) {
			p.Spec.Volumes[1].EmptyDir.SizeLimit = ptr.To(resource.MustParse("8Mi"))
		},
		"gate store unlimited": func(p *corev1.Pod) { p.Spec.Volumes[1].EmptyDir.SizeLimit = nil },
		"duplicate gate store": func(p *corev1.Pod) {
			p.Spec.Volumes = append(p.Spec.Volumes, *p.Spec.Volumes[1].DeepCopy())
		},
		"missing gate store": func(p *corev1.Pod) { p.Spec.Volumes = p.Spec.Volumes[:1] },
		"reordered preflight": func(p *corev1.Pod) {
			p.Spec.InitContainers[0], p.Spec.InitContainers[1] = p.Spec.InitContainers[1], p.Spec.InitContainers[0]
		},
		"missing preflight": func(p *corev1.Pod) { p.Spec.InitContainers = p.Spec.InitContainers[:1] },
		"missing gate":      func(p *corev1.Pod) { p.Spec.InitContainers = p.Spec.InitContainers[1:] },
		"missing inits":     func(p *corev1.Pod) { p.Spec.InitContainers = nil },
		"extra init": func(p *corev1.Pod) {
			p.Spec.InitContainers = append(p.Spec.InitContainers, corev1.Container{Name: "foreign"})
		},
		"restartable preflight": func(p *corev1.Pod) {
			p.Spec.InitContainers[1].RestartPolicy = ptr.To(corev1.ContainerRestartPolicyAlways)
		},
		"restartable gate": func(p *corev1.Pod) {
			p.Spec.InitContainers[0].RestartPolicy = ptr.To(corev1.ContainerRestartPolicyAlways)
		},
		"preflight root": func(p *corev1.Pod) {
			p.Spec.InitContainers[1].SecurityContext.RunAsUser = ptr.To(int64(0))
		},
		"preflight writable tun": func(p *corev1.Pod) { p.Spec.InitContainers[1].VolumeMounts[0].ReadOnly = false },
		"preflight image":        func(p *corev1.Pod) { p.Spec.InitContainers[1].Image = "foreign-image" },
		"preflight gate mount": func(p *corev1.Pod) {
			p.Spec.InitContainers[1].VolumeMounts = append(p.Spec.InitContainers[1].VolumeMounts, corev1.VolumeMount{Name: networkGateVolume, MountPath: "/fixture-gate"})
		},
		"host network": func(p *corev1.Pod) { p.Spec.HostNetwork = true },
		"token":        func(p *corev1.Pod) { p.Spec.AutomountServiceAccountToken = ptr.To(true) },
		"ephemeral":    func(p *corev1.Pod) { p.Spec.EphemeralContainers = []corev1.EphemeralContainer{{}} },
		"extra app": func(p *corev1.Pod) {
			p.Spec.Containers = append(p.Spec.Containers, corev1.Container{Name: "foreign"})
		},
		"missing apps": func(p *corev1.Pod) { p.Spec.Containers = nil },
		"privileged app": func(p *corev1.Pod) {
			p.Spec.Containers[0].SecurityContext.Privileged = ptr.To(true)
		},
		"app escalation": func(p *corev1.Pod) {
			p.Spec.Containers[0].SecurityContext.AllowPrivilegeEscalation = ptr.To(true)
		},
		"app capability": func(p *corev1.Pod) {
			p.Spec.Containers[0].SecurityContext.Capabilities.Add = append(p.Spec.Containers[0].SecurityContext.Capabilities.Add, "SYS_ADMIN")
		},
		"root coredns": func(p *corev1.Pod) { p.Spec.Containers[1].SecurityContext.RunAsUser = ptr.To(int64(0)) },
		"tailscale gate store": func(p *corev1.Pod) {
			p.Spec.Containers[0].VolumeMounts = append(p.Spec.Containers[0].VolumeMounts, corev1.VolumeMount{Name: networkGateVolume, MountPath: "/other"})
		},
		"coredns gate store": func(p *corev1.Pod) {
			p.Spec.Containers[1].VolumeMounts = []corev1.VolumeMount{{Name: networkGateVolume, MountPath: "/other"}}
		},
		"app gate path": func(p *corev1.Pod) {
			p.Spec.Containers[1].VolumeMounts = []corev1.VolumeMount{{Name: "other", MountPath: "/fixture-gate"}}
		},
	} {
		t.Run(name, func(t *testing.T) {
			p := gatedGatewayValidationPod(t)
			mutate(p)
			before := p.DeepCopy()
			if err := ValidateGatewayNetworkGate(p, ownedGateImage); err != ErrAgentCA {
				t.Errorf("unsafe gate validation = %v, want %v", err, ErrAgentCA)
			}
			if !reflect.DeepEqual(p, before) {
				t.Fatal("rejection mutated the gated Pod")
			}
		})
	}
}

func TestValidateGatewayNetworkGateRejectsInvalidInputs(t *testing.T) {
	if err := ValidateGatewayNetworkGate(nil, ownedGateImage); err != ErrAgentCA {
		t.Errorf("nil Pod validation = %v, want %v", err, ErrAgentCA)
	}
	for _, image := range []string{"", "registry.example/fixture:tag", ownedGateImage + "-foreign", "localhost/tn-source-netprobe:tn-kind-0123456789"} {
		t.Run(image, func(t *testing.T) {
			p := gatedGatewayValidationPod(t)
			before := p.DeepCopy()
			if err := ValidateGatewayNetworkGate(p, image); err != ErrAgentCA {
				t.Errorf("foreign image validation = %v, want %v", err, ErrAgentCA)
			}
			if !reflect.DeepEqual(p, before) {
				t.Fatal("invalid image rejection mutated the Pod")
			}
		})
	}
}
