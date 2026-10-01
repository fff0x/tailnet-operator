package kindfixture

import (
	"regexp"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"
)

const (
	NetworkGateContainer = "fixture-network-gate"
	networkGateVolume    = "fixture-network-proof"
)

var gateImagePattern = regexp.MustCompile(`^localhost/tn-source-netprobe:tn-kind-[a-z0-9]{10}$`)

func ValidNetworkGateImage(image string) bool { return gateImagePattern.MatchString(image) }

// AddNetworkGate is fixture-only startup wiring. It gives only the init
// container a small writable volume. The application image, command, environment
// and mounts stay unchanged. A trusted driver must verify the actual Pod's
// network and live ownership before releasing the init process via exec.
func AddNetworkGate(pod *corev1.Pod, image string) error {
	v, c, err := networkGateResources(pod, image)
	if err != nil {
		return err
	}
	pod.Spec.Volumes = append(pod.Spec.Volumes, v)
	pod.Spec.InitContainers = []corev1.Container{c}
	return nil
}

func networkGateResources(pod *corev1.Pod, image string) (corev1.Volume, corev1.Container, error) {
	if !ValidNetworkGateImage(image) || pod == nil || len(pod.Spec.Containers) == 0 || len(pod.Spec.InitContainers) != 0 || len(pod.Spec.EphemeralContainers) != 0 || pod.Spec.HostNetwork || pod.Spec.HostPID || pod.Spec.HostIPC ||
		pod.Spec.ShareProcessNamespace != nil && *pod.Spec.ShareProcessNamespace || pod.Spec.AutomountServiceAccountToken == nil || *pod.Spec.AutomountServiceAccountToken {
		return corev1.Volume{}, corev1.Container{}, ErrAgentCA
	}
	for _, v := range pod.Spec.Volumes {
		if v.Name == networkGateVolume || v.HostPath != nil {
			return corev1.Volume{}, corev1.Container{}, ErrAgentCA
		}
	}
	for _, c := range pod.Spec.Containers {
		// Resolve UID/non-root from Pod and container settings without changing them.
		var user *int64
		var nonRoot *bool
		if pod.Spec.SecurityContext != nil {
			user = pod.Spec.SecurityContext.RunAsUser
			nonRoot = pod.Spec.SecurityContext.RunAsNonRoot
		}
		sc := c.SecurityContext
		if sc != nil {
			if sc.RunAsUser != nil {
				user = sc.RunAsUser
			}
			if sc.RunAsNonRoot != nil {
				nonRoot = sc.RunAsNonRoot
			}
		}
		if user == nil || *user != 65532 || nonRoot == nil || !*nonRoot {
			return corev1.Volume{}, corev1.Container{}, ErrAgentCA
		}
		if c.Name == NetworkGateContainer || sc == nil || sc.Privileged != nil && *sc.Privileged || sc.AllowPrivilegeEscalation == nil || *sc.AllowPrivilegeEscalation || sc.Capabilities == nil || len(sc.Capabilities.Add) != 0 {
			return corev1.Volume{}, corev1.Container{}, ErrAgentCA
		}
		all := false
		for _, cap := range sc.Capabilities.Drop {
			all = all || cap == "ALL"
		}
		if !all {
			return corev1.Volume{}, corev1.Container{}, ErrAgentCA
		}
		for _, m := range c.VolumeMounts {
			if m.Name == networkGateVolume || m.MountPath == "/fixture-gate" {
				return corev1.Volume{}, corev1.Container{}, ErrAgentCA
			}
		}
	}
	yes, no := true, false
	uid := int64(65532)
	size := resource.MustParse("4Mi")
	v := corev1.Volume{Name: networkGateVolume, VolumeSource: corev1.VolumeSource{EmptyDir: &corev1.EmptyDirVolumeSource{Medium: corev1.StorageMediumMemory, SizeLimit: &size}}}
	c := corev1.Container{Name: NetworkGateContainer, Image: image, ImagePullPolicy: corev1.PullNever, Command: []string{"/netgate"}, Args: []string{"--action=hold", "--fixture=p1.8-http"},
		Env:             []corev1.EnvVar{{Name: "POD_UID", ValueFrom: &corev1.EnvVarSource{FieldRef: &corev1.ObjectFieldSelector{APIVersion: "v1", FieldPath: "metadata.uid"}}}},
		SecurityContext: &corev1.SecurityContext{RunAsNonRoot: &yes, RunAsUser: &uid, RunAsGroup: &uid, AllowPrivilegeEscalation: &no, ReadOnlyRootFilesystem: &yes, Capabilities: &corev1.Capabilities{Drop: []corev1.Capability{"ALL"}}, SeccompProfile: &corev1.SeccompProfile{Type: corev1.SeccompProfileTypeRuntimeDefault}},
		Resources:       corev1.ResourceRequirements{Requests: corev1.ResourceList{corev1.ResourceCPU: resource.MustParse("10m"), corev1.ResourceMemory: resource.MustParse("16Mi")}, Limits: corev1.ResourceList{corev1.ResourceCPU: resource.MustParse("100m"), corev1.ResourceMemory: resource.MustParse("64Mi")}},
		VolumeMounts:    []corev1.VolumeMount{{Name: networkGateVolume, MountPath: "/fixture-gate"}},
	}
	return v, c, nil
}
