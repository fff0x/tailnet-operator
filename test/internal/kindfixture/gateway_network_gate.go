package kindfixture

import (
	corev1 "k8s.io/api/core/v1"
)

// AddGatewayNetworkGate is exclusively for disposable gateway fixtures. It
// accepts the kernel pod shape, not the unprivileged agent shape accepted by
// AddNetworkGate. It does not grant privileges, mount devices, or release the
// init gate: the isolated runner must still bind and release the live Pod.
func AddGatewayNetworkGate(pod *corev1.Pod, image string) error {
	if !ValidNetworkGateImage(image) || !gatewayNetworkPod(pod) {
		return ErrAgentCA
	}
	v, c := newNetworkGateResources(image)
	pod.Spec.Volumes = append(pod.Spec.Volumes, v)
	pod.Spec.InitContainers = append([]corev1.Container{c}, pod.Spec.InitContainers...)
	return nil
}

func gatewayNetworkPod(p *corev1.Pod) bool {
	if p == nil {
		return false
	}
	s := &p.Spec
	if len(s.Containers) != 2 || len(s.InitContainers) > 1 || len(s.EphemeralContainers) != 0 ||
		s.HostNetwork || s.HostPID || s.HostIPC || s.ShareProcessNamespace != nil && *s.ShareProcessNamespace ||
		s.AutomountServiceAccountToken == nil || *s.AutomountServiceAccountToken ||
		s.OS != nil && s.OS.Name != corev1.Linux ||
		s.SecurityContext == nil || s.SecurityContext.SeccompProfile == nil || s.SecurityContext.SeccompProfile.Type != corev1.SeccompProfileTypeRuntimeDefault {
		return false
	}
	// A gateway fixture may request only the namespaced forwarding prerequisite
	// allowed by the isolated Kind node. No other pod sysctl is authorized.
	for _, sysctl := range s.SecurityContext.Sysctls {
		if sysctl.Name != "net.ipv4.ip_forward" || sysctl.Value != "1" {
			return false
		}
	}
	if len(s.SecurityContext.Sysctls) > 1 {
		return false
	}
	tunCount := 0
	volumes := make(map[string]bool, len(s.Volumes))
	for _, v := range s.Volumes {
		if v.Name == networkGateVolume || volumes[v.Name] {
			return false
		}
		volumes[v.Name] = true
		if v.HostPath != nil {
			if v.Name != "tun" || v.HostPath.Path != "/dev/net/tun" || v.HostPath.Type == nil || *v.HostPath.Type != corev1.HostPathCharDev || v.VolumeSource.EmptyDir != nil {
				return false
			}
			tunCount++
		} else if v.Name == "tun" {
			return false
		}
	}
	if tunCount != 1 {
		return false
	}
	if len(s.InitContainers) == 1 && !gatewayKernelPreflight(s.InitContainers[0], s.Containers[0].Image) {
		return false
	}
	for i, c := range s.Containers {
		if i == 0 && c.Name != "tailscale" || i == 1 && c.Name != "coredns" || c.SecurityContext == nil ||
			c.SecurityContext.Privileged != nil && *c.SecurityContext.Privileged ||
			c.SecurityContext.AllowPrivilegeEscalation == nil || *c.SecurityContext.AllowPrivilegeEscalation ||
			c.SecurityContext.ReadOnlyRootFilesystem == nil || !*c.SecurityContext.ReadOnlyRootFilesystem ||
			c.SecurityContext.SeccompProfile != nil && c.SecurityContext.SeccompProfile.Type != corev1.SeccompProfileTypeRuntimeDefault ||
			c.SecurityContext.ProcMount != nil && *c.SecurityContext.ProcMount != corev1.DefaultProcMount ||
			c.SecurityContext.Capabilities == nil || len(c.SecurityContext.Capabilities.Drop) != 1 || c.SecurityContext.Capabilities.Drop[0] != "ALL" ||
			len(c.SecurityContext.Capabilities.Add) != 1 {
			return false
		}
		sc := c.SecurityContext
		if sc.RunAsUser == nil || sc.RunAsGroup == nil || sc.RunAsNonRoot == nil {
			return false
		}
		if i == 0 && (*sc.RunAsUser != 0 || *sc.RunAsGroup != 0 || *sc.RunAsNonRoot || sc.Capabilities.Add[0] != "NET_ADMIN") ||
			i == 1 && (*sc.RunAsUser != 65532 || *sc.RunAsGroup != 65532 || !*sc.RunAsNonRoot || sc.Capabilities.Add[0] != "NET_BIND_SERVICE") {
			return false
		}
		tunMounts := 0
		for _, m := range c.VolumeMounts {
			if m.Name == networkGateVolume || m.MountPath == "/fixture-gate" || m.MountPropagation != nil || m.SubPath != "" || m.SubPathExpr != "" {
				return false
			}
			if m.MountPath == "/dev/net/tun" && m.Name != "tun" {
				return false
			}
			if m.Name == "tun" {
				if i != 0 || m.MountPath != "/dev/net/tun" || m.ReadOnly {
					return false
				}
				tunMounts++
			}
		}
		if i == 0 && tunMounts != 1 || i == 1 && tunMounts != 0 {
			return false
		}
	}
	return true
}

// The unprivileged kernel check must remain after the fixture gate. Its only
// mount is read-only TUN, with no token or state. This validates the existing
// init's privilege boundary, not its image contents or shell script semantics.
func gatewayKernelPreflight(c corev1.Container, image string) bool {
	sc := c.SecurityContext
	if c.Name != "kernel-preflight" || c.Image != image || sc == nil ||
		sc.RunAsUser == nil || *sc.RunAsUser != 65532 || sc.RunAsGroup == nil || *sc.RunAsGroup != 65532 ||
		sc.RunAsNonRoot == nil || !*sc.RunAsNonRoot || sc.Privileged != nil && *sc.Privileged ||
		sc.AllowPrivilegeEscalation == nil || *sc.AllowPrivilegeEscalation ||
		sc.ReadOnlyRootFilesystem == nil || !*sc.ReadOnlyRootFilesystem ||
		sc.Capabilities == nil || len(sc.Capabilities.Drop) != 1 || sc.Capabilities.Drop[0] != "ALL" || len(sc.Capabilities.Add) != 0 ||
		sc.SeccompProfile != nil && sc.SeccompProfile.Type != corev1.SeccompProfileTypeRuntimeDefault ||
		len(c.VolumeMounts) != 1 || c.VolumeMounts[0].Name != "tun" || c.VolumeMounts[0].MountPath != "/dev/net/tun" || !c.VolumeMounts[0].ReadOnly ||
		c.VolumeMounts[0].SubPath != "" || c.VolumeMounts[0].SubPathExpr != "" || c.VolumeMounts[0].MountPropagation != nil {
		return false
	}
	return true
}
