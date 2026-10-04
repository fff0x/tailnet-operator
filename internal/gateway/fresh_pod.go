package gateway

import (
	"net/netip"
	"slices"
	"strings"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	"k8s.io/apimachinery/pkg/util/intstr"
	"k8s.io/utils/ptr"

	tnv1 "tsunaro.io/tailnet-operator/api/v1alpha1"
)

// The optional root argument is only used by synthetic filesystem tests. No CR
// value enters this script. In the pod it reads the actual pod network namespace;
// it NEVER enables forwarding or creates a device. A char-device check does not
// prove TUN ioctl/device-cgroup permissions or packet forwarding.
func forwardingCheck(routes RoutePlan) string {
	script := "set -eu\nroot=${1:-}\nfail() { echo 'gateway kernel prerequisites unavailable' >&2; exit 1; }\n[ -c \"$root/dev/net/tun\" ] || fail\n"
	v4, v6 := false, false
	for _, route := range routes.Routes {
		p := netip.MustParsePrefix(route) // Only called with PlanRoutes output.
		v4 = v4 || p.Addr().Is4()
		v6 = v6 || p.Addr().Is6()
	}
	if v4 {
		script += "[ \"$(cat \"$root/proc/sys/net/ipv4/ip_forward\" 2>/dev/null)\" = 1 ] || fail\n"
	}
	if v6 {
		script += "[ \"$(cat \"$root/proc/sys/net/ipv6/conf/all/forwarding\" 2>/dev/null)\" = 1 ] || fail\n"
	}
	return script
}

func freshPod(g *tnv1.TailnetGateway, server string, routes RoutePlan, configName string) corev1.PodSpec {
	security := func(uid int64, capabilities ...corev1.Capability) *corev1.SecurityContext {
		return &corev1.SecurityContext{RunAsUser: ptr.To(uid), RunAsGroup: ptr.To(uid), RunAsNonRoot: ptr.To(uid != 0),
			Privileged: ptr.To(false), AllowPrivilegeEscalation: ptr.To(false), ReadOnlyRootFilesystem: ptr.To(true),
			Capabilities: &corev1.Capabilities{Drop: []corev1.Capability{"ALL"}, Add: capabilities}}
	}
	resources := func(memory string) corev1.ResourceRequirements {
		return corev1.ResourceRequirements{Requests: corev1.ResourceList{corev1.ResourceCPU: resource.MustParse("50m"), corev1.ResourceMemory: resource.MustParse("64Mi")}, Limits: corev1.ResourceList{corev1.ResourceMemory: resource.MustParse(memory)}}
	}
	tags := slices.Clone(g.Spec.Tags)
	slices.Sort(tags)
	tags = slices.Compact(tags)
	healthAddr := "0.0.0.0:8080"
	if netip.MustParseAddr(string(g.Spec.DNS.ServiceClusterIP)).Is6() {
		healthAddr = "[::]:8080"
	}
	tailscale := corev1.Container{
		Name: "tailscale", Image: string(g.Spec.Image), ImagePullPolicy: corev1.PullIfNotPresent,
		Command: []string{"/usr/local/bin/containerboot"}, SecurityContext: security(0, "NET_ADMIN"),
		Env: []corev1.EnvVar{
			{Name: "TS_USERSPACE", Value: "false"}, {Name: "TS_DEBUG_FIREWALL_MODE", Value: "nftables"},
			{Name: "TS_ROUTES", Value: strings.Join(routes.Routes, ",")}, {Name: "TS_HOSTNAME", Value: g.Spec.Hostname},
			{Name: "TS_STATE_DIR", Value: "/var/lib/tailscale"}, {Name: "TS_SOCKET", Value: "/tmp/tailscaled.sock"},
			{Name: "TS_KUBE_SECRET", Value: string(g.Spec.StateSecretRef.Name)}, {Name: "TS_ACCEPT_DNS", Value: "false"},
			// Reconcile explicit prefs on each boot; no --force-reauth. This fresh-only
			// model must not reset the preferences of an adopted node.
			{Name: "TS_AUTH_ONCE", Value: "false"},
			{Name: "TS_EXTRA_ARGS", Value: "--login-server=" + server + " --reset --accept-routes=false --advertise-tags=" + strings.Join(tags, ",")},
			{Name: "TS_AUTHKEY", ValueFrom: &corev1.EnvVarSource{SecretKeyRef: &corev1.SecretKeySelector{LocalObjectReference: corev1.LocalObjectReference{Name: string(g.Spec.AuthKeySecretRef.Name)}, Key: g.Spec.AuthKeySecretRef.Key}}},
			{Name: "TS_ENABLE_HEALTH_CHECK", Value: "true"}, {Name: "TS_LOCAL_ADDR_PORT", Value: healthAddr},
		},
		Ports: []corev1.ContainerPort{{Name: "kernel-health", ContainerPort: 8080, Protocol: corev1.ProtocolTCP}},
		// containerboot health only establishes a Tailscale address, not routes,
		// persistent identity binding, DNS correctness or Gateway Ready.
		ReadinessProbe: &corev1.Probe{ProbeHandler: corev1.ProbeHandler{HTTPGet: &corev1.HTTPGetAction{Path: "/healthz", Port: intstr.FromString("kernel-health")}}, PeriodSeconds: 10, TimeoutSeconds: 2},
		Resources:      resources("256Mi"),
		VolumeMounts: []corev1.VolumeMount{
			{Name: "state-cache", MountPath: "/var/lib/tailscale"}, {Name: "tmp", MountPath: "/tmp"}, {Name: "run", MountPath: "/var/run"},
			{Name: "tun", MountPath: "/dev/net/tun"}, {Name: "api-access", MountPath: "/var/run/secrets/kubernetes.io/serviceaccount", ReadOnly: true},
		},
	}
	dns := corev1.Container{
		Name: "coredns", Image: string(g.Spec.DNS.Image), ImagePullPolicy: corev1.PullIfNotPresent,
		Command: []string{"/coredns"}, Args: []string{"-conf", DNSWorkingDirectory + "/Corefile"}, WorkingDir: DNSWorkingDirectory,
		SecurityContext: security(65532, "NET_BIND_SERVICE"), Resources: resources("128Mi"),
		Ports:          []corev1.ContainerPort{{Name: "dns-udp", ContainerPort: 53, Protocol: corev1.ProtocolUDP}, {Name: "dns-tcp", ContainerPort: 53, Protocol: corev1.ProtocolTCP}},
		ReadinessProbe: &corev1.Probe{ProbeHandler: corev1.ProbeHandler{TCPSocket: &corev1.TCPSocketAction{Port: intstr.FromString("dns-tcp")}}, PeriodSeconds: 10, TimeoutSeconds: 2},
		VolumeMounts:   []corev1.VolumeMount{{Name: "dns-config", MountPath: DNSWorkingDirectory, ReadOnly: true}},
	}
	return corev1.PodSpec{
		OS: &corev1.PodOS{Name: corev1.Linux}, NodeSelector: map[string]string{"kubernetes.io/os": "linux"},
		ServiceAccountName: g.Name, AutomountServiceAccountToken: ptr.To(false), EnableServiceLinks: ptr.To(false),
		SecurityContext: &corev1.PodSecurityContext{SeccompProfile: &corev1.SeccompProfile{Type: corev1.SeccompProfileTypeRuntimeDefault}},
		InitContainers: []corev1.Container{{Name: "kernel-preflight", Image: string(g.Spec.Image), ImagePullPolicy: corev1.PullIfNotPresent,
			Command: []string{"/bin/sh", "-c", forwardingCheck(routes)}, SecurityContext: security(65532), Resources: resources("64Mi"),
			VolumeMounts: []corev1.VolumeMount{{Name: "tun", MountPath: "/dev/net/tun", ReadOnly: true}}}},
		Containers: []corev1.Container{tailscale, dns},
		Volumes: []corev1.Volume{
			{Name: "state-cache", VolumeSource: corev1.VolumeSource{EmptyDir: &corev1.EmptyDirVolumeSource{}}},
			{Name: "tmp", VolumeSource: corev1.VolumeSource{EmptyDir: &corev1.EmptyDirVolumeSource{}}},
			{Name: "run", VolumeSource: corev1.VolumeSource{EmptyDir: &corev1.EmptyDirVolumeSource{}}},
			{Name: "tun", VolumeSource: corev1.VolumeSource{HostPath: &corev1.HostPathVolumeSource{Path: "/dev/net/tun", Type: ptr.To(corev1.HostPathCharDev)}}},
			{Name: "dns-config", VolumeSource: corev1.VolumeSource{ConfigMap: &corev1.ConfigMapVolumeSource{LocalObjectReference: corev1.LocalObjectReference{Name: configName}, Items: []corev1.KeyToPath{{Key: "Corefile", Path: "Corefile"}, {Key: DNSZoneFile, Path: DNSZoneFile}}}}},
			// Only tailscale receives this bounded, rotating token projection. No
			// token or persistent state is shared with CoreDNS or the init container.
			{Name: "api-access", VolumeSource: corev1.VolumeSource{Projected: &corev1.ProjectedVolumeSource{DefaultMode: ptr.To(int32(0400)), Sources: []corev1.VolumeProjection{
				{ServiceAccountToken: &corev1.ServiceAccountTokenProjection{Path: "token", ExpirationSeconds: ptr.To(int64(3600))}},
				{ConfigMap: &corev1.ConfigMapProjection{LocalObjectReference: corev1.LocalObjectReference{Name: "kube-root-ca.crt"}, Items: []corev1.KeyToPath{{Key: "ca.crt", Path: "ca.crt"}}}},
				{DownwardAPI: &corev1.DownwardAPIProjection{Items: []corev1.DownwardAPIVolumeFile{{Path: "namespace", FieldRef: &corev1.ObjectFieldSelector{APIVersion: "v1", FieldPath: "metadata.namespace"}}}}},
			}}}},
		},
	}
}
