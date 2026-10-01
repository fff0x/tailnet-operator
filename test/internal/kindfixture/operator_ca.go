package kindfixture

import (
	"errors"
	"regexp"
	"time"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
)

var (
	ErrOperatorCA        = errors.New("kind fixture: operator CA injection rejected")
	operatorImagePattern = regexp.MustCompile(`^localhost/tailnet-operator-e2e:tn-kind-[a-z0-9]{10}$`)
)

// AddOperatorCA mounts only an owned, immutable public control CA into the
// installed fixture operator. The caller verifies live cluster ownership and
// persists the Deployment; this helper performs no API operations. Reinvocation
// fails closed rather than replacing an existing volume or mount.
func AddOperatorCA(deployment *appsv1.Deployment, namespace *corev1.Namespace, public *corev1.ConfigMap, expectedImage string) error {
	if deployment == nil || !ownedNamespace(namespace) || public == nil || !operatorImagePattern.MatchString(expectedImage) {
		return ErrOperatorCA
	}
	if deployment.Namespace != namespace.Name || deployment.Name != "tailnet-operator" || deployment.UID == "" || deployment.ResourceVersion == "" || deployment.DeletionTimestamp != nil ||
		public.Name != controlCAVolume || public.Namespace != namespace.Name || public.Labels[OwnerLabel] != string(namespace.UID) || public.DeletionTimestamp != nil ||
		public.Immutable == nil || !*public.Immutable || len(public.Data) != 1 || len(public.BinaryData) != 0 || !publicRoot([]byte(public.Data[controlCAKey]), time.Now()) {
		return ErrOperatorCA
	}
	pod := &deployment.Spec.Template
	p := &pod.Spec
	if pod.Labels["app.kubernetes.io/name"] != "tailnet-operator" || len(p.Containers) != 1 || p.ServiceAccountName != "tailnet-operator" ||
		p.AutomountServiceAccountToken != nil && !*p.AutomountServiceAccountToken || p.HostNetwork || p.HostPID || p.HostIPC ||
		p.ShareProcessNamespace != nil && *p.ShareProcessNamespace || len(p.InitContainers) != 0 || len(p.EphemeralContainers) != 0 || len(p.Volumes) != 0 {
		return ErrOperatorCA
	}
	c := &p.Containers[0]
	if c.Name != "operator" || c.Image != expectedImage || len(c.Command) != 1 || c.Command[0] != "/tailnet-operator" || len(c.Args) != 1 || c.Args[0] != "--leader-elect=true" ||
		len(c.VolumeMounts) != 0 || len(c.VolumeDevices) != 0 || len(c.EnvFrom) != 0 || !literalEnv(c.Env, "SSL_CERT_FILE", controlCAPath) || !literalEnv(c.Env, "OPERATOR_IMAGE", expectedImage) || !operatorCASecurity(p.SecurityContext, c.SecurityContext) {
		return ErrOperatorCA
	}
	seen := make(map[string]bool, len(c.Env))
	for _, env := range c.Env {
		if env.Name == "" || seen[env.Name] {
			return ErrOperatorCA
		}
		seen[env.Name] = true
	}

	// All checks precede both mutations. This is a public immutable file, not a
	// rotating Secret; SubPath deliberately replaces the scratch bundle path.
	mode := int32(0644)
	p.Volumes = []corev1.Volume{{Name: controlCAVolume, VolumeSource: corev1.VolumeSource{
		ConfigMap: &corev1.ConfigMapVolumeSource{
			LocalObjectReference: corev1.LocalObjectReference{Name: controlCAVolume},
			DefaultMode:          &mode,
			Items:                []corev1.KeyToPath{{Key: controlCAKey, Path: controlCAKey}},
		},
	}}}
	c.VolumeMounts = []corev1.VolumeMount{{Name: controlCAVolume, MountPath: controlCAPath, SubPath: controlCAKey, ReadOnly: true}}
	return nil
}

// Require chart hardening at Pod level and reject weakening container overrides.
func operatorCASecurity(p *corev1.PodSecurityContext, c *corev1.SecurityContext) bool {
	if p == nil || p.RunAsNonRoot == nil || !*p.RunAsNonRoot || p.RunAsUser == nil || *p.RunAsUser != 65532 || p.RunAsGroup == nil || *p.RunAsGroup != 65532 || !operatorCARuntimeDefault(p.SeccompProfile) ||
		p.SELinuxOptions != nil || p.WindowsOptions != nil || len(p.Sysctls) != 0 || len(p.SupplementalGroups) != 0 || p.FSGroup != nil && *p.FSGroup != 65532 ||
		p.AppArmorProfile != nil && (p.AppArmorProfile.Type != corev1.AppArmorProfileTypeRuntimeDefault || p.AppArmorProfile.LocalhostProfile != nil) {
		return false
	}
	if c == nil || c.Privileged != nil && *c.Privileged || c.AllowPrivilegeEscalation == nil || *c.AllowPrivilegeEscalation || c.ReadOnlyRootFilesystem == nil || !*c.ReadOnlyRootFilesystem ||
		c.RunAsNonRoot != nil && !*c.RunAsNonRoot || c.RunAsUser != nil && *c.RunAsUser != 65532 || c.RunAsGroup != nil && *c.RunAsGroup != 65532 ||
		c.SeccompProfile != nil && !operatorCARuntimeDefault(c.SeccompProfile) || c.ProcMount != nil && *c.ProcMount != corev1.DefaultProcMount ||
		c.SELinuxOptions != nil || c.WindowsOptions != nil || c.AppArmorProfile != nil && (c.AppArmorProfile.Type != corev1.AppArmorProfileTypeRuntimeDefault || c.AppArmorProfile.LocalhostProfile != nil) ||
		c.Capabilities == nil || len(c.Capabilities.Add) != 0 {
		return false
	}
	for _, capability := range c.Capabilities.Drop {
		if capability == "ALL" {
			return true
		}
	}
	return false
}

func operatorCARuntimeDefault(profile *corev1.SeccompProfile) bool {
	return profile != nil && profile.Type == corev1.SeccompProfileTypeRuntimeDefault && profile.LocalhostProfile == nil
}
