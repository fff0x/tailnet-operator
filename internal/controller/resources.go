package controller

import (
	"encoding/json"
	"fmt"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/intstr"

	tnv1 "this-is-fine.io/tailnet-operator/api/v1alpha1"
)

const (
	// fieldOwner is the server-side-apply manager name for everything the operator writes.
	fieldOwner = "tailnet-operator"
	// agentHealthPort is where the agent serves /healthz, /status, /targets.
	agentHealthPort = 9080
	configMount     = "/config"
	targetsFile     = "targets.json"
	// authKeySecretKey is the data key holding the pre-auth key in a CR's authkey Secret.
	authKeySecretKey = "TS_AUTHKEY"
)

// selectorLabels identify one CR's pods and objects. Instance is the CR name, so two egress
// identities in the same namespace never share a selector.
func selectorLabels(crName string) map[string]string {
	return map[string]string{
		"app.kubernetes.io/name":     "tailnet-egress",
		"app.kubernetes.io/instance": crName,
	}
}

func objLabels(crName string) map[string]string {
	l := selectorLabels(crName)
	l["app.kubernetes.io/managed-by"] = fieldOwner
	return l
}

func authKeySecretName(cr string) string    { return cr + "-authkey" }
func targetsConfigMapName(cr string) string { return cr + "-targets" }

// agentTarget is the ConfigMap JSON entry the agent reads.
type agentTarget struct {
	Name       string `json:"name"`
	Address    string `json:"address"`
	Port       int32  `json:"port"`
	ListenPort int32  `json:"listenPort"`
}

// targetsConfigMap holds the agent's target list. Its mtime changing is what makes the agent rebind.
func targetsConfigMap(eg *tnv1.TailnetEgress, ns string, listen map[string]int32) (*corev1.ConfigMap, error) {
	out := make([]agentTarget, 0, len(eg.Spec.Targets))
	for _, t := range eg.Spec.Targets {
		out = append(out, agentTarget{Name: t.Name, Address: t.Address, Port: t.Port, ListenPort: listen[t.Name]})
	}
	b, err := json.Marshal(out)
	if err != nil {
		return nil, err
	}
	return &corev1.ConfigMap{
		TypeMeta:   metav1.TypeMeta{APIVersion: "v1", Kind: "ConfigMap"},
		ObjectMeta: metav1.ObjectMeta{Name: targetsConfigMapName(eg.Name), Namespace: ns, Labels: objLabels(eg.Name)},
		Data:       map[string]string{targetsFile: string(b)},
	}, nil
}

// authKeySecret carries the reusable ephemeral pre-auth key. expiresAt is annotated so the reconciler
// can judge rotation without re-parsing the key.
func authKeySecret(eg *tnv1.TailnetEgress, ns, key, expiresAt string) *corev1.Secret {
	return &corev1.Secret{
		TypeMeta: metav1.TypeMeta{APIVersion: "v1", Kind: "Secret"},
		ObjectMeta: metav1.ObjectMeta{
			Name:        authKeySecretName(eg.Name),
			Namespace:   ns,
			Labels:      objLabels(eg.Name),
			Annotations: map[string]string{"tailnet.this-is-fine.io/expires-at": expiresAt},
		},
		Type:       corev1.SecretTypeOpaque,
		StringData: map[string]string{authKeySecretKey: key},
	}
}

// targetService publishes one target under its own name, so consumers dial <target>.<ns>:<port>.
func targetService(eg *tnv1.TailnetEgress, ns string, t tnv1.Target, listenPort int32) *corev1.Service {
	return &corev1.Service{
		TypeMeta:   metav1.TypeMeta{APIVersion: "v1", Kind: "Service"},
		ObjectMeta: metav1.ObjectMeta{Name: t.Name, Namespace: ns, Labels: objLabels(eg.Name)},
		Spec: corev1.ServiceSpec{
			Selector: selectorLabels(eg.Name),
			Ports: []corev1.ServicePort{{
				Name:       "proxy",
				Port:       t.Port,
				TargetPort: intstr.FromInt32(listenPort),
				Protocol:   corev1.ProtocolTCP,
			}},
		},
	}
}

// egressNetworkPolicy is the only thing keeping the proxy pointed at its allowed namespaces now that
// it no longer lives inside the namespace it serves. Consumers reach the proxy ports; the operator
// (in operatorNS) reaches only the health port, because it scrapes /status and /targets to fill the
// CR status — without that second rule the operator's own probe is blocked and every target shows a
// false NoGrant/unreachable even when the data plane works. Egress stays open, because the pod must
// reach DERP and its peers to work at all.
func egressNetworkPolicy(eg *tnv1.TailnetEgress, ns, operatorNS string) *networkingv1.NetworkPolicy {
	peers := make([]networkingv1.NetworkPolicyPeer, 0, len(eg.Spec.ConsumerNamespaces))
	for _, cns := range eg.Spec.ConsumerNamespaces {
		peers = append(peers, networkingv1.NetworkPolicyPeer{
			NamespaceSelector: &metav1.LabelSelector{
				MatchLabels: map[string]string{"kubernetes.io/metadata.name": cns},
			},
		})
	}
	health := intstr.FromInt32(agentHealthPort)
	return &networkingv1.NetworkPolicy{
		TypeMeta:   metav1.TypeMeta{APIVersion: "networking.k8s.io/v1", Kind: "NetworkPolicy"},
		ObjectMeta: metav1.ObjectMeta{Name: eg.Name, Namespace: ns, Labels: objLabels(eg.Name)},
		Spec: networkingv1.NetworkPolicySpec{
			PodSelector: metav1.LabelSelector{MatchLabels: selectorLabels(eg.Name)},
			PolicyTypes: []networkingv1.PolicyType{networkingv1.PolicyTypeIngress},
			Ingress: []networkingv1.NetworkPolicyIngressRule{
				// Consumers: full access to the proxy ports.
				{From: peers},
				// Operator: health/status scrape only.
				{
					From: []networkingv1.NetworkPolicyPeer{{
						NamespaceSelector: &metav1.LabelSelector{
							MatchLabels: map[string]string{"kubernetes.io/metadata.name": operatorNS},
						},
					}},
					Ports: []networkingv1.NetworkPolicyPort{{Port: &health}},
				},
			},
		},
	}
}

// nonRoot is the pod/container security context. Userspace tsnet needs no privileges and no device,
// so this satisfies PodSecurity "restricted", not just "baseline". RunAsUser is explicit because the
// published image is scratch (no USER directive): without a numeric uid the kubelet cannot verify
// RunAsNonRoot and refuses the pod.
func nonRoot() (*corev1.PodSecurityContext, *corev1.SecurityContext) {
	yes := true
	no := false
	uid := int64(65532)
	pod := &corev1.PodSecurityContext{
		RunAsNonRoot:   &yes,
		RunAsUser:      &uid,
		RunAsGroup:     &uid,
		SeccompProfile: &corev1.SeccompProfile{Type: corev1.SeccompProfileTypeRuntimeDefault},
	}
	container := &corev1.SecurityContext{
		RunAsNonRoot:             &yes,
		RunAsUser:                &uid,
		RunAsGroup:               &uid,
		AllowPrivilegeEscalation: &no,
		Capabilities:             &corev1.Capabilities{Drop: []corev1.Capability{"ALL"}},
	}
	return pod, container
}

// agentImagePullSecrets resolves Tailnet overrides without sharing mutable backing storage with
// defaults, the Tailnet, or another generated pod. Secrets must already exist in the pod namespace.
func agentImagePullSecrets(override *[]string, defaults []string) []corev1.LocalObjectReference {
	names := defaults
	if override != nil {
		names = *override
	}
	// Pod imagePullSecrets is keyed by name for server-side apply. Duplicate entries
	// are rejected by its type converter, even if a CR or environment list contains them.
	refs := make([]corev1.LocalObjectReference, 0, len(names))
	seen := make(map[string]bool, len(names))
	for _, name := range names {
		if !seen[name] {
			refs = append(refs, corev1.LocalObjectReference{Name: name})
			seen[name] = true
		}
	}
	return refs
}

// agentDeployment runs one agent pod. Recreate, not RollingUpdate: two pods would briefly share one
// tailnet hostname and fight over the identity. The tailnet identity is in-memory and ephemeral by
// design; the only volumes are the targets ConfigMap and a throwaway emptyDir for tsnet's work Dir.
func agentDeployment(eg *tnv1.TailnetEgress, tn *tnv1.Tailnet, ns, image string, defaultImagePullSecrets []string) *appsv1.Deployment {
	replicas := int32(1)
	podSec, cSec := nonRoot()

	res := eg.Spec.Resources
	if res.Requests == nil && res.Limits == nil {
		res = tn.Spec.Proxy.Resources
	}

	probeInterval := tn.Spec.Proxy.ProbeInterval.Duration.String()
	mtu := tn.Spec.Proxy.MTU
	if mtu == 0 {
		mtu = 1200
	}

	return &appsv1.Deployment{
		TypeMeta:   metav1.TypeMeta{APIVersion: "apps/v1", Kind: "Deployment"},
		ObjectMeta: metav1.ObjectMeta{Name: eg.Name, Namespace: ns, Labels: objLabels(eg.Name)},
		Spec: appsv1.DeploymentSpec{
			Replicas: &replicas,
			Strategy: appsv1.DeploymentStrategy{Type: appsv1.RecreateDeploymentStrategyType},
			Selector: &metav1.LabelSelector{MatchLabels: selectorLabels(eg.Name)},
			Template: corev1.PodTemplateSpec{
				ObjectMeta: metav1.ObjectMeta{Labels: objLabels(eg.Name)},
				Spec: corev1.PodSpec{
					SecurityContext:  podSec,
					ImagePullSecrets: agentImagePullSecrets(tn.Spec.Proxy.ImagePullSecrets, defaultImagePullSecrets),
					Containers: []corev1.Container{{
						Name:  "agent",
						Image: image,
						// Absolute path: the scratch image has no PATH and the binary sits at /.
						Command:         []string{"/tailnet-agent"},
						SecurityContext: cSec,
						Resources:       res,
						Env: []corev1.EnvVar{
							{Name: "CONTROL_URL", Value: tn.Spec.Server},
							{Name: "TS_HOSTNAME", Value: eg.Status.Hostname},
							{Name: "TS_DEBUG_MTU", Value: fmt.Sprintf("%d", mtu)},
							{Name: "PROBE_INTERVAL", Value: probeInterval},
							{Name: "TARGETS_FILE", Value: configMount + "/" + targetsFile},
							// scratch carries no CA bundle: point Go at the one we bundled into the image.
							{Name: "SSL_CERT_FILE", Value: "/ca-certificates.crt"},
							// tsnet needs a writable Dir; scratch has no $HOME, so use the state emptyDir.
							{Name: "TS_STATE_DIR", Value: "/state"},
							{Name: "HOME", Value: "/state"},
							{Name: "TS_AUTHKEY", ValueFrom: &corev1.EnvVarSource{
								SecretKeyRef: &corev1.SecretKeySelector{
									LocalObjectReference: corev1.LocalObjectReference{Name: authKeySecretName(eg.Name)},
									Key:                  authKeySecretKey,
								},
							}},
						},
						Ports: []corev1.ContainerPort{{Name: "health", ContainerPort: agentHealthPort}},
						ReadinessProbe: &corev1.Probe{
							ProbeHandler: corev1.ProbeHandler{HTTPGet: &corev1.HTTPGetAction{
								Path: "/healthz", Port: intstr.FromInt32(agentHealthPort),
							}},
							InitialDelaySeconds: 10,
							PeriodSeconds:       20,
						},
						VolumeMounts: []corev1.VolumeMount{
							{Name: "targets", MountPath: configMount, ReadOnly: true},
							{Name: "state", MountPath: "/state"},
						},
					}},
					Volumes: []corev1.Volume{
						{
							Name: "targets",
							VolumeSource: corev1.VolumeSource{ConfigMap: &corev1.ConfigMapVolumeSource{
								LocalObjectReference: corev1.LocalObjectReference{Name: targetsConfigMapName(eg.Name)},
							}},
						},
						// Writable scratch space for tsnet's Dir (emptyDir is world-writable, uid-agnostic).
						{
							Name:         "state",
							VolumeSource: corev1.VolumeSource{EmptyDir: &corev1.EmptyDirVolumeSource{}},
						},
					},
				},
			},
		},
	}
}
