package controller

import (
	"encoding/json"
	"fmt"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/intstr"

	tnv1 "tsunaro.io/tailnet-operator/api/v1alpha1"
)

// ingressSelectorLabels identify one TailnetIngress CR's pods and objects. A distinct name from the
// egress labels keeps the two data planes' pods, Services and NetworkPolicies from ever selecting
// each other when both run in the same namespace.
func ingressSelectorLabels(crName string) map[string]string {
	return map[string]string{
		"app.kubernetes.io/name":     "tailnet-ingress",
		"app.kubernetes.io/instance": crName,
	}
}

func ingressObjLabels(crName string) map[string]string {
	l := ingressSelectorLabels(crName)
	l["app.kubernetes.io/managed-by"] = fieldOwner
	return l
}

// exposesConfigMap holds the agent's expose list, reusing the agentTarget shape the agent already
// parses: for ingress ListenPort is the tailnet listen port and Address:Port is the in-cluster
// backend (full cluster-DNS name so it resolves regardless of the pod's search path). Its mtime
// changing is what makes the agent rebind.
func exposesConfigMap(in *tnv1.TailnetIngress, ns string) (*corev1.ConfigMap, error) {
	// Without a resolved TLS source, HTTP must not fall back to plaintext L4.
	return ingressExposesConfigMap(in, ns, ingressTLSPlan{})
}

func ingressExposesConfigMap(in *tnv1.TailnetIngress, ns string, plan ingressTLSPlan) (*corev1.ConfigMap, error) {
	out := make([]agentTarget, 0, len(in.Spec.Exposes))
	exposes := in.Spec.Exposes
	if !safeIngressExposes(exposes) {
		// An ambiguous or admission-bypassed configuration withdraws listeners.
		exposes = nil
	}
	for _, e := range exposes {
		if e.Mode == "http" && (ns != in.Namespace || !projectIngressTLS(in, plan)) {
			continue
		}
		bns := e.Backend.Namespace
		if bns == "" {
			bns = ns
		}
		target := agentTarget{
			Name:       e.Name,
			Address:    fmt.Sprintf("%s.%s.svc.cluster.local", e.Backend.Service, bns),
			Port:       e.Backend.Port,
			ListenPort: e.Port,
		}
		if e.Mode == "http" {
			target.Mode, target.DNSName = "http", in.Status.DNSName
			target.CertFile, target.KeyFile = ingressTLSMount+"/tls.crt", ingressTLSMount+"/tls.key"
			target.ConfigID = ingressHTTPConfigID(in, target, plan)
		}
		out = append(out, target)
	}
	var config any = out
	if ingressHTTPProtocol(in) {
		// Old agents reject an object at startup instead of ignoring HTTP mode and
		// forwarding plaintext. The Pod template also changes to retire old listeners.
		config = struct {
			Version int           `json:"version"`
			Targets []agentTarget `json:"targets"`
		}{Version: 1, Targets: out}
	}
	b, err := json.Marshal(config)
	if err != nil {
		return nil, err
	}
	return &corev1.ConfigMap{
		TypeMeta:   metav1.TypeMeta{APIVersion: "v1", Kind: "ConfigMap"},
		ObjectMeta: metav1.ObjectMeta{Name: targetsConfigMapName(in.Name), Namespace: ns, Labels: ingressObjLabels(in.Name)},
		Data:       map[string]string{targetsFile: string(b)},
	}, nil
}

// ingressAuthKeySecret carries the reusable ephemeral pre-auth key for an ingress node. Same shape
// as the egress one; kept separate because it labels and owner-references the TailnetIngress.
func ingressAuthKeySecret(in *tnv1.TailnetIngress, ns, key, expiresAt string) *corev1.Secret {
	return &corev1.Secret{
		TypeMeta: metav1.TypeMeta{APIVersion: "v1", Kind: "Secret"},
		ObjectMeta: metav1.ObjectMeta{
			Name:        authKeySecretName(in.Name),
			Namespace:   ns,
			Labels:      ingressObjLabels(in.Name),
			Annotations: map[string]string{annExpiresAt: expiresAt},
		},
		Type:       corev1.SecretTypeOpaque,
		StringData: map[string]string{authKeySecretKey: key},
	}
}

// ingressNetworkPolicy lets only the operator reach the agent's health port. Consumers are tailnet
// peers, not in-cluster pods, so there is no consumer ingress rule; egress stays open because the
// pod must reach DERP, the control server and its in-cluster backends to work at all.
func ingressNetworkPolicy(in *tnv1.TailnetIngress, ns, operatorNS string) *networkingv1.NetworkPolicy {
	health := intstr.FromInt32(agentHealthPort)
	return &networkingv1.NetworkPolicy{
		TypeMeta:   metav1.TypeMeta{APIVersion: "networking.k8s.io/v1", Kind: "NetworkPolicy"},
		ObjectMeta: metav1.ObjectMeta{Name: in.Name, Namespace: ns, Labels: ingressObjLabels(in.Name)},
		Spec: networkingv1.NetworkPolicySpec{
			PodSelector: metav1.LabelSelector{MatchLabels: ingressSelectorLabels(in.Name)},
			PolicyTypes: []networkingv1.PolicyType{networkingv1.PolicyTypeIngress},
			Ingress: []networkingv1.NetworkPolicyIngressRule{
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

// ingressAgentDeployment runs one ingress agent pod (AGENT_MODE=ingress). Same security posture,
// state emptyDir and health probe as the egress agent; the only behavioural difference is the mode
// env, which flips the agent from listen-local/dial-tailnet to listen-tailnet/dial-cluster.
func ingressAgentDeployment(in *tnv1.TailnetIngress, tn *tnv1.Tailnet, ns, image string, defaultImagePullSecrets []string) *appsv1.Deployment {
	replicas := int32(1)
	automount := false
	podSec, cSec := nonRoot()

	res := in.Spec.Resources
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
		ObjectMeta: metav1.ObjectMeta{Name: in.Name, Namespace: ns, Labels: ingressObjLabels(in.Name)},
		Spec: appsv1.DeploymentSpec{
			Replicas: &replicas,
			Strategy: appsv1.DeploymentStrategy{Type: appsv1.RecreateDeploymentStrategyType},
			Selector: &metav1.LabelSelector{MatchLabels: ingressSelectorLabels(in.Name)},
			Template: corev1.PodTemplateSpec{
				ObjectMeta: metav1.ObjectMeta{Labels: ingressObjLabels(in.Name), Annotations: ingressProtocolAnnotations(in)},
				Spec: corev1.PodSpec{
					SecurityContext:              podSec,
					AutomountServiceAccountToken: &automount,
					ImagePullSecrets:             agentImagePullSecrets(tn.Spec.Proxy.ImagePullSecrets, defaultImagePullSecrets),
					Containers: []corev1.Container{{
						Name:            "agent",
						Image:           image,
						Command:         []string{"/tailnet-agent"},
						SecurityContext: cSec,
						Resources:       res,
						Env: []corev1.EnvVar{
							{Name: "AGENT_MODE", Value: "ingress"},
							{Name: "CONTROL_URL", Value: tn.Spec.Server},
							{Name: "TS_HOSTNAME", Value: in.Status.Hostname},
							{Name: "TS_DEBUG_MTU", Value: fmt.Sprintf("%d", mtu)},
							{Name: "PROBE_INTERVAL", Value: probeInterval},
							{Name: "TARGETS_FILE", Value: configMount + "/" + targetsFile},
							{Name: "SSL_CERT_FILE", Value: "/ca-certificates.crt"},
							{Name: "TS_STATE_DIR", Value: "/state"},
							{Name: "HOME", Value: "/state"},
							{Name: "TS_AUTHKEY", ValueFrom: &corev1.EnvVarSource{
								SecretKeyRef: &corev1.SecretKeySelector{
									LocalObjectReference: corev1.LocalObjectReference{Name: authKeySecretName(in.Name)},
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
								LocalObjectReference: corev1.LocalObjectReference{Name: targetsConfigMapName(in.Name)},
							}},
						},
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
