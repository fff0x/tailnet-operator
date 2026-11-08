package controller

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"maps"
	"slices"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/intstr"
	"sigs.k8s.io/controller-runtime/pkg/client"

	tnv1 "tsunaro.io/tailnet-operator/api/v1alpha1"
)

// labelIngressState marks the tsnet state Secrets of an ingress, so the one of a retired identity
// (other name, same CR labels) can be found and removed.
const labelIngressState = "tsunaro.io/state"

// ingressSelectorLabels identify one TailnetIngress CR's pods and objects. A distinct name from the
// egress labels keeps the two data planes' pods, Services and NetworkPolicies from ever selecting
// each other when both run in the same namespace.
func ingressSelectorLabels(crName string) map[string]string {
	return map[string]string{
		"app.kubernetes.io/name":     "tailnet-ingress",
		"app.kubernetes.io/instance": crName,
	}
}

// ingressWorkloadName is the Deployment and NetworkPolicy name of one TailnetIngress. It is decoupled
// from the CR name (and consistent with the Headscale host "ingress-<CR>") so a CR may share its name
// with a user workload in the same namespace.
func ingressWorkloadName(crName string) string { return "ingress-" + crName }

func ingressWorkloadKey(in *tnv1.TailnetIngress) types.NamespacedName {
	return types.NamespacedName{Namespace: in.Namespace, Name: ingressWorkloadName(in.Name)}
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
			target.Mode, target.DNSName = "http", plan.names.exposeNames[e.Name]
			if alias := plan.names.aliasNames[e.Name]; alias != "" {
				target.DNSAliases = []string{alias}
			}
			target.CertFile, target.KeyFile = ingressTLSMount+"/tls.crt", ingressTLSMount+"/tls.key"
			if e.Backend.TLS != nil {
				target.BackendServerName = e.Backend.TLS.ServerName
				_, mountPath := ingressBackendTLSProjection(in, e)
				target.BackendCAFile = mountPath + "/ca.crt"
			}
			if e.Timeouts != nil {
				if e.Timeouts.Request != nil {
					target.RequestTimeout = *e.Timeouts.Request
				}
				if e.Timeouts.BackendRequest != nil {
					target.BackendRequestTimeout = *e.Timeouts.BackendRequest
				}
			}
			target.ConfigID = ingressHTTPConfigID(in, target, plan)
		}
		out = append(out, target)
	}
	var config any = out
	if ingressConfigVersion(in) > 0 {
		// Old agents reject an object at startup instead of ignoring HTTP mode and
		// forwarding plaintext. The Pod template also changes to retire old listeners.
		config = struct {
			Version int           `json:"version"`
			Targets []agentTarget `json:"targets"`
		}{Version: ingressConfigVersion(in), Targets: out}
	}
	if ingressConfigVersion(in) == 3 {
		names := []string{}
		for _, target := range out {
			if target.Mode == "http" {
				names = plan.names.certificateNames
				break
			}
		}
		config = struct {
			Version             int           `json:"version"`
			CertificateDNSNames []string      `json:"certificateDNSNames"`
			Targets             []agentTarget `json:"targets"`
		}{3, names, out}
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

// ingressAuthKeySecret carries the reusable pre-auth key for an ingress node. Same shape
// as the egress one; kept separate because it labels and owner-references the TailnetIngress.
func ingressAuthKeySecret(in *tnv1.TailnetIngress, ns, key, expiresAt string, binding map[string]string) *corev1.Secret {
	ann := maps.Clone(binding)
	ann[annExpiresAt] = expiresAt
	return &corev1.Secret{
		TypeMeta: metav1.TypeMeta{APIVersion: "v1", Kind: "Secret"},
		ObjectMeta: metav1.ObjectMeta{
			Name:        authKeySecretName(in.Name),
			Namespace:   ns,
			Labels:      ingressObjLabels(in.Name),
			Annotations: ann,
		},
		Type:       corev1.SecretTypeOpaque,
		StringData: map[string]string{authKeySecretKey: key},
	}
}

// ingressStateSecretName names the tsnet state Secret of one ingress identity: control server, tag
// and hostname. The node key inside belongs to that server and carries the tag; the hostname is
// the MagicDNS name Headscale fixed at registration (a rename is a re-registration, see
// associateNode). A change of any of them yields a new, empty Secret and the agent registers fresh
// instead of reviving the old node. retireIngressNode and dropRetiredStateSecrets remove the rest.
func ingressStateSecretName(in *tnv1.TailnetIngress, tn *tnv1.Tailnet) string {
	h := sha256.Sum256([]byte(tn.Spec.Server + "\x00" + ingressTag(tn, in) + "\x00" + in.Status.Hostname))
	return ingressWorkloadName(in.Name) + "-state-" + hex.EncodeToString(h[:4])
}

// ingressIdentityObjects are what a persistent ingress node needs besides its Deployment: a
// ServiceAccount, a Role limited to its one state Secret (get/update/patch — the operator creates the
// Secret, so the agent never needs create) and the binding. The Secret itself is created empty and
// only its metadata is managed here; the agent owns the data. Mirrors the gateway's state handling.
func ingressIdentityObjects(in *tnv1.TailnetIngress, ns, stateSecret string) []client.Object {
	name := ingressWorkloadName(in.Name)
	labels := ingressObjLabels(in.Name)
	stateLabels := ingressObjLabels(in.Name)
	stateLabels[labelIngressState] = "true"
	automount := false
	return []client.Object{
		&corev1.ServiceAccount{
			TypeMeta:                     metav1.TypeMeta{APIVersion: "v1", Kind: "ServiceAccount"},
			ObjectMeta:                   metav1.ObjectMeta{Name: name, Namespace: ns, Labels: labels},
			AutomountServiceAccountToken: &automount, // mounted explicitly by the agent pod only
		},
		&rbacv1.Role{
			TypeMeta:   metav1.TypeMeta{APIVersion: "rbac.authorization.k8s.io/v1", Kind: "Role"},
			ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: ns, Labels: labels},
			Rules: []rbacv1.PolicyRule{{
				APIGroups: []string{""}, Resources: []string{"secrets"}, ResourceNames: []string{stateSecret},
				Verbs: []string{"get", "update", "patch"},
			}},
		},
		&rbacv1.RoleBinding{
			TypeMeta:   metav1.TypeMeta{APIVersion: "rbac.authorization.k8s.io/v1", Kind: "RoleBinding"},
			ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: ns, Labels: labels},
			RoleRef:    rbacv1.RoleRef{APIGroup: rbacv1.GroupName, Kind: "Role", Name: name},
			Subjects:   []rbacv1.Subject{{Kind: "ServiceAccount", Name: name, Namespace: ns}},
		},
		&corev1.Secret{
			TypeMeta:   metav1.TypeMeta{APIVersion: "v1", Kind: "Secret"},
			ObjectMeta: metav1.ObjectMeta{Name: stateSecret, Namespace: ns, Labels: stateLabels},
			Type:       corev1.SecretTypeOpaque,
		},
	}
}

// ingressNetworkPolicy lets only the operator reach the agent's health port. Consumers are tailnet
// peers, not in-cluster pods, so there is no consumer ingress rule; egress stays open because the
// pod must reach DERP, the control server and its in-cluster backends to work at all.
func ingressNetworkPolicy(in *tnv1.TailnetIngress, ns, operatorNS string, scrape []networkingv1.NetworkPolicyPeer) *networkingv1.NetworkPolicy {
	health := intstr.FromInt32(agentHealthPort)
	np := &networkingv1.NetworkPolicy{
		TypeMeta:   metav1.TypeMeta{APIVersion: "networking.k8s.io/v1", Kind: "NetworkPolicy"},
		ObjectMeta: metav1.ObjectMeta{Name: ingressWorkloadName(in.Name), Namespace: ns, Labels: ingressObjLabels(in.Name)},
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
	if len(scrape) > 0 {
		np.Spec.Ingress = append(np.Spec.Ingress, networkingv1.NetworkPolicyIngressRule{
			From: slices.Clone(scrape), Ports: []networkingv1.NetworkPolicyPort{{Port: &health}},
		})
	}
	return np
}

// ingressAgentDeployment runs one ingress agent pod (AGENT_MODE=ingress). Same security posture,
// scratch emptyDir and health probe as the egress agent; it differs in the mode env, which flips
// the agent from listen-local/dial-tailnet to listen-tailnet/dial-cluster, and in its identity:
// the tsnet state lives in a Secret (TS_STATE_SECRET, written through the pod's own ServiceAccount),
// so a restarted pod keeps its node ID and tailnet IP instead of registering anew.
func ingressAgentDeployment(in *tnv1.TailnetIngress, tn *tnv1.Tailnet, ns, image string, defaultImagePullSecrets []string, defaultResources corev1.ResourceRequirements) *appsv1.Deployment {
	replicas := int32(1)
	automount := true
	podSec, cSec := nonRoot()

	res := agentResources(in.Spec.Resources, tn.Spec.Proxy.Resources, defaultResources)

	probeInterval := tn.Spec.Proxy.ProbeInterval.Duration.String()
	mtu := tn.Spec.Proxy.MTU
	if mtu == 0 {
		mtu = 1200
	}

	return &appsv1.Deployment{
		TypeMeta:   metav1.TypeMeta{APIVersion: "apps/v1", Kind: "Deployment"},
		ObjectMeta: metav1.ObjectMeta{Name: ingressWorkloadName(in.Name), Namespace: ns, Labels: ingressObjLabels(in.Name)},
		Spec: appsv1.DeploymentSpec{
			Replicas: &replicas,
			Strategy: appsv1.DeploymentStrategy{Type: appsv1.RecreateDeploymentStrategyType},
			Selector: &metav1.LabelSelector{MatchLabels: ingressSelectorLabels(in.Name)},
			Template: corev1.PodTemplateSpec{
				ObjectMeta: metav1.ObjectMeta{Labels: ingressObjLabels(in.Name), Annotations: ingressPodAnnotations(in, tn)},
				Spec: corev1.PodSpec{
					SecurityContext:              podSec,
					ServiceAccountName:           ingressWorkloadName(in.Name),
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
							{Name: "TS_STATE_SECRET", Value: ingressStateSecretName(in, tn)},
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
