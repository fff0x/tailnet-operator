package controller

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/validation"

	tnv1 "this-is-fine.io/tailnet-operator/api/v1alpha1"
	"this-is-fine.io/tailnet-operator/internal/naming"
)

const ingressTLSMount = "/tls"

// A protocol transition retires the old process: legacy agents keep last-good listeners on
// reload errors, but reject the HTTP envelope at startup. This is not an atomic cutover; the
// old Pod must finish terminating before the transition is accepted.
func ingressHTTPProtocol(in *tnv1.TailnetIngress) bool {
	for _, e := range in.Spec.Exposes {
		if e.Mode != "" && e.Mode != "l4" {
			return true
		}
	}
	return false
}

func ingressProtocolAnnotations(in *tnv1.TailnetIngress) map[string]string {
	if ingressHTTPProtocol(in) {
		return map[string]string{"tailnet.this-is-fine.io/agent-config-protocol": "http-v1"}
	}
	return nil
}

// safeIngressExposes prevents ambiguous configurations from keeping or creating plaintext
// listeners when admission was bypassed. Backend namespaces retain their existing semantics.
func safeIngressExposes(exposes []tnv1.Expose) bool {
	if len(exposes) == 0 || len(exposes) > 50 {
		return false
	}
	names, ports := map[string]bool{}, map[int32]bool{}
	httpCount := 0
	for _, e := range exposes {
		if names[e.Name] || ports[e.Port] || len(validation.IsDNS1123Label(e.Name)) != 0 ||
			e.Port < 1 || e.Port > 65535 || e.Backend.Port < 1 || e.Backend.Port > 65535 ||
			len(validation.IsDNS1123Label(e.Backend.Service)) != 0 ||
			(e.Backend.Namespace != "" && len(validation.IsDNS1123Label(e.Backend.Namespace)) != 0) {
			return false
		}
		names[e.Name], ports[e.Port] = true, true
		switch e.Mode {
		case "", "l4":
		case "http":
			httpCount++
			if e.Port != 443 || httpCount > 1 {
				return false
			}
		default:
			return false
		}
	}
	return true
}

func projectIngressTLS(in *tnv1.TailnetIngress, plan ingressTLSPlan) bool {
	if !plan.http || in.UID == "" || len(validation.IsDNS1123Subdomain(plan.secretName)) != 0 ||
		naming.ValidateDNSName(in.Status.DNSName) != nil || net.ParseIP(in.Status.DNSName) != nil ||
		!safeIngressExposes(in.Spec.Exposes) {
		return false
	}
	for _, e := range in.Spec.Exposes {
		if e.Mode == "http" {
			return true
		}
	}
	return false
}

// The revision binds probe results to this CR and its resolved configuration, not Secret data.
// Certificate rotation must not change targets, restart listeners, or replace the Pod.
func ingressHTTPConfigID(in *tnv1.TailnetIngress, target agentTarget, plan ingressTLSPlan) string {
	target.ConfigID = ""
	data, _ := json.Marshal(struct {
		UID        types.UID
		Generation int64
		Target     agentTarget
		Secret     string
		Issuer     *tnv1.TLSIssuerReference
	}{in.UID, in.Generation, target, plan.secretName, plan.issuer})
	digest := sha256.Sum256(data)
	return hex.EncodeToString(digest[:])
}

// ingressAgentDeploymentTLS adds only a reference to namespace-local material. Optional projection
// lets other L4 listeners run while certificate issuance is pending; HTTP handshakes still fail closed.
func ingressAgentDeploymentTLS(in *tnv1.TailnetIngress, tn *tnv1.Tailnet, ns, image string, pullSecrets []string, plan ingressTLSPlan) *appsv1.Deployment {
	dep := ingressAgentDeployment(in, tn, ns, image, pullSecrets)
	if ns != in.Namespace || !projectIngressTLS(in, plan) {
		return dep
	}
	mode, group, optional := int32(0440), int64(65532), true
	pod := &dep.Spec.Template.Spec
	pod.SecurityContext.FSGroup = &group
	pod.Volumes = append(pod.Volumes, corev1.Volume{
		Name: "tls",
		VolumeSource: corev1.VolumeSource{Secret: &corev1.SecretVolumeSource{
			SecretName: plan.secretName, DefaultMode: &mode, Optional: &optional,
			Items: []corev1.KeyToPath{{Key: corev1.TLSCertKey, Path: "tls.crt"}, {Key: corev1.TLSPrivateKeyKey, Path: "tls.key"}},
		}},
	})
	pod.Containers[0].VolumeMounts = append(pod.Containers[0].VolumeMounts,
		corev1.VolumeMount{Name: "tls", MountPath: ingressTLSMount, ReadOnly: true})
	return dep
}
