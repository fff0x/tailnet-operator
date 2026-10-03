package controller

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/validation"

	tnv1 "tsunaro.io/tailnet-operator/api/v1alpha1"
	"tsunaro.io/tailnet-operator/internal/naming"
)

const ingressTLSMount = "/tls"
const ingressBackendTLSMount = "/backend-tls"
const ingressProtocolAnnotation = "tsunaro.io/agent-config-protocol"
const ingressHTTPConfigAnnotation = "tsunaro.io/agent-http-config"
const ingressHTTPSourceAnnotation = "tsunaro.io/agent-http-source"

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

// Presence, not validity, selects v2/v3: even malformed admission-bypassed intent
// must retire an older process rather than let it ignore security-sensitive fields.
func ingressConfigVersion(in *tnv1.TailnetIngress) int {
	httpCount := 0
	for _, e := range in.Spec.Exposes {
		if e.DNSLabel != "" || e.Alias {
			return 3
		}
		if e.Mode == "http" {
			httpCount++
		}
	}
	if httpCount > 1 {
		return 3
	}
	for _, e := range in.Spec.Exposes {
		if e.Backend.TLS != nil || e.Timeouts != nil {
			return 2
		}
	}
	if ingressHTTPProtocol(in) {
		return 1
	}
	return 0
}

func ingressProtocolAnnotations(in *tnv1.TailnetIngress) map[string]string {
	if version := ingressConfigVersion(in); version >= 2 {
		return map[string]string{
			ingressProtocolAnnotation:   fmt.Sprintf("http-v%d", version),
			ingressHTTPConfigAnnotation: ingressDesiredHTTPConfigDigest(in),
		}
	}
	if ingressHTTPProtocol(in) {
		return map[string]string{ingressProtocolAnnotation: "http-v1"}
	}
	return nil
}

// ingressDesiredHTTPConfigDigest is available before any dependency lookup. Include
// reference identity and optional-field presence, not resolved material, generation,
// or status: trust/certificate rotation must not restart an unchanged process.
func ingressDesiredHTTPConfigDigest(in *tnv1.TailnetIngress) string {
	data, _ := json.Marshal(struct {
		Exposes       []tnv1.Expose
		TLS           *tnv1.IngressTLS
		TailnetRef    tnv1.TailnetRef
		Tag, Hostname string
	}{in.Spec.Exposes, in.Spec.TLS, in.Spec.TailnetRef, in.Spec.Tag, in.Spec.Hostname})
	digest := sha256.Sum256(data)
	return hex.EncodeToString(digest[:])
}

// safeIngressExposes prevents ambiguous configurations from keeping or creating plaintext
// listeners when admission was bypassed. Backend namespaces retain their existing semantics.
func safeIngressExposes(exposes []tnv1.Expose) bool {
	if len(exposes) == 0 || len(exposes) > 50 {
		return false
	}
	names, ports, labels := map[string]bool{}, map[int32]bool{}, map[string]bool{}
	httpCount := 0
	for _, e := range exposes {
		if names[e.Name] || len(validation.IsDNS1123Label(e.Name)) != 0 ||
			e.Port < 1 || e.Port > 65535 || e.Backend.Port < 1 || e.Backend.Port > 65535 ||
			len(validation.IsDNS1123Label(e.Backend.Service)) != 0 ||
			(e.Backend.Namespace != "" && len(validation.IsDNS1123Label(e.Backend.Namespace)) != 0) {
			return false
		}
		if !safeIngressHTTPExtensions(e) {
			return false
		}
		names[e.Name] = true
		switch e.Mode {
		case "", "l4":
			if ports[e.Port] || e.DNSLabel != "" {
				return false
			}
			ports[e.Port] = true
		case "http":
			httpCount++
			if e.Port != 443 || labels[e.DNSLabel] || (e.DNSLabel != "" && naming.ValidateHostname(e.DNSLabel) != nil) {
				return false
			}
			labels[e.DNSLabel] = true
		default:
			return false
		}
	}
	return httpCount == 0 || !ports[443]
}

func projectIngressTLS(in *tnv1.TailnetIngress, plan ingressTLSPlan) bool {
	if !plan.http || in.UID == "" || len(validation.IsDNS1123Subdomain(plan.secretName)) != 0 ||
		len(plan.names.certificateNames) == 0 ||
		!safeIngressExposes(in.Spec.Exposes) {
		return false
	}
	for _, e := range in.Spec.Exposes {
		if e.Mode == "http" && plan.names.exposeNames[e.Name] == "" {
			return false
		}
	}
	return true
}

// The revision binds probe results to this CR and its resolved configuration, not Secret data.
// Certificate rotation must not change targets, restart listeners, or replace the Pod.
func ingressHTTPConfigID(in *tnv1.TailnetIngress, target agentTarget, plan ingressTLSPlan) string {
	target.ConfigID = ""
	var extension *tnv1.Expose
	for _, e := range in.Spec.Exposes {
		if e.Name == target.Name && (e.Backend.TLS != nil || e.Timeouts != nil) {
			copy := e
			extension = &copy
			break
		}
	}
	data, _ := json.Marshal(struct {
		UID        types.UID
		Generation int64
		Target     agentTarget
		Secret     string
		Issuer     *tnv1.TLSIssuerReference
		// Bind CA reference identity and optional-field presence, never CA contents.
		Extension        *tnv1.Expose `json:"Extension,omitempty"`
		CertificateNames []string
		ControlIdentity  string
	}{in.UID, in.Generation, target, plan.secretName, plan.issuer, extension, plan.names.certificateNames, plan.controlIdentity})
	digest := sha256.Sum256(data)
	return hex.EncodeToString(digest[:])
}

// ingressAgentDeploymentTLS adds only a reference to namespace-local material. Optional projection
// lets other L4 listeners run while certificate issuance is pending; HTTP handshakes still fail closed.
func ingressAgentDeploymentTLS(in *tnv1.TailnetIngress, tn *tnv1.Tailnet, ns, image string, pullSecrets []string, defaultResources corev1.ResourceRequirements, plan ingressTLSPlan) *appsv1.Deployment {
	dep := ingressAgentDeployment(in, tn, ns, image, pullSecrets, defaultResources)
	if ingressConfigVersion(in) > 0 {
		dep.Spec.Template.Annotations[ingressHTTPSourceAnnotation] = ingressResolvedSourceDigest(in, tn)
	}
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
	for _, e := range in.Spec.Exposes {
		if e.Mode != "http" || e.Backend.TLS == nil {
			continue
		}
		ref := e.Backend.TLS.CAConfigMapRef
		volumeName, mountPath := ingressBackendTLSProjection(in, e)
		pod.Volumes = append(pod.Volumes, corev1.Volume{
			Name: volumeName,
			VolumeSource: corev1.VolumeSource{ConfigMap: &corev1.ConfigMapVolumeSource{
				LocalObjectReference: corev1.LocalObjectReference{Name: ref.Name},
				DefaultMode:          &mode, Optional: &optional,
				Items: []corev1.KeyToPath{{Key: ref.Key, Path: "ca.crt"}},
			}},
		})
		pod.Containers[0].VolumeMounts = append(pod.Containers[0].VolumeMounts,
			corev1.VolumeMount{Name: volumeName, MountPath: mountPath, ReadOnly: true})
	}
	return dep
}
