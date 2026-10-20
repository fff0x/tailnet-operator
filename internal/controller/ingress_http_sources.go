package controller

import (
	"crypto/sha256"
	"encoding/base32"
	"encoding/hex"
	"encoding/json"
	"strings"

	tnv1 "tsunaro.io/tailnet-operator/api/v1alpha1"
	"tsunaro.io/tailnet-operator/internal/naming"
)

// Stable across expose reorder; include target and reference identity, never trust bytes.
// The full SHA-256 encoded as DNS-safe base32 keeps the volume name below 63 bytes.
func ingressBackendTLSProjection(in *tnv1.TailnetIngress, e tnv1.Expose) (string, string) {
	if ingressConfigVersion(in) < 3 {
		return "backend-tls", ingressBackendTLSMount
	}
	data, _ := json.Marshal(struct{ Target, Namespace, Name, Key string }{
		e.Name, in.Namespace, e.Backend.TLS.CAConfigMapRef.Name, e.Backend.TLS.CAConfigMapRef.Key,
	})
	digest := sha256.Sum256(data)
	name := "bca-" + strings.ToLower(base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(digest[:]))
	return name, ingressBackendTLSMount + "/" + name
}

// This second marker is resolved immediately after reading the Tailnet, before keys or
// Headscale. Only effective naming, TLS reference and control identity participate;
// overridden defaults, material bytes and unrelated Tailnet resources do not.
func ingressResolvedSourceDigest(in *tnv1.TailnetIngress, tn *tnv1.Tailnet) string {
	plan, reason := resolveIngressTLS(in, tn)
	data, _ := json.Marshal(struct {
		Control          string
		BaseName         string
		ExposeNames      map[string]string
		CertificateNames []string
		Secret           string
		Issuer           *tnv1.TLSIssuerReference
		Reason           string
	}{ingressResolvedControlDigest(in, tn), plan.names.baseName, plan.names.exposeNames,
		plan.names.certificateNames, plan.secretName, plan.issuer, reason})
	digest := sha256.Sum256(data)
	return hex.EncodeToString(digest[:])
}

func ingressResolvedControlDigest(in *tnv1.TailnetIngress, tn *tnv1.Tailnet) string {
	tag, hostname := in.Spec.Tag, in.Spec.Hostname
	if tag == "" {
		tag = naming.Render(tn.Spec.IngressTagTemplate, in.Name)
	}
	if hostname == "" {
		hostname = naming.Render(tn.Spec.IngressHostnameTemplate, in.Name)
	}
	// apiUrl is the operator's own path to the Headscale REST API; agents only ever dial Server.
	// Keeping it out means switching apiUrl (say, http -> https) does not re-roll every HTTP agent.
	data, _ := json.Marshal(struct {
		Tailnet, UID, Server, Tag, Hostname string
	}{tn.Name, string(tn.UID), tn.Spec.Server, tag, hostname})
	digest := sha256.Sum256(data)
	return hex.EncodeToString(digest[:])
}
