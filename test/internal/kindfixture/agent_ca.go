// Package kindfixture contains test-only building blocks for an owned kind cluster.
package kindfixture

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"mime"
	"net/http"
	"slices"

	admissionv1 "k8s.io/api/admission/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

const (
	MaxAdmissionBytes = 1 << 20
	controlCAPath     = "/ca-certificates.crt"
	controlCAVolume   = "fixture-control-ca"
	controlCAKey      = "ca.pem"
)

var ErrAgentCA = errors.New("kind fixture: agent CA injection rejected")

type AgentCAConfig struct {
	Namespace string
	Image     string
	ConfigMap string
	// NetworkGateImage enables the separately approved, fixture-only init gate.
	// Empty retains the CA-only admission shape used by projection tests.
	NetworkGateImage string
}

type patchOperation struct {
	Op    string `json:"op"`
	Path  string `json:"path"`
	Value any    `json:"value"`
}

// AgentCAPatch adds a public, immutable fixture control-CA mount and optionally
// the explicitly selected, unprivileged network startup gate. The caller
// must bind the webhook to its owned namespace and exact local image, with a
// failing-closed admission policy. This function grants no cluster ownership.
// No production binary, application environment, TLS Secret mount or API is changed.
func AgentCAPatch(req *admissionv1.AdmissionRequest, cfg AgentCAConfig) ([]byte, error) {
	if req == nil || cfg.Namespace == "" || cfg.Image == "" || cfg.ConfigMap == "" || req.UID == "" ||
		req.Operation != admissionv1.Create || req.Namespace != cfg.Namespace || req.SubResource != "" ||
		req.Kind.Group != "" || req.Kind.Version != "v1" || req.Kind.Kind != "Pod" ||
		req.Resource.Group != "" || req.Resource.Version != "v1" || req.Resource.Resource != "pods" ||
		len(req.Object.Raw) == 0 || len(req.Object.Raw) > MaxAdmissionBytes {
		return nil, ErrAgentCA
	}
	var pod corev1.Pod
	d := json.NewDecoder(bytes.NewReader(req.Object.Raw))
	d.DisallowUnknownFields()
	if d.Decode(&pod) != nil || pod.Namespace != cfg.Namespace {
		return nil, ErrAgentCA
	}
	var extra any
	wantMode, known := agentMode(pod.Labels)
	if d.Decode(&extra) != io.EOF || !known ||
		pod.Labels["app.kubernetes.io/managed-by"] != "tailnet-operator" || len(pod.Spec.Containers) != 1 ||
		pod.Spec.HostNetwork || pod.Spec.HostPID || pod.Spec.HostIPC ||
		pod.Spec.AutomountServiceAccountToken == nil || *pod.Spec.AutomountServiceAccountToken {
		return nil, ErrAgentCA
	}
	c := pod.Spec.Containers[0]
	if c.Name != "agent" || c.Image != cfg.Image || len(c.Command) != 1 || c.Command[0] != "/tailnet-agent" || len(c.Args) != 0 ||
		!literalEnv(c.Env, "SSL_CERT_FILE", controlCAPath) || !declaresMode(c.Env, wantMode) {
		return nil, ErrAgentCA
	}
	for _, v := range pod.Spec.Volumes {
		if v.Name == controlCAVolume || v.HostPath != nil {
			return nil, ErrAgentCA
		}
	}
	for _, m := range c.VolumeMounts {
		if m.Name == controlCAVolume || m.MountPath == controlCAPath {
			return nil, ErrAgentCA
		}
	}
	mode := int32(0444)
	volume := corev1.Volume{Name: controlCAVolume, VolumeSource: corev1.VolumeSource{
		ConfigMap: &corev1.ConfigMapVolumeSource{
			LocalObjectReference: corev1.LocalObjectReference{Name: cfg.ConfigMap},
			DefaultMode:          &mode,
			Items:                []corev1.KeyToPath{{Key: controlCAKey, Path: controlCAKey}},
		},
	}}
	// SubPath is intentional for this immutable public control CA, not the
	// rotating serving Secret. The production /tls projection is untouched.
	mount := corev1.VolumeMount{Name: controlCAVolume, MountPath: controlCAPath, SubPath: controlCAKey, ReadOnly: true}
	patch := []patchOperation{{Op: "add", Path: "/spec/volumes/-", Value: volume},
		{Op: "add", Path: "/spec/containers/0/volumeMounts/-", Value: mount}}
	if pod.Spec.Volumes == nil {
		patch[0].Path, patch[0].Value = "/spec/volumes", []corev1.Volume{volume}
	}
	if c.VolumeMounts == nil {
		patch[1].Path, patch[1].Value = "/spec/containers/0/volumeMounts", []corev1.VolumeMount{mount}
	}
	if cfg.NetworkGateImage != "" {
		gateVolume, gateContainer, err := networkGateResources(&pod, cfg.NetworkGateImage)
		if err != nil {
			return nil, ErrAgentCA
		}
		// The CA patch has already established spec.volumes even when absent.
		patch = append(patch,
			patchOperation{Op: "add", Path: "/spec/volumes/-", Value: gateVolume},
			patchOperation{Op: "add", Path: "/spec/initContainers", Value: []corev1.Container{gateContainer}})
	}
	b, err := json.Marshal(patch)
	if err != nil {
		return nil, ErrAgentCA
	}
	return b, nil
}

// AgentCAHandler serves only the fixture's Pod admission endpoint. Its caller
// supplies the TLS listener, server deadlines and namespace-scoped webhook rules.
func AgentCAHandler(cfg AgentCAConfig) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/mutate-agent" {
			http.Error(w, "fixture admission request rejected", http.StatusMethodNotAllowed)
			return
		}
		defer r.Body.Close()
		media, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
		b, readErr := io.ReadAll(io.LimitReader(r.Body, MaxAdmissionBytes+1))
		if err != nil || media != "application/json" || readErr != nil || len(b) > MaxAdmissionBytes || r.Context().Err() != nil {
			http.Error(w, "fixture admission request rejected", http.StatusBadRequest)
			return
		}
		var review admissionv1.AdmissionReview
		d := json.NewDecoder(bytes.NewReader(b))
		d.DisallowUnknownFields()
		var extra any
		if d.Decode(&review) != nil || d.Decode(&extra) != io.EOF || review.Request == nil || review.Response != nil ||
			review.APIVersion != "admission.k8s.io/v1" || review.Kind != "AdmissionReview" {
			http.Error(w, "fixture admission request rejected", http.StatusBadRequest)
			return
		}
		response := &admissionv1.AdmissionResponse{UID: review.Request.UID}
		patch, err := AgentCAPatch(review.Request, cfg)
		if err != nil {
			response.Result = &metav1.Status{Code: http.StatusForbidden, Message: ErrAgentCA.Error()}
		} else {
			kind := admissionv1.PatchTypeJSONPatch
			response.Allowed, response.PatchType, response.Patch = true, &kind, patch
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(admissionv1.AdmissionReview{
			TypeMeta: metav1.TypeMeta{APIVersion: "admission.k8s.io/v1", Kind: "AdmissionReview"}, Response: response,
		})
	})
}

// agentMode maps the workload label to the mode that Pod must declare. Returning the pair instead
// of checking each value on its own keeps out a Pod that claims one role and runs the other, which
// is what a plain "either label, either mode" widening would have allowed.
func agentMode(labels map[string]string) (string, bool) {
	switch labels["app.kubernetes.io/name"] {
	case "tailnet-ingress":
		return "ingress", true
	case "tailnet-egress":
		return "egress", true
	}
	return "", false
}

// declaresMode accepts the mode the Pod's workload label implies. An egress agent may leave
// AGENT_MODE unset, because egress is the agent binary's default and the egress Deployment relies
// on it. An ingress agent never gets that benefit: it has to say so, and its Deployment does.
func declaresMode(vars []corev1.EnvVar, want string) bool {
	if literalEnv(vars, "AGENT_MODE", want) {
		return true
	}
	return want == "egress" && !slices.ContainsFunc(vars, func(v corev1.EnvVar) bool { return v.Name == "AGENT_MODE" })
}

func literalEnv(vars []corev1.EnvVar, name, value string) bool {
	found := 0
	for _, v := range vars {
		if v.Name == name {
			if v.Value != value || v.ValueFrom != nil {
				return false
			}
			found++
		}
	}
	return found == 1
}
