package kindfixture

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"reflect"
	"testing"

	jsonpatch "github.com/evanphx/json-patch/v5"
	admissionv1 "k8s.io/api/admission/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
)

func agentFixture(t *testing.T) (*admissionv1.AdmissionRequest, AgentCAConfig, corev1.Pod) {
	t.Helper()
	no := false
	cfg := AgentCAConfig{Namespace: "owned-test", Image: "localhost/tailnet-operator-e2e:fixture", ConfigMap: "owned-public-ca"}
	pod := corev1.Pod{ObjectMeta: metav1.ObjectMeta{Namespace: cfg.Namespace, Labels: map[string]string{
		"app.kubernetes.io/name": "tailnet-ingress", "app.kubernetes.io/managed-by": "tailnet-operator",
	}}, Spec: corev1.PodSpec{AutomountServiceAccountToken: &no,
		Containers: []corev1.Container{{Name: "agent", Image: cfg.Image, Command: []string{"/tailnet-agent"},
			Env:          []corev1.EnvVar{{Name: "SSL_CERT_FILE", Value: controlCAPath}, {Name: "AGENT_MODE", Value: "ingress"}},
			VolumeMounts: []corev1.VolumeMount{{Name: "tls", MountPath: "/tls", ReadOnly: true}},
		}},
		Volumes: []corev1.Volume{{Name: "tls", VolumeSource: corev1.VolumeSource{Secret: &corev1.SecretVolumeSource{SecretName: "serving-cert"}}}},
	}}
	raw, err := json.Marshal(pod)
	if err != nil {
		t.Fatal(err)
	}
	return &admissionv1.AdmissionRequest{UID: "fixture-review", Namespace: cfg.Namespace, Operation: admissionv1.Create,
		Kind: metav1.GroupVersionKind{Version: "v1", Kind: "Pod"}, Resource: metav1.GroupVersionResource{Version: "v1", Resource: "pods"},
		Object: runtime.RawExtension{Raw: raw}}, cfg, pod
}

// asEgress rewrites the fixture into the other admitted agent class. Both must pass; the gate and
// the control CA are what make either Pod safe to start, and neither depends on the mode.
// declared=false mirrors the real egress Deployment, which omits AGENT_MODE and relies on the
// agent binary's default.
func asEgress(p *corev1.Pod, declared bool) {
	p.Labels["app.kubernetes.io/name"] = "tailnet-egress"
	env := p.Spec.Containers[0].Env
	for i := range env {
		if env[i].Name != "AGENT_MODE" {
			continue
		}
		if declared {
			env[i].Value = "egress"
			return
		}
		p.Spec.Containers[0].Env = append(env[:i:i], env[i+1:]...)
		return
	}
}

func TestAgentCAPatchAcceptsBothAgentClasses(t *testing.T) {
	for _, gate := range []string{"", ownedGateImage} {
		for _, declared := range []bool{true, false} {
			req, cfg, _ := agentFixture(t)
			cfg.NetworkGateImage = gate
			pod := hardenedFixturePod(t)
			asEgress(&pod, declared)
			req.Object.Raw, _ = json.Marshal(pod)
			if !agentCAGatesEgress(t, req, cfg, gate != "") {
				return
			}
		}
	}
}

func agentCAGatesEgress(t *testing.T, req *admissionv1.AdmissionRequest, cfg AgentCAConfig, wantGate bool) bool {
	t.Helper()
	patch, err := AgentCAPatch(req, cfg)
	if err != nil {
		t.Error("egress agent rejected")
		return false
	}
	var ops []patchOperation
	if json.Unmarshal(patch, &ops) != nil {
		t.Error("egress patch is not a JSON patch")
		return false
	}
	// An egress agent must receive the same startup gate an ingress agent gets, otherwise widening
	// admission would have let a tsnet Pod start without the network proof.
	var gated bool
	for _, op := range ops {
		gated = gated || op.Path == "/spec/initContainers"
	}
	if gated != wantGate {
		t.Error("egress agent did not receive the same startup gate as an ingress agent")
		return false
	}
	return true
}

func TestAgentCAPatchPreservesProductionPod(t *testing.T) {
	for _, existing := range []bool{true, false} {
		req, cfg, original := agentFixture(t)
		if !existing {
			original.Spec.Volumes = nil
			original.Spec.Containers[0].VolumeMounts = nil
			req.Object.Raw, _ = json.Marshal(original)
		}
		before := append([]byte(nil), req.Object.Raw...)
		patchBytes, err := AgentCAPatch(req, cfg)
		if err != nil {
			t.Fatal(err)
		}
		patch, err := jsonpatch.DecodePatch(patchBytes)
		if err != nil {
			t.Fatal(err)
		}
		patched, err := patch.Apply(req.Object.Raw)
		if err != nil {
			t.Fatal(err)
		}
		var actual corev1.Pod
		if json.Unmarshal(patched, &actual) != nil || !bytes.Equal(before, req.Object.Raw) {
			t.Fatal("mutation changed input or produced an invalid Pod")
		}
		v := actual.Spec.Volumes[len(actual.Spec.Volumes)-1]
		m := actual.Spec.Containers[0].VolumeMounts[len(actual.Spec.Containers[0].VolumeMounts)-1]
		if v.ConfigMap == nil || v.ConfigMap.Name != cfg.ConfigMap || v.ConfigMap.DefaultMode == nil || *v.ConfigMap.DefaultMode != 0444 ||
			!reflect.DeepEqual(v.ConfigMap.Items, []corev1.KeyToPath{{Key: "ca.pem", Path: "ca.pem"}}) ||
			!m.ReadOnly || m.MountPath != controlCAPath || m.SubPath != "ca.pem" || m.Name != v.Name {
			t.Fatal("public CA is not the expected read-only ConfigMap file")
		}
		actual.Spec.Volumes = actual.Spec.Volumes[:len(actual.Spec.Volumes)-1]
		actual.Spec.Containers[0].VolumeMounts = actual.Spec.Containers[0].VolumeMounts[:len(actual.Spec.Containers[0].VolumeMounts)-1]
		if !existing {
			actual.Spec.Volumes = nil
			actual.Spec.Containers[0].VolumeMounts = nil
		}
		if !reflect.DeepEqual(actual, original) {
			t.Fatal("mutation changed production fields beyond the public CA addition")
		}
		// Reinvocation must not silently replace an existing mount.
		req.Object.Raw = patched
		if _, err := AgentCAPatch(req, cfg); err != ErrAgentCA {
			t.Fatal("existing fixture mount overwritten")
		}
	}
}

func TestAgentCAPatchRejectsUnexpectedPod(t *testing.T) {
	for name, mutate := range map[string]func(*corev1.Pod){
		"namespace":    func(p *corev1.Pod) { p.Namespace = "foreign" },
		"labels":       func(p *corev1.Pod) { p.Labels = nil },
		"image":        func(p *corev1.Pod) { p.Spec.Containers[0].Image = "foreign" },
		"command":      func(p *corev1.Pod) { p.Spec.Containers[0].Command = []string{"/different"} },
		"args":         func(p *corev1.Pod) { p.Spec.Containers[0].Args = []string{"extra"} },
		"sidecar":      func(p *corev1.Pod) { p.Spec.Containers = append(p.Spec.Containers, corev1.Container{Name: "foreign"}) },
		"host network": func(p *corev1.Pod) { p.Spec.HostNetwork = true },
		"host path":    func(p *corev1.Pod) { p.Spec.Volumes[0].HostPath = &corev1.HostPathVolumeSource{Path: "/"} },
		"token":        func(p *corev1.Pod) { p.Spec.AutomountServiceAccountToken = nil },
		"env override": func(p *corev1.Pod) { p.Spec.Containers[0].Env[0].Value = "/foreign" },
		"env duplicate": func(p *corev1.Pod) {
			p.Spec.Containers[0].Env = append(p.Spec.Containers[0].Env, p.Spec.Containers[0].Env[0])
		},
		"env indirect":     func(p *corev1.Pod) { p.Spec.Containers[0].Env[0].ValueFrom = &corev1.EnvVarSource{} },
		"volume collision": func(p *corev1.Pod) { p.Spec.Volumes[0].Name = controlCAVolume },
		"mount collision":  func(p *corev1.Pod) { p.Spec.Containers[0].VolumeMounts[0].MountPath = controlCAPath },
		// Label and mode are admitted as a pair: a Pod claiming one role while running the other
		// stays out, and a third workload class is not admitted at all. Only egress may omit the
		// variable, so an ingress Pod without it is rejected rather than defaulted.
		"egress mode under ingress label": func(p *corev1.Pod) { p.Spec.Containers[0].Env[1].Value = "egress" },
		"ingress mode under egress label": func(p *corev1.Pod) { p.Labels["app.kubernetes.io/name"] = "tailnet-egress" },
		"unknown workload":                func(p *corev1.Pod) { p.Labels["app.kubernetes.io/name"] = "tailnet-gateway" },
		"missing mode under ingress label": func(p *corev1.Pod) {
			p.Spec.Containers[0].Env = p.Spec.Containers[0].Env[:1]
		},
		"empty mode": func(p *corev1.Pod) {
			asEgress(p, true)
			p.Spec.Containers[0].Env[1].Value = ""
		},
	} {
		t.Run(name, func(t *testing.T) {
			req, cfg, pod := agentFixture(t)
			mutate(&pod)
			req.Object.Raw, _ = json.Marshal(pod)
			if _, err := AgentCAPatch(req, cfg); err != ErrAgentCA {
				t.Fatal("unexpected Pod accepted")
			}
		})
	}
}

func TestAgentCAAdmissionProtocol(t *testing.T) {
	req, cfg, _ := agentFixture(t)
	for _, deny := range []bool{false, true} {
		if deny {
			req.Namespace = "foreign"
		}
		input, _ := json.Marshal(admissionv1.AdmissionReview{
			TypeMeta: metav1.TypeMeta{APIVersion: "admission.k8s.io/v1", Kind: "AdmissionReview"}, Request: req,
		})
		r := httptest.NewRequest(http.MethodPost, "/mutate-agent", bytes.NewReader(input))
		r.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		AgentCAHandler(cfg).ServeHTTP(w, r)
		var got admissionv1.AdmissionReview
		if w.Code != http.StatusOK || json.Unmarshal(w.Body.Bytes(), &got) != nil || got.Request != nil || got.Response == nil ||
			got.Response.UID != req.UID || got.Response.Allowed == deny || got.APIVersion != "admission.k8s.io/v1" {
			t.Fatal("invalid admission response")
		}
		if deny {
			if got.Response.PatchType != nil || len(got.Response.Patch) != 0 || got.Response.Result.Message != ErrAgentCA.Error() {
				t.Fatal("denial leaked data or included a patch")
			}
		} else if got.Response.PatchType == nil || *got.Response.PatchType != admissionv1.PatchTypeJSONPatch || len(got.Response.Patch) == 0 {
			t.Fatal("admission patch missing")
		}
	}
	for _, input := range [][]byte{[]byte(`{"private-marker":true}`), []byte(`null`), bytes.Repeat([]byte(" "), MaxAdmissionBytes+1)} {
		r := httptest.NewRequest(http.MethodPost, "/mutate-agent", bytes.NewReader(input))
		r.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		AgentCAHandler(cfg).ServeHTTP(w, r)
		if w.Code != http.StatusBadRequest || bytes.Contains(w.Body.Bytes(), []byte("private-marker")) {
			t.Fatal("malformed admission request accepted or exposed")
		}
	}
}

func TestAgentCAPatchRequestBoundary(t *testing.T) {
	for _, mutate := range []func(*admissionv1.AdmissionRequest){
		func(r *admissionv1.AdmissionRequest) { r.UID = "" },
		func(r *admissionv1.AdmissionRequest) { r.Namespace = "foreign" },
		func(r *admissionv1.AdmissionRequest) { r.Operation = admissionv1.Update },
		func(r *admissionv1.AdmissionRequest) { r.Kind.Kind = "Deployment" },
		func(r *admissionv1.AdmissionRequest) { r.Resource.Resource = "secrets" },
		func(r *admissionv1.AdmissionRequest) { r.SubResource = "status" },
		func(r *admissionv1.AdmissionRequest) { r.Object.Raw = []byte(`{"unknown":true}`) },
		func(r *admissionv1.AdmissionRequest) { r.Object.Raw = append(r.Object.Raw, []byte(` {}`)...) },
		func(r *admissionv1.AdmissionRequest) { r.Object.Raw = bytes.Repeat([]byte(" "), MaxAdmissionBytes+1) },
	} {
		req, cfg, _ := agentFixture(t)
		mutate(req)
		if _, err := AgentCAPatch(req, cfg); err != ErrAgentCA {
			t.Fatal("unexpected admission request accepted")
		}
	}
}
