//go:build e2e_kind

package e2ekind

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	admissionv1 "k8s.io/api/admissionregistration/v1"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/util/wait"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

const cmNamespace = "cert-manager"
const cmChartSHA = "73a56e1728edd6c99f1f31082618c3259d279a76b7ebd3d4bdc5475c2442d34a"

// Raw diagnostics stay in the runner's private evidence; failure must not skip
// cleanup just because an individual observation could not be collected.
func captureCertManagerDiagnostics(f *fixture) {
	ctx, cancel := context.WithTimeout(context.Background(), 25*time.Second)
	defer cancel()
	root := os.Getenv("E2E_KIND_NET_EVIDENCE")
	save := func(name string, b []byte) {
		if len(b) > 1<<20 {
			return
		}
		file, err := os.OpenFile(filepath.Join(root, name), os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
		if err == nil {
			_, _ = file.Write(b)
			_ = file.Close()
		}
	}
	for _, kind := range []string{"Certificate", "CertificateRequest"} {
		objects := &unstructured.UnstructuredList{}
		objects.SetAPIVersion("cert-manager.io/v1")
		objects.SetKind(kind + "List")
		if f.kube.List(ctx, objects, client.InNamespace(cmNamespace)) == nil {
			b, _ := json.Marshal(objects)
			save("cm-failed-"+kind+".private.json", b)
		}
	}
	var pods corev1.PodList
	var deployments appsv1.DeploymentList
	if f.kube.List(ctx, &deployments, client.InNamespace(cmNamespace)) == nil {
		b, _ := json.Marshal(&deployments)
		save("cm-failed-deployments.private.json", b)
	}
	if f.kube.List(ctx, &pods, client.InNamespace(cmNamespace)) != nil || len(pods.Items) > 8 {
		return
	}
	b, _ := json.Marshal(&pods)
	save("cm-failed-pods.private.json", b)
	for i, p := range pods.Items {
		for j, c := range p.Spec.Containers {
			logs, _ := f.command(ctx, "", "kubectl", "--kubeconfig", f.config, "--context", f.context, "--request-timeout=5s", "--namespace", cmNamespace, "logs", p.Name, "-c", c.Name, "--tail=100", "--limit-bytes=32768")
			save(fmt.Sprintf("cm-failed-pod-%d-container-%d.private.log", i, j), logs)
		}
	}
}

func cmObject(kind, namespace, name string, spec map[string]any) *unstructured.Unstructured {
	meta := map[string]any{"name": name}
	if namespace != "" {
		meta["namespace"] = namespace
	}
	o := map[string]any{"apiVersion": "cert-manager.io/v1", "kind": kind, "metadata": meta}
	if spec != nil {
		o["spec"] = spec
	}
	return &unstructured.Unstructured{Object: o}
}
func cmInvalidRenewal(err error) bool {
	if err == nil {
		return false
	}
	var status apierrors.APIStatus
	if !errors.As(err, &status) {
		return false
	}
	s := status.Status()
	if apierrors.IsInvalid(err) && s.Details != nil {
		for _, cause := range s.Details.Causes {
			if cause.Field == "spec.renewBefore" && cause.Type == metav1.CauseTypeFieldValueInvalid {
				return true
			}
		}
	}
	// Admission-denied responses need not carry Kubernetes' Invalid reason.
	// A generic Forbidden/timeout/TLS failure is not a validation result.
	return (s.Code == 400 || s.Code == 403 || s.Code == 422) && strings.HasPrefix(s.Message, `admission webhook "webhook.cert-manager.io" denied the request: `) && strings.Contains(s.Message, "spec.renewBefore")
}

func cmRequestIdentity(request, certificate *unstructured.Unstructured, expectedUser string) bool {
	if request == nil || certificate == nil || certificate.GetUID() == "" || expectedUser == "" {
		return false
	}
	owner := metav1.GetControllerOf(request)
	username, found, err := unstructured.NestedString(request.Object, "spec", "username")
	return request.GetAnnotations()["cert-manager.io/certificate-name"] == certificate.GetName() &&
		owner != nil && owner.APIVersion == "cert-manager.io/v1" && owner.Kind == "Certificate" && owner.UID == certificate.GetUID() && owner.Name == certificate.GetName() &&
		found && err == nil && username == expectedUser
}

func cmReady(o *unstructured.Unstructured) bool {
	cs, ok, _ := unstructured.NestedSlice(o.Object, "status", "conditions")
	if !ok {
		return false
	}
	for _, c := range cs {
		v, ok := c.(map[string]any)
		if ok && v["type"] == "Ready" && v["status"] == "True" {
			if o.GetKind() != "Certificate" {
				return true
			}
			gen, ok := v["observedGeneration"].(int64)
			return ok && gen == o.GetGeneration() && gen > 0
		}
	}
	return false
}

// installFixtureCertManager installs the real pinned chart with its own SAs,
// RBAC, fail-closed admission and startup hook. No external issuer is submitted.
// It returns only the public serving CA; private keys stay in Kubernetes Secrets.
func installFixtureCertManager(t *testing.T, f *fixture) []byte {
	t.Helper()
	if os.Getenv("E2E_KIND_HTTP_NETWORK_GATE") != "passed" {
		t.Fatal("cert-manager requires owned network proof")
	}
	chart := filepath.Join(f.work, "cert-manager", "chart.tgz")
	reportPath := filepath.Join(os.Getenv("E2E_KIND_NET_EVIDENCE"), "cert-manager-assets.json")
	data, err := os.ReadFile(chart)
	if err != nil {
		t.Fatal("pinned cert-manager chart absent")
	}
	sum := sha256.Sum256(data)
	if hex.EncodeToString(sum[:]) != cmChartSHA {
		t.Fatal("cert-manager chart differs")
	}
	var report struct {
		Version      string `json:"version"`
		Architecture string `json:"architecture"`
		ChartSHA     string `json:"chartSHA256"`
		Images       map[string]struct {
			Reference string `json:"reference"`
			Tag       string `json:"tag"`
			Manifest  string `json:"manifestDigest"`
		} `json:"images"`
	}
	raw, err := os.ReadFile(reportPath)
	if err != nil || json.Unmarshal(raw, &report) != nil || report.Version != "v1.21.2" || report.ChartSHA != cmChartSHA || len(report.Images) != 4 {
		t.Fatal("cert-manager assets not verified")
	}
	imageValues := func(role string) map[string]any {
		t.Helper()
		i, ok := report.Images[role]
		repo := "quay.io/jetstack/cert-manager-" + role
		if !ok || i.Reference != repo+"@"+i.Manifest || i.Tag != repo+":v1.21.2" || len(i.Manifest) != 71 || !strings.HasPrefix(i.Manifest, "sha256:") {
			t.Fatal("cert-manager image reference differs")
		}
		return map[string]any{"repository": repo, "digest": i.Manifest, "pullPolicy": "Never"}
	}
	ns := &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: cmNamespace}}
	if f.kube.Create(t.Context(), ns) != nil {
		t.Fatal("owned cert-manager namespace create failed")
	}
	var issuers, certificates []*unstructured.Unstructured
	installed := false
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 150*time.Second)
		defer cancel()
		if t.Failed() {
			captureCertManagerDiagnostics(f)
		}
		// Drain owned Certificate children while their controller and webhook run.
		for _, o := range certificates {
			uid := o.GetUID()
			if uid == "" {
				t.Error("owned CA Certificate identity missing")
				continue
			}
			if err := f.kube.Delete(ctx, o, client.Preconditions{UID: &uid}, client.PropagationPolicy(metav1.DeletePropagationForeground)); err != nil && !apierrors.IsNotFound(err) {
				t.Error("owned CA Certificate deletion failed")
				continue
			}
			if err := wait.PollUntilContextTimeout(ctx, 250*time.Millisecond, 30*time.Second, true, func(ctx context.Context) (bool, error) {
				current := cmObject("Certificate", o.GetNamespace(), o.GetName(), nil)
				err := f.kube.Get(ctx, client.ObjectKeyFromObject(o), current)
				return apierrors.IsNotFound(err), client.IgnoreNotFound(err)
			}); err != nil {
				t.Error("owned CA Certificate cleanup failed")
			}
		}
		for _, o := range issuers {
			if o.GetUID() != "" {
				uid := o.GetUID()
				if err := f.kube.Delete(ctx, o, client.Preconditions{UID: &uid}); err != nil && !apierrors.IsNotFound(err) {
					t.Error("owned issuer cleanup failed")
				}
			}
		}
		if installed {
			if _, err := f.command(ctx, "", "helm", "uninstall", "cm", "--kubeconfig", f.config, "--kube-context", f.context, "--namespace", cmNamespace, "--wait", "--timeout", "100s"); err != nil {
				t.Error("cert-manager release cleanup failed")
			}
		}
		if err := f.kube.Delete(ctx, ns, client.Preconditions{UID: &ns.UID}); err != nil && !apierrors.IsNotFound(err) {
			t.Error("cert-manager namespace cleanup failed")
			return
		}
		for {
			if apierrors.IsNotFound(f.kube.Get(ctx, client.ObjectKey{Name: cmNamespace}, &corev1.Namespace{})) {
				return
			}
			select {
			case <-ctx.Done():
				t.Error("cert-manager namespace still present")
				return
			case <-time.After(time.Second):
			}
		}
	})
	// No ACME/orders/challenges/shims or ambient credentials. Keep revision
	// management, approver restrictions, webhook and normal leader-election RBAC.
	values := map[string]any{
		"crds":            map[string]any{"enabled": true, "keep": true},
		"image":           imageValues("controller"),
		"extraArgs":       []string{"--issuer-ambient-credentials=false", "--cluster-issuer-ambient-credentials=false", "--controllers=issuers,clusterissuers,certificates-trigger,certificates-key-manager,certificates-request-manager,certificates-issuing,certificates-readiness,certificates-revision-manager,certificaterequests-approver,certificaterequests-issuer-selfsigned,certificaterequests-issuer-ca"},
		"cainjector":      map[string]any{"image": imageValues("cainjector")},
		"webhook":         map[string]any{"image": imageValues("webhook")},
		"startupapicheck": map[string]any{"image": imageValues("startupapicheck")},
	}
	input, _ := json.Marshal(values)
	ctx, cancel := context.WithTimeout(t.Context(), 240*time.Second)
	defer cancel()
	installed = true // A partially installed release also needs cleanup.
	if _, err := f.command(ctx, string(input), "helm", "install", "cm", chart, "--kubeconfig", f.config, "--kube-context", f.context, "--namespace", cmNamespace, "--wait", "--wait-for-jobs", "--timeout", "210s", "--values", "-"); err != nil {
		t.Fatalf("real cert-manager chart install failed: %v", err)
	}
	for _, name := range []string{"certificates", "certificaterequests", "issuers", "clusterissuers", "orders.acme", "challenges.acme"} {
		crd := name + ".cert-manager.io"
		if strings.Contains(name, ".acme") {
			crd = strings.TrimSuffix(name, ".acme") + ".acme.cert-manager.io"
		}
		f.child(t, "", "kubectl", "--kubeconfig", f.config, "--context", f.context, "--request-timeout=10s", "wait", "--for=condition=Established", "--timeout=30s", "crd/"+crd)
	}
	if admissionv1.AddToScheme(f.kube.Scheme()) != nil {
		t.Fatal("cert-manager admission scheme failed")
	}
	var deployments appsv1.DeploymentList
	if f.kube.List(t.Context(), &deployments, client.InNamespace(cmNamespace)) != nil || len(deployments.Items) != 3 {
		t.Fatal("real cert-manager deployments missing")
	}
	controllerSA := ""
	for _, d := range deployments.Items {
		if d.Status.ReadyReplicas != 1 || d.Status.ObservedGeneration != d.Generation || d.Spec.Template.Spec.HostNetwork || d.Spec.Template.Spec.ServiceAccountName == "" || len(d.Spec.Template.Spec.Containers) != 1 {
			t.Fatal("cert-manager workload readiness/security differs")
		}
		if strings.Contains(d.Spec.Template.Spec.Containers[0].Image, "cert-manager-controller") {
			controllerSA = d.Spec.Template.Spec.ServiceAccountName
		}
	}
	if controllerSA == "" {
		t.Fatal("cert-manager controller identity missing")
	}
	var validation admissionv1.ValidatingWebhookConfiguration
	var mutation admissionv1.MutatingWebhookConfiguration
	if f.kube.Get(t.Context(), client.ObjectKey{Name: "cm-cert-manager-webhook"}, &validation) != nil || f.kube.Get(t.Context(), client.ObjectKey{Name: "cm-cert-manager-webhook"}, &mutation) != nil {
		t.Fatal("real cert-manager admission missing")
	}
	for _, h := range validation.Webhooks {
		if h.FailurePolicy == nil || *h.FailurePolicy != admissionv1.Fail || len(h.ClientConfig.CABundle) == 0 || h.ClientConfig.Service == nil || h.ClientConfig.Service.Namespace != cmNamespace {
			t.Fatal("cert-manager validation not fail-closed")
		}
	}
	for _, h := range mutation.Webhooks {
		if h.FailurePolicy == nil || *h.FailurePolicy != admissionv1.Fail || len(h.ClientConfig.CABundle) == 0 {
			t.Fatal("cert-manager mutation unavailable")
		}
	}
	create := func(o *unstructured.Unstructured) {
		t.Helper()
		if f.kube.Create(t.Context(), o) != nil {
			t.Fatal("private issuer fixture create rejected")
		}
	}
	self := cmObject("ClusterIssuer", "", "fixture-selfsigned", map[string]any{"selfSigned": map[string]any{}})
	create(self)
	issuers = append(issuers, self)
	eventually(t, "selfsigned issuer Ready", func() bool {
		return f.kube.Get(t.Context(), client.ObjectKeyFromObject(self), self) == nil && cmReady(self)
	})
	root := cmObject("Certificate", cmNamespace, "fixture-ca", map[string]any{"secretName": "fixture-serving-root", "isCA": true, "commonName": "owned-kind-serving-ca", "duration": "2h", "renewBefore": "30m", "privateKey": map[string]any{"algorithm": "ECDSA", "size": int64(256)}, "usages": []any{"cert sign", "crl sign"}, "issuerRef": map[string]any{"name": self.GetName(), "kind": "ClusterIssuer", "group": "cert-manager.io"}})
	create(root)
	certificates = append(certificates, root.DeepCopy())
	eventually(t, "cert-manager selfsigned root Ready", func() bool {
		return f.kube.Get(t.Context(), client.ObjectKeyFromObject(root), root) == nil && cmReady(root)
	})
	var secret corev1.Secret
	if f.kube.Get(t.Context(), client.ObjectKey{Name: "fixture-serving-root", Namespace: cmNamespace}, &secret) != nil || secret.Type != corev1.SecretTypeTLS || len(secret.Data["tls.crt"]) == 0 {
		t.Fatal("serving root unavailable")
	}
	issuer := cmObject("ClusterIssuer", "", "fixture-serving", map[string]any{"ca": map[string]any{"secretName": secret.Name}})
	create(issuer)
	issuers = append(issuers, issuer)
	eventually(t, "private CA issuer Ready", func() bool {
		return f.kube.Get(t.Context(), client.ObjectKeyFromObject(issuer), issuer) == nil && cmReady(issuer)
	})
	bad := cmObject("Certificate", cmNamespace, "invalid-renewal", map[string]any{"secretName": "invalid-renewal", "dnsNames": []any{"http-agent.fixture.test"}, "duration": "1h", "renewBefore": "2h", "issuerRef": map[string]any{"name": issuer.GetName(), "kind": "ClusterIssuer", "group": "cert-manager.io"}})
	validationErr := f.kube.Create(t.Context(), bad, client.DryRunAll)
	var admissionStatus apierrors.APIStatus
	if errors.As(validationErr, &admissionStatus) {
		b, _ := json.Marshal(admissionStatus.Status())
		path := filepath.Join(os.Getenv("E2E_KIND_NET_EVIDENCE"), "cm-renewal-validation.private.json")
		if file, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600); err == nil {
			_, _ = file.Write(b)
			_ = file.Close()
		}
	}
	if !cmInvalidRenewal(validationErr) {
		t.Fatalf("real certificate validation not established (accepted=%t, structuredStatus=%t)", validationErr == nil, admissionStatus != nil)
	}
	var requests unstructured.UnstructuredList
	requests.SetAPIVersion("cert-manager.io/v1")
	requests.SetKind("CertificateRequestList")
	if f.kube.List(t.Context(), &requests, client.InNamespace(cmNamespace)) != nil || len(requests.Items) == 0 {
		t.Fatal("real root certificate request missing")
	}
	identityVerified := false
	for _, request := range requests.Items {
		identityVerified = identityVerified || cmRequestIdentity(&request, root, "system:serviceaccount:"+cmNamespace+":"+controllerSA)
	}
	if !identityVerified {
		t.Fatal("certificate request did not record controller ServiceAccount")
	}
	t.Log("gate: actual cert-manager chart/SA/RBAC/startup hook/admission, selfsigned root and private issuer Ready")
	return append([]byte(nil), secret.Data["tls.crt"]...)
}
