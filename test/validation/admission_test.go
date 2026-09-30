//go:build integration

package validation

import (
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/client-go/tools/clientcmd"
	clientcmdapi "k8s.io/client-go/tools/clientcmd/api"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/envtest"
	"sigs.k8s.io/yaml"
)

// TestAdmission runs a disposable API server, never the user's current kube-context. It validates
// the generated CRDs, examples and optional live export against actual Kubernetes admission/CEL.
func TestAdmission(t *testing.T) {
	if os.Getenv("KUBEBUILDER_ASSETS") == "" {
		t.Fatal("set KUBEBUILDER_ASSETS to envtest binaries for Kubernetes >= 1.31")
	}
	root, err := filepath.Abs(filepath.Join("..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	useExistingCluster := false // Override USE_EXISTING_CLUSTER: this test must never install CRDs in a real cluster.
	env := &envtest.Environment{
		UseExistingCluster:    &useExistingCluster,
		CRDDirectoryPaths:     []string{filepath.Join(root, "deploy", "crds")},
		ErrorIfCRDPathMissing: true,
	}
	t.Cleanup(func() {
		if err := env.Stop(); err != nil {
			t.Errorf("stop envtest: %v", err)
		}
	})
	cfg, err := env.Start()
	if err != nil {
		t.Fatal(err)
	}
	c, err := client.New(cfg, client.Options{})
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	namespaces := map[string]bool{}
	prepare := func(t *testing.T, obj *unstructured.Unstructured) {
		t.Helper()
		if obj.GetKind() == "Tailnet" {
			return
		}
		if obj.GetNamespace() == "" {
			obj.SetNamespace("validation")
		}
		ns := obj.GetNamespace()
		if !namespaces[ns] {
			if err := c.Create(ctx, &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: ns}}); err != nil && !apierrors.IsAlreadyExists(err) {
				t.Fatal(err)
			}
			namespaces[ns] = true
		}
	}
	accept := func(t *testing.T, obj *unstructured.Unstructured) {
		t.Helper()
		prepare(t, obj)
		if err := c.Create(ctx, obj.DeepCopy(), client.DryRunAll); err != nil {
			t.Fatalf("valid %s/%s rejected: %v", obj.GetKind(), obj.GetName(), err)
		}
	}
	load := func(t *testing.T, path string) *unstructured.Unstructured {
		t.Helper()
		b, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		obj := &unstructured.Unstructured{}
		if err := yaml.Unmarshal(b, &obj.Object); err != nil {
			t.Fatal(err)
		}
		return obj
	}

	templates := map[string]*unstructured.Unstructured{}
	for _, kind := range []string{"tailnet", "tailnetegress", "tailnetingress"} {
		obj := load(t, filepath.Join(root, "deploy", "examples", kind+".yaml"))
		templates[kind] = obj
		t.Run("example/"+kind, func(t *testing.T) { accept(t, obj) })
	}

	t.Run("valid-boundaries", func(t *testing.T) {
		for _, address := range []string{"10.0.0.1", "2001:db8::1", "printer", "db.magic.example", strings.Repeat("a", 63) + "." + strings.Repeat("b", 63) + "." + strings.Repeat("c", 63) + "." + strings.Repeat("d", 61)} {
			t.Run("address/"+address, func(t *testing.T) {
				obj := templates["tailnetegress"].DeepCopy()
				obj.Object["spec"].(map[string]any)["targets"] = []any{map[string]any{"name": "db", "address": address, "port": int64(1)}}
				accept(t, obj)
			})
		}
		for _, kind := range []string{"tailnetegress", "tailnetingress"} {
			obj := templates[kind].DeepCopy()
			obj.SetName(strings.Repeat("a", 40))
			accept(t, obj)
		}
		eg := templates["tailnetegress"].DeepCopy()
		targets := make([]any, 50)
		for i := range targets {
			targets[i] = map[string]any{"name": strings.Repeat("a", i+1), "address": "10.0.0.1", "port": int64(65535)}
		}
		targets[0].(map[string]any)["name"] = strings.Repeat("b", 63)
		targets[0].(map[string]any)["aliases"] = []any{strings.Repeat("c", 63)}
		eg.Object["spec"].(map[string]any)["targets"] = targets
		accept(t, eg)

		in := templates["tailnetingress"].DeepCopy()
		exposes := make([]any, 50)
		for i := range exposes {
			exposes[i] = map[string]any{"name": strings.Repeat("a", i+1), "port": int64(i + 1),
				"backend": map[string]any{"service": strings.Repeat("b", 63), "port": int64(65535)}}
		}
		exposes[0].(map[string]any)["name"] = strings.Repeat("c", 63)
		exposes[0].(map[string]any)["port"] = int64(65535)
		exposes[0].(map[string]any)["backend"].(map[string]any)["namespace"] = strings.Repeat("d", 63)
		in.Object["spec"].(map[string]any)["exposes"] = exposes
		accept(t, in)

		for _, duration := range []string{"1h", "1h30m", "1.5h", "720h"} {
			obj := templates["tailnet"].DeepCopy()
			obj.Object["spec"].(map[string]any)["apiKeyLifetime"] = duration
			accept(t, obj)
		}
		for _, template := range []string{"", "{name}.cluster.example", "{namespace}.{name}-app.cluster.example"} {
			obj := templates["tailnet"].DeepCopy()
			spec := obj.Object["spec"].(map[string]any)
			spec["dns"] = map[string]any{"ingressNameTemplate": template}
			spec["policy"].(map[string]any)["ingressSourceAllowlist"] = []any{"group:*", "tag:apps-*", "autogroup:member", "alice@example.com", "*@example.com"}
			accept(t, obj)
		}
	})

	t.Run("service-name-boundaries", func(t *testing.T) {
		for _, name := range []string{"a", "db1", "a-0", strings.Repeat("a", 63)} {
			t.Run(name, func(t *testing.T) {
				obj := templates["tailnetegress"].DeepCopy()
				obj.Object["spec"].(map[string]any)["targets"] = []any{map[string]any{"name": name, "address": "10.0.0.1", "port": int64(5432)}}
				accept(t, obj)
				// Target names are used verbatim for Services; test both admission surfaces.
				svc := &corev1.Service{
					ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: obj.GetNamespace()},
					Spec:       corev1.ServiceSpec{Ports: []corev1.ServicePort{{Port: 5432}}},
				}
				if err := c.Create(ctx, svc, client.DryRunAll); err != nil {
					t.Fatalf("admitted target name %q rejected for Service: %v", name, err)
				}
			})
		}
	})

	t.Run("invalid-address-boundaries", func(t *testing.T) {
		for _, address := range []string{"010.0.0.1", "[::1]:443", "2001:db8::/64", "fe80::1%eth0", "https://db.example", "Upper.example", strings.Repeat("a", 64) + ".example"} {
			t.Run(address, func(t *testing.T) {
				obj := templates["tailnetegress"].DeepCopy()
				obj.Object["spec"].(map[string]any)["targets"] = []any{map[string]any{"name": "db", "address": address, "port": int64(5432)}}
				err := c.Create(ctx, obj, client.DryRunAll)
				if !apierrors.IsInvalid(err) || !strings.Contains(err.Error(), "address must be an IP or a lowercase DNS name") {
					t.Fatalf("invalid address %q: %v", address, err)
				}
			})
		}
	})

	t.Run("negative-fixtures", func(t *testing.T) {
		files, err := filepath.Glob(filepath.Join(root, "deploy", "examples", "invalid", "*.yaml"))
		if err != nil || len(files) == 0 {
			t.Fatalf("invalid fixtures: %v (%d files)", err, len(files))
		}
		for _, file := range files {
			t.Run(filepath.Base(file), func(t *testing.T) {
				b, err := os.ReadFile(file)
				if err != nil {
					t.Fatal(err)
				}
				line, _, _ := strings.Cut(string(b), "\n")
				expected, ok := strings.CutPrefix(line, "# ExpectedError: ")
				if !ok || expected == "" {
					t.Fatal("missing ExpectedError header")
				}
				obj := load(t, file)
				prepare(t, obj)
				err = c.Create(ctx, obj, client.DryRunAll)
				if !apierrors.IsInvalid(err) || !strings.Contains(err.Error(), expected) {
					t.Fatalf("want Invalid containing %q, got %v", expected, err)
				}
			})
		}
	})

	t.Run("live-export", func(t *testing.T) {
		path := os.Getenv("LIVE_CR_FILE")
		if path == "" {
			t.Skip("set LIVE_CR_FILE to a kubectl get tailnet,tailnetegress,tailnetingress -A -o json export")
		}
		b, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		var list unstructured.UnstructuredList
		if err := json.Unmarshal(b, &list); err != nil || len(list.Items) == 0 {
			t.Fatalf("invalid or empty live export: %v", err)
		}
		for _, live := range list.Items {
			t.Run(live.GetKind()+"/"+live.GetName(), func(t *testing.T) {
				// Validate the complete spec as a fresh object; do not rely on validation ratcheting
				// to hide invalid legacy values. No real cluster is written to.
				obj := &unstructured.Unstructured{Object: map[string]any{
					"apiVersion": live.GetAPIVersion(), "kind": live.GetKind(),
					"metadata": map[string]any{"name": live.GetName()}, "spec": live.Object["spec"],
				}}
				obj.SetNamespace(live.GetNamespace())
				accept(t, obj)
			})
		}
	})

	t.Run("validation-script", func(t *testing.T) {
		kc := clientcmdapi.Config{
			Clusters:       map[string]*clientcmdapi.Cluster{"envtest": {Server: cfg.Host, CertificateAuthorityData: cfg.CAData}},
			AuthInfos:      map[string]*clientcmdapi.AuthInfo{"envtest": {ClientCertificateData: cfg.CertData, ClientKeyData: cfg.KeyData}},
			Contexts:       map[string]*clientcmdapi.Context{"envtest": {Cluster: "envtest", AuthInfo: "envtest", Namespace: "validation"}},
			CurrentContext: "envtest",
		}
		path := filepath.Join(t.TempDir(), "kubeconfig")
		if err := clientcmd.WriteToFile(kc, path); err != nil {
			t.Fatal(err)
		}
		cmd := exec.Command("bash", filepath.Join(root, "hack", "validate-examples.sh"), "--kubeconfig", path, "--context", "envtest")
		out, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("validation script: %v\n%s", err, out)
		}
		t.Log(string(out))
	})

	// All CR operations above must be dry-runs, including the shell script.
	for _, kind := range []string{"TailnetList", "TailnetEgressList", "TailnetIngressList"} {
		list := &unstructured.UnstructuredList{}
		list.SetAPIVersion("tailnet.this-is-fine.io/v1alpha1")
		list.SetKind(kind)
		if err := c.List(ctx, list); err != nil || len(list.Items) != 0 {
			t.Errorf("dry-run invariant: kind=%s persisted=%d err=%v", kind, len(list.Items), err)
		}
	}
}
