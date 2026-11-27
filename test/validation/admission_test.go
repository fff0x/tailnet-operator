//go:build integration

package validation

import (
	"context"
	"encoding/json"
	"fmt"
	"maps"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
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

	tnv1 "tsunaro.io/tailnet-operator/api/v1alpha1"
	"tsunaro.io/tailnet-operator/test/internal/isolation"
)

// TestAdmission runs a disposable API server, never the user's current kube-context. It validates
// the generated CRDs, examples and optional live export against actual Kubernetes admission/CEL.
func TestAdmission(t *testing.T) {
	if err := isolation.ClearEnvtestOverrides(); err != nil {
		t.Fatal(err)
	}
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
		if obj.GetKind() == "Tailnet" || obj.GetKind() == "TailnetGateway" {
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
	for _, kind := range []string{"tailnet", "tailnetegress", "tailnetingress", "tailnetgateway", "tailnetsite", "tailnetgrant"} {
		obj := load(t, filepath.Join(root, "deploy", "examples", kind+".yaml"))
		templates[kind] = obj
		t.Run("example/"+kind, func(t *testing.T) { accept(t, obj) })
	}
	t.Run("example/tailnet-hub-spokes", func(t *testing.T) {
		accept(t, load(t, filepath.Join(root, "deploy", "examples", "tailnet-hub-spokes.yaml")))
	})
	for _, example := range []string{"tailnetegress-bridge", "tailnetingress-bridge", "console-ingress"} {
		t.Run("example/"+example, func(t *testing.T) {
			accept(t, load(t, filepath.Join(root, "deploy", "examples", example+".yaml")))
		})
	}
	t.Run("expose-boundaries", func(t *testing.T) {
		// The narrowest allowed prefixes per family and an exposed egress without LB passthrough.
		for _, prefixes := range [][]any{{"10.1.0.0/16"}, {"2001:db8::/48"}, {"192.0.2.77/32", "2001:db8:1::1/128"}} {
			obj := templates["tailnetegress"].DeepCopy()
			obj.Object["spec"].(map[string]any)["expose"] = map[string]any{"allowFrom": prefixes}
			accept(t, obj)
		}
		tn := templates["tailnet"].DeepCopy()
		tn.Object["spec"].(map[string]any)["exposeSourceAllowlist"] = []any{"10.0.0.0/8", "2001:db8::/32"}
		tn.Object["spec"].(map[string]any)["bridgeNameAllowlist"] = []any{"site.example", "corp.example.internal"}
		accept(t, tn)
		for _, zones := range [][]any{{"site"}, {"Site.example"}, {"site.example."}, {"site.example", "site.example"}, {""}} {
			bad := tn.DeepCopy()
			bad.Object["spec"].(map[string]any)["bridgeNameAllowlist"] = zones
			if err := c.Create(ctx, bad, client.DryRunAll); !apierrors.IsInvalid(err) {
				t.Fatalf("bridgeNameAllowlist=%v accepted: %v", zones, err)
			}
		}
	})

	t.Run("grant-sources", func(t *testing.T) {
		// A source is group:<name> or a user reference with exactly one @; a site target is a prefix list.
		with := func(source string) *unstructured.Unstructured {
			obj := templates["tailnetgrant"].DeepCopy()
			obj.Object["spec"].(map[string]any)["sources"] = []any{source}
			return obj
		}
		for _, source := range []string{"group:ops", "alice@", "alice@example.com", "https://id.example.com/59ac9125@"} {
			accept(t, with(source))
		}
		for _, source := range []string{"alice", "a@b@c", "@", "group:", "group:two words", "tag:x@", "autogroup:member", "autogroup:member@", "two words@"} {
			if err := c.Create(ctx, with(source), client.DryRunAll); !apierrors.IsInvalid(err) {
				t.Fatalf("source %q accepted: %v", source, err)
			}
		}
		site := templates["tailnetgrant"].DeepCopy()
		site.Object["spec"].(map[string]any)["target"] = map[string]any{"prefixes": []any{"203.0.113.5/32", "2001:db8::/64"}}
		delete(site.Object["spec"].(map[string]any), "expiresAt")
		accept(t, site)
		// Upper bounds: 16 sources, ports and prefixes, and port 65535.
		many := func(n int, item func(int) any) []any {
			out := make([]any, n)
			for i := range out {
				out[i] = item(i)
			}
			return out
		}
		source := func(i int) any { return fmt.Sprintf("user-%d@", i) }
		port := func(i int) any { return int64(65535 - i) }
		prefix := func(i int) any { return fmt.Sprintf("203.0.113.%d/32", i) }
		for _, tc := range []struct {
			name string
			set  func(spec map[string]any, n int)
		}{
			{"sources", func(spec map[string]any, n int) { spec["sources"] = many(n, source) }},
			{"ports", func(spec map[string]any, n int) { spec["ports"] = many(n, port) }},
			{"prefixes", func(spec map[string]any, n int) { spec["target"] = map[string]any{"prefixes": many(n, prefix)} }},
		} {
			full := templates["tailnetgrant"].DeepCopy()
			tc.set(full.Object["spec"].(map[string]any), 16)
			accept(t, full)
			over := templates["tailnetgrant"].DeepCopy()
			tc.set(over.Object["spec"].(map[string]any), 17)
			if err := c.Create(ctx, over, client.DryRunAll); !apierrors.IsInvalid(err) {
				t.Fatalf("17 %s accepted: %v", tc.name, err)
			}
		}
		high := templates["tailnetgrant"].DeepCopy()
		high.Object["spec"].(map[string]any)["ports"] = []any{int64(65536)}
		if err := c.Create(ctx, high, client.DryRunAll); !apierrors.IsInvalid(err) {
			t.Fatalf("port 65536 accepted: %v", err)
		}
	})

	t.Run("access-request", func(t *testing.T) {
		// Written only by the console: a Create carries sources, target and ports, an Extend only
		// grantName; the spec never changes and the status names nobody.
		request := func(name string, spec map[string]any) *unstructured.Unstructured {
			base := map[string]any{"tailnetRef": map[string]any{"name": "corp"}, "requester": "https://id.example.com/59ac9125",
				"requestedAs": "User", "duration": "8h"}
			for k, v := range spec {
				if v == nil {
					delete(base, k)
				} else {
					base[k] = v
				}
			}
			return &unstructured.Unstructured{Object: map[string]any{"apiVersion": "tsunaro.io/v1alpha1", "kind": "TailnetAccessRequest",
				"metadata": map[string]any{"name": name}, "spec": base}}
		}
		create := map[string]any{"action": "Create", "sources": []any{"https://id.example.com/59ac9125@"},
			"target": map[string]any{"tag": "tag:shop"}, "ports": []any{int64(5432)}, "description": "on call"}
		extend := map[string]any{"action": "Extend", "grantName": "console-abc123defg", "duration": "permanent", "requestedAs": "Admin"}
		accept(t, request("request-create", create))
		accept(t, request("request-extend", extend))
		with := func(base map[string]any, k string, v any) map[string]any {
			out := maps.Clone(base)
			out[k] = v
			return out
		}
		for name, spec := range map[string]map[string]any{
			"extend without grantName": with(extend, "grantName", nil),
			"create with grantName":    with(create, "grantName", "console-x"),
			"create without target":    with(create, "target", nil),
			"create without ports":     with(create, "ports", nil),
			"extend with sources":      with(extend, "sources", []any{"alice@"}),
			"unknown action":           with(create, "action", "Revoke"),
			"free duration":            with(create, "duration", "2h"),
			"unknown role":             with(create, "requestedAs", "Owner"),
			"no requester":             with(create, "requester", nil),
			"tag source":               with(create, "sources", []any{"tag:ci"}),
			"both targets":             with(create, "target", map[string]any{"tag": "tag:shop", "prefixes": []any{"10.0.0.1/32"}}),
		} {
			if err := c.Create(ctx, request("request-bad", spec), client.DryRunAll); !apierrors.IsInvalid(err) {
				t.Errorf("%s accepted: %v", name, err)
			}
		}
		live := request("request-live", create)
		if err := c.Create(ctx, live); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = c.Delete(context.Background(), live) })
		changed := live.DeepCopy()
		changed.Object["spec"].(map[string]any)["duration"] = "30d"
		if err := c.Update(ctx, changed); !apierrors.IsInvalid(err) {
			t.Fatalf("spec change accepted: %v", err)
		}
		live.Object["status"] = map[string]any{"phase": "Approved", "decidedAt": "2026-11-27T13:00:00Z", "grantName": "console-abc123defg"}
		if err := c.Status().Update(ctx, live); err != nil {
			t.Fatalf("status rejected: %v", err)
		}
		live.Object["status"] = map[string]any{"phase": "Done"}
		if err := c.Status().Update(ctx, live); !apierrors.IsInvalid(err) {
			t.Fatalf("unknown phase accepted: %v", err)
		}
	})

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

		// A spoke in Export mode has no base; a hub may list fragment ConfigMaps alongside its base.
		spoke := templates["tailnet"].DeepCopy()
		spoke.SetName("spoke")
		spokePolicy := spoke.Object["spec"].(map[string]any)["policy"].(map[string]any)
		delete(spokePolicy, "baseConfigMap")
		spokePolicy["mode"] = "Export"
		accept(t, spoke)

		hub := templates["tailnet"].DeepCopy()
		hub.SetName("hub")
		hubPolicy := hub.Object["spec"].(map[string]any)["policy"].(map[string]any)
		hubPolicy["mode"] = "Apply"
		hubPolicy["fragmentConfigMaps"] = []any{"spoke-frag", "other-frag"}
		accept(t, hub)
	})

	// The rule: spokes[] is a hub-only field — it needs a base and is refused in mode Export; each
	// entry is a DNS label with a kubeconfig Secret, its approval is Auto or Manual and defaults to
	// Auto, tag patterns are tag globs.
	t.Run("policy-spokes", func(t *testing.T) {
		withSpokes := func(spokes ...map[string]any) *unstructured.Unstructured {
			obj := templates["tailnet"].DeepCopy()
			obj.SetName("hub-spokes")
			policy := obj.Object["spec"].(map[string]any)["policy"].(map[string]any)
			policy["mode"] = "Apply"
			list := make([]any, 0, len(spokes))
			for _, s := range spokes {
				list = append(list, s)
			}
			policy["spokes"] = list
			return obj
		}
		spoke := func(name string) map[string]any {
			return map[string]any{"name": name, "kubeconfigSecretRef": map[string]any{"name": name + "-kubeconfig"}}
		}
		reject := func(t *testing.T, obj *unstructured.Unstructured, message string) {
			t.Helper()
			err := c.Create(ctx, obj, client.DryRunAll)
			if !apierrors.IsInvalid(err) || !strings.Contains(err.Error(), message) {
				t.Fatalf("want Invalid containing %q, got %v", message, err)
			}
		}

		full := spoke("prod-2")
		full["namespace"] = "tailnet-system"
		full["configMap"] = "prod-2-policy-fragment"
		full["tagPatterns"] = []any{"tag:*-prod-2-*", "tag:prod2-*"}
		full["routeAllowlist"] = []any{"192.0.2.0/24", "2001:db8::/32"}
		full["approval"] = "Manual"
		accept(t, withSpokes(spoke("edge"), full))

		// Defaults land in the persisted object.
		stored := withSpokes(spoke("edge"))
		if err := c.Create(ctx, stored); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = c.Delete(ctx, stored) })
		got := &unstructured.Unstructured{}
		got.SetGroupVersionKind(stored.GroupVersionKind())
		if err := c.Get(ctx, client.ObjectKeyFromObject(stored), got); err != nil {
			t.Fatal(err)
		}
		entry := got.Object["spec"].(map[string]any)["policy"].(map[string]any)["spokes"].([]any)[0].(map[string]any)
		if entry["approval"] != "Auto" || entry["kubeconfigSecretRef"].(map[string]any)["key"] != "kubeconfig" {
			t.Fatalf("spoke defaults: %v", entry)
		}

		noBase := withSpokes(spoke("edge"))
		delete(noBase.Object["spec"].(map[string]any)["policy"].(map[string]any), "baseConfigMap")
		reject(t, noBase, "policy.spokes requires baseConfigMap")

		export := withSpokes(spoke("edge"))
		exportPolicy := export.Object["spec"].(map[string]any)["policy"].(map[string]any)
		delete(exportPolicy, "baseConfigMap")
		exportPolicy["mode"] = "Export"
		reject(t, export, "policy.spokes requires baseConfigMap and is not allowed in mode Export")

		reject(t, withSpokes(spoke("edge"), spoke("edge")), "Duplicate value")
		reject(t, withSpokes(spoke("Prod_2")), "should match")
		reject(t, withSpokes(map[string]any{"name": "edge"}), "Required value")
		bad := spoke("edge")
		bad["approval"] = "Ask"
		reject(t, withSpokes(bad), "Unsupported value")
		bad = spoke("edge")
		bad["tagPatterns"] = []any{"group:*"}
		reject(t, withSpokes(bad), "should match")
		bad = spoke("edge")
		bad["routeAllowlist"] = []any{"not-a-prefix"}
		reject(t, withSpokes(bad), "")
	})

	t.Run("image-pull-secrets", func(t *testing.T) {
		for _, tt := range []struct {
			name  string
			names []any
		}{
			{name: "omitted"},
			{name: "empty", names: []any{}},
			{name: "duplicates", names: []any{"registry", "registry"}},
			{name: "override", names: []any{"registry.example", "0-registry", strings.Repeat("a", 253)}},
		} {
			t.Run(tt.name, func(t *testing.T) {
				obj := templates["tailnet"].DeepCopy()
				obj.SetName("pull-secrets-" + tt.name)
				if tt.names != nil {
					if err := unstructured.SetNestedSlice(obj.Object, tt.names, "spec", "proxy", "imagePullSecrets"); err != nil {
						t.Fatal(err)
					}
				}
				// Persist only in the disposable API server, then remove before the dry-run invariant.
				if err := c.Create(ctx, obj); err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() {
					if err := c.Delete(ctx, obj); err != nil {
						t.Error(err)
					}
				})
				stored := &unstructured.Unstructured{}
				stored.SetGroupVersionKind(obj.GroupVersionKind())
				if err := c.Get(ctx, client.ObjectKeyFromObject(obj), stored); err != nil {
					t.Fatal(err)
				}
				got, found, err := unstructured.NestedSlice(stored.Object, "spec", "proxy", "imagePullSecrets")
				if err != nil || found != (tt.names != nil) || !reflect.DeepEqual(got, tt.names) {
					t.Fatalf("stored names=%v present=%v err=%v; want %v", got, found, err, tt.names)
				}
				// Exercise the typed client's JSON representation, including explicit [].
				data, err := json.Marshal(stored)
				if err != nil {
					t.Fatal(err)
				}
				var typed tnv1.Tailnet
				if err := json.Unmarshal(data, &typed); err != nil {
					t.Fatal(err)
				}
				data, err = json.Marshal(&typed)
				if err != nil {
					t.Fatal(err)
				}
				if err := json.Unmarshal(data, stored); err != nil {
					t.Fatal(err)
				}
				if err := c.Update(ctx, stored); err != nil {
					t.Fatal(err)
				}
				if err := c.Get(ctx, client.ObjectKeyFromObject(obj), stored); err != nil {
					t.Fatal(err)
				}
				got, found, err = unstructured.NestedSlice(stored.Object, "spec", "proxy", "imagePullSecrets")
				if err != nil || found != (tt.names != nil) || !reflect.DeepEqual(got, tt.names) {
					t.Fatalf("roundtrip names=%v present=%v err=%v; want %v", got, found, err, tt.names)
				}
			})
		}
		for _, value := range []any{
			"registry", map[string]any{"name": "registry"}, []any{int64(1)}, []any{nil},
			[]any{""}, []any{"Registry"}, []any{"registry/name"}, []any{"registry_name"},
			[]any{"-registry"}, []any{"registry-"}, []any{"registry..example"},
			[]any{strings.Repeat("a", 254)},
		} {
			obj := templates["tailnet"].DeepCopy()
			if err := unstructured.SetNestedField(obj.Object, value, "spec", "proxy", "imagePullSecrets"); err != nil {
				t.Fatal(err)
			}
			if err := c.Create(ctx, obj, client.DryRunAll); !apierrors.IsInvalid(err) {
				t.Fatalf("invalid imagePullSecrets %v: %v", value, err)
			}
		}
	})

	t.Run("http-tls-api", func(t *testing.T) {
		// These cases validate only the API contract, not HTTP/TLS runtime support.
		newIngress := func() *unstructured.Unstructured {
			return &unstructured.Unstructured{Object: map[string]any{
				"apiVersion": "tsunaro.io/v1alpha1", "kind": "TailnetIngress",
				"metadata": map[string]any{"name": "http-api", "namespace": "validation"},
				"spec": map[string]any{
					"tailnetRef": map[string]any{"name": "default-tls"},
					"allowFrom":  []any{"group:team"},
					"exposes": []any{map[string]any{"name": "app", "mode": "http", "port": int64(443),
						"backend": map[string]any{"service": "app", "port": int64(8080)}}},
				},
			}}
		}
		expose := func(obj *unstructured.Unstructured) map[string]any {
			return obj.Object["spec"].(map[string]any)["exposes"].([]any)[0].(map[string]any)
		}
		admit := func(t *testing.T, obj *unstructured.Unstructured) {
			t.Helper()
			prepare(t, obj)
			if err := c.Create(ctx, obj, client.DryRunAll); err != nil {
				t.Fatalf("API shape rejected: %v", err)
			}
		}
		reject := func(t *testing.T, obj *unstructured.Unstructured, message string) {
			t.Helper()
			prepare(t, obj)
			err := c.Create(ctx, obj, client.DryRunAll)
			if !apierrors.IsInvalid(err) || !strings.Contains(err.Error(), message) {
				t.Fatalf("want Invalid containing %q, got %v", message, err)
			}
		}
		checkIssuer := func(t *testing.T, obj *unstructured.Unstructured, kind string, path ...string) {
			t.Helper()
			ref, found, err := unstructured.NestedMap(obj.Object, path...)
			if err != nil || !found || ref["kind"] != kind || ref["group"] != "cert-manager.io" || ref["name"] != "ca.example" {
				t.Fatalf("issuer defaulting: ref=%v found=%v err=%v", ref, found, err)
			}
		}

		t.Run("extensions", func(t *testing.T) {
			testHTTPExtensionAdmission(t, newIngress, admit, reject)
		})
		t.Run("virtual-hosts", func(t *testing.T) {
			testHTTPVirtualHostAdmission(t, newIngress, admit, reject)
		})

		for _, mode := range []string{"omitted", "l4", "http"} {
			t.Run("mode/"+mode, func(t *testing.T) {
				obj := newIngress()
				want := mode
				if mode == "omitted" {
					delete(expose(obj), "mode")
					want = "l4"
				} else {
					expose(obj)["mode"] = mode
				}
				admit(t, obj) // HTTP without any local source must be accepted.
				if expose(obj)["mode"] != want {
					t.Fatalf("mode=%v, want %s", expose(obj)["mode"], want)
				}
			})
		}
		for _, tt := range []struct {
			name string
			tls  map[string]any
		}{
			{"empty-inherits-tailnet-default", map[string]any{}},
			{"explicit-secret", map[string]any{"secretName": "app.tls"}},
			{"issuer-defaults", map[string]any{"issuerRef": map[string]any{"name": "ca.example"}}},
			{"issuer", map[string]any{"issuerRef": map[string]any{"name": "ca.example", "kind": "Issuer", "group": "cert-manager.io"}}},
			{"cluster-issuer", map[string]any{"issuerRef": map[string]any{"name": "ca.example", "kind": "ClusterIssuer"}}},
		} {
			t.Run(tt.name, func(t *testing.T) {
				obj := newIngress()
				obj.Object["spec"].(map[string]any)["tls"] = tt.tls
				admit(t, obj)
				if ref, ok := tt.tls["issuerRef"].(map[string]any); ok {
					kind := "Issuer"
					if ref["kind"] == "ClusterIssuer" {
						kind = "ClusterIssuer"
					}
					checkIssuer(t, obj, kind, "spec", "tls", "issuerRef")
				}
			})
		}
		t.Run("mixed-l4-http", func(t *testing.T) {
			obj := newIngress()
			spec := obj.Object["spec"].(map[string]any)
			spec["tls"] = map[string]any{}
			spec["exposes"] = append(spec["exposes"].([]any), map[string]any{
				"name": "db", "port": int64(5432), "backend": map[string]any{"service": "db", "port": int64(5432)},
			})
			admit(t, obj)
		})
		for _, kind := range []string{"omitted", "Issuer", "ClusterIssuer"} {
			t.Run("tailnet-default/"+kind, func(t *testing.T) {
				obj := templates["tailnet"].DeepCopy()
				ref := map[string]any{"name": "ca.example"}
				want := kind
				if kind == "omitted" {
					want = "Issuer"
				} else {
					ref["kind"] = kind
				}
				obj.Object["spec"].(map[string]any)["defaults"] = map[string]any{"tls": map[string]any{"issuerRef": ref}}
				admit(t, obj)
				checkIssuer(t, obj, want, "spec", "defaults", "tls", "issuerRef")
			})
		}
		for _, defaults := range []map[string]any{{}, {"tls": map[string]any{}}} {
			obj := templates["tailnet"].DeepCopy()
			obj.Object["spec"].(map[string]any)["defaults"] = defaults
			admit(t, obj)
		}
		for _, tt := range []struct {
			name    string
			mutate  func(*unstructured.Unstructured)
			message string
		}{
			{"bad-mode", func(o *unstructured.Unstructured) { expose(o)["mode"] = "tcp" }, "Unsupported value"},
			{"empty-mode", func(o *unstructured.Unstructured) { expose(o)["mode"] = "" }, "Unsupported value"},
			{"http-port", func(o *unstructured.Unstructured) { expose(o)["port"] = int64(80) }, "HTTP exposes must listen on port 443"},
			{"multiple-http", func(o *unstructured.Unstructured) {
				spec := o.Object["spec"].(map[string]any)
				second := newIngress()
				expose(second)["name"] = "another"
				spec["exposes"] = append(spec["exposes"].([]any), expose(second))
			}, "at most one HTTP expose without a nonempty dnsLabel is allowed"},
			{"mutually-exclusive", func(o *unstructured.Unstructured) {
				o.Object["spec"].(map[string]any)["tls"] = map[string]any{"secretName": "app-tls", "issuerRef": map[string]any{"name": "ca"}}
			}, "tls.secretName and tls.issuerRef are mutually exclusive"},
		} {
			t.Run(tt.name, func(t *testing.T) {
				obj := newIngress()
				tt.mutate(obj)
				reject(t, obj, tt.message)
			})
		}
		for _, mode := range []string{"omitted", "l4"} {
			for _, tls := range []map[string]any{{}, {"secretName": "app-tls"}, {"issuerRef": map[string]any{"name": "ca"}}} {
				obj := newIngress()
				if mode == "omitted" {
					delete(expose(obj), "mode")
				} else {
					expose(obj)["mode"] = mode
				}
				obj.Object["spec"].(map[string]any)["tls"] = tls
				reject(t, obj, "tls requires an HTTP expose")
			}
		}

		// The same reference schema must validate both local and Tailnet-default issuers.
		for _, target := range []string{"secret", "issuer", "default-issuer"} {
			t.Run("names/"+target, func(t *testing.T) {
				withName := func(name any, include bool) *unstructured.Unstructured {
					obj := newIngress()
					ref := map[string]any{}
					if include {
						ref["name"] = name
					}
					switch target {
					case "secret":
						obj.Object["spec"].(map[string]any)["tls"] = map[string]any{"secretName": name}
					case "issuer":
						obj.Object["spec"].(map[string]any)["tls"] = map[string]any{"issuerRef": ref}
					case "default-issuer":
						obj = templates["tailnet"].DeepCopy()
						obj.Object["spec"].(map[string]any)["defaults"] = map[string]any{"tls": map[string]any{"issuerRef": ref}}
					}
					return obj
				}
				for _, name := range []string{"a", "0-ca", "ca.example", strings.Repeat("a", 253)} {
					admit(t, withName(name, true))
				}
				for _, name := range []string{"", "CA", "ca/name", "ca_name", "-ca", "ca-", "ca..example", ".ca", "ca.", strings.Repeat("a", 254)} {
					reject(t, withName(name, true), "")
				}
				if target == "secret" {
					return
				}
				reject(t, withName(nil, false), "Required value")
				for _, field := range []string{"group", "kind"} {
					for _, value := range []string{"", "unsupported", "issuer"} {
						obj := withName("ca", true)
						path := []string{"spec", "tls", "issuerRef", field}
						if target == "default-issuer" {
							path = []string{"spec", "defaults", "tls", "issuerRef", field}
						}
						if err := unstructured.SetNestedField(obj.Object, value, path...); err != nil {
							t.Fatal(err)
						}
						reject(t, obj, "Unsupported value")
					}
				}
			})
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

	// All CR operations are dry-runs except the storage roundtrip tests, which clean up their CRs.
	for _, kind := range []string{"TailnetList", "TailnetEgressList", "TailnetIngressList", "TailnetGatewayList"} {
		list := &unstructured.UnstructuredList{}
		list.SetAPIVersion("tsunaro.io/v1alpha1")
		list.SetKind(kind)
		if err := c.List(ctx, list); err != nil || len(list.Items) != 0 {
			t.Errorf("dry-run invariant: kind=%s persisted=%d err=%v", kind, len(list.Items), err)
		}
	}
}
