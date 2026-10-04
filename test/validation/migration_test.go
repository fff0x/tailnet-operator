//go:build integration

package validation

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	apiextensionsv1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/client-go/discovery"
	"k8s.io/client-go/dynamic"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/envtest"
	"sigs.k8s.io/yaml"

	"tsunaro.io/tailnet-operator/internal/migration"
	"tsunaro.io/tailnet-operator/test/internal/isolation"
)

// This tests real admission, persistence and JSONPatch CAS only. Envtest has no
// garbage collector, Deployment controller or kubelet; no dataplane claim follows.
func TestMigration(t *testing.T) {
	if err := isolation.ClearEnvtestOverrides(); err != nil {
		t.Fatal(err)
	}
	assets := os.Getenv("KUBEBUILDER_ASSETS")
	if assets == "" {
		t.Fatal("set KUBEBUILDER_ASSETS to verified envtest binaries")
	}
	root, err := filepath.Abs(filepath.Join("..", "..", "deploy", "crds"))
	if err != nil {
		t.Fatal(err)
	}
	// This suite models only the reviewed three-kind legacy-group handover.
	// New kinds must not be cloned into a fictitious historical API. Discovery
	// deliberately rejects an installed gateway kind (see the unit regression).
	var definitions []*apiextensionsv1.CustomResourceDefinition
	for _, file := range []string{"tsunaro.io_tailnets.yaml", "tsunaro.io_tailnetegresses.yaml", "tsunaro.io_tailnetingresses.yaml"} {
		data, err := os.ReadFile(filepath.Join(root, file))
		if err != nil {
			t.Fatal(err)
		}
		var crd apiextensionsv1.CustomResourceDefinition
		if err := yaml.Unmarshal(data, &crd); err != nil {
			t.Fatal(err)
		}
		definitions = append(definitions, crd.DeepCopy())
		clone := crd.DeepCopy()
		clone.Spec.Group = strings.Split(migration.LegacyAPIVersion, "/")[0]
		clone.Name = clone.Spec.Names.Plural + "." + clone.Spec.Group
		clone.Spec.Names.ShortNames = nil
		// Synthetic legacy-group schemas, not a historical-release CRD snapshot.
		// Reproduce the important v0.3 ingress difference: mode did not exist, while
		// the destination API persists mode=l4 through admission defaulting.
		if clone.Spec.Names.Kind == "TailnetIngress" {
			for i := range clone.Spec.Versions {
				root := clone.Spec.Versions[i].Schema.OpenAPIV3Schema
				// Object-level rules (e.g. a dnsLabel colliding with metadata.name) also reference
				// exposes mode and must drop when the legacy schema has no mode field.
				root.XValidations = withoutMigrationModeRules(root.XValidations)
				spec := root.Properties["spec"]
				delete(spec.Properties, "tls")
				spec.XValidations = withoutMigrationModeRules(spec.XValidations)
				exposes := spec.Properties["exposes"]
				exposes.XValidations = withoutMigrationModeRules(exposes.XValidations)
				delete(exposes.Items.Schema.Properties, "mode")
				exposes.Items.Schema.XValidations = withoutMigrationModeRules(exposes.Items.Schema.XValidations)
				spec.Properties["exposes"] = exposes
				root.Properties["spec"] = spec
			}
		}
		definitions = append(definitions, clone)
	}
	useExisting := false
	env := &envtest.Environment{
		UseExistingCluster: &useExisting, BinaryAssetsDirectory: assets,
		CRDs: definitions,
	}
	t.Cleanup(func() {
		if err := env.Stop(); err != nil {
			t.Errorf("stop disposable envtest: %v", err)
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
	get := func(t *testing.T, obj *unstructured.Unstructured) *unstructured.Unstructured {
		t.Helper()
		stored := &unstructured.Unstructured{}
		stored.SetGroupVersionKind(obj.GroupVersionKind())
		if err := c.Get(ctx, client.ObjectKeyFromObject(obj), stored); err != nil {
			t.Fatal("get fixture failed") // Never print API responses or object contents.
		}
		return stored
	}
	create := func(t *testing.T, obj *unstructured.Unstructured) *unstructured.Unstructured {
		t.Helper()
		if err := c.Create(ctx, obj); err != nil {
			t.Fatalf("create %s fixture failed", obj.GetKind())
		}
		return get(t, obj) // Plan only from API-persisted/defaulted snapshots.
	}
	mutate := func(t *testing.T, obj *unstructured.Unstructured) *unstructured.Unstructured {
		t.Helper()
		current := get(t, obj)
		annotations := current.GetAnnotations()
		if annotations == nil {
			annotations = map[string]string{}
		}
		annotations["example.org/concurrent-writer"] = "changed"
		current.SetAnnotations(annotations)
		if err := c.Update(ctx, current); err != nil {
			t.Fatal("mutate fixture failed")
		}
		return get(t, current)
	}
	parents := func(t *testing.T, name string) (old, next *unstructured.Unstructured) {
		t.Helper()
		create(t, migrationObject("v1", "Namespace", name, "", nil))
		spec := map[string]any{
			"server": "https://headscale.invalid", "apiSecretRef": map[string]any{"name": "bootstrap", "key": "apiKey"},
			"policy": map[string]any{"baseConfigMap": "base", "mode": "Apply", "tagOwners": []any{"group:operators"}, "routeApprovers": []any{"tag:fabric"}},
		}
		old = create(t, migrationObject(migration.LegacyAPIVersion, "Tailnet", name, "", spec))
		next = migrationObject(migration.APIVersion, "Tailnet", name, "", spec)
		if err := unstructured.SetNestedField(next.Object, "DryRun", "spec", "policy", "mode"); err != nil {
			t.Fatal(err)
		}
		next = create(t, next)
		return
	}
	secret := func(t *testing.T, old *unstructured.Unstructured, ns string) *unstructured.Unstructured {
		t.Helper()
		o := migrationObject("v1", "Secret", "working-key", ns, nil)
		o.Object["data"] = map[string]any{"apiKey": "c3ludGhldGljLW9ubHk="}
		annotations := map[string]string{
			"tailnet.this-is-fine.io/expires-at": "2099-01-01T00:00:00Z", "example.org/keep": "yes",
		}
		if old.GetKind() == "Tailnet" {
			annotations["tailnet.this-is-fine.io/prefix"] = "synthetic-token-must-not-be-copied"
		}
		o.SetAnnotations(annotations)
		migrationOwn(o, old)
		return create(t, o)
	}
	plan := func(t *testing.T, child, old, next, tailnet *unstructured.Unstructured) *migration.Transfer {
		t.Helper()
		p, err := migration.PlanTransfer(child, old, next, tailnet)
		if err != nil {
			t.Fatalf("plan %s: %v", child.GetKind(), err)
		}
		return p
	}
	equal := func(t *testing.T, a, b *unstructured.Unstructured, message string) {
		t.Helper()
		if !reflect.DeepEqual(a.Object, b.Object) {
			t.Fatal(message) // Deliberately do not render a diff containing Secret material.
		}
	}

	t.Run("discovery-inventory", func(t *testing.T) {
		old, next := parents(t, "inventory")
		child := secret(t, old, "inventory")
		discover, err := discovery.NewDiscoveryClientForConfig(cfg)
		if err != nil {
			t.Fatal("create isolated discovery client failed")
		}
		api, err := dynamic.NewForConfig(cfg)
		if err != nil {
			t.Fatal("create isolated dynamic client failed")
		}
		inventory, err := migration.PlanInventory(ctx, discover, api, "inventory")
		if err != nil {
			t.Fatalf("read-only inventory: %v", err)
		}
		pairs, children, resources := inventory.Counts()
		if pairs != 1 || children != 1 || resources < 7 {
			t.Fatal("inventory omitted parents, child or discovered resource types")
		}
		equal(t, get(t, old), old, "inventory changed legacy parent")
		equal(t, get(t, next), next, "inventory changed destination parent")
		equal(t, get(t, child), child, "inventory changed Secret")

		// No operator label: ownership alone must expose this unsupported dependency.
		pod := migrationObject("v1", "Pod", "unexpected", "inventory", map[string]any{
			"containers": []any{map[string]any{"name": "unused", "image": "example.invalid/unused:synthetic"}},
		})
		migrationOwn(pod, old)
		pod = create(t, pod)
		inventory, err = migration.PlanInventory(ctx, discover, api, "inventory")
		if inventory != nil || !errors.Is(err, migration.ErrInvalid) {
			t.Fatal("unsupported direct dependent was omitted from discovery inventory")
		}
		equal(t, get(t, child), child, "rejected inventory changed Secret")
		if err := c.Delete(ctx, pod, client.GracePeriodSeconds(0)); err != nil {
			t.Fatal("remove synthetic unsupported child failed")
		}
		if _, err := migration.PlanInventory(ctx, discover, api, "inventory"); err != nil {
			t.Fatalf("inventory after removing unsupported dependency: %v", err)
		}
	})

	t.Run("metadata-only-handover", func(t *testing.T) {
		old, next := parents(t, "preservation")
		type entry struct{ child, old, next *unstructured.Unstructured }
		entries := []entry{{secret(t, old, "preservation"), old, next}}
		for _, role := range []string{"dns-hosts", "policy-rendered"} {
			o := migrationObject("v1", "ConfigMap", role, "preservation", nil)
			o.Object["data"] = map[string]any{"content": "synthetic preserved content"}
			o.SetLabels(map[string]string{"tailnet.this-is-fine.io/role": role, "example.org/keep": "yes"})
			migrationOwn(o, old)
			entries = append(entries, entry{create(t, o), old, next})
		}
		for _, kind := range []string{"TailnetEgress", "TailnetIngress"} {
			name := strings.ToLower(kind)
			spec := map[string]any{"tailnetRef": map[string]any{"name": next.GetName()}}
			if kind == "TailnetEgress" {
				spec["consumerNamespaces"] = []any{"preservation"}
				spec["targets"] = []any{map[string]any{"name": "db", "address": "192.0.2.1", "port": int64(5432)}}
			} else {
				spec["allowFrom"] = []any{"group:operators"}
				spec["exposes"] = []any{map[string]any{"name": "db", "port": int64(5432), "backend": map[string]any{"service": "db", "port": int64(5432)}}}
			}
			op := create(t, migrationObject(migration.LegacyAPIVersion, kind, name, "preservation", spec))
			np := create(t, migrationObject(migration.APIVersion, kind, name, "preservation", spec))
			if kind == "TailnetIngress" {
				oldExposes, _, _ := unstructured.NestedSlice(op.Object, "spec", "exposes")
				newExposes, _, _ := unstructured.NestedSlice(np.Object, "spec", "exposes")
				if _, exists := oldExposes[0].(map[string]any)["mode"]; exists || newExposes[0].(map[string]any)["mode"] != "l4" {
					t.Fatal("fixture did not reproduce the new ingress admission default")
				}
			}
			children := []*unstructured.Unstructured{
				migrationObject("apps/v1", "Deployment", name, "preservation", map[string]any{
					"replicas": int64(1), "selector": map[string]any{"matchLabels": map[string]any{"app": name}},
					"template": map[string]any{"metadata": map[string]any{"labels": map[string]any{"app": name}},
						"spec": map[string]any{"containers": []any{map[string]any{"name": "agent", "image": "example.invalid/agent:synthetic"}}}},
				}),
				migrationObject("networking.k8s.io/v1", "NetworkPolicy", name, "preservation", map[string]any{
					"podSelector": map[string]any{"matchLabels": map[string]any{"app": name}}, "policyTypes": []any{"Ingress"},
				}),
			}
			if kind == "TailnetEgress" {
				children = append(children, migrationObject("v1", "Service", name, "preservation", map[string]any{
					"selector": map[string]any{"app": name}, "ports": []any{map[string]any{"port": int64(5432), "targetPort": int64(5432)}},
				}))
			}
			for _, child := range children {
				migrationOwn(child, op)
				entries = append(entries, entry{create(t, child), op, np})
			}
		}
		for _, e := range entries {
			t.Run(e.child.GetKind()+"/"+e.child.GetName(), func(t *testing.T) {
				p := plan(t, e.child, e.old, e.next, next)
				cc := &migrationPatchClient{Client: c}
				if err := migration.ApplyTransfer(ctx, cc, p, true); err != nil {
					t.Fatalf("server dry-run: %v", err)
				}
				equal(t, get(t, e.child), e.child, "dry-run changed persisted object")
				if cc.patches != 1 {
					t.Fatal("dry-run did not reach API patch")
				}
				if err := migration.ApplyTransfer(ctx, cc, p, false); err != nil {
					t.Fatalf("apply: %v", err)
				}
				stored := get(t, e.child)
				want := e.child.DeepCopy()
				migrationOwn(want, e.next)
				for _, field := range []string{"annotations", "labels"} {
					values, found, _ := unstructured.NestedStringMap(want.Object, "metadata", field)
					if !found {
						continue
					}
					for _, suffix := range []string{"expires-at", "role", "prefix"} {
						key := "tailnet.this-is-fine.io/" + suffix
						if value, ok := values[key]; ok {
							if suffix != "prefix" {
								values["tsunaro.io/"+suffix] = value
							}
							delete(values, key)
						}
					}
					if err := unstructured.SetNestedStringMap(want.Object, values, "metadata", field); err != nil {
						t.Fatal(err)
					}
				}
				if stored.GetResourceVersion() == e.child.GetResourceVersion() {
					t.Fatal("apply did not persist a metadata update")
				}
				// Exact comparison except server bookkeeping proves UID, data, allocated
				// Service IPs, pod template/spec and generation all remain unchanged.
				want.SetResourceVersion(stored.GetResourceVersion())
				want.SetManagedFields(stored.GetManagedFields())
				equal(t, stored, want, "handover changed more than approved metadata")
				if err := migration.ApplyTransfer(ctx, cc, p, false); err != nil {
					t.Fatalf("retry: %v", err)
				}
				if cc.patches != 2 {
					t.Fatal("idempotent retry issued a write")
				}
				equal(t, get(t, stored), stored, "retry changed persisted post-state")
			})
		}
	})

	t.Run("original-manager-ssa-handover", func(t *testing.T) {
		_, next := parents(t, "ssa-handover")
		spec := map[string]any{"tailnetRef": map[string]any{"name": next.GetName()},
			"consumerNamespaces": []any{"ssa-handover"},
			"targets":            []any{map[string]any{"name": "db", "address": "192.0.2.1", "port": int64(5432)}}}
		op := create(t, migrationObject(migration.LegacyAPIVersion, "TailnetEgress", "ssa-egress", "ssa-handover", spec))
		np := create(t, migrationObject(migration.APIVersion, "TailnetEgress", "ssa-egress", "ssa-handover", spec))
		for _, kind := range []string{"Secret", "Deployment"} {
			t.Run(kind, func(t *testing.T) {
				child := migrationObject("v1", kind, "ssa-child", "ssa-handover", nil)
				if kind == "Secret" {
					child.Object["data"] = map[string]any{"authKey": "c3ludGhldGljLW9ubHk="}
					child.SetAnnotations(map[string]string{"tailnet.this-is-fine.io/expires-at": "2099-01-01T00:00:00Z"})
				} else {
					child.SetAPIVersion("apps/v1")
					child.Object["spec"] = map[string]any{
						"replicas": int64(1), "selector": map[string]any{"matchLabels": map[string]any{"app": "ssa"}},
						"template": map[string]any{"metadata": map[string]any{"labels": map[string]any{"app": "ssa"}},
							"spec": map[string]any{"containers": []any{map[string]any{"name": "agent", "image": "example.invalid/agent:synthetic"}}}},
					}
				}
				migrationOwn(child, op)
				desired := child.DeepCopy() // Keep SSA input free of server-generated fields/defaults.
				if err := c.Patch(ctx, child, client.Apply, client.FieldOwner("tailnet-operator")); err != nil {
					t.Fatal("original manager SSA creation failed")
				}
				child = get(t, child)
				p := plan(t, child, op, np, next)
				if err := migration.ApplyTransfer(ctx, c, p, false); err != nil {
					t.Fatalf("SSA-created child migration: %v", err)
				}
				migrated := get(t, child)
				migrationOwn(desired, np)
				if kind == "Secret" {
					desired.SetAnnotations(map[string]string{"tsunaro.io/expires-at": "2099-01-01T00:00:00Z"})
				}
				// No ForceOwnership: equivalent desired state must not need a takeover.
				if err := c.Patch(ctx, desired, client.Apply, client.FieldOwner("tailnet-operator")); err != nil {
					t.Fatal("original manager SSA after migration failed")
				}
				stored := get(t, child)
				migrated.SetResourceVersion(stored.GetResourceVersion())
				migrated.SetManagedFields(stored.GetManagedFields())
				equal(t, stored, migrated, "SSA handover changed UID, data, spec or approved metadata")
			})
		}
	})

	for _, scenario := range []string{"stale-rv", "recreated-child", "old-parent", "new-parent", "destination-tailnet", "changed-post-state", "patch-race"} {
		t.Run(scenario, func(t *testing.T) {
			old, next := parents(t, scenario)
			tailnet := next
			if scenario == "destination-tailnet" {
				spec := map[string]any{"tailnetRef": map[string]any{"name": tailnet.GetName()},
					"consumerNamespaces": []any{scenario},
					"targets":            []any{map[string]any{"name": "db", "address": "192.0.2.1", "port": int64(5432)}}}
				old = create(t, migrationObject(migration.LegacyAPIVersion, "TailnetEgress", scenario, scenario, spec))
				next = create(t, migrationObject(migration.APIVersion, "TailnetEgress", scenario, scenario, spec))
			}
			child := secret(t, old, scenario)
			p := plan(t, child, old, next, tailnet)
			cc := &migrationPatchClient{Client: c}
			var raced *unstructured.Unstructured
			expected := migration.ErrStale
			switch scenario {
			case "stale-rv":
				reverted := mutate(t, child)
				reverted.SetAnnotations(child.GetAnnotations())
				if err := c.Update(ctx, reverted); err != nil {
					t.Fatal("restore original content failed")
				}
				if get(t, child).GetResourceVersion() == child.GetResourceVersion() {
					t.Fatal("fixture did not advance resourceVersion")
				}
			case "recreated-child":
				if err := c.Delete(ctx, child); err != nil {
					t.Fatal("delete fixture failed")
				}
				recreated := secret(t, old, scenario)
				if recreated.GetUID() == child.GetUID() {
					t.Fatal("recreated child retained UID")
				}
			case "old-parent":
				mutate(t, old)
			case "new-parent":
				mutate(t, next)
			case "destination-tailnet":
				mutate(t, tailnet)
			case "changed-post-state":
				if err := migration.ApplyTransfer(ctx, c, p, false); err != nil {
					t.Fatalf("initial apply: %v", err)
				}
				mutate(t, child)
			case "patch-race":
				expected = migration.ErrAPI
				cc.beforePatch = func(obj client.Object, patch client.Patch) {
					data, err := patch.Data(obj)
					if err != nil {
						t.Fatal("cannot inspect CAS patch")
					}
					var ops []struct {
						Op, Path string
						Value    any
					}
					if json.Unmarshal(data, &ops) != nil || len(ops) < 2 ||
						ops[0].Op != "test" || ops[0].Path != "/metadata/uid" || ops[0].Value != string(child.GetUID()) ||
						ops[1].Op != "test" || ops[1].Path != "/metadata/resourceVersion" || ops[1].Value != child.GetResourceVersion() {
						t.Fatal("missing UID/resourceVersion JSONPatch guards")
					}
					raced = mutate(t, child) // Real write after Get but before the real JSONPatch.
				}
			}
			before := get(t, child)
			if err := migration.ApplyTransfer(ctx, cc, p, false); !errors.Is(err, expected) {
				t.Fatalf("unsafe transfer: want %v, got %v", expected, err)
			}
			if scenario == "patch-race" {
				if cc.patches != 1 {
					t.Fatal("race did not reach API patch")
				}
				before = raced
			} else if cc.patches != 0 {
				t.Fatal("stale snapshot reached API patch")
			}
			equal(t, get(t, child), before, "rejected transfer altered persisted child")
		})
	}
}

func withoutMigrationModeRules(rules apiextensionsv1.ValidationRules) apiextensionsv1.ValidationRules {
	var keep apiextensionsv1.ValidationRules
	for _, rule := range rules {
		if !strings.Contains(rule.Rule, ".mode") {
			keep = append(keep, rule)
		}
	}
	return keep
}

func migrationObject(api, kind, name, namespace string, spec map[string]any) *unstructured.Unstructured {
	o := &unstructured.Unstructured{Object: map[string]any{"apiVersion": api, "kind": kind}}
	o.SetName(name)
	if namespace != "" {
		o.SetNamespace(namespace)
	}
	if spec != nil {
		o.Object["spec"] = spec
	}
	return o.DeepCopy()
}

func migrationOwn(child, parent *unstructured.Unstructured) {
	controller, block := true, true
	child.SetOwnerReferences([]metav1.OwnerReference{{
		APIVersion: parent.GetAPIVersion(), Kind: parent.GetKind(), Name: parent.GetName(), UID: parent.GetUID(),
		Controller: &controller, BlockOwnerDeletion: &block,
	}})
}

type migrationPatchClient struct {
	client.Client
	patches     int
	beforePatch func(client.Object, client.Patch)
}

func (c *migrationPatchClient) Patch(ctx context.Context, obj client.Object, patch client.Patch, opts ...client.PatchOption) error {
	c.patches++
	if c.beforePatch != nil {
		c.beforePatch(obj, patch)
	}
	return c.Client.Patch(ctx, obj, patch, opts...)
}
