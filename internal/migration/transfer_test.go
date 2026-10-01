package migration

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"

	jsonpatch "github.com/evanphx/json-patch/v5"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/types"
)

func migrationObject(version, kind, ns, name, uid string) *unstructured.Unstructured {
	obj := &unstructured.Unstructured{Object: map[string]any{
		"apiVersion": version, "kind": kind,
		"metadata": map[string]any{"name": name, "uid": uid, "resourceVersion": "10"},
	}}
	if ns != "" {
		obj.SetNamespace(ns)
	}
	return obj
}

func transferFixture() (child, old, next, tailnet *unstructured.Unstructured) {
	old = migrationObject(LegacyAPIVersion, "Tailnet", "", "corp", "old-uid")
	old.Object["spec"] = map[string]any{"server": "https://control.example.com", "policy": map[string]any{
		"baseConfigMap": "policy", "mode": "Apply",
	}}
	next = old.DeepCopy()
	next.SetAPIVersion(APIVersion)
	next.SetUID("new-uid")
	_ = unstructured.SetNestedField(next.Object, "DryRun", "spec", "policy", "mode")
	child = migrationObject("v1", "Secret", "operator", "corp-apikey", "child-uid")
	child.Object["data"] = map[string]any{"apiKey": "c3ludGhldGljLXNlY3JldA=="}
	child.SetAnnotations(map[string]string{
		legacyDomain + "expires-at": "2030-01-01T00:00:00Z",
		legacyDomain + "prefix":     "synthetic-private-token",
		"unrelated":                 "keep",
	})
	yes, no := true, false
	child.SetOwnerReferences([]metav1.OwnerReference{{APIVersion: LegacyAPIVersion, Kind: "Tailnet", Name: "corp", UID: "old-uid", Controller: &yes, BlockOwnerDeletion: &no}})
	return child, old, next, next
}

func TestPlanTransferMetadataOnly(t *testing.T) {
	child, old, next, tn := transferFixture()
	// A non-controller owner unrelated to the migration must survive unchanged.
	owners := child.GetOwnerReferences()
	owners = append(owners, metav1.OwnerReference{APIVersion: "v1", Kind: "ConfigMap", Name: "retain", UID: "another-uid"})
	child.SetOwnerReferences(owners)
	before, oldBefore, nextBefore := child.DeepCopy(), old.DeepCopy(), next.DeepCopy()
	plan, err := PlanTransfer(child, old, next, tn)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(child.Object, before.Object) || !reflect.DeepEqual(old.Object, oldBefore.Object) || !reflect.DeepEqual(next.Object, nextBefore.Object) {
		t.Fatal("planning mutated caller objects")
	}
	if bytes.Contains(plan.patch, []byte("synthetic-private-token")) || bytes.Contains(plan.patch, []byte("c3ludGhldGlj")) {
		t.Fatal("patch contains credentials")
	}
	for _, diagnostic := range []string{fmt.Sprint(plan), fmt.Sprintf("%+v", plan), fmt.Sprintf("%#v", plan), fmt.Sprintf("%+v", *plan), fmt.Sprintf("%#v", *plan)} {
		if diagnostic != "migration.Transfer (redacted)" {
			t.Fatal("formatted plan exposes private snapshots")
		}
	}
	encodedPlan, err := json.Marshal(plan)
	if err != nil || string(encodedPlan) != "{}" {
		t.Fatal("JSON exposes private plan fields")
	}
	patch, err := jsonpatch.DecodePatch(plan.patch)
	if err != nil {
		t.Fatal(err)
	}
	data, _ := json.Marshal(child.Object)
	patched, err := patch.Apply(data)
	if err != nil {
		t.Fatal("patch application failed")
	}
	var got map[string]any
	if err := json.Unmarshal(patched, &got); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(got, plan.after.Object) {
		t.Fatal("patch differs from planned post-state")
	}
	if !reflect.DeepEqual(plan.before.Object["data"], plan.after.Object["data"]) {
		t.Fatal("Secret contents changed")
	}
	afterOwners := plan.after.GetOwnerReferences()
	if len(afterOwners) != 2 || afterOwners[0].UID != "new-uid" || afterOwners[0].APIVersion != APIVersion ||
		afterOwners[0].BlockOwnerDeletion == nil || *afterOwners[0].BlockOwnerDeletion || !reflect.DeepEqual(afterOwners[1], owners[1]) {
		t.Fatal("owner identity/flags not preserved")
	}
	annotations := plan.after.GetAnnotations()
	if len(annotations) != 2 || annotations[domain+"expires-at"] != "2030-01-01T00:00:00Z" || annotations["unrelated"] != "keep" {
		t.Fatal("unexpected metadata translation")
	}
	// Plans hold independent snapshots; caller mutations cannot bypass apply preconditions.
	child.SetUID("mutated")
	next.SetResourceVersion("999")
	if plan.before.GetUID() != "child-uid" || plan.parents[1].GetResourceVersion() != "10" {
		t.Fatal("plan aliases caller storage")
	}
}

func TestPlanTransferRejectsUnsafeInput(t *testing.T) {
	tests := map[string]func(child, old, next, tn *unstructured.Unstructured){
		"unknown old version": func(c, o, n, tn *unstructured.Unstructured) { o.SetAPIVersion("foreign.io/v1") },
		"unknown new version": func(c, o, n, tn *unstructured.Unstructured) { n.SetAPIVersion(LegacyAPIVersion) },
		"changed name":        func(c, o, n, tn *unstructured.Unstructured) { n.SetName("different") },
		"changed kind":        func(c, o, n, tn *unstructured.Unstructured) { n.SetKind("TailnetEgress") },
		"same uid":            func(c, o, n, tn *unstructured.Unstructured) { n.SetUID(o.GetUID()) },
		"missing child uid":   func(c, o, n, tn *unstructured.Unstructured) { c.SetUID("") },
		"missing parent rv":   func(c, o, n, tn *unstructured.Unstructured) { o.SetResourceVersion("") },
		"missing child rv":    func(c, o, n, tn *unstructured.Unstructured) { c.SetResourceVersion("") },
		"cluster child":       func(c, o, n, tn *unstructured.Unstructured) { c.SetNamespace("") },
		"namespaced tailnet":  func(c, o, n, tn *unstructured.Unstructured) { n.SetNamespace("operator") },
		"parent spec drift": func(c, o, n, tn *unstructured.Unstructured) {
			_ = unstructured.SetNestedField(n.Object, "https://other.example.com", "spec", "server")
		},
		"parent missing spec": func(c, o, n, tn *unstructured.Unstructured) { delete(n.Object, "spec") },
		"destination Apply": func(c, o, n, tn *unstructured.Unstructured) {
			_ = unstructured.SetNestedField(n.Object, "Apply", "spec", "policy", "mode")
		},
		"unsupported kind": func(c, o, n, tn *unstructured.Unstructured) { c.SetKind("Pod") },
		"wrong child version": func(c, o, n, tn *unstructured.Unstructured) {
			c.SetAPIVersion("foreign.io/v1")
		},
		"foreign owner": func(c, o, n, tn *unstructured.Unstructured) {
			refs := c.GetOwnerReferences()
			refs[0].UID = "foreign-uid"
			c.SetOwnerReferences(refs)
		},
		"wrong owner group": func(c, o, n, tn *unstructured.Unstructured) {
			refs := c.GetOwnerReferences()
			refs[0].APIVersion = APIVersion
			c.SetOwnerReferences(refs)
		},
		"wrong owner kind": func(c, o, n, tn *unstructured.Unstructured) {
			refs := c.GetOwnerReferences()
			refs[0].Kind = "TailnetIngress"
			c.SetOwnerReferences(refs)
		},
		"wrong owner name": func(c, o, n, tn *unstructured.Unstructured) {
			refs := c.GetOwnerReferences()
			refs[0].Name = "different"
			c.SetOwnerReferences(refs)
		},
		"missing controller": func(c, o, n, tn *unstructured.Unstructured) {
			refs := c.GetOwnerReferences()
			refs[0].Controller = nil
			c.SetOwnerReferences(refs)
		},
		"multiple controllers": func(c, o, n, tn *unstructured.Unstructured) {
			refs := c.GetOwnerReferences()
			c.SetOwnerReferences(append(refs, refs[0]))
		},
		"duplicate destination owner": func(c, o, n, tn *unstructured.Unstructured) {
			refs := c.GetOwnerReferences()
			c.SetOwnerReferences(append(refs, metav1.OwnerReference{APIVersion: APIVersion, Kind: n.GetKind(), Name: n.GetName(), UID: n.GetUID()}))
		},
		"noncontroller legacy owner": func(c, o, n, tn *unstructured.Unstructured) {
			refs := c.GetOwnerReferences()
			c.SetOwnerReferences(append(refs, metav1.OwnerReference{APIVersion: LegacyAPIVersion, Kind: "Tailnet", Name: "other", UID: "other"}))
		},
		"unknown legacy key": func(c, o, n, tn *unstructured.Unstructured) {
			values := c.GetAnnotations()
			values[legacyDomain+"unreviewed"] = "something"
			c.SetAnnotations(values)
		},
		"expiry conflict": func(c, o, n, tn *unstructured.Unstructured) {
			values := c.GetAnnotations()
			values[domain+"expires-at"] = "2031-01-01T00:00:00Z"
			c.SetAnnotations(values)
		},
		"prefix conflict": func(c, o, n, tn *unstructured.Unstructured) {
			values := c.GetAnnotations()
			values[domain+"prefix"] = "other"
			c.SetAnnotations(values)
		},
		"missing expiry": func(c, o, n, tn *unstructured.Unstructured) { c.SetAnnotations(nil) },
		"invalid expiry": func(c, o, n, tn *unstructured.Unstructured) {
			c.SetAnnotations(map[string]string{legacyDomain + "expires-at": "synthetic-private-token"})
		},
		"legacy nested key": func(c, o, n, tn *unstructured.Unstructured) {
			_ = unstructured.SetNestedStringMap(c.Object, map[string]string{legacyDomain + "agent-config-protocol": "http-v1"}, "spec", "template", "metadata", "annotations")
		},
	}
	for _, field := range []string{"child", "old", "new"} {
		tests["deleting "+field] = func(c, o, n, tn *unstructured.Unstructured) {
			obj := map[string]*unstructured.Unstructured{"child": c, "old": o, "new": n}[field]
			now := metav1.Now()
			obj.SetDeletionTimestamp(&now)
		}
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			child, old, next, tn := transferFixture()
			mutate(child, old, next, tn)
			plan, err := PlanTransfer(child, old, next, tn)
			if !errors.Is(err, ErrInvalid) || plan != nil {
				t.Fatal("unsafe input accepted")
			}
			if strings.Contains(err.Error(), "synthetic-private-token") {
				t.Fatal("error leaked metadata")
			}
		})
	}
	if _, err := PlanTransfer(nil, nil, nil, nil); !errors.Is(err, ErrInvalid) {
		t.Fatal("nil inputs accepted")
	}
	if err := ApplyTransfer(context.Background(), nil, &Transfer{}, false); !errors.Is(err, ErrInvalid) {
		t.Fatal("empty plan accepted")
	}
}

func TestPlanTransferConfigMapRole(t *testing.T) {
	for _, role := range []string{"dns-hosts", "policy-rendered", "", "unknown"} {
		t.Run(role, func(t *testing.T) {
			child, old, next, tn := transferFixture()
			child.SetKind("ConfigMap")
			child.SetAnnotations(nil)
			child.SetLabels(map[string]string{legacyDomain + "role": role, "keep": "yes"})
			plan, err := PlanTransfer(child, old, next, tn)
			if role == "" || role == "unknown" {
				if err == nil {
					t.Fatal("ambiguous role accepted")
				}
				return
			}
			if err != nil || plan.after.GetLabels()[domain+"role"] != role || len(plan.after.GetLabels()) != 2 {
				t.Fatal("role translation failed")
			}
		})
	}
}

func TestPlanTransferNamespacedScope(t *testing.T) {
	for _, kind := range []string{"TailnetEgress", "TailnetIngress"} {
		child, _, _, tn := transferFixture()
		old := migrationObject(LegacyAPIVersion, kind, "operator", "app", "old-app")
		old.Object["spec"] = map[string]any{"tailnetRef": map[string]any{"name": "corp"}}
		next := old.DeepCopy()
		next.SetAPIVersion(APIVersion)
		next.SetUID("new-app")
		child.SetAnnotations(map[string]string{legacyDomain + "expires-at": "2030-01-01T00:00:00Z"})
		yes := true
		child.SetOwnerReferences([]metav1.OwnerReference{{APIVersion: LegacyAPIVersion, Kind: kind, Name: "app", UID: types.UID("old-app"), Controller: &yes}})
		if _, err := PlanTransfer(child, old, next, tn); err != nil {
			t.Fatal("valid namespaced transfer rejected")
		}
		child.SetNamespace("tenant")
		if _, err := PlanTransfer(child, old, next, tn); err == nil {
			t.Fatal("cross-namespace adoption accepted")
		}
		child.SetNamespace("operator")
		tn.SetName("other")
		if _, err := PlanTransfer(child, old, next, tn); err == nil {
			t.Fatal("unrelated destination Tailnet accepted")
		}
	}
}

func TestPlanTransferIngressL4Default(t *testing.T) {
	for _, mode := range []string{"l4", "http", ""} {
		t.Run(mode, func(t *testing.T) {
			child, _, _, tn := transferFixture()
			old := migrationObject(LegacyAPIVersion, "TailnetIngress", "operator", "app", "old-app")
			old.Object["spec"] = map[string]any{
				"tailnetRef": map[string]any{"name": "corp"},
				"exposes":    []any{map[string]any{"name": "app", "port": int64(443)}},
			}
			next := old.DeepCopy()
			next.SetAPIVersion(APIVersion)
			next.SetUID("new-app")
			next.Object["spec"].(map[string]any)["exposes"].([]any)[0].(map[string]any)["mode"] = mode
			child.SetAnnotations(map[string]string{legacyDomain + "expires-at": "2030-01-01T00:00:00Z"})
			yes := true
			child.SetOwnerReferences([]metav1.OwnerReference{{APIVersion: LegacyAPIVersion, Kind: "TailnetIngress", Name: "app", UID: old.GetUID(), Controller: &yes}})
			_, err := PlanTransfer(child, old, next, tn)
			if (err == nil) != (mode == "l4") {
				t.Fatal("implicit L4 normalization accepted a behavior change or rejected the admission default")
			}
			if _, mutated := old.Object["spec"].(map[string]any)["exposes"].([]any)[0].(map[string]any)["mode"]; mutated {
				t.Fatal("default normalization mutated caller's spec")
			}
		})
	}
}

func TestPlanTransferMatchingDestinationMetadata(t *testing.T) {
	child, old, next, tn := transferFixture()
	annotations := child.GetAnnotations()
	annotations[domain+"expires-at"] = annotations[legacyDomain+"expires-at"]
	annotations[domain+"prefix"] = annotations[legacyDomain+"prefix"]
	child.SetAnnotations(annotations)
	plan, err := PlanTransfer(child, old, next, tn)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := plan.after.GetAnnotations()[domain+"prefix"]; ok {
		t.Fatal("duplicated unsafe prefix survived transfer")
	}
	if bytes.Contains(plan.patch, []byte("synthetic-private-token")) {
		t.Fatal("prefix value entered patch")
	}
}
