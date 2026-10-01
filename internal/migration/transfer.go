// Package migration provides stop-first API-group handover primitives. It is not a fleet
// migration runner: callers must inventory the complete fleet, stop all writers, protect
// parents from deletion/pruning and retain secure backups before applying any transfer.
package migration

import (
	"context"
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

const (
	LegacyAPIVersion = "tailnet.this-is-fine.io/v1alpha1"
	APIVersion       = "tsunaro.io/v1alpha1"
	legacyDomain     = "tailnet.this-is-fine.io/"
	domain           = "tsunaro.io/"
)

var (
	ErrInvalid = errors.New("invalid migration input")
	ErrStale   = errors.New("migration snapshot changed; stop and review")
	ErrAPI     = errors.New("migration API request failed; stop and review")
)

// Transfer is an immutable, in-memory plan for one child. Its snapshots and patch are
// deliberately private: serializing or logging a plan must not disclose Secret data or
// credential-bearing annotations. This is not a portable or user-editable plan format.
type Transfer struct {
	before, after *unstructured.Unstructured
	parents       []*unstructured.Unstructured
	patch         []byte
}

// String and GoString prevent formatted diagnostics from exposing private snapshots.
func (Transfer) String() string   { return "migration.Transfer (redacted)" }
func (Transfer) GoString() string { return "migration.Transfer (redacted)" }

type operation struct {
	Op    string `json:"op"`
	Path  string `json:"path"`
	Value any    `json:"value,omitempty"`
}

// PlanTransfer validates one old/new parent pair and prepares a metadata-only CAS patch.
// Parents must already exist with equivalent specs (only Tailnet policy Apply -> DryRun
// and the new ingress mode=l4 admission default are normalized).
// tailnet is the destination Tailnet, including for transfers owned by ingress/egress CRs.
// Planning performs no I/O and does not establish fleet completeness or writer quiescence.
func PlanTransfer(child, oldParent, newParent, tailnet *unstructured.Unstructured) (*Transfer, error) {
	if !live(oldParent) || !live(newParent) || !live(child) || !live(tailnet) {
		return nil, ErrInvalid
	}
	kind := oldParent.GetKind()
	if oldParent.GetAPIVersion() != LegacyAPIVersion || newParent.GetAPIVersion() != APIVersion ||
		newParent.GetKind() != kind || oldParent.GetName() != newParent.GetName() ||
		oldParent.GetNamespace() != newParent.GetNamespace() || oldParent.GetUID() == newParent.GetUID() {
		return nil, ErrInvalid
	}
	if kind != "Tailnet" && kind != "TailnetEgress" && kind != "TailnetIngress" {
		return nil, ErrInvalid
	}
	if (kind == "Tailnet") != (newParent.GetNamespace() == "") || child.GetNamespace() == "" ||
		(kind != "Tailnet" && child.GetNamespace() != newParent.GetNamespace()) {
		return nil, ErrInvalid
	}
	if tailnet.GetAPIVersion() != APIVersion || tailnet.GetKind() != "Tailnet" || tailnet.GetNamespace() != "" || !dryRun(tailnet) {
		return nil, ErrInvalid
	}
	if kind == "Tailnet" {
		if !reflect.DeepEqual(tailnet.Object, newParent.Object) {
			return nil, ErrInvalid
		}
	} else {
		ref, _, _ := unstructured.NestedString(newParent.Object, "spec", "tailnetRef", "name")
		if ref == "" || ref != tailnet.GetName() {
			return nil, ErrInvalid
		}
	}
	oldSpec, oldOK, oldErr := unstructured.NestedMap(oldParent.Object, "spec")
	newSpec, newOK, newErr := unstructured.NestedMap(newParent.Object, "spec")
	if !oldOK || !newOK || oldErr != nil || newErr != nil {
		return nil, ErrInvalid
	}
	if kind == "Tailnet" {
		// Missing/disabled policy must still match; only an enabled policy's mode may change.
		if base, _, _ := unstructured.NestedString(oldSpec, "policy", "baseConfigMap"); base != "" {
			if err := unstructured.SetNestedField(oldSpec, "DryRun", "policy", "mode"); err != nil {
				return nil, ErrInvalid
			}
		}
	}
	if kind == "TailnetIngress" {
		normalizeL4(oldSpec)
		normalizeL4(newSpec)
	}
	if !reflect.DeepEqual(oldSpec, newSpec) || !supported(child, kind) || nestedLegacyMetadata(child) {
		return nil, ErrInvalid
	}
	owners := child.GetOwnerReferences()
	index := -1
	for i, owner := range owners {
		if owner.Controller != nil && *owner.Controller {
			if index != -1 || !matches(owner, oldParent) {
				return nil, ErrInvalid
			}
			index = i
		} else if owner.APIVersion == LegacyAPIVersion || owner.UID == oldParent.GetUID() || owner.UID == newParent.GetUID() {
			return nil, ErrInvalid
		}
	}
	if index == -1 {
		return nil, ErrInvalid
	}

	after := child.DeepCopy()
	owners[index].APIVersion = APIVersion
	owners[index].UID = newParent.GetUID()
	after.SetOwnerReferences(owners)
	ops := []operation{
		{Op: "test", Path: "/metadata/uid", Value: string(child.GetUID())},
		{Op: "test", Path: "/metadata/resourceVersion", Value: child.GetResourceVersion()},
		{Op: "replace", Path: "/metadata/ownerReferences", Value: owners},
	}
	for _, field := range []string{"annotations", "labels"} {
		values := child.GetAnnotations()
		if field == "labels" {
			values = child.GetLabels()
		}
		if values == nil {
			continue
		}
		updated := make(map[string]string, len(values))
		for key, value := range values {
			updated[key] = value
			if strings.HasPrefix(key, legacyDomain) && !knownMetadata(child, kind, field, strings.TrimPrefix(key, legacyDomain)) {
				return nil, ErrInvalid
			}
		}
		// Fixed order keeps patches deterministic; map iteration must not order mutations.
		for _, suffix := range []string{"expires-at", "prefix", "role"} {
			oldKey, newKey := legacyDomain+suffix, domain+suffix
			value, exists := values[oldKey]
			if !exists {
				continue
			}
			if current, exists := values[newKey]; exists && current != value {
				return nil, ErrInvalid
			}
			if suffix != "prefix" {
				updated[newKey] = value
				ops = append(ops, operation{Op: "add", Path: "/metadata/" + field + "/" + pointer(newKey), Value: value})
			} else if _, exists := values[newKey]; exists {
				delete(updated, newKey)
				ops = append(ops, operation{Op: "remove", Path: "/metadata/" + field + "/" + pointer(newKey)})
			}
			// Legacy prefix annotations can contain a full token. Never copy their value;
			// the working-key controller derives the canonical prefix from Secret data.
			delete(updated, oldKey)
			ops = append(ops, operation{Op: "remove", Path: "/metadata/" + field + "/" + pointer(oldKey)})
		}
		if field == "labels" {
			after.SetLabels(updated)
		} else {
			after.SetAnnotations(updated)
		}
	}
	if child.GetKind() == "Secret" {
		expiry := after.GetAnnotations()[domain+"expires-at"]
		if _, err := time.Parse(time.RFC3339, expiry); err != nil {
			return nil, ErrInvalid
		}
	}
	if kind == "Tailnet" && child.GetKind() == "ConfigMap" {
		role := after.GetLabels()[domain+"role"]
		if role != "dns-hosts" && role != "policy-rendered" {
			return nil, ErrInvalid
		}
	}
	patch, err := json.Marshal(ops)
	if err != nil {
		return nil, ErrInvalid
	}
	parents := []*unstructured.Unstructured{oldParent.DeepCopy(), newParent.DeepCopy()}
	if kind != "Tailnet" {
		parents = append(parents, tailnet.DeepCopy())
	}
	return &Transfer{before: child.DeepCopy(), after: after, parents: parents, patch: patch}, nil
}

// ApplyTransfer applies one preplanned transfer, or verifies its exact post-state on retry.
// dryRun uses Kubernetes server-side dry-run. There is no multi-object transaction, rollback,
// parent-deletion fence, inventory discovery or permission to prune old CRDs here.
// All external writers and pruning must stay stopped throughout the complete handover.
func ApplyTransfer(ctx context.Context, c client.Client, transfer *Transfer, dryRun bool) error {
	if transfer == nil || transfer.before == nil || transfer.after == nil || len(transfer.patch) == 0 {
		return ErrInvalid
	}
	for _, parent := range transfer.parents {
		current := &unstructured.Unstructured{}
		current.SetGroupVersionKind(parent.GroupVersionKind())
		if err := c.Get(ctx, client.ObjectKeyFromObject(parent), current); err != nil {
			return ErrAPI
		}
		if !reflect.DeepEqual(current.Object, parent.Object) {
			return ErrStale
		}
	}
	current := &unstructured.Unstructured{}
	current.SetGroupVersionKind(transfer.before.GroupVersionKind())
	if err := c.Get(ctx, client.ObjectKeyFromObject(transfer.before), current); err != nil {
		return ErrAPI
	}
	if sameContent(current, transfer.after) {
		return nil
	}
	if !reflect.DeepEqual(current.Object, transfer.before.Object) {
		return ErrStale
	}
	opts := []client.PatchOption{client.FieldOwner("tsunaro-api-group-migration")}
	if dryRun {
		opts = append(opts, client.DryRunAll)
	}
	if err := c.Patch(ctx, current, client.RawPatch(types.JSONPatchType, transfer.patch), opts...); err != nil {
		// API admission and proxy errors can echo Secret values; never expose the raw error.
		return ErrAPI
	}
	if !sameContent(current, transfer.after) {
		return ErrStale
	}
	return nil
}

func normalizeL4(spec map[string]any) {
	// v0.3 ingress exposed only L4; v0.4 admission persists the explicit default.
	// No other default or added field is silently accepted as part of the group handover.
	exposes, ok := spec["exposes"].([]any)
	if !ok {
		return
	}
	for _, value := range exposes {
		if expose, ok := value.(map[string]any); ok {
			if _, present := expose["mode"]; !present {
				expose["mode"] = "l4"
			}
		}
	}
}

func live(obj *unstructured.Unstructured) bool {
	return obj != nil && obj.GetUID() != "" && obj.GetResourceVersion() != "" && obj.GetName() != "" && obj.GetDeletionTimestamp() == nil
}

func dryRun(tailnet *unstructured.Unstructured) bool {
	base, _, err := unstructured.NestedString(tailnet.Object, "spec", "policy", "baseConfigMap")
	if err != nil {
		return false
	}
	mode, _, err := unstructured.NestedString(tailnet.Object, "spec", "policy", "mode")
	return err == nil && (base == "" || mode == "DryRun")
}

func matches(ref metav1.OwnerReference, parent *unstructured.Unstructured) bool {
	return ref.APIVersion == parent.GetAPIVersion() && ref.Kind == parent.GetKind() && ref.Name == parent.GetName() && ref.UID == parent.GetUID()
}

func supported(child *unstructured.Unstructured, ownerKind string) bool {
	switch child.GetAPIVersion() + "/" + child.GetKind() {
	case "v1/Secret", "v1/ConfigMap":
		return true
	case "v1/Service":
		return ownerKind == "TailnetEgress"
	case "apps/v1/Deployment", "networking.k8s.io/v1/NetworkPolicy":
		return ownerKind != "Tailnet"
	case "cert-manager.io/v1/Certificate":
		return ownerKind == "TailnetIngress"
	default:
		return false
	}
}

func knownMetadata(child *unstructured.Unstructured, ownerKind, field, suffix string) bool {
	if child.GetKind() == "Secret" && field == "annotations" {
		return suffix == "expires-at" || suffix == "prefix" && ownerKind == "Tailnet"
	}
	return child.GetKind() == "ConfigMap" && ownerKind == "Tailnet" && field == "labels" && suffix == "role"
}

func pointer(key string) string {
	return strings.ReplaceAll(strings.ReplaceAll(key, "~", "~0"), "/", "~1")
}

func nestedLegacyMetadata(child *unstructured.Unstructured) bool {
	// Never rewrite pod templates: doing so can roll an agent and lose its ephemeral state.
	for _, field := range []string{"labels", "annotations"} {
		values, _, err := unstructured.NestedStringMap(child.Object, "spec", "template", "metadata", field)
		if err != nil {
			return true
		}
		for key := range values {
			if strings.HasPrefix(key, legacyDomain) {
				return true
			}
		}
	}
	return false
}

func sameContent(a, b *unstructured.Unstructured) bool {
	a, b = a.DeepCopy(), b.DeepCopy()
	for _, obj := range []*unstructured.Unstructured{a, b} {
		obj.SetResourceVersion("")
		obj.SetManagedFields(nil)
	}
	return reflect.DeepEqual(a.Object, b.Object)
}
