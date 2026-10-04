package gateway

import (
	"encoding/base64"
	"errors"
	"reflect"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/validation"
)

// AdoptionAnnotation explicitly authorizes takeover by the UID of one gateway CR.
// A name is insufficient: deleting and recreating a CR must not renew consent.
const AdoptionAnnotation = "tsunaro.io/adopt-gateway"

var (
	ErrAdoptionInvalid  = errors.New("gateway adoption: invalid snapshot or reference")
	ErrAdoptionConsent  = errors.New("gateway adoption: explicit UID-bound consent required")
	ErrAdoptionOwned    = errors.New("gateway adoption: resource already has an owner")
	ErrAdoptionChanged  = errors.New("gateway adoption: desired resource differs from current resource")
	ErrAdoptionNotReady = errors.New("gateway adoption: singleton StatefulSet is not settled")
	ErrAdoptionState    = errors.New("gateway adoption: persistent state is missing or immutable")
	ErrAdoptionStale    = errors.New("gateway adoption: resource identity or revision changed")
)

// AdoptionReference binds an explicit resource name and GVK to its inventoried UID.
// References and snapshots belong to the operator namespace, never a tenant namespace.
// This is an internal planning contract, not an installed Kubernetes API.
type AdoptionReference struct {
	APIVersion string    `json:"apiVersion"`
	Kind       string    `json:"kind"`
	Name       string    `json:"name"`
	UID        types.UID `json:"uid"`
}

// AdoptionSnapshot contains current and desired API-defaulted objects. Desired must
// include existing unmanaged payload fields; a partial SSA apply document is not a
// full snapshot and deliberately fails comparison. Secret contents are read only.
// Do not log snapshots: they can contain credentials and private node state.
type AdoptionSnapshot struct {
	Reference AdoptionReference
	Current   *unstructured.Unstructured
	Desired   *unstructured.Unstructured
}

// AdoptionRequest inventories the complete set of resources to retain, including
// the StatefulSet and its existing TS_KUBE_SECRET. Optional auth-key Secrets are
// external dependencies, not adopted resources. The caller is responsible for
// inventory completeness (Services, DNS, RBAC and PDB) and resolving all references.
// No Headscale node association or state-format inference occurs in this layer.
type AdoptionRequest struct {
	GatewayUID  types.UID
	Namespace   string
	StatefulSet string
	StateSecret string
	Snapshots   []AdoptionSnapshot
}

// AdoptionTarget is a non-secret receipt for one validated snapshot. ResourceVersion
// is a required compare-and-swap precondition, not permission to force-apply a later
// snapshot. A writer must also recheck the live gateway and the entire inventory.
type AdoptionTarget struct {
	Reference       AdoptionReference
	Namespace       string
	ResourceVersion string
}

// PlanAdoption validates every supplied snapshot before returning any receipts.
// It performs no writes. The first takeover must leave workload/configuration
// payloads, labels, state and existing annotations unchanged. The UID-bound consent
// annotation may subsequently be consumed by a separately reviewed metadata writer.
// No owner reference is added: adopted resources must survive CR deletion.
//
// This is a necessary check, not a complete takeover protocol. Kubernetes does not
// offer a cross-object transaction. The eventual controller must establish the
// state-to-Headscale-node binding, dry-run/default desired objects, preserve Secret
// data, stop competing writers, and handle conflicts without partial takeover.
func PlanAdoption(in AdoptionRequest) ([]AdoptionTarget, error) {
	if in.GatewayUID == "" || len(validation.IsDNS1123Label(in.Namespace)) != 0 ||
		len(validation.IsDNS1123Subdomain(in.StatefulSet)) != 0 ||
		len(validation.IsDNS1123Subdomain(in.StateSecret)) != 0 || len(in.Snapshots) == 0 {
		return nil, ErrAdoptionInvalid
	}
	seenNames := make(map[string]bool, len(in.Snapshots))
	seenUIDs := make(map[types.UID]bool, len(in.Snapshots))
	var workload *unstructured.Unstructured
	var state *unstructured.Unstructured
	out := make([]AdoptionTarget, 0, len(in.Snapshots))
	for _, snapshot := range in.Snapshots {
		ref := snapshot.Reference
		key := ref.APIVersion + "/" + ref.Kind + "/" + ref.Name
		if seenNames[key] || seenUIDs[ref.UID] || ref.UID == in.GatewayUID {
			return nil, ErrAdoptionInvalid
		}
		seenNames[key], seenUIDs[ref.UID] = true, true
		current, err := validateSnapshot(in.GatewayUID, in.Namespace, snapshot)
		if err != nil {
			return nil, err
		}
		if ref.Kind == "StatefulSet" {
			if ref.Name != in.StatefulSet || workload != nil {
				return nil, ErrAdoptionInvalid
			}
			workload = snapshot.Current
		}
		if ref.Kind == "Secret" {
			if ref.Name != in.StateSecret || state != nil {
				return nil, ErrAdoptionInvalid
			}
			state = snapshot.Current
		}
		out = append(out, AdoptionTarget{Reference: ref, Namespace: in.Namespace, ResourceVersion: current.ResourceVersion})
	}
	if workload == nil || state == nil {
		return nil, ErrAdoptionState
	}
	if err := validatePersistentWorkload(workload, in.StateSecret); err != nil {
		return nil, err
	}
	data, found, err := unstructured.NestedStringMap(state.Object, "data")
	if err != nil || !found || len(data) == 0 {
		return nil, ErrAdoptionState
	}
	// Secret data contains base64 strings. A populated map need not hold any
	// bytes. This checks presence only, not the tailscaled state format/identity.
	hasState := false
	for _, encoded := range data {
		decoded, err := base64.StdEncoding.DecodeString(encoded)
		if err != nil {
			return nil, ErrAdoptionState
		}
		hasState = hasState || len(decoded) > 0
	}
	if !hasState {
		return nil, ErrAdoptionState
	}
	immutable, _, err := unstructured.NestedBool(state.Object, "immutable")
	if err != nil || immutable {
		return nil, ErrAdoptionState
	}
	return out, nil
}

func validateSnapshot(gatewayUID types.UID, namespace string, s AdoptionSnapshot) (metav1.ObjectMeta, error) {
	var current, desired metav1.ObjectMeta
	ref := s.Reference
	if !adoptableKind(ref.APIVersion, ref.Kind) || ref.UID == "" ||
		len(validation.IsDNS1123Subdomain(ref.Name)) != 0 || s.Current == nil || s.Desired == nil {
		return current, ErrAdoptionInvalid
	}
	for _, object := range []*unstructured.Unstructured{s.Current, s.Desired} {
		if object.GetAPIVersion() != ref.APIVersion || object.GetKind() != ref.Kind {
			return current, ErrAdoptionInvalid
		}
	}
	// Decode metadata strictly enough that malformed ownerReferences/deletionTimestamp
	// cannot disappear through Unstructured's forgiving getters.
	for _, entry := range []struct {
		obj  *unstructured.Unstructured
		meta *metav1.ObjectMeta
	}{{s.Current, &current}, {s.Desired, &desired}} {
		meta, ok := entry.obj.Object["metadata"].(map[string]any)
		if !ok || runtime.DefaultUnstructuredConverter.FromUnstructured(meta, entry.meta) != nil {
			return current, ErrAdoptionInvalid
		}
		if entry.meta.Name != ref.Name || entry.meta.Namespace != namespace || entry.meta.DeletionTimestamp != nil {
			return current, ErrAdoptionInvalid
		}
		if len(entry.meta.OwnerReferences) != 0 {
			return current, ErrAdoptionOwned
		}
	}
	if current.UID != ref.UID || current.ResourceVersion == "" ||
		(desired.UID != "" && desired.UID != current.UID) ||
		(desired.ResourceVersion != "" && desired.ResourceVersion != current.ResourceVersion) {
		return current, ErrAdoptionStale
	}
	if current.Annotations[AdoptionAnnotation] != string(gatewayUID) {
		return current, ErrAdoptionConsent
	}
	if !reflect.DeepEqual(current.Labels, desired.Labels) ||
		!reflect.DeepEqual(current.Annotations, desired.Annotations) ||
		!reflect.DeepEqual(current.Finalizers, desired.Finalizers) {
		return current, ErrAdoptionChanged
	}
	payload := func(obj *unstructured.Unstructured) map[string]any {
		out := make(map[string]any, len(obj.Object))
		for key, value := range obj.Object {
			if key != "metadata" && key != "status" {
				out[key] = value
			}
		}
		return out
	}
	if !reflect.DeepEqual(payload(s.Current), payload(s.Desired)) {
		return current, ErrAdoptionChanged
	}
	return current, nil
}

func adoptableKind(apiVersion, kind string) bool {
	switch apiVersion {
	case "v1":
		return kind == "Secret" || kind == "Service" || kind == "ConfigMap" || kind == "ServiceAccount"
	case "apps/v1":
		return kind == "StatefulSet"
	case "policy/v1":
		return kind == "PodDisruptionBudget"
	case "rbac.authorization.k8s.io/v1":
		return kind == "Role" || kind == "RoleBinding"
	}
	return false
}

func validatePersistentWorkload(obj *unstructured.Unstructured, stateSecret string) error {
	for _, path := range [][]string{{"spec", "replicas"}, {"status", "replicas"}, {"status", "readyReplicas"}, {"status", "currentReplicas"}, {"status", "updatedReplicas"}} {
		value, found, err := unstructured.NestedInt64(obj.Object, path...)
		if err != nil || !found || value != 1 {
			return ErrAdoptionNotReady
		}
	}
	generation, found, err := unstructured.NestedInt64(obj.Object, "metadata", "generation")
	if err != nil || !found || generation < 1 {
		return ErrAdoptionNotReady
	}
	observed, _, err := unstructured.NestedInt64(obj.Object, "status", "observedGeneration")
	if err != nil || observed != generation {
		return ErrAdoptionNotReady
	}
	current, _, err := unstructured.NestedString(obj.Object, "status", "currentRevision")
	if err != nil || current == "" {
		return ErrAdoptionNotReady
	}
	updated, _, err := unstructured.NestedString(obj.Object, "status", "updateRevision")
	if err != nil || current != updated {
		return ErrAdoptionNotReady
	}
	containers, _, err := unstructured.NestedSlice(obj.Object, "spec", "template", "spec", "containers")
	if err != nil {
		return ErrAdoptionState
	}
	matches := 0
	for _, raw := range containers {
		container, ok := raw.(map[string]any)
		if !ok {
			return ErrAdoptionState
		}
		if container["name"] != "tailscale" {
			continue
		}
		env, _, err := unstructured.NestedSlice(container, "env")
		if err != nil {
			return ErrAdoptionState
		}
		for _, raw := range env {
			entry, ok := raw.(map[string]any)
			if !ok {
				return ErrAdoptionState
			}
			if entry["name"] == "TS_KUBE_SECRET" {
				if entry["value"] != stateSecret || entry["valueFrom"] != nil {
					return ErrAdoptionState
				}
				matches++
			}
		}
	}
	if matches != 1 {
		return ErrAdoptionState
	}
	return nil
}
