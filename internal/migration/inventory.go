package migration

import (
	"context"
	"reflect"
	"slices"
	"sort"
	"strings"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/validation"
	"k8s.io/client-go/dynamic"
)

// ResourceDiscovery is satisfied by a non-caching discovery client. Partial discovery
// errors must be returned: skipping an unavailable API can hide owned resources.
type ResourceDiscovery interface {
	ServerPreferredResources() ([]*metav1.APIResourceList, error)
}

// Inventory contains validated parent pairs and child plans from a read-only scan.
// It is deliberately opaque and in-memory, like Transfer. It provides neither crash
// recovery nor an apply-all operation. All writers/pruning must already be stopped;
// Kubernetes offers no atomic snapshot across resource types.
type Inventory struct {
	transfers []*Transfer
	pairs     int
	resources int
}

func (Inventory) String() string   { return "migration.Inventory (redacted)" }
func (Inventory) GoString() string { return "migration.Inventory (redacted)" }

// Counts returns only non-sensitive inventory totals, never object data or annotations.
func (i *Inventory) Counts() (parentPairs, children, resourceTypes int) {
	if i == nil {
		return 0, 0, 0
	}
	return i.pairs, len(i.transfers), i.resources
}

type inventoryResource struct {
	GVR        schema.GroupVersionResource
	Kind       string
	Namespaced bool
}

type parentKey struct{ Kind, Namespace, Name string }

type parentPair struct {
	old, next, tailnet *unstructured.Unstructured
}

// PlanInventory lists every discoverable, listable top-level resource type, without
// label or namespace selectors. It plans only exact old-group controller ownership;
// unknown kinds, dangling references, unmatched CRs and already-transferred children
// block the entire plan. No partial inventory is returned on discovery/list failure.
// operatorNamespace binds cluster-scoped Tailnet children and namespaced egress CRs.
// This does not inventory unreferenced name collisions or certify safe CRD deletion.
func PlanInventory(ctx context.Context, discovery ResourceDiscovery, api dynamic.Interface, operatorNamespace string) (*Inventory, error) {
	if discovery == nil || api == nil || len(validation.IsDNS1123Label(operatorNamespace)) != 0 {
		return nil, ErrInvalid
	}
	resources, err := inventoryResources(discovery)
	if err != nil {
		return nil, err
	}
	old, next, err := inventoryParents(ctx, api, resources)
	if err != nil {
		return nil, err
	}
	if len(old) == 0 || len(old) != len(next) {
		return nil, ErrInvalid
	}
	pairs := map[types.UID]parentPair{}
	allUIDs := map[types.UID]bool{}
	for key, parent := range old {
		destination := next[key]
		tailnet := destination
		if key.Kind != "Tailnet" && destination != nil {
			ref, _, _ := unstructured.NestedString(destination.Object, "spec", "tailnetRef", "name")
			tailnet = next[parentKey{Kind: "Tailnet", Name: ref}]
		}
		if validateParents(parent, destination, tailnet) != nil || key.Kind == "TailnetEgress" && key.Namespace != operatorNamespace {
			return nil, ErrInvalid
		}
		for _, uid := range []types.UID{parent.GetUID(), destination.GetUID()} {
			if allUIDs[uid] {
				return nil, ErrInvalid
			}
			allUIDs[uid] = true
		}
		pairs[parent.GetUID()] = parentPair{parent, destination, tailnet}
	}
	out := &Inventory{pairs: len(pairs), resources: len(resources)}
	seenChildren := map[types.UID]bool{}
	for _, resource := range resources {
		if parentResource(resource) {
			continue
		}
		err := listInventory(ctx, api, resource, func(child *unstructured.Unstructured) error {
			owners, err := inventoryOwners(child)
			if err != nil || allUIDs[child.GetUID()] {
				return ErrInvalid
			}
			var pair *parentPair
			for _, owner := range owners {
				if !migrationGroup(owner.APIVersion) && !allUIDs[owner.UID] {
					continue
				}
				match, exists := pairs[owner.UID]
				if pair != nil || !exists || owner.Controller == nil || !*owner.Controller || !matches(owner, match.old) {
					return ErrInvalid
				}
				pair = &match
			}
			if pair == nil {
				return nil
			}
			if seenChildren[child.GetUID()] || pair.old.GetKind() == "Tailnet" && child.GetNamespace() != operatorNamespace {
				return ErrInvalid
			}
			transfer, err := PlanTransfer(child, pair.old, pair.next, pair.tailnet)
			if err != nil {
				return err
			}
			seenChildren[child.GetUID()] = true
			out.transfers = append(out.transfers, transfer)
			return nil
		})
		if err != nil {
			return nil, err
		}
	}
	// Re-list to detect new/removed parents as well as parent content changes.
	oldAfter, nextAfter, err := inventoryParents(ctx, api, resources)
	if err != nil {
		return nil, err
	}
	if !reflect.DeepEqual(old, oldAfter) || !reflect.DeepEqual(next, nextAfter) {
		return nil, ErrStale
	}
	afterResources, err := inventoryResources(discovery)
	if err != nil {
		return nil, err
	}
	if !reflect.DeepEqual(resources, afterResources) {
		return nil, ErrStale
	}
	sort.Slice(out.transfers, func(a, b int) bool {
		return inventoryObjectKey(out.transfers[a].before) < inventoryObjectKey(out.transfers[b].before)
	})
	return out, nil
}

func inventoryResources(discovery ResourceDiscovery) ([]inventoryResource, error) {
	lists, err := discovery.ServerPreferredResources()
	if err != nil {
		return nil, ErrAPI
	}
	var resources []inventoryResource
	seen := map[schema.GroupVersionResource]bool{}
	parentCount := 0
	for _, list := range lists {
		if list == nil {
			return nil, ErrInvalid
		}
		gv, err := schema.ParseGroupVersion(list.GroupVersion)
		if err != nil {
			return nil, ErrInvalid
		}
		for _, resource := range list.APIResources {
			if strings.Contains(resource.Name, "/") || !slices.Contains(resource.Verbs, "list") {
				continue
			}
			entry := inventoryResource{GVR: gv.WithResource(resource.Name), Kind: resource.Kind, Namespaced: resource.Namespaced}
			if entry.Kind == "" || resource.Name == "" || seen[entry.GVR] {
				return nil, ErrInvalid
			}
			seen[entry.GVR] = true
			if parentResource(entry) {
				if resource.Namespaced != (resource.Kind != "Tailnet") {
					return nil, ErrInvalid
				}
				parentCount++
			} else if migrationGroup(gv.String()) {
				// An additional custom kind/version needs an explicitly reviewed contract.
				return nil, ErrInvalid
			}
			resources = append(resources, entry)
		}
	}
	if parentCount != 6 {
		return nil, ErrInvalid
	}
	sort.Slice(resources, func(a, b int) bool { return resources[a].GVR.String() < resources[b].GVR.String() })
	return resources, nil
}

func inventoryParents(ctx context.Context, api dynamic.Interface, resources []inventoryResource) (map[parentKey]*unstructured.Unstructured, map[parentKey]*unstructured.Unstructured, error) {
	old, next := map[parentKey]*unstructured.Unstructured{}, map[parentKey]*unstructured.Unstructured{}
	for _, resource := range resources {
		if !parentResource(resource) {
			continue
		}
		parents := next
		if resource.GVR.GroupVersion().String() == LegacyAPIVersion {
			parents = old
		}
		err := listInventory(ctx, api, resource, func(parent *unstructured.Unstructured) error {
			key := parentKey{parent.GetKind(), parent.GetNamespace(), parent.GetName()}
			owners, err := inventoryOwners(parent)
			if err != nil || !live(parent) || parents[key] != nil || len(owners) != 0 {
				return ErrInvalid
			}
			parents[key] = parent.DeepCopy()
			return nil
		})
		if err != nil {
			return nil, nil, err
		}
	}
	return old, next, nil
}

func listInventory(ctx context.Context, api dynamic.Interface, resource inventoryResource, visit func(*unstructured.Unstructured) error) error {
	var continuation, revision string
	seenTokens := map[string]bool{}
	seenNames := map[string]bool{}
	for {
		list, err := api.Resource(resource.GVR).List(ctx, metav1.ListOptions{Limit: 500, Continue: continuation})
		if err != nil || list == nil {
			return ErrAPI // API/proxy bodies can echo credentials.
		}
		if continuation != "" && list.GetResourceVersion() != revision {
			return ErrStale
		}
		revision = list.GetResourceVersion()
		for i := range list.Items {
			item := &list.Items[i]
			gvk := resource.GVR.GroupVersion().WithKind(resource.Kind)
			if item.GetAPIVersion() != "" && item.GetAPIVersion() != gvk.GroupVersion().String() || item.GetKind() != "" && item.GetKind() != gvk.Kind ||
				resource.Namespaced != (item.GetNamespace() != "") || item.GetName() == "" {
				return ErrInvalid
			}
			item.SetGroupVersionKind(gvk)
			key := item.GetNamespace() + "/" + item.GetName()
			if seenNames[key] {
				return ErrInvalid
			}
			seenNames[key] = true
			if err := visit(item); err != nil {
				return err
			}
		}
		continuation = list.GetContinue()
		if continuation == "" {
			return nil
		}
		if revision == "" || seenTokens[continuation] {
			return ErrInvalid
		}
		seenTokens[continuation] = true
	}
}

// GetOwnerReferences silently skips malformed entries on unstructured objects.
// Inventory must not turn a malformed dependency into an apparently unowned object.
func inventoryOwners(obj *unstructured.Unstructured) ([]metav1.OwnerReference, error) {
	items, _, err := unstructured.NestedSlice(obj.Object, "metadata", "ownerReferences")
	if err != nil {
		return nil, ErrInvalid
	}
	owners := make([]metav1.OwnerReference, len(items))
	for i, item := range items {
		fields, ok := item.(map[string]any)
		if !ok || runtime.DefaultUnstructuredConverter.FromUnstructured(fields, &owners[i]) != nil {
			return nil, ErrInvalid
		}
		owner := owners[i]
		if owner.APIVersion == "" || owner.Kind == "" || owner.Name == "" || owner.UID == "" {
			return nil, ErrInvalid
		}
	}
	return owners, nil
}

func parentResource(resource inventoryResource) bool {
	version := resource.GVR.GroupVersion().String()
	kinds := map[string]string{"tailnets": "Tailnet", "tailnetegresses": "TailnetEgress", "tailnetingresses": "TailnetIngress"}
	return (version == LegacyAPIVersion || version == APIVersion) && kinds[resource.GVR.Resource] == resource.Kind && resource.Kind != ""
}

func migrationGroup(version string) bool {
	group, _, _ := strings.Cut(version, "/")
	return group == strings.TrimSuffix(legacyDomain, "/") || group == strings.TrimSuffix(domain, "/")
}

func inventoryObjectKey(obj *unstructured.Unstructured) string {
	return obj.GetAPIVersion() + "/" + obj.GetKind() + "/" + obj.GetNamespace() + "/" + obj.GetName()
}
