package migration

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"reflect"
	"slices"
	"strings"
	"testing"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/rest"
)

type inventoryDiscovery struct {
	catalog []*metav1.APIResourceList
	calls   int
	hook    func(int, []*metav1.APIResourceList) ([]*metav1.APIResourceList, error)
}

func (d *inventoryDiscovery) ServerPreferredResources() ([]*metav1.APIResourceList, error) {
	d.calls++
	copy := make([]*metav1.APIResourceList, len(d.catalog))
	for i, r := range d.catalog {
		copy[i] = r.DeepCopy()
	}
	if d.hook != nil {
		return d.hook(d.calls, copy)
	}
	return copy, nil
}

type inventoryTestFixture struct {
	discovery inventoryDiscovery
	// Tailnet old/new, Secret, then childless egress old/new and ingress old/new.
	objects []*unstructured.Unstructured
	hook    func(schema.GroupVersionResource, int, metav1.ListOptions, *unstructured.UnstructuredList) error
	calls   map[schema.GroupVersionResource]int
}

func newInventoryFixture() *inventoryTestFixture {
	child, old, next, _ := transferFixture()
	f := &inventoryTestFixture{objects: []*unstructured.Unstructured{old, next, child}, calls: map[schema.GroupVersionResource]int{}}
	for _, version := range []string{LegacyAPIVersion, APIVersion} {
		f.discovery.catalog = append(f.discovery.catalog, &metav1.APIResourceList{GroupVersion: version, APIResources: []metav1.APIResource{
			{Name: "tailnets", Kind: "Tailnet", Verbs: metav1.Verbs{"list"}},
			{Name: "tailnetegresses", Kind: "TailnetEgress", Namespaced: true, Verbs: metav1.Verbs{"list"}},
			{Name: "tailnetingresses", Kind: "TailnetIngress", Namespaced: true, Verbs: metav1.Verbs{"list"}},
		}})
	}
	f.discovery.catalog = append(f.discovery.catalog, &metav1.APIResourceList{GroupVersion: "v1", APIResources: []metav1.APIResource{
		{Name: "secrets", Kind: "Secret", Namespaced: true, Verbs: metav1.Verbs{"list"}},
		{Name: "configmaps", Kind: "ConfigMap", Namespaced: true, Verbs: metav1.Verbs{"list"}},
		{Name: "pods", Kind: "Pod", Namespaced: true, Verbs: metav1.Verbs{"list"}},
		{Name: "services", Kind: "Service", Namespaced: true, Verbs: metav1.Verbs{"list"}},
		{Name: "pods/status", Kind: "Pod", Namespaced: true, Verbs: metav1.Verbs{"list"}},
		{Name: "bindings", Kind: "Binding", Namespaced: true, Verbs: metav1.Verbs{"create"}},
	}})
	for _, kind := range []string{"TailnetEgress", "TailnetIngress"} {
		o := migrationObject(LegacyAPIVersion, kind, "operator", "app", "old-"+kind)
		o.Object["spec"] = map[string]any{"tailnetRef": map[string]any{"name": "corp"}}
		n := o.DeepCopy()
		n.SetAPIVersion(APIVersion)
		n.SetUID("new-" + o.GetUID())
		f.objects = append(f.objects, o, n)
	}
	return f
}

func (f *inventoryTestFixture) plan(t *testing.T) (*Inventory, error) {
	t.Helper()
	kinds, paths := map[schema.GroupVersionResource]string{}, map[string]schema.GroupVersionResource{}
	for _, list := range f.discovery.catalog {
		gv, _ := schema.ParseGroupVersion(list.GroupVersion)
		for _, r := range list.APIResources {
			if strings.Contains(r.Name, "/") || !slices.Contains(r.Verbs, "list") {
				continue
			}
			gvr := gv.WithResource(r.Name)
			kinds[gvr] = r.Kind + "List"
			prefix := "/apis/"
			if gv.Group == "" {
				prefix = "/api/"
			}
			paths[prefix+gv.String()+"/"+r.Name] = gvr
		}
	}
	// The dynamic fake drops Limit/Continue in list actions; exercise real HTTP encoding.
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gvr, exists := paths[r.URL.Path]
		if r.Method != http.MethodGet || !exists {
			t.Errorf("not a read-only cluster-wide list: %s %s", r.Method, r.URL.Path)
			http.Error(w, "unexpected action", http.StatusBadRequest)
			return
		}
		query := r.URL.Query()
		if query.Get("labelSelector") != "" || query.Get("fieldSelector") != "" || query.Get("watch") != "" || query.Get("limit") != "500" {
			t.Errorf("restricted or unpaged list: %v", query)
		}
		opts := metav1.ListOptions{Continue: query.Get("continue")}
		f.calls[gvr]++
		if f.calls[gvr] > 8 {
			t.Error("list did not terminate")
			http.Error(w, "too many requests", http.StatusBadRequest)
			return
		}
		list := &unstructured.UnstructuredList{}
		list.SetAPIVersion(gvr.GroupVersion().String())
		list.SetKind(kinds[gvr])
		list.SetResourceVersion("100")
		for _, obj := range f.objects {
			if obj.GetAPIVersion() == gvr.GroupVersion().String() && obj.GetKind()+"List" == kinds[gvr] {
				list.Items = append(list.Items, *obj.DeepCopy())
			}
		}
		if f.hook != nil {
			if err := f.hook(gvr, f.calls[gvr], opts, list); err != nil {
				http.Error(w, err.Error(), http.StatusForbidden)
				return
			}
		}
		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(list); err != nil {
			t.Error(err)
		}
	}))
	defer server.Close()
	api, err := dynamic.NewForConfig(&rest.Config{Host: server.URL, QPS: -1})
	if err != nil {
		t.Fatal(err)
	}
	before, _ := json.Marshal(f.objects)
	result, err := PlanInventory(context.Background(), &f.discovery, api, "operator")
	after, _ := json.Marshal(f.objects)
	if string(before) != string(after) {
		t.Fatal("planning mutated input objects")
	}
	return result, err
}

func inventoryFailure(t *testing.T, f *inventoryTestFixture, want error) {
	t.Helper()
	got, err := f.plan(t)
	if got != nil || !errors.Is(err, want) {
		t.Fatalf("got inventory=%v error=%v; want nil inventory and %v", got, err, want)
	}
	// Exact sentinel text prevents proxy bodies, names, annotations or tokens leaking.
	if err.Error() != want.Error() {
		t.Fatalf("error is not redacted: %q", err)
	}
}

func TestPlanInventoryDeterministicReadOnly(t *testing.T) {
	var first *Inventory
	for _, reverse := range []bool{false, true} {
		f := newInventoryFixture()
		second := f.objects[2].DeepCopy()
		second.SetName("aaa-key")
		second.SetUID("second-child")
		cm := f.objects[2].DeepCopy()
		cm.SetKind("ConfigMap")
		cm.SetName("hosts")
		cm.SetUID("hosts-uid")
		cm.SetAnnotations(nil)
		cm.SetLabels(map[string]string{legacyDomain + "role": "dns-hosts"})
		unowned := migrationObject("v1", "Pod", "tenant", "unrelated", "pod-uid")
		f.objects = append(f.objects, second, cm, unowned)
		if reverse {
			slices.Reverse(f.objects)
			slices.Reverse(f.discovery.catalog)
			for _, r := range f.discovery.catalog {
				slices.Reverse(r.APIResources)
			}
		}
		got, err := f.plan(t)
		if err != nil {
			t.Fatal(err)
		}
		p, c, r := got.Counts()
		if p != 3 || c != 3 || r != 10 {
			t.Fatalf("counts = %d/%d/%d", p, c, r)
		}
		if f.discovery.calls != 2 || len(f.calls) != 10 {
			t.Fatal("did not enumerate the complete catalog and rediscover it")
		}
		for gvr, calls := range f.calls {
			want := 1
			if gvr.Group != "" {
				want = 2
			}
			if calls != want {
				t.Fatalf("%s listed %d times, want %d", gvr, calls, want)
			}
		}
		var names []string
		for _, transfer := range got.transfers {
			names = append(names, transfer.before.GetName())
			if transfer.after.GetOwnerReferences()[0].UID != "new-uid" {
				t.Fatal("wrong destination parent")
			}
			if _, retained := transfer.after.GetAnnotations()[legacyDomain+"prefix"]; retained {
				t.Fatal("unsafe annotation retained")
			}
		}
		if !reflect.DeepEqual(names, []string{"hosts", "aaa-key", "corp-apikey"}) {
			t.Fatalf("wrong children/order: %v", names)
		}
		if first != nil && !reflect.DeepEqual(first, got) {
			t.Fatal("resource/item order changed plans")
		}
		first = got
		for _, text := range []string{fmt.Sprint(got), fmt.Sprintf("%+v", got), fmt.Sprintf("%#v", got), fmt.Sprintf("%+v", *got), fmt.Sprintf("%#v", *got)} {
			if text != "migration.Inventory (redacted)" {
				t.Fatal("inventory formatting exposed snapshots")
			}
		}
		encoded, err := json.Marshal(got)
		if err != nil || string(encoded) != "{}" {
			t.Fatal("inventory JSON exposed snapshots")
		}
	}
	var empty *Inventory
	if p, c, r := empty.Counts(); p != 0 || c != 0 || r != 0 {
		t.Fatal("nil inventory counts")
	}
}

func TestPlanInventoryRejectsUnsafeOwnership(t *testing.T) {
	for name, mutate := range map[string]func(*metav1.OwnerReference){
		"dangling":                     func(o *metav1.OwnerReference) { o.UID = "missing" },
		"foreign group with known uid": func(o *metav1.OwnerReference) { o.APIVersion = "foreign.io/v1" },
		"unknown old version":          func(o *metav1.OwnerReference) { o.APIVersion = legacyDomain + "v99" },
		"unknown new version":          func(o *metav1.OwnerReference) { o.APIVersion = domain + "v99" },
		"wrong name":                   func(o *metav1.OwnerReference) { o.Name = "foreign" },
		"wrong kind":                   func(o *metav1.OwnerReference) { o.Kind = "TailnetIngress" },
		"missing uid":                  func(o *metav1.OwnerReference) { o.UID = "" },
		"missing controller":           func(o *metav1.OwnerReference) { o.Controller = nil },
		"non-controller":               func(o *metav1.OwnerReference) { no := false; o.Controller = &no },
		"new-group child":              func(o *metav1.OwnerReference) { o.APIVersion = APIVersion; o.UID = "new-uid" },
	} {
		t.Run(name, func(t *testing.T) {
			f := newInventoryFixture()
			refs := f.objects[2].GetOwnerReferences()
			mutate(&refs[0])
			f.objects[2].SetOwnerReferences(refs)
			inventoryFailure(t, f, ErrInvalid)
		})
	}
	for name, mutate := range map[string]func(*inventoryTestFixture){
		"unsupported owned Pod":      func(f *inventoryTestFixture) { f.objects[2].SetKind("Pod") },
		"unexpected child namespace": func(f *inventoryTestFixture) { f.objects[2].SetNamespace("tenant") },
		"multiple controllers": func(f *inventoryTestFixture) {
			refs := f.objects[2].GetOwnerReferences()
			f.objects[2].SetOwnerReferences(append(refs, refs[0]))
		},
		"malformed owner list": func(f *inventoryTestFixture) {
			refs, _, _ := unstructured.NestedSlice(f.objects[2].Object, "metadata", "ownerReferences")
			_ = unstructured.SetNestedSlice(f.objects[2].Object, append(refs, "malformed-private-token"), "metadata", "ownerReferences")
		},
		"duplicate child uid": func(f *inventoryTestFixture) {
			c := f.objects[2].DeepCopy()
			c.SetName("duplicate")
			f.objects = append(f.objects, c)
		},
		"child reuses parent uid": func(f *inventoryTestFixture) { f.objects[2].SetUID(f.objects[0].GetUID()) },
		"extra new-group child": func(f *inventoryTestFixture) {
			c := f.objects[2].DeepCopy()
			c.SetName("already-transferred")
			c.SetUID("extra-uid")
			refs := c.GetOwnerReferences()
			refs[0].APIVersion = APIVersion
			refs[0].UID = "new-uid"
			c.SetOwnerReferences(refs)
			f.objects = append(f.objects, c)
		},
	} {
		t.Run(name, func(t *testing.T) { f := newInventoryFixture(); mutate(f); inventoryFailure(t, f, ErrInvalid) })
	}
}

func TestPlanInventoryValidatesChildlessPairs(t *testing.T) {
	for name, mutate := range map[string]func(*inventoryTestFixture){
		"missing destination": func(f *inventoryTestFixture) { f.objects = f.objects[:len(f.objects)-1] },
		"extra destination": func(f *inventoryTestFixture) {
			n := f.objects[1].DeepCopy()
			n.SetName("extra")
			n.SetUID("extra")
			f.objects = append(f.objects, n)
		},
		"different destination name": func(f *inventoryTestFixture) { f.objects[6].SetName("different") },
		"duplicate parent uid":       func(f *inventoryTestFixture) { f.objects[6].SetUID(f.objects[1].GetUID()) },
		"missing parent rv":          func(f *inventoryTestFixture) { f.objects[5].SetResourceVersion("") },
		"destination Apply": func(f *inventoryTestFixture) {
			_ = unstructured.SetNestedField(f.objects[1].Object, "Apply", "spec", "policy", "mode")
		},
		"spec drift": func(f *inventoryTestFixture) {
			_ = unstructured.SetNestedField(f.objects[6].Object, "private-value", "spec", "extra")
		},
		"unresolved tailnet": func(f *inventoryTestFixture) {
			for _, i := range []int{5, 6} {
				_ = unstructured.SetNestedField(f.objects[i].Object, "missing", "spec", "tailnetRef", "name")
			}
		},
		"unexpected egress namespace": func(f *inventoryTestFixture) {
			f.objects[3].SetNamespace("tenant")
			f.objects[4].SetNamespace("tenant")
		},
		"deleting parent": func(f *inventoryTestFixture) { now := metav1.Now(); f.objects[5].SetDeletionTimestamp(&now) },
	} {
		t.Run(name, func(t *testing.T) {
			f := newInventoryFixture()
			mutate(f)
			f.objects = append(f.objects[:2], f.objects[3:]...)
			inventoryFailure(t, f, ErrInvalid)
		})
	}
	f := newInventoryFixture()
	f.objects = append(f.objects[:2], f.objects[3:]...)
	got, err := f.plan(t)
	if err != nil {
		t.Fatal(err)
	}
	if p, c, _ := got.Counts(); p != 3 || c != 0 {
		t.Fatal("valid childless pairs lost")
	}
}

func TestPlanInventoryParentRescan(t *testing.T) {
	for _, group := range []string{LegacyAPIVersion, APIVersion} {
		for _, change := range []string{"added", "removed", "stale", "list failure"} {
			t.Run(group+"/"+change, func(t *testing.T) {
				f := newInventoryFixture()
				f.objects = append(f.objects[:2], f.objects[3:]...)
				f.hook = func(gvr schema.GroupVersionResource, call int, _ metav1.ListOptions, list *unstructured.UnstructuredList) error {
					if gvr.GroupVersion().String() != group || gvr.Resource != "tailnetingresses" || call != 2 {
						return nil
					}
					switch change {
					case "added":
						obj := list.Items[0].DeepCopy()
						obj.SetName("new-parent")
						obj.SetUID("new-parent")
						list.Items = append(list.Items, *obj)
					case "removed":
						list.Items = nil
					case "stale":
						list.Items[0].SetResourceVersion("11")
					case "list failure":
						return errors.New("private-proxy-body")
					}
					return nil
				}
				want := ErrStale
				if change == "list failure" {
					want = ErrAPI
				}
				inventoryFailure(t, f, want)
			})
		}
	}
}

func TestPlanInventoryDiscoveryAndListFailures(t *testing.T) {
	for _, scenario := range []string{"partial discovery", "rediscovery failure", "catalog changed", "missing parent GVR", "unknown migration version", "duplicate GVR", "unrelated list failure"} {
		t.Run(scenario, func(t *testing.T) {
			f := newInventoryFixture()
			want := ErrInvalid
			switch scenario {
			case "partial discovery", "rediscovery failure":
				want = ErrAPI
				f.discovery.hook = func(call int, lists []*metav1.APIResourceList) ([]*metav1.APIResourceList, error) {
					if scenario == "partial discovery" || call == 2 {
						return lists, errors.New("private-discovery-body")
					}
					return lists, nil
				}
			case "catalog changed":
				want = ErrStale
				f.discovery.hook = func(call int, lists []*metav1.APIResourceList) ([]*metav1.APIResourceList, error) {
					if call == 2 {
						lists[2].APIResources = lists[2].APIResources[1:]
					}
					return lists, nil
				}
			case "missing parent GVR":
				f.discovery.catalog[0].APIResources = f.discovery.catalog[0].APIResources[:2]
			case "unknown migration version":
				extra := f.discovery.catalog[0].DeepCopy()
				extra.GroupVersion = legacyDomain + "v99"
				f.discovery.catalog = append(f.discovery.catalog, extra)
			case "duplicate GVR":
				f.discovery.catalog = append(f.discovery.catalog, f.discovery.catalog[0].DeepCopy())
			case "unrelated list failure":
				want = ErrAPI
				f.hook = func(gvr schema.GroupVersionResource, _ int, _ metav1.ListOptions, _ *unstructured.UnstructuredList) error {
					if gvr.Resource == "services" {
						return errors.New("private-list-body")
					}
					return nil
				}
			}
			inventoryFailure(t, f, want)
		})
	}
}

func TestPlanInventoryPagination(t *testing.T) {
	for _, scenario := range []string{"success", "second page failure", "rv mismatch", "missing rv", "repeated token", "duplicate name", "duplicate uid"} {
		t.Run(scenario, func(t *testing.T) {
			f := newInventoryFixture()
			second := f.objects[2].DeepCopy()
			second.SetName("page-two")
			second.SetUID("page-two-uid")
			f.hook = func(gvr schema.GroupVersionResource, call int, opts metav1.ListOptions, list *unstructured.UnstructuredList) error {
				if gvr.Resource != "secrets" {
					return nil
				}
				if call == 1 {
					if opts.Continue != "" {
						t.Error("unexpected initial continuation")
					}
					list.SetContinue("page-two-token")
					if scenario == "missing rv" {
						list.SetResourceVersion("")
					}
					return nil
				}
				if opts.Continue != "page-two-token" {
					t.Errorf("continuation not forwarded: %q", opts.Continue)
				}
				list.Items = []unstructured.Unstructured{*second.DeepCopy()}
				switch scenario {
				case "second page failure":
					return errors.New("private-second-page-body")
				case "rv mismatch":
					list.SetResourceVersion("101")
				case "repeated token":
					list.Items = nil
					list.SetContinue("page-two-token")
				case "duplicate name":
					list.Items[0].SetName(f.objects[2].GetName())
				case "duplicate uid":
					list.Items[0].SetUID(f.objects[2].GetUID())
				}
				return nil
			}
			if scenario == "success" {
				got, err := f.plan(t)
				if err != nil {
					t.Fatal(err)
				}
				if _, c, _ := got.Counts(); c != 2 || len(got.transfers) != 2 || got.transfers[1].before.GetUID() != "page-two-uid" {
					t.Fatal("second page omitted or wrong child planned")
				}
			} else {
				want := ErrInvalid
				if scenario == "second page failure" {
					want = ErrAPI
				}
				if scenario == "rv mismatch" {
					want = ErrStale
				}
				inventoryFailure(t, f, want)
			}
			wantCalls := 2
			if scenario == "missing rv" {
				wantCalls = 1
			}
			if f.calls[schema.GroupVersionResource{Version: "v1", Resource: "secrets"}] != wantCalls {
				t.Fatal("unexpected page request count")
			}
		})
	}
}
