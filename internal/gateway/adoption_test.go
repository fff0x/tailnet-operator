package gateway

import (
	"errors"
	"reflect"
	"strings"
	"testing"

	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/types"
)

func adoptionFixture() AdoptionRequest {
	makeSnapshot := func(version, kind, name string, payload map[string]any) AdoptionSnapshot {
		ref := AdoptionReference{APIVersion: version, Kind: kind, Name: name, UID: types.UID(kind + "-" + name + "-uid")}
		obj := &unstructured.Unstructured{Object: map[string]any{
			"apiVersion": version, "kind": kind,
			"metadata": map[string]any{
				"name": name, "namespace": "tailnet-system", "uid": string(ref.UID), "resourceVersion": "7",
				"generation": int64(1), "annotations": map[string]any{AdoptionAnnotation: "gateway-uid"},
			},
		}}
		for key, value := range payload {
			obj.Object[key] = value
		}
		return AdoptionSnapshot{Reference: ref, Current: obj, Desired: obj.DeepCopy()}
	}
	workload := makeSnapshot("apps/v1", "StatefulSet", "router", map[string]any{
		"spec": map[string]any{
			"replicas": int64(1), "serviceName": "router-headless",
			"selector": map[string]any{"matchLabels": map[string]any{"app": "router"}},
			"template": map[string]any{
				"metadata": map[string]any{"labels": map[string]any{"app": "router"}},
				"spec": map[string]any{"containers": []any{map[string]any{
					"name": "tailscale", "image": "tailscale:test",
					"env": []any{map[string]any{"name": "TS_KUBE_SECRET", "value": "router-state"}},
				}}},
			},
		},
		"status": map[string]any{
			"replicas": int64(1), "readyReplicas": int64(1), "currentReplicas": int64(1), "updatedReplicas": int64(1),
			"observedGeneration": int64(1), "currentRevision": "router-revision", "updateRevision": "router-revision",
		},
	})
	// Opaque fixture bytes are not a real tailscaled state format. This unit test
	// proves byte preservation, never a state-to-Headscale identity association.
	state := makeSnapshot("v1", "Secret", "router-state", map[string]any{
		"type": "Opaque", "data": map[string]any{"fixture": "cHJpdmF0ZS1zdGF0ZS1maXh0dXJl"},
	})
	service := makeSnapshot("v1", "Service", "router", map[string]any{
		"spec": map[string]any{
			"type": "LoadBalancer", "loadBalancerIP": "192.0.2.17", "clusterIP": "10.96.0.54",
			"selector": map[string]any{"app": "router"},
			"ports":    []any{map[string]any{"name": "dns", "protocol": "UDP", "port": int64(53), "targetPort": int64(53)}},
		},
	})
	return AdoptionRequest{GatewayUID: "gateway-uid", Namespace: "tailnet-system", StatefulSet: "router", StateSecret: "router-state", Snapshots: []AdoptionSnapshot{workload, state, service}}
}

func TestAdoptionIdenticalRetainedResources(t *testing.T) {
	in := adoptionFixture()
	before := adoptionFixture()
	got, err := PlanAdoption(in)
	if err != nil || len(got) != 3 {
		t.Fatalf("receipts=%d error=%v", len(got), err)
	}
	for i, receipt := range got {
		if receipt.Reference != in.Snapshots[i].Reference || receipt.ResourceVersion != "7" || receipt.Namespace != in.Namespace {
			t.Fatal("receipt does not bind the inventoried identity and revision")
		}
	}
	if !reflect.DeepEqual(in, before) {
		t.Fatal("read-only planner mutated its inputs")
	}
	for _, snapshot := range in.Snapshots {
		if len(snapshot.Current.GetOwnerReferences()) != 0 || len(snapshot.Desired.GetOwnerReferences()) != 0 {
			t.Fatal("retained resources must not acquire GC ownership")
		}
	}
}

func TestAdoptionFailsClosed(t *testing.T) {
	set := func(in *AdoptionRequest, index int, desired bool, value any, path ...string) {
		obj := in.Snapshots[index].Current
		if desired {
			obj = in.Snapshots[index].Desired
		}
		if err := unstructured.SetNestedField(obj.Object, value, path...); err != nil {
			t.Fatal("invalid test fixture path")
		}
	}
	tests := []struct {
		name string
		want error
		edit func(*AdoptionRequest)
	}{
		{"missing-gateway-uid", ErrAdoptionInvalid, func(in *AdoptionRequest) { in.GatewayUID = "" }},
		{"invalid-namespace", ErrAdoptionInvalid, func(in *AdoptionRequest) { in.Namespace = "../tenant" }},
		{"empty-inventory", ErrAdoptionInvalid, func(in *AdoptionRequest) { in.Snapshots = nil }},
		{"missing-state", ErrAdoptionState, func(in *AdoptionRequest) { in.Snapshots = append(in.Snapshots[:1], in.Snapshots[2:]...) }},
		{"missing-workload", ErrAdoptionState, func(in *AdoptionRequest) { in.Snapshots = in.Snapshots[1:] }},
		{"duplicate-reference", ErrAdoptionInvalid, func(in *AdoptionRequest) { in.Snapshots = append(in.Snapshots, in.Snapshots[0]) }},
		{"duplicate-uid", ErrAdoptionInvalid, func(in *AdoptionRequest) { in.Snapshots[1].Reference.UID = in.Snapshots[0].Reference.UID }},
		{"nil-current", ErrAdoptionInvalid, func(in *AdoptionRequest) { in.Snapshots[0].Current = nil }},
		{"nil-desired", ErrAdoptionInvalid, func(in *AdoptionRequest) { in.Snapshots[0].Desired = nil }},
		{"namespace-escape", ErrAdoptionInvalid, func(in *AdoptionRequest) { in.Snapshots[2].Current.SetNamespace("tenant") }},
		{"name-mismatch", ErrAdoptionInvalid, func(in *AdoptionRequest) { in.Snapshots[2].Current.SetName("foreign") }},
		{"unsupported-kind", ErrAdoptionInvalid, func(in *AdoptionRequest) { in.Snapshots[2].Reference.Kind = "ClusterRole" }},
		{"unsupported-version", ErrAdoptionInvalid, func(in *AdoptionRequest) { in.Snapshots[0].Reference.APIVersion = "apps/v1beta1" }},
		{"gvk-mismatch", ErrAdoptionInvalid, func(in *AdoptionRequest) { in.Snapshots[2].Desired.SetKind("ConfigMap") }},
		{"replacement-uid", ErrAdoptionStale, func(in *AdoptionRequest) { in.Snapshots[0].Current.SetUID("replacement") }},
		{"no-resource-version", ErrAdoptionStale, func(in *AdoptionRequest) { in.Snapshots[0].Current.SetResourceVersion("") }},
		{"stale-desired", ErrAdoptionStale, func(in *AdoptionRequest) { in.Snapshots[0].Desired.SetResourceVersion("6") }},
		{"old-gateway-consent", ErrAdoptionConsent, func(in *AdoptionRequest) { in.GatewayUID = "new-gateway-uid" }},
		{"name-only-consent", ErrAdoptionConsent, func(in *AdoptionRequest) {
			in.Snapshots[0].Current.SetAnnotations(map[string]string{AdoptionAnnotation: "router"})
		}},
		{"no-consent", ErrAdoptionConsent, func(in *AdoptionRequest) { in.Snapshots[2].Current.SetAnnotations(nil) }},
		{"deleting", ErrAdoptionInvalid, func(in *AdoptionRequest) { set(in, 0, false, "2026-01-01T00:00:00Z", "metadata", "deletionTimestamp") }},
		{"malformed-deletion-time", ErrAdoptionInvalid, func(in *AdoptionRequest) { set(in, 0, false, "not-a-time", "metadata", "deletionTimestamp") }},
		{"malformed-owner", ErrAdoptionInvalid, func(in *AdoptionRequest) { set(in, 0, false, "invalid", "metadata", "ownerReferences") }},
		{"foreign-owner", ErrAdoptionOwned, func(in *AdoptionRequest) {
			set(in, 0, false, []any{map[string]any{"apiVersion": "v1", "kind": "Pod", "name": "owner", "uid": "owner-uid", "controller": false}}, "metadata", "ownerReferences")
		}},
		{"proposed-gc-owner", ErrAdoptionOwned, func(in *AdoptionRequest) {
			set(in, 0, true, []any{map[string]any{"apiVersion": "tsunaro.io/v1alpha1", "kind": "TailnetGateway", "name": "router", "uid": "gateway-uid", "controller": true}}, "metadata", "ownerReferences")
		}},
		{"pod-restart", ErrAdoptionChanged, func(in *AdoptionRequest) {
			set(in, 0, true, "new-revision", "spec", "template", "metadata", "annotations", "rollout")
		}},
		{"new-image", ErrAdoptionChanged, func(in *AdoptionRequest) {
			containers, _, _ := unstructured.NestedSlice(in.Snapshots[0].Desired.Object, "spec", "template", "spec", "containers")
			containers[0].(map[string]any)["image"] = "tailscale:new"
			set(in, 0, true, containers, "spec", "template", "spec", "containers")
		}},
		{"new-selector", ErrAdoptionChanged, func(in *AdoptionRequest) { set(in, 0, true, "new", "spec", "selector", "matchLabels", "app") }},
		{"new-service-name", ErrAdoptionChanged, func(in *AdoptionRequest) { set(in, 0, true, "new", "spec", "serviceName") }},
		{"new-cluster-ip", ErrAdoptionChanged, func(in *AdoptionRequest) { set(in, 2, true, "10.96.0.55", "spec", "clusterIP") }},
		{"new-lb-ip", ErrAdoptionChanged, func(in *AdoptionRequest) { set(in, 2, true, "192.0.2.18", "spec", "loadBalancerIP") }},
		{"state-mutation", ErrAdoptionChanged, func(in *AdoptionRequest) { set(in, 1, true, "c2VjcmV0LWNoYW5nZQ==", "data", "fixture") }},
		{"new-label", ErrAdoptionChanged, func(in *AdoptionRequest) { in.Snapshots[2].Desired.SetLabels(map[string]string{"new": "label"}) }},
		{"new-annotation", ErrAdoptionChanged, func(in *AdoptionRequest) { set(in, 2, true, "new", "metadata", "annotations", "other") }},
		{"new-finalizer", ErrAdoptionChanged, func(in *AdoptionRequest) { in.Snapshots[2].Desired.SetFinalizers([]string{"example.com/hold"}) }},
		{"empty-state", ErrAdoptionState, func(in *AdoptionRequest) {
			for _, desired := range []bool{false, true} {
				set(in, 1, desired, map[string]any{}, "data")
			}
		}},
		{"one-empty-state-value", ErrAdoptionState, func(in *AdoptionRequest) {
			for _, desired := range []bool{false, true} {
				set(in, 1, desired, map[string]any{"fixture": ""}, "data")
			}
		}},
		{"multiple-empty-state-values", ErrAdoptionState, func(in *AdoptionRequest) {
			for _, desired := range []bool{false, true} {
				set(in, 1, desired, map[string]any{"first": "", "second": ""}, "data")
			}
		}},
		{"empty-decoded-state", ErrAdoptionState, func(in *AdoptionRequest) {
			for _, desired := range []bool{false, true} {
				set(in, 1, desired, map[string]any{"fixture": "\r\n"}, "data")
			}
		}},
		{"invalid-state-encoding", ErrAdoptionState, func(in *AdoptionRequest) {
			for _, desired := range []bool{false, true} {
				set(in, 1, desired, map[string]any{"fixture": "private-invalid-encoding"}, "data")
			}
		}},
		{"invalid-state-type", ErrAdoptionState, func(in *AdoptionRequest) {
			for _, desired := range []bool{false, true} {
				set(in, 1, desired, map[string]any{"fixture": int64(42)}, "data")
			}
		}},
		{"immutable-state", ErrAdoptionState, func(in *AdoptionRequest) {
			for _, desired := range []bool{false, true} {
				set(in, 1, desired, true, "immutable")
			}
		}},
		{"two-replicas", ErrAdoptionNotReady, func(in *AdoptionRequest) {
			for _, desired := range []bool{false, true} {
				set(in, 0, desired, int64(2), "spec", "replicas")
			}
		}},
		{"stale-status", ErrAdoptionNotReady, func(in *AdoptionRequest) { set(in, 0, false, int64(2), "metadata", "generation") }},
		{"not-ready", ErrAdoptionNotReady, func(in *AdoptionRequest) { set(in, 0, false, int64(0), "status", "readyReplicas") }},
		{"rolling", ErrAdoptionNotReady, func(in *AdoptionRequest) { set(in, 0, false, "next", "status", "updateRevision") }},
		{"different-state-reference", ErrAdoptionState, func(in *AdoptionRequest) {
			for _, desired := range []bool{false, true} {
				set(in, 0, desired, []any{map[string]any{"name": "tailscale", "env": []any{map[string]any{"name": "TS_KUBE_SECRET", "value": "other-state"}}}}, "spec", "template", "spec", "containers")
			}
		}},
		{"indirect-state-reference", ErrAdoptionState, func(in *AdoptionRequest) {
			for _, desired := range []bool{false, true} {
				set(in, 0, desired, []any{map[string]any{"name": "tailscale", "env": []any{map[string]any{"name": "TS_KUBE_SECRET", "value": "router-state", "valueFrom": map[string]any{}}}}}, "spec", "template", "spec", "containers")
			}
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			in := adoptionFixture()
			test.edit(&in)
			got, err := PlanAdoption(in)
			if !errors.Is(err, test.want) || got != nil {
				t.Fatalf("receipts=%d error=%v; want no receipts and %v", len(got), err, test.want)
			}
			if strings.Contains(err.Error(), "cHJpdmF0ZS") || strings.Contains(err.Error(), "c2VjcmV0") {
				t.Fatal("error exposed secret data")
			}
		})
	}
}

func TestAdoptionAllowsEmptyAuxiliaryStateValue(t *testing.T) {
	in := adoptionFixture()
	for _, obj := range []*unstructured.Unstructured{in.Snapshots[1].Current, in.Snapshots[1].Desired} {
		if err := unstructured.SetNestedField(obj.Object, "", "data", "auxiliary"); err != nil {
			t.Fatal("invalid fixture")
		}
	}
	if receipts, err := PlanAdoption(in); err != nil || len(receipts) != len(in.Snapshots) {
		t.Fatalf("nonempty state with empty auxiliary value rejected: %v", err)
	}
}

func TestAdoptionDoesNotBorrowObjectData(t *testing.T) {
	in := adoptionFixture()
	got, err := PlanAdoption(in)
	if err != nil {
		t.Fatal(err)
	}
	in.Snapshots[0].Current.SetResourceVersion("8")
	in.Snapshots[0].Reference.Name = "replacement"
	if got[0].ResourceVersion != "7" || got[0].Reference.Name != "router" {
		t.Fatal("receipts alias mutable inventory data")
	}
}
