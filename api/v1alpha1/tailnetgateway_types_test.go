package v1alpha1

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
)

func TestTailnetGatewaySchemeAndDeepCopy(t *testing.T) {
	scheme := runtime.NewScheme()
	if err := AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	for _, kind := range []string{"TailnetGateway", "TailnetGatewayList"} {
		gvk := GroupVersion.WithKind(kind)
		obj, err := scheme.New(gvk)
		if err != nil {
			t.Fatal(err)
		}
		kinds, unversioned, err := scheme.ObjectKinds(obj)
		if err != nil || unversioned || len(kinds) != 1 || kinds[0] != gvk {
			t.Fatalf("incorrect scheme registration for %s", kind)
		}
	}
	flag := true
	image := GatewayImage("registry.invalid/test@sha256:" + strings.Repeat("a", 64))
	original := &TailnetGateway{
		ObjectMeta: metav1.ObjectMeta{Name: "gateway", Labels: map[string]string{"app": "gateway"}},
		Spec: TailnetGatewaySpec{
			Suspend: &flag, Image: image, Tags: []string{"tag:fabric"},
			AuthKeySecretRef: &GatewayAuthKeyReference{Name: "auth", Key: "TS_AUTHKEY"},
			Routes:           GatewayRoutes{LAN: []GatewayPrefix{"10.0.0.0/24"}, AdvertiseEgressTargets: &flag},
			Service:          GatewayService{PoolLabels: map[string]GatewayLabelValue{"pool": "tailnet"}},
			DNS:              GatewayDNS{Image: image, ExtraZones: []GatewayExtraZone{{Zone: "extra.example", Upstreams: []GatewayIP{"10.0.0.1"}}}, StaticRecords: []GatewayStaticRecord{{Name: "api", Address: "10.0.0.2"}}},
			ForwardImage:     image, Forwards: []GatewayForward{{Name: "api", Port: 6443, TargetPort: 443}},
			Adoption: &GatewayAdoption{NodeID: "42", Objects: []GatewayAdoptionObject{{APIVersion: "apps/v1", Kind: "StatefulSet", Name: "gateway", UID: "sts-uid"}, {APIVersion: "v1", Kind: "Secret", Name: "state", UID: "state-uid"}}},
		},
		Status: TailnetGatewayStatus{
			RoutesAdvertised: []string{"10.0.0.0/24"}, RoutesApproved: []string{"10.0.0.0/24"}, StaleNodes: []string{"41"},
			Conditions: []metav1.Condition{{Type: "Ready", Status: metav1.ConditionFalse, Reason: "Suspended"}},
		},
	}
	mutations := []func(*TailnetGateway){
		func(o *TailnetGateway) { o.Labels["app"] = "changed" },
		func(o *TailnetGateway) { *o.Spec.Suspend = false },
		func(o *TailnetGateway) { *o.Spec.Routes.AdvertiseEgressTargets = false },
		func(o *TailnetGateway) { o.Spec.Tags[0] = "tag:changed" },
		func(o *TailnetGateway) { o.Spec.Routes.LAN[0] = "10.2.0.0/24" },
		func(o *TailnetGateway) { o.Spec.Service.PoolLabels["pool"] = "changed" },
		func(o *TailnetGateway) { o.Spec.AuthKeySecretRef.Name = "changed" },
		func(o *TailnetGateway) { o.Spec.Adoption.NodeID = "43" },
		func(o *TailnetGateway) { o.Spec.Adoption.Objects[0].UID = "changed" },
		func(o *TailnetGateway) { o.Spec.DNS.ExtraZones[0].Upstreams[0] = "10.0.0.3" },
		func(o *TailnetGateway) { o.Spec.DNS.StaticRecords[0].Address = "10.0.0.3" },
		func(o *TailnetGateway) { o.Spec.Forwards[0].TargetPort = 8443 },
		func(o *TailnetGateway) { o.Status.RoutesAdvertised[0] = "10.2.0.0/24" },
		func(o *TailnetGateway) { o.Status.RoutesApproved[0] = "10.2.0.0/24" },
		func(o *TailnetGateway) { o.Status.StaleNodes[0] = "40" },
		func(o *TailnetGateway) { o.Status.Conditions[0].Reason = "Changed" },
	}
	for i, mutate := range mutations {
		before, err := json.Marshal(original)
		if err != nil {
			t.Fatal(err)
		}
		copy := original.DeepCopyObject().(*TailnetGateway)
		if !reflect.DeepEqual(original, copy) {
			t.Fatal("deepcopy changed values")
		}
		mutate(copy)
		after, err := json.Marshal(original)
		if err != nil {
			t.Fatal(err)
		}
		if string(before) != string(after) || reflect.DeepEqual(original, copy) {
			t.Errorf("mutation %d aliased the original", i)
		}
	}
	list := &TailnetGatewayList{Items: []TailnetGateway{*original}}
	copy := list.DeepCopyObject().(*TailnetGatewayList)
	copy.Items[0].Spec.Adoption.Objects[1].UID = "changed"
	if list.Items[0].Spec.Adoption.Objects[1].UID != "state-uid" {
		t.Fatal("list deepcopy aliased nested inventory")
	}
	empty := (&TailnetGateway{}).DeepCopy()
	if empty.Spec.Suspend != nil || empty.Spec.Routes.AdvertiseEgressTargets != nil || empty.Spec.Adoption != nil {
		t.Fatal("deepcopy allocated omitted pointers")
	}
}
