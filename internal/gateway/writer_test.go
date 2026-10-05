package gateway

import (
	"reflect"
	"testing"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/utils/ptr"

	tnv1 "tsunaro.io/tailnet-operator/api/v1alpha1"
)

func TestFreshCompletionScope(t *testing.T) {
	in := freshFixture()
	g, tn := in.Gateway, in.Tailnet
	g.Spec.AuthKeySecretRef = nil
	g.Spec.Suspend = ptr.To(false)
	g.ResourceVersion, tn.ResourceVersion = "10", "11"
	tn.UID = "tailnet-uid"
	g.Generation, tn.Generation = 2, 3
	initial, err := freshScope(g, tn, in.Namespace)
	if err != nil {
		t.Fatal("scope rejected valid fresh input")
	}
	changedG, changedTN := g.DeepCopy(), tn.DeepCopy()
	changedG.ResourceVersion, changedTN.ResourceVersion = "20", "21"
	changedG.Status.NodeID = "1"
	changedG.Annotations = map[string]string{"example.test/note": "metadata-only"}
	after, err := freshScope(changedG, changedTN, in.Namespace)
	if err != nil || !reflect.DeepEqual(initial, after) {
		t.Fatal("status or metadata RV churn invalidates completed provenance")
	}
	for _, field := range []string{"gatewayUID", "tailnetUID", "gatewayGeneration", "tailnetGeneration", "gatewaySpec", "tailnetSpec", "suspended", "externalAuth", "adoption"} {
		t.Run(field, func(t *testing.T) {
			cg, ct := g.DeepCopy(), tn.DeepCopy()
			switch field {
			case "gatewayUID":
				cg.UID = "replacement"
			case "tailnetUID":
				ct.UID = "replacement"
			case "gatewayGeneration":
				cg.Generation++
			case "tailnetGeneration":
				ct.Generation++
			case "gatewaySpec":
				cg.Spec.Hostname = "different"
			case "tailnetSpec":
				ct.Spec.Server = "https://different.example"
			case "suspended":
				cg.Spec.Suspend = ptr.To(true)
			case "externalAuth":
				cg.Spec.AuthKeySecretRef = &tnv1.GatewayAuthKeyReference{Name: "foreign"}
			case "adoption":
				cg.Spec.Adoption = &tnv1.GatewayAdoption{NodeID: "1"}
			}
			got, err := freshScope(cg, ct, in.Namespace)
			if err == nil && reflect.DeepEqual(initial, got) {
				t.Fatal("changed scope reused completion receipt")
			}
		})
	}
}

func TestFreshWriterIPv4Boundary(t *testing.T) {
	in := freshFixture()
	in.Egresses = nil
	p, err := RenderFresh(in)
	if err != nil {
		t.Fatal("render fixture")
	}
	if !freshIPv4(in.Gateway, p, "198.51.100.8 app.tail.example\n") {
		t.Fatal("IPv4 fixture rejected")
	}
	for _, field := range []string{"route", "dnsService", "loadBalancer", "static", "wildcard", "hosts"} {
		t.Run(field, func(t *testing.T) {
			g := in.Gateway.DeepCopy()
			plan := p
			hosts := ""
			switch field {
			case "route":
				plan.Routes.Routes = []string{"2001:db8::/64"}
			case "dnsService":
				g.Spec.DNS.ServiceClusterIP = "2001:db8::53"
			case "loadBalancer":
				g.Spec.Service.LoadBalancerIP = "2001:db8::17"
			case "static":
				g.Spec.DNS.StaticRecords = []tnv1.GatewayStaticRecord{{Name: "app", Address: "2001:db8::8"}}
			case "wildcard":
				g.Spec.DNS.WildcardAddress = "2001:db8::8"
			case "hosts":
				hosts = "2001:db8::8 app.tail.example\n"
			}
			if freshIPv4(g, plan, hosts) {
				t.Fatal("IPv6 passed minimal writer boundary")
			}
		})
	}
}

func TestFreshInventoryIncludesAllRetainedNames(t *testing.T) {
	in := freshFixture()
	in.Gateway.Spec.AuthKeySecretRef = nil
	names := freshNames(in.Gateway)
	seen := map[string]bool{}
	for _, n := range names {
		if seen[n] {
			t.Fatal("duplicate fresh inventory key")
		}
		seen[n] = true
	}
	if len(seen) != 14 || !seen["Pod/router-0"] || !seen["ConfigMap/router-auth-receipt"] || !seen["ConfigMap/router-fresh"] || !seen["Secret/router-state"] || !seen["Secret/router-auth"] {
		t.Fatal("incomplete writer inventory")
	}
	in.Gateway.Spec.AuthKeySecretRef = &tnv1.GatewayAuthKeyReference{Name: "foreign-auth"}
	if len(freshNames(in.Gateway)) != 15 {
		t.Fatal("peer external auth reference omitted from collision checks")
	}
}

func TestFreshStateSelectors(t *testing.T) {
	in := freshFixture()
	plan, err := RenderFresh(in)
	if err != nil {
		t.Fatal("render fixture")
	}
	bindFreshState(plan, "created-state-uid")
	for _, obj := range plan.Objects {
		switch obj := obj.(type) {
		case *appsv1.StatefulSet:
			if obj.Spec.Selector.MatchLabels[gatewayStateUIDLabel] != "created-state-uid" || obj.Spec.Template.Labels[gatewayStateUIDLabel] != "created-state-uid" {
				t.Fatal("StatefulSet can select a pre-existing orphan")
			}
		case *corev1.Service:
			if obj.Spec.Selector[gatewayStateUIDLabel] != "created-state-uid" {
				t.Fatal("Service can select a pre-existing orphan")
			}
		}
	}
}

func TestFreshPayloadFingerprint(t *testing.T) {
	in := freshFixture()
	p, err := RenderFresh(in)
	if err != nil {
		t.Fatal("render fixture")
	}
	for _, obj := range p.Objects {
		obj.SetUID("created-uid")
		obj.SetResourceVersion("10")
		original := objectReceipt(obj)
		obj.SetResourceVersion("11")
		obj.SetAnnotations(map[string]string{"example.test/note": "metadata-only"})
		if sts, ok := obj.(*appsv1.StatefulSet); ok {
			sts.Status.ReadyReplicas = 1
		}
		if objectReceipt(obj) != original {
			t.Fatal("API bookkeeping/status changed payload digest")
		}
		obj.SetUID("replacement")
		if objectReceipt(obj) == original {
			t.Fatal("replacement object retained provenance")
		}
	}
	cm := &corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Name: "router-coredns", UID: "dns-uid"}, Data: map[string]string{"Corefile": "original"}}
	original := objectReceipt(cm)
	cm.Data["Corefile"] = "changed"
	if objectReceipt(cm) == original {
		t.Fatal("in-place DNS drift not bound")
	}
}
