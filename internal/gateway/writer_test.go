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
	// Mutable fields and churn must keep the receipt valid ...
	for name, mutate := range map[string]func(*tnv1.TailnetGateway, *tnv1.Tailnet){
		"gatewayGeneration": func(g *tnv1.TailnetGateway, _ *tnv1.Tailnet) { g.Generation++ },
		"tailnetGeneration": func(_ *tnv1.TailnetGateway, tn *tnv1.Tailnet) { tn.Generation++ },
		"image":             func(g *tnv1.TailnetGateway, _ *tnv1.Tailnet) { g.Spec.Image = "ghcr.io/tailscale/tailscale:v1.102.5" },
		"dns image":         func(g *tnv1.TailnetGateway, _ *tnv1.Tailnet) { g.Spec.DNS.Image = "coredns/coredns:1.14.7" },
		"static records": func(g *tnv1.TailnetGateway, _ *tnv1.Tailnet) {
			g.Spec.DNS.StaticRecords = []tnv1.GatewayStaticRecord{{Name: "app", Address: "198.51.100.8"}}
		},
		"wildcard": func(g *tnv1.TailnetGateway, _ *tnv1.Tailnet) { g.Spec.DNS.WildcardAddress = "198.51.100.9" },
		"deletion policy": func(g *tnv1.TailnetGateway, _ *tnv1.Tailnet) {
			g.Spec.DeletionPolicy = tnv1.GatewayDeletionPolicyDelete
		},
		"lan": func(g *tnv1.TailnetGateway, _ *tnv1.Tailnet) {
			g.Spec.Routes.LAN = append(g.Spec.Routes.LAN, "10.9.0.0/16")
		},
		"egress adv":      func(g *tnv1.TailnetGateway, _ *tnv1.Tailnet) { g.Spec.Routes.AdvertiseEgressTargets = ptr.To(false) },
		"lb cidr":         func(g *tnv1.TailnetGateway, _ *tnv1.Tailnet) { g.Spec.Service.TailnetLBCIDR = "198.51.0.0/16" },
		"pool labels":     func(g *tnv1.TailnetGateway, _ *tnv1.Tailnet) { g.Spec.Service.PoolLabels = nil },
		"tag order":       func(g *tnv1.TailnetGateway, _ *tnv1.Tailnet) { g.Spec.Tags = []string{"tag:fabric", "tag:mesh"} },
		"tailnet api url": func(_ *tnv1.TailnetGateway, tn *tnv1.Tailnet) { tn.Spec.APIURL = "https://api.example" },
	} {
		t.Run("mutable/"+name, func(t *testing.T) {
			cg, ct := g.DeepCopy(), tn.DeepCopy()
			mutate(cg, ct)
			got, err := freshScope(cg, ct, in.Namespace)
			if err != nil || !reflect.DeepEqual(initial, got) {
				t.Fatal("mutable field invalidated the completion receipt")
			}
		})
	}
	// ... while every pinned identity field must not reuse it.
	for name, mutate := range map[string]func(*tnv1.TailnetGateway, *tnv1.Tailnet){
		"gatewayUID":  func(g *tnv1.TailnetGateway, _ *tnv1.Tailnet) { g.UID = "replacement" },
		"tailnetUID":  func(_ *tnv1.TailnetGateway, tn *tnv1.Tailnet) { tn.UID = "replacement" },
		"hostname":    func(g *tnv1.TailnetGateway, _ *tnv1.Tailnet) { g.Spec.Hostname = "different" },
		"tags":        func(g *tnv1.TailnetGateway, _ *tnv1.Tailnet) { g.Spec.Tags = []string{"tag:fabric"} },
		"lb ip":       func(g *tnv1.TailnetGateway, _ *tnv1.Tailnet) { g.Spec.Service.LoadBalancerIP = "198.51.100.2" },
		"lb class":    func(g *tnv1.TailnetGateway, _ *tnv1.Tailnet) { g.Spec.Service.LoadBalancerClass = "example.com/other" },
		"dns zone":    func(g *tnv1.TailnetGateway, _ *tnv1.Tailnet) { g.Spec.DNS.Zone = "other.example" },
		"dns service": func(g *tnv1.TailnetGateway, _ *tnv1.Tailnet) { g.Spec.DNS.ServiceName = "other-dns" },
		"dns cluster": func(g *tnv1.TailnetGateway, _ *tnv1.Tailnet) { g.Spec.DNS.ServiceClusterIP = "10.96.0.54" },
		"extra zones": func(g *tnv1.TailnetGateway, _ *tnv1.Tailnet) {
			g.Spec.DNS.ExtraZones = []tnv1.GatewayExtraZone{{Zone: "x.example"}}
		},
		"forwards":     func(g *tnv1.TailnetGateway, _ *tnv1.Tailnet) { g.Spec.Forwards = []tnv1.GatewayForward{{Name: "api"}} },
		"tailnet url":  func(_ *tnv1.TailnetGateway, tn *tnv1.Tailnet) { tn.Spec.Server = "https://different.example" },
		"tailnet host": func(_ *tnv1.TailnetGateway, tn *tnv1.Tailnet) { tn.Spec.DNS.HostsConfigMap = "other-hosts" },
	} {
		t.Run("pinned/"+name, func(t *testing.T) {
			cg, ct := g.DeepCopy(), tn.DeepCopy()
			mutate(cg, ct)
			got, err := freshScope(cg, ct, in.Namespace)
			if err == nil && reflect.DeepEqual(initial, got) {
				t.Fatal("changed identity reused completion receipt")
			}
		})
	}
	// Suspend, external auth and adoption are refused outright, not just unequal.
	for name, mutate := range map[string]func(*tnv1.TailnetGateway){
		"suspended":    func(g *tnv1.TailnetGateway) { g.Spec.Suspend = ptr.To(true) },
		"externalAuth": func(g *tnv1.TailnetGateway) { g.Spec.AuthKeySecretRef = &tnv1.GatewayAuthKeyReference{Name: "foreign"} },
		"adoption":     func(g *tnv1.TailnetGateway) { g.Spec.Adoption = &tnv1.GatewayAdoption{NodeID: "1"} },
	} {
		t.Run("refused/"+name, func(t *testing.T) {
			cg := g.DeepCopy()
			mutate(cg)
			if _, err := freshScope(cg, tn, in.Namespace); err == nil {
				t.Fatal("scope accepted refused input")
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
	// Both Corefile and zone.db are reconciled live from the Gateway spec and the
	// Tailnet hosts source via UpdateDNSRevision (CoreDNS has a `reload` plugin so
	// Corefile changes land without a Pod restart). The receipt digest therefore
	// excludes both; integrity rides on the DNSHash/DNSSerial annotations.
	cm := &corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Name: "router-coredns", UID: "dns-uid"}, Data: map[string]string{"Corefile": "original", DNSZoneFile: "zone1"}}
	original := objectReceipt(cm)
	cm.Data["Corefile"] = "changed"
	cm.Data[DNSZoneFile] = "zone-after-live-reconcile"
	if objectReceipt(cm) != original {
		t.Fatal("derived zone or Corefile drift must be excluded from the fingerprint")
	}
	cm.Data["Corefile"], cm.Data[DNSZoneFile] = "original", "zone1"
	cm.Data["other"] = "x"
	if objectReceipt(cm) == original {
		t.Fatal("foreign key drift in -coredns ConfigMap must stay bound")
	}
	delete(cm.Data, "other")
	// A non-coredns ConfigMap must keep every key digest-bound.
	other := &corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Name: "router-fresh", UID: "fresh-uid"}, Data: map[string]string{DNSZoneFile: "retained"}}
	before := objectReceipt(other)
	other.Data[DNSZoneFile] = "mutated"
	if objectReceipt(other) == before {
		t.Fatal("foreign ConfigMap drift not bound")
	}
}
