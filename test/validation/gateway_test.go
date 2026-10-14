//go:build integration

package validation

import (
	"context"
	"net/netip"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/envtest"

	tnv1 "tsunaro.io/tailnet-operator/api/v1alpha1"
	"tsunaro.io/tailnet-operator/internal/gateway"
	"tsunaro.io/tailnet-operator/test/internal/isolation"
)

// Admission proves default suspension and explicit activation, not ownership or node identity.
func TestGatewayAdmission(t *testing.T) {
	must := func(err error) {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
	}
	must(isolation.ClearEnvtestOverrides())
	if os.Getenv("KUBEBUILDER_ASSETS") == "" {
		t.Fatal("set KUBEBUILDER_ASSETS to envtest binaries for Kubernetes >= 1.31")
	}
	root, err := filepath.Abs(filepath.Join("..", ".."))
	must(err)
	useExisting := false
	env := &envtest.Environment{UseExistingCluster: &useExisting, CRDDirectoryPaths: []string{filepath.Join(root, "deploy", "crds")}, ErrorIfCRDPathMissing: true}
	t.Cleanup(func() {
		if err := env.Stop(); err != nil {
			t.Errorf("stop envtest: %v", err)
		}
	})
	cfg, err := env.Start()
	must(err)
	scheme := runtime.NewScheme()
	must(tnv1.AddToScheme(scheme))
	c, err := client.New(cfg, client.Options{Scheme: scheme})
	must(err)
	ctx := context.Background()
	image := tnv1.GatewayImage("registry.invalid/test@sha256:" + strings.Repeat("a", 64))
	fresh := func() *unstructured.Unstructured {
		obj := &tnv1.TailnetGateway{
			TypeMeta: metav1.TypeMeta{APIVersion: "tsunaro.io/v1alpha1", Kind: "TailnetGateway"}, ObjectMeta: metav1.ObjectMeta{Name: "gateway"},
			Spec: tnv1.TailnetGatewaySpec{
				TailnetRef: tnv1.GatewayLocalReference{Name: "default"}, Hostname: "router", StateSecretRef: tnv1.GatewayLocalReference{Name: "router-state"},
				AuthKeySecretRef: &tnv1.GatewayAuthKeyReference{Name: "router-auth"}, Image: image,
				Routes:  tnv1.GatewayRoutes{LAN: []tnv1.GatewayPrefix{"10.0.0.0/24"}},
				Service: tnv1.GatewayService{LoadBalancerIP: "10.1.0.53", TailnetLBCIDR: "10.1.0.0/24"},
				DNS:     tnv1.GatewayDNS{Zone: "tail.example", ServiceName: "tailnet-dns", ServiceClusterIP: "10.96.0.53", Image: image},
			},
		}
		raw, err := runtime.DefaultUnstructuredConverter.ToUnstructured(obj)
		must(err)
		return &unstructured.Unstructured{Object: raw}
	}
	set := func(o *unstructured.Unstructured, path string, value any) {
		must(unstructured.SetNestedField(o.Object, value, strings.Split(path, ".")...))
	}
	adoption := func() map[string]any {
		return map[string]any{"nodeId": "42", "objects": []any{
			map[string]any{"apiVersion": "apps/v1", "kind": "StatefulSet", "name": "gateway", "uid": "sts-uid"},
			map[string]any{"apiVersion": "v1", "kind": "Secret", "name": "router-state", "uid": "state-uid"},
		}}
	}
	forward := func(port, target int64) []any {
		return []any{map[string]any{"name": "api", "port": port, "targetAddress": "10.0.0.2", "targetPort": target}}
	}
	check := func(t *testing.T, o *unstructured.Unstructured, valid bool) {
		t.Helper()
		err := c.Create(ctx, o, client.DryRunAll)
		if valid && err != nil {
			t.Fatalf("valid gateway rejected: %v", err)
		}
		if !valid && !apierrors.IsInvalid(err) {
			t.Fatalf("want Invalid, got %v", err)
		}
	}
	t.Run("defaults", func(t *testing.T) {
		o := fresh()
		check(t, o, true)
		for path, want := range map[string]any{"suspend": true, "replicas": int64(1), "deletionPolicy": "Retain", "tags": []any{"tag:fabric"}, "authKeySecretRef.key": "TS_AUTHKEY", "routes.advertiseEgressTargets": true} {
			got, found, err := unstructured.NestedFieldNoCopy(o.Object, append([]string{"spec"}, strings.Split(path, ".")...)...)
			if err != nil || !found || !reflect.DeepEqual(got, want) {
				t.Errorf("default %s mismatch", path)
			}
		}
		o = fresh()
		set(o, "spec.routes.advertiseEgressTargets", false)
		check(t, o, true)
		got, _, err := unstructured.NestedBool(o.Object, "spec", "routes", "advertiseEgressTargets")
		if err != nil || got {
			t.Fatal("explicit false was not preserved")
		}
		o = fresh()
		unstructured.RemoveNestedField(o.Object, "spec", "authKeySecretRef")
		check(t, o, true)
	})
	t.Run("cname-static-records-admitted", func(t *testing.T) {
		for name, value := range map[string]any{
			"bare-label-within-zone": []any{map[string]any{"name": "k8s", "target": "ingress.tail.example"}},
			"nested-fqdn":            []any{map[string]any{"name": "talos", "target": "ingress-talos.other.tail.example"}},
			"apex-target":            []any{map[string]any{"name": "root", "target": "tail.example"}},
			"mixed-with-address":     []any{map[string]any{"name": "a", "address": "10.0.0.1"}, map[string]any{"name": "b", "target": "a.tail.example"}},
		} {
			t.Run(name, func(t *testing.T) {
				o := fresh()
				set(o, "spec.dns.staticRecords", value)
				check(t, o, true)
			})
		}
	})
	t.Run("explicit-activation", func(t *testing.T) {
		o := fresh()
		o.SetName("active-gateway")
		set(o, "spec.suspend", false)
		must(c.Create(ctx, o))
		t.Cleanup(func() { must(c.Delete(ctx, o)) })
		for _, suspend := range []bool{false, true, false} {
			set(o, "spec.suspend", suspend)
			must(c.Update(ctx, o))
			must(c.Get(ctx, client.ObjectKeyFromObject(o), o))
			got, found, err := unstructured.NestedBool(o.Object, "spec", "suspend")
			if err != nil || !found || got != suspend {
				t.Fatalf("explicit suspend=%t was not preserved", suspend)
			}
		}
	})
	t.Run("version-pinned-images", func(t *testing.T) {
		for _, pin := range []string{"ghcr.io/tailscale/tailscale:v1.102.4", "coredns/coredns:1.14.7", "example.invalid/socat:1.8.0.3-r2"} {
			o := fresh()
			set(o, "spec.image", pin)
			set(o, "spec.dns.image", pin)
			set(o, "spec.forwardImage", pin)
			check(t, o, true)
		}
		for _, pin := range []string{"example.invalid/router", "example.invalid/router:1", "example.invalid/router:stable"} {
			o := fresh()
			set(o, "spec.image", pin)
			check(t, o, false)
		}
	})
	t.Run("image-reference-syntax", func(t *testing.T) {
		for _, field := range []string{"image", "dns.image", "forwardImage"} {
			for _, pin := range []string{"registry.invalid/router:1.2.3:4.5.6", "registry.invalid/router/:1.2.3", "https://registry.invalid/router:v1.2.3", "registry.invalid//router:1.2.3", "registry.invalid:5000:6000/router:1.2.3", "registry.invalid/Team/router:1.2.3", strings.Repeat("a", 256) + ":1.2.3", "router:1.2.3-" + strings.Repeat("a", 123)} {
				o := fresh()
				set(o, "spec."+field, pin)
				check(t, o, false)
			}
			for _, pin := range []string{"localhost:5000/team/router:v1.2.3", "registry.invalid/team/router:1.2.3@sha256:" + strings.Repeat("a", 64), strings.Repeat("a", 255) + ":1.2.3", "router:1.2.3-" + strings.Repeat("a", 122)} {
				o := fresh()
				set(o, "spec."+field, pin)
				check(t, o, true)
			}
		}
	})
	t.Run("dns-record-length", func(t *testing.T) {
		for _, length := range []int{250, 251, 252, 253} {
			zone := strings.Repeat(strings.Repeat("a", 63)+".", 3) + strings.Repeat("b", length-192)
			for _, wildcard := range []bool{false, true} {
				o := fresh()
				set(o, "spec.dns.zone", zone)
				if wildcard {
					set(o, "spec.dns.wildcardAddress", "10.0.0.1")
				} else {
					set(o, "spec.dns.staticRecords", []any{map[string]any{"name": "a", "address": "10.0.0.1"}})
				}
				check(t, o, length <= 251)
			}
		}
	})
	t.Run("route-planner-parity", func(t *testing.T) {
		for _, prefix := range []string{"10.2.0.0/24", "2001:db8::/64", "fd00::/64", "169.254.0.0/16", "10.0.0.1/24", "0.0.0.0/0", "::/0", "::ffff:10.0.0.0/120", "224.0.0.0/4", "ff00::/8", "127.0.0.0/8", "::1/128", "126.0.0.0/7", "fe00::/7", "0.0.0.0/32", "::/128", "2001:0db8::/64", "not-a-cidr"} {
			for _, field := range []string{"LAN", "LB"} {
				t.Run(field+"/"+prefix, func(t *testing.T) {
					o := fresh()
					in := gateway.RouteInputs{LAN: []string{"10.0.0.0/24"}, LoadBalancerCIDR: "10.1.0.0/24"}
					if field == "LAN" {
						in.LAN = []string{prefix}
						set(o, "spec.routes.lan", []any{prefix})
					} else {
						in.LoadBalancerCIDR = prefix
						set(o, "spec.service.tailnetLBCIDR", prefix)
						if p, err := netip.ParsePrefix(prefix); err == nil {
							set(o, "spec.service.loadBalancerIP", p.Addr().Next().String())
						}
					}
					_, err := gateway.PlanRoutes(in)
					// Link-local routes are valid, but a link-local service IP is not.
					if field == "LB" && prefix == "169.254.0.0/16" {
						set(o, "spec.service.loadBalancerIP", "169.254.0.1")
						check(t, o, false)
						return
					}
					check(t, o, err == nil)
				})
			}
		}
		o := fresh()
		set(o, "spec.routes.lan", []any{"10.0.0.0/24", "2001:db8::/64"})
		set(o, "spec.dns.serviceClusterIP", "fd00::53")
		check(t, o, true)
		o = fresh()
		set(o, "spec.dns.extraZones", []any{map[string]any{"zone": "konzern.intern", "upstreams": []any{"10.0.0.1", "10.0.0.2"}}, map[string]any{"zone": "it.persona.de", "upstreams": []any{"10.0.0.3"}}})
		check(t, o, true)
	})
	for _, tc := range []struct {
		name, path string
		value      any
	}{
		{"invalid-pool-label", "service.poolLabels", map[string]any{"pool": "invalid/value"}},
		{"invalid-pool-key", "service.poolLabels", map[string]any{"invalid/key/again": "pool"}},
		{"dotted-dns-service", "dns.serviceName", "router.dns"},
		{"long-dns-service", "dns.serviceName", strings.Repeat("a", 64)},
		{"numeric-dns-service", "dns.serviceName", "1router-dns"}, {"invalid-class", "service.loadBalancerClass", "example.com/a/b"},
		{"replicas-zero", "replicas", int64(0)}, {"replicas-two", "replicas", int64(2)}, {"deletion-unknown", "deletionPolicy", "Orphan"},
		{"lb-outside", "service.loadBalancerIP", "10.2.0.53"}, {"lb-family", "service.loadBalancerIP", "fd00::53"}, {"empty-lan", "routes.lan", []any{}},
		{"dns-shell", "dns.zone", "tail.example;id"}, {"dns-upstream-shell", "dns.extraZones", []any{map[string]any{"zone": "extra.example", "upstreams": []any{"10.0.0.1;id"}}}},
		{"primary-overlap", "dns.extraZones", []any{map[string]any{"zone": "sub.tail.example", "upstreams": []any{"10.0.0.1"}}}},
		{"primary-parent", "dns.extraZones", []any{map[string]any{"zone": "example", "upstreams": []any{"10.0.0.1"}}}},
		{"extra-overlap", "dns.extraZones", []any{map[string]any{"zone": "extra.example", "upstreams": []any{"10.0.0.1"}}, map[string]any{"zone": "sub.extra.example", "upstreams": []any{"10.0.0.2"}}}},
		{"static-duplicates", "dns.staticRecords", []any{map[string]any{"name": "api", "address": "10.0.0.1"}, map[string]any{"name": "api", "address": "10.0.0.2"}}},
		{"static-shell", "dns.staticRecords", []any{map[string]any{"name": "api;id", "address": "10.0.0.1"}}},
		{"static-both-address-and-target", "dns.staticRecords", []any{map[string]any{"name": "a", "address": "10.0.0.1", "target": "x.tail.example"}}},
		{"static-neither-address-nor-target", "dns.staticRecords", []any{map[string]any{"name": "a"}}},
		{"static-target-out-of-zone", "dns.staticRecords", []any{map[string]any{"name": "a", "target": "x.other.example"}}},
		{"static-target-self-fqdn", "dns.staticRecords", []any{map[string]any{"name": "api", "target": "api.tail.example"}}},
		{"wildcard-shell", "dns.wildcardAddress", "10.0.0.1\nexec"}, {"service-collision", "dns.serviceName", "gateway"}, {"headless-collision", "dns.serviceName", "gateway-headless"},
		{"mutable-router-image", "image", "registry.invalid/router:latest"}, {"mutable-dns-image", "dns.image", "registry.invalid/dns:latest"}, {"mutable-forward-image", "forwardImage", "registry.invalid/forward:latest"},
		{"same-secret", "authKeySecretRef.name", "router-state"}, {"secret-shell", "stateSecretRef.name", "state;id"}, {"auth-key-shell", "authKeySecretRef.key", "KEY;id"},
		{"missing-forward-image", "forwards", forward(6443, 6443)}, {"empty-tags", "tags", []any{}}, {"bad-tag", "tags", []any{"tag:Bad"}},
	} {
		t.Run(tc.name, func(t *testing.T) { o := fresh(); set(o, "spec."+tc.path, tc.value); check(t, o, false) })
	}
	t.Run("forwards", func(t *testing.T) {
		for _, ports := range [][2]int64{{1, 65535}, {65535, 1}, {53, 80}, {8080, 80}, {8181, 80}, {9153, 80}, {0, 80}, {65536, 80}, {-1, 80}, {80, 0}, {80, 65536}} {
			o := fresh()
			set(o, "spec.forwardImage", string(image))
			set(o, "spec.forwards", forward(ports[0], ports[1]))
			check(t, o, ports[0] == 1 || ports[0] == 65535)
		}
		o := fresh()
		set(o, "spec.forwardImage", string(image))
		fs := forward(6443, 443)
		second := forward(6443, 8443)[0].(map[string]any)
		second["name"] = "other"
		set(o, "spec.forwards", append(fs, second))
		check(t, o, false)
		for _, address := range []string{"10.0.0.2;id", "TCP:10.0.0.2:443", "::ffff:10.0.0.2", "127.0.0.1"} {
			o = fresh()
			set(o, "spec.forwardImage", string(image))
			fs = forward(6443, 443)
			fs[0].(map[string]any)["targetAddress"] = address
			set(o, "spec.forwards", fs)
			check(t, o, false)
		}
	})
	t.Run("adoption-inventory", func(t *testing.T) {
		o := fresh()
		set(o, "spec.adoption", adoption())
		check(t, o, true)
		for _, mutation := range []func(map[string]any){
			func(a map[string]any) { a["objects"] = a["objects"].([]any)[:1] },
			func(a map[string]any) { a["objects"].([]any)[1].(map[string]any)["name"] = "wrong-state" },
			func(a map[string]any) { a["objects"].([]any)[0].(map[string]any)["name"] = "wrong-router" },
			func(a map[string]any) { a["objects"].([]any)[1].(map[string]any)["uid"] = "sts-uid" },
			func(a map[string]any) { a["objects"].([]any)[1].(map[string]any)["uid"] = "" },
			func(a map[string]any) { a["objects"].([]any)[0].(map[string]any)["kind"] = "Deployment" },
			func(a map[string]any) { a["objects"].([]any)[0].(map[string]any)["apiVersion"] = "apps/v2" },
			func(a map[string]any) {
				a["objects"] = append(a["objects"].([]any), map[string]any{"apiVersion": "v1", "kind": "Secret", "name": "router-state", "uid": "other-uid"})
			},
			func(a map[string]any) { a["nodeId"] = "0" },
		} {
			a := adoption()
			mutation(a)
			o = fresh()
			set(o, "spec.adoption", a)
			check(t, o, false)
		}
	})
	t.Run("storage-status-and-immutability", func(t *testing.T) {
		o := fresh()
		set(o, "spec.adoption", adoption())
		set(o, "spec.service.loadBalancerClass", "example.com/router")
		mapping, err := c.RESTMapper().RESTMapping(o.GroupVersionKind().GroupKind(), o.GroupVersionKind().Version)
		must(err)
		if mapping.Scope.Name() != meta.RESTScopeNameRoot {
			t.Fatal("gateway must be cluster scoped")
		}
		set(o, "status.nodeId", "ignored-on-create")
		must(c.Create(ctx, o))
		t.Cleanup(func() {
			if err := c.Delete(ctx, o); err != nil {
				t.Errorf("delete gateway: %v", err)
			}
		})
		stored := &tnv1.TailnetGateway{}
		key := client.ObjectKey{Name: o.GetName()}
		must(c.Get(ctx, key, stored))
		if stored.Namespace != "" || stored.Status.NodeID != "" {
			t.Fatal("cluster scope or status create isolation failed")
		}
		stored.Status.NodeID = "42"
		must(c.Status().Update(ctx, stored))
		must(c.Get(ctx, key, stored))
		if stored.Status.NodeID != "42" {
			t.Fatal("status subresource did not persist")
		}
		stored.Status.NodeID = "ignored-on-update"
		stored.Spec.Routes.LAN = []tnv1.GatewayPrefix{"10.2.0.0/24", "fd00::/64"}
		must(c.Update(ctx, stored))
		must(c.Get(ctx, key, stored))
		if stored.Status.NodeID != "42" || len(stored.Spec.Routes.LAN) != 2 {
			t.Fatal("routing update or status isolation failed")
		}
		must(c.Get(ctx, key, o))
		for path, value := range map[string]any{"tailnetRef.name": "other", "hostname": "other", "stateSecretRef.name": "other", "service.loadBalancerIP": "10.1.0.54", "dns.serviceName": "other-dns", "dns.serviceClusterIP": "10.96.0.54", "adoption.nodeId": "43", "service.loadBalancerClass": "example.com/other"} {
			copy := o.DeepCopy()
			set(copy, "spec."+path, value)
			if err := c.Update(ctx, copy); !apierrors.IsInvalid(err) {
				t.Errorf("immutable %s: want Invalid, got %v", path, err)
			}
		}
		copy := o.DeepCopy()
		unstructured.RemoveNestedField(copy.Object, "spec", "service", "loadBalancerClass")
		if err := c.Update(ctx, copy); !apierrors.IsInvalid(err) {
			t.Errorf("remove class: want Invalid, got %v", err)
		}
		copy = o.DeepCopy()
		unstructured.RemoveNestedField(copy.Object, "spec", "adoption")
		if err := c.Update(ctx, copy); !apierrors.IsInvalid(err) {
			t.Errorf("remove adoption: want Invalid, got %v", err)
		}
		copy = o.DeepCopy()
		a := adoption()
		a["objects"].([]any)[1].(map[string]any)["uid"] = "replacement-uid"
		set(copy, "spec.adoption", a)
		if err := c.Update(ctx, copy); !apierrors.IsInvalid(err) {
			t.Errorf("replace inventory: want Invalid, got %v", err)
		}
		plain := fresh()
		plain.SetName("plain")
		must(c.Create(ctx, plain))
		t.Cleanup(func() {
			if err := c.Delete(ctx, plain); err != nil {
				t.Errorf("delete plain gateway: %v", err)
			}
		})
		copy = plain.DeepCopy()
		set(copy, "spec.service.loadBalancerClass", "example.com/router")
		if err := c.Update(ctx, copy); !apierrors.IsInvalid(err) {
			t.Errorf("add class: want Invalid, got %v", err)
		}
		a = adoption()
		a["objects"].([]any)[0].(map[string]any)["name"] = "plain"
		set(plain, "spec.adoption", a)
		if err := c.Update(ctx, plain); !apierrors.IsInvalid(err) {
			t.Errorf("add adoption: want Invalid, got %v", err)
		}
		list := &tnv1.TailnetGatewayList{}
		must(c.List(ctx, list))
		if len(list.Items) != 2 {
			t.Fatal("typed gateway list registration failed")
		}
	})
}
