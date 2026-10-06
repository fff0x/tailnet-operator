package gateway

import (
	"context"
	"errors"
	"slices"
	"testing"
	"time"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/utils/ptr"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	tnv1 "tsunaro.io/tailnet-operator/api/v1alpha1"
)

func freshStatefulSet(t *testing.T) *appsv1.StatefulSet {
	t.Helper()
	plan, err := RenderFresh(freshFixture())
	if err != nil {
		t.Fatal(err)
	}
	for _, obj := range plan.Objects {
		if v, ok := obj.(*appsv1.StatefulSet); ok {
			return v
		}
	}
	t.Fatal("no StatefulSet rendered")
	return nil
}

// podTemplateHash must flip for every field UpdateWorkloadRevision rewrites, so a
// stale template never silently reports current. Changes outside the template
// (metadata, replicas) are handled by the receipt digest and are deliberately
// not covered here.
func TestPodTemplateHashDetectsTemplateDrift(t *testing.T) {
	sts := freshStatefulSet(t)
	base := podTemplateHash(sts.Spec.Template)
	for name, mutate := range map[string]func(*appsv1.StatefulSet){
		"tailscale image": func(s *appsv1.StatefulSet) {
			s.Spec.Template.Spec.Containers[0].Image = "ghcr.io/tailscale/tailscale:v1.102.5"
		},
		"coredns image": func(s *appsv1.StatefulSet) { s.Spec.Template.Spec.Containers[1].Image = "coredns/coredns:1.14.7" },
		"init image": func(s *appsv1.StatefulSet) {
			s.Spec.Template.Spec.InitContainers[0].Image = "ghcr.io/tailscale/tailscale:v1.102.5"
		},
		"env": func(s *appsv1.StatefulSet) { s.Spec.Template.Spec.Containers[0].Env[0].Value = "x" },
		"port": func(s *appsv1.StatefulSet) {
			s.Spec.Template.Spec.Containers[1].Ports = append(s.Spec.Template.Spec.Containers[1].Ports, corev1.ContainerPort{Name: "x", ContainerPort: 9999})
		},
		"labels": func(s *appsv1.StatefulSet) { s.Spec.Template.Labels["x"] = "y" },
	} {
		c := sts.DeepCopy()
		mutate(c)
		if podTemplateHash(c.Spec.Template) == base {
			t.Fatalf("%s drift escaped the template hash", name)
		}
	}
}

// The receipt digest binds every StatefulSet field EXCEPT spec.template, whose
// drift is tracked separately through the template hash + annotation. See
// TestPodTemplateHashDetectsTemplateDrift for the complementary coverage.
func TestObjectReceiptStatefulSetTemplateExcluded(t *testing.T) {
	sts := freshStatefulSet(t)
	base := objectReceipt(sts)
	for name, mutate := range map[string]func(*appsv1.StatefulSet){
		"image": func(s *appsv1.StatefulSet) {
			s.Spec.Template.Spec.Containers[0].Image = "ghcr.io/tailscale/tailscale:v1.102.5"
		},
		"env":   func(s *appsv1.StatefulSet) { s.Spec.Template.Spec.Containers[0].Env[0].Value = "x" },
		"ports": func(s *appsv1.StatefulSet) { s.Spec.Template.Spec.Containers[1].Ports = nil },
		"hostname": func(s *appsv1.StatefulSet) {
			for i, e := range s.Spec.Template.Spec.Containers[0].Env {
				if e.Name == "TS_HOSTNAME" {
					s.Spec.Template.Spec.Containers[0].Env[i].Value = "other"
				}
			}
		},
	} {
		c := sts.DeepCopy()
		mutate(c)
		if objectReceipt(c) != base {
			t.Fatalf("%s drift must stay out of the receipt digest", name)
		}
	}
	for name, mutate := range map[string]func(*appsv1.StatefulSet){
		"replicas": func(s *appsv1.StatefulSet) { s.Spec.Replicas = ptr.To(int32(2)) },
		"service":  func(s *appsv1.StatefulSet) { s.Spec.ServiceName = "other" },
		"strategy": func(s *appsv1.StatefulSet) { s.Spec.UpdateStrategy.Type = appsv1.RollingUpdateStatefulSetStrategyType },
		"selector": func(s *appsv1.StatefulSet) { s.Spec.Selector.MatchLabels["x"] = "y" },
	} {
		c := sts.DeepCopy()
		mutate(c)
		if objectReceipt(c) == base {
			t.Fatalf("%s drift escaped the receipt digest", name)
		}
	}
	if routes, ok := podRoutes(sts.Spec.Template.Spec); !ok || len(routes) != 4 {
		t.Fatalf("podRoutes = %v %v", routes, ok)
	}
}

func TestSpecRouteInputsScope(t *testing.T) {
	in := freshFixture()
	in.Egresses = append(in.Egresses,
		tnv1.TailnetEgress{ObjectMeta: metav1.ObjectMeta{Name: "other-ns", Namespace: "tenant"}, Spec: tnv1.TailnetEgressSpec{TailnetRef: tnv1.TailnetRef{Name: "tailnet"}, Targets: []tnv1.Target{{Name: "x", Address: "203.0.113.9", Port: 1}}}},
		tnv1.TailnetEgress{ObjectMeta: metav1.ObjectMeta{Name: "other-tn", Namespace: "operator"}, Spec: tnv1.TailnetEgressSpec{TailnetRef: tnv1.TailnetRef{Name: "lab"}, Targets: []tnv1.Target{{Name: "y", Address: "203.0.113.10", Port: 1}}}},
		tnv1.TailnetEgress{ObjectMeta: metav1.ObjectMeta{Name: "gone", Namespace: "operator", DeletionTimestamp: &metav1.Time{Time: time.Unix(1, 0)}}, Spec: tnv1.TailnetEgressSpec{TailnetRef: tnv1.TailnetRef{Name: "tailnet"}, Targets: []tnv1.Target{{Name: "z", Address: "203.0.113.11", Port: 1}}}})
	got := SpecRouteInputs(in.Gateway, "tailnet", "operator", in.Egresses)
	if !slices.Equal(got.EgressTargets, []string{"203.0.113.8", "2001:db8::8", "external.example"}) || !got.AdvertiseEgressTargets {
		t.Fatalf("egress targets = %v", got.EgressTargets)
	}
	off := in.Gateway.DeepCopy()
	off.Spec.Routes.AdvertiseEgressTargets = ptr.To(false)
	if got := SpecRouteInputs(off, "tailnet", "operator", in.Egresses); len(got.EgressTargets) != 0 {
		t.Fatal("egress targets used although advertiseEgressTargets is false")
	}
}

func TestPlanSpecRoutes(t *testing.T) {
	s := runtime.NewScheme()
	_ = tnv1.AddToScheme(s)
	in := freshFixture()
	in.Egresses[0].Spec.Targets = in.Egresses[0].Spec.Targets[:1] // IPv4 target only
	c := fake.NewClientBuilder().WithScheme(s).WithObjects(&in.Egresses[0]).Build()
	plan, err := PlanSpecRoutes(context.Background(), c, "operator", in.Gateway)
	if err != nil || !slices.Equal(plan.Routes, []string{"192.0.2.0/24", "198.51.100.0/24", "203.0.113.8/32"}) {
		t.Fatalf("plan = %v, %v", plan.Routes, err)
	}
	for name, mutate := range map[string]func(*tnv1.TailnetGateway){
		"lb cidr without lb ip": func(g *tnv1.TailnetGateway) { g.Spec.Service.TailnetLBCIDR = "198.51.0.0/24" },
		"ipv6 lan":              func(g *tnv1.TailnetGateway) { g.Spec.Routes.LAN = []tnv1.GatewayPrefix{"2001:db8::/64"} },
		"invalid lan":           func(g *tnv1.TailnetGateway) { g.Spec.Routes.LAN = []tnv1.GatewayPrefix{"10.0.0.1/24"} },
	} {
		g := in.Gateway.DeepCopy()
		mutate(g)
		if _, err := PlanSpecRoutes(context.Background(), c, "operator", g); err == nil {
			t.Fatalf("%s planned", name)
		}
	}
}

func TestUpdateServiceRevision(t *testing.T) {
	s := runtime.NewScheme()
	_ = corev1.AddToScheme(s)
	in := freshFixture()
	plan, err := RenderFresh(in)
	if err != nil {
		t.Fatal(err)
	}
	var lb *corev1.Service
	for _, obj := range plan.Objects {
		if v, ok := obj.(*corev1.Service); ok && v.Name == "router" {
			lb = v
		}
	}
	lb.UID, lb.ResourceVersion = "lb-uid", ""
	if lb.Annotations[PoolLabelKeysAnnotation] != "example.com/pool" {
		t.Fatal("renderer did not record the pool label keys")
	}
	obs := FreshObservation{Completed: true, service: objectReceipt(lb)}
	c := fake.NewClientBuilder().WithScheme(s).WithObjects(lb).Build()
	get := func() *corev1.Service {
		v := &corev1.Service{}
		if err := c.Get(context.Background(), client.ObjectKeyFromObject(lb), v); err != nil {
			t.Fatal(err)
		}
		return v
	}
	run := func(g *tnv1.TailnetGateway) error {
		return UpdateServiceRevision(context.Background(), c, "operator", g, obs)
	}
	g := in.Gateway.DeepCopy()
	rv := get().ResourceVersion
	if err := run(g); err != nil || get().ResourceVersion != rv {
		t.Fatalf("unchanged spec wrote: %v", err)
	}
	// change a value, add a key
	g.Spec.Service.PoolLabels = map[string]tnv1.GatewayLabelValue{"example.com/pool": "other", "zone": "a"}
	if err := run(g); err != nil {
		t.Fatal(err)
	}
	if v := get(); v.Labels["example.com/pool"] != "other" || v.Labels["zone"] != "a" || v.Annotations[PoolLabelKeysAnnotation] != "example.com/pool,zone" || v.Labels["app.kubernetes.io/managed-by"] == "" {
		t.Fatalf("labels after change = %v %v", v.Labels, v.Annotations)
	}
	// remove: only owned keys go, base labels stay
	g.Spec.Service.PoolLabels = nil
	if err := run(g); err != nil {
		t.Fatal(err)
	}
	if v := get(); v.Labels["zone"] != "" || v.Labels["example.com/pool"] != "" || v.Labels["app.kubernetes.io/managed-by"] == "" || v.Annotations[PoolLabelKeysAnnotation] != "" {
		t.Fatalf("labels after removal = %v %v", v.Labels, v.Annotations)
	}
	// collision with a label we did not write, even with the same value
	for _, v := range []tnv1.GatewayLabelValue{"someone-else", "tailnet-operator"} {
		g.Spec.Service.PoolLabels = map[string]tnv1.GatewayLabelValue{"app.kubernetes.io/managed-by": v}
		if err := run(g); !errors.Is(err, ErrServiceBlocked) {
			t.Fatalf("collision = %v", err)
		}
	}
	// wrong UID in the receipt
	obs.service.UID = "different"
	g.Spec.Service.PoolLabels = nil
	if err := run(g); !errors.Is(err, ErrServiceBlocked) {
		t.Fatalf("uid mismatch = %v", err)
	}
}

func TestUpdateWorkloadRevision(t *testing.T) {
	s := runtime.NewScheme()
	_ = corev1.AddToScheme(s)
	_ = appsv1.AddToScheme(s)
	in := freshFixture()
	plan, err := RenderFresh(in)
	if err != nil {
		t.Fatal(err)
	}
	var sts *appsv1.StatefulSet
	for _, obj := range plan.Objects {
		if v, ok := obj.(*appsv1.StatefulSet); ok {
			sts = v
		}
	}
	sts.UID = "sts-uid"
	// Simulate a running gateway created before this release: the template-hash
	// annotation is absent and the template has stale image + routes. The receipt
	// digest excludes the template, so the write path still verifies it.
	stale := sts.DeepCopy()
	stale.Spec.Template.Spec.Containers[0].Image = "ghcr.io/tailscale/tailscale:v1.100.0"
	for i, e := range stale.Spec.Template.Spec.Containers[0].Env {
		if e.Name == "TS_ROUTES" {
			stale.Spec.Template.Spec.Containers[0].Env[i].Value = "10.0.0.0/16"
		}
	}
	delete(stale.Annotations, GatewayTemplateHashAnnotation)
	receipt := objectReceipt(stale) // template is blanked, so this matches sts even if we rendered them differently
	obs := FreshObservation{Completed: true, workload: receipt}
	c := fake.NewClientBuilder().WithScheme(s).WithObjects(stale).Build()
	get := func() *appsv1.StatefulSet {
		v := &appsv1.StatefulSet{}
		if err := c.Get(context.Background(), client.ObjectKeyFromObject(stale), v); err != nil {
			t.Fatal(err)
		}
		return v
	}
	routes := []string{"192.0.2.0/24", "198.51.100.0/24"}
	// First reconcile writes the full template + annotation.
	if err := UpdateWorkloadRevision(context.Background(), c, "operator", in.Gateway, in.Tailnet, obs, routes); err != nil {
		t.Fatalf("initial write: %v", err)
	}
	after := get()
	if after.Annotations[GatewayTemplateHashAnnotation] == "" {
		t.Fatal("template hash annotation missing after write")
	}
	if after.Spec.Template.Spec.Containers[0].Image != string(in.Gateway.Spec.Image) {
		t.Fatal("tailscale image not updated")
	}
	if got, _ := podRoutes(after.Spec.Template.Spec); !slices.Equal(got, routes) {
		t.Fatalf("TS_ROUTES after write = %v", got)
	}
	hasMetrics, hasDNSMetricsPort := false, false
	for _, e := range after.Spec.Template.Spec.Containers[0].Env {
		if e.Name == "TS_ENABLE_METRICS" && e.Value == "true" {
			hasMetrics = true
		}
	}
	for _, p := range after.Spec.Template.Spec.Containers[1].Ports {
		if p.Name == "metrics-dns" && p.ContainerPort == 9153 {
			hasDNSMetricsPort = true
		}
	}
	if !hasMetrics || !hasDNSMetricsPort {
		t.Fatalf("metrics env/port missing: metrics=%v dns-port=%v", hasMetrics, hasDNSMetricsPort)
	}
	rv1 := after.ResourceVersion
	// Receipt still matches after our template rewrite (template excluded from digest).
	obs.workload = objectReceipt(after)
	// Second reconcile is a no-op (annotation + hash match).
	if err := UpdateWorkloadRevision(context.Background(), c, "operator", in.Gateway, in.Tailnet, obs, routes); err != nil {
		t.Fatal(err)
	}
	if get().ResourceVersion != rv1 {
		t.Fatal("no-op reconcile wrote the StatefulSet")
	}
	// A route change triggers one more write.
	newRoutes := []string{"192.0.2.0/24", "198.51.100.0/24", "203.0.113.8/32"}
	if err := UpdateWorkloadRevision(context.Background(), c, "operator", in.Gateway, in.Tailnet, obs, newRoutes); err != nil {
		t.Fatal(err)
	}
	after2 := get()
	if after2.ResourceVersion == rv1 {
		t.Fatal("route change did not write")
	}
	if got, _ := podRoutes(after2.Spec.Template.Spec); !slices.Equal(got, newRoutes) {
		t.Fatalf("TS_ROUTES after route bump = %v", got)
	}
	// UID mismatch is blocked.
	badObs := obs
	badObs.workload.UID = "other"
	if err := UpdateWorkloadRevision(context.Background(), c, "operator", in.Gateway, in.Tailnet, badObs, routes); !errors.Is(err, ErrWorkloadBlocked) {
		t.Fatalf("uid mismatch = %v", err)
	}
	// nil tailnet is blocked.
	if err := UpdateWorkloadRevision(context.Background(), c, "operator", in.Gateway, nil, obs, routes); !errors.Is(err, ErrWorkloadBlocked) {
		t.Fatalf("nil tailnet = %v", err)
	}
}
