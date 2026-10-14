//go:build integration

package validation

import (
	"context"
	"encoding/json"
	"slices"
	"strings"
	"testing"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/utils/ptr"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"

	tnv1 "tsunaro.io/tailnet-operator/api/v1alpha1"
	"tsunaro.io/tailnet-operator/internal/gateway"
	"tsunaro.io/tailnet-operator/internal/headscale"
)

// Spec updates on a completed fresh set: identity stays pinned, everything
// else keeps Ready, and the Pod template follows the spec without the operator
// ever restarting a Pod. The Pod, kubelet and StatefulSet controller are synthetic.
func gatewayUpdateCases(t *testing.T, newFixture func(*testing.T, bool) *gatewayWriterFixture, admin client.Client, ctx context.Context) {
	// ready drives a fixture to FreshRuntimeReady with a synthetic Pod.
	ready := func(t *testing.T) (*gatewayWriterFixture, headscale.Node) {
		t.Helper()
		f := newFixture(t, false)
		f.reconcile("Provisioning")
		f.assertComplete()
		node := f.seedSyntheticState()
		f.hs.setNodes([]headscale.Node{node})
		f.createSyntheticReadyPod()
		f.reconcile("FreshRuntimeReady")
		return f, node
	}
	update := func(t *testing.T, f *gatewayWriterFixture, mutate func(*tnv1.TailnetGateway)) {
		t.Helper()
		gatewayWriterMust(t, admin.Get(ctx, client.ObjectKeyFromObject(f.g), f.g), "read gateway")
		mutate(f.g)
		gatewayWriterMust(t, admin.Update(ctx, f.g), "update gateway spec")
	}
	workload := func(t *testing.T, f *gatewayWriterFixture, status metav1.ConditionStatus, reason string) {
		t.Helper()
		c := meta.FindStatusCondition(f.g.Status.Conditions, "WorkloadCurrent")
		if c == nil || c.Status != status || c.Reason != reason {
			t.Fatalf("WorkloadCurrent mismatch: want %s/%s", status, reason)
		}
	}
	rolePod := func(t *testing.T, f *gatewayWriterFixture) {
		t.Helper()
		pod := &corev1.Pod{}
		f.get(f.g.Name+"-0", pod)
		gatewayWriterMust(t, admin.Delete(ctx, pod, client.GracePeriodSeconds(0)), "delete Pod as the synthetic StatefulSet controller would")
		f.createSyntheticReadyPod()
	}

	t.Run("deletionPolicy flips on a running gateway keep Ready", func(t *testing.T) {
		f, _ := ready(t)
		update(t, f, func(g *tnv1.TailnetGateway) { g.Spec.DeletionPolicy = tnv1.GatewayDeletionPolicyDelete })
		f.reconcile("FreshRuntimeReady")
		if !controllerutil.ContainsFinalizer(f.g, gateway.TeardownFinalizer) {
			t.Fatal("Delete consent did not record the teardown finalizer")
		}
		update(t, f, func(g *tnv1.TailnetGateway) { g.Spec.DeletionPolicy = tnv1.GatewayDeletionPolicyRetain })
		f.reconcile("FreshRuntimeReady")
		if controllerutil.ContainsFinalizer(f.g, gateway.TeardownFinalizer) {
			t.Fatal("Retain did not release the teardown finalizer")
		}
		f.assertMints(1)
	})

	t.Run("suspend round trip does not brick the gateway", func(t *testing.T) {
		f, _ := ready(t)
		update(t, f, func(g *tnv1.TailnetGateway) { g.Spec.Suspend = ptr.To(true) })
		f.reconcile("Suspended")
		if c := meta.FindStatusCondition(f.g.Status.Conditions, "WorkloadCurrent"); c == nil || c.Status != metav1.ConditionUnknown || c.Reason != "Suspended" {
			t.Fatalf("suspended gateway must report WorkloadCurrent=Unknown/Suspended, got %+v", c)
		}
		update(t, f, func(g *tnv1.TailnetGateway) { g.Spec.Suspend = ptr.To(false) })
		f.reconcile("FreshRuntimeReady")
		f.assertMints(1)
	})

	for _, field := range []string{"image", "dns.image"} {
		t.Run(field+" bump follows into the template, never restarts the Pod", func(t *testing.T) {
			f, _ := ready(t)
			workload(t, f, metav1.ConditionTrue, "PodCurrent")
			receipt := &corev1.ConfigMap{}
			f.get(f.g.Name+"-fresh", receipt)
			sts := &appsv1.StatefulSet{}
			f.get(f.g.Name, sts)
			oldPod := &corev1.Pod{}
			f.get(f.g.Name+"-0", oldPod)
			next := tnv1.GatewayImage("registry.invalid/next/component:v9.9.9")
			update(t, f, func(g *tnv1.TailnetGateway) {
				if field == "image" {
					g.Spec.Image = next
				} else {
					g.Spec.DNS.Image = next
				}
			})
			f.reconcile("FreshRuntimeReady")
			workload(t, f, metav1.ConditionFalse, "PodTemplateStale")
			bumped := &appsv1.StatefulSet{}
			f.get(f.g.Name, bumped)
			index := 0
			if field == "dns.image" {
				index = 1
			}
			if bumped.Spec.Template.Spec.Containers[index].Image != string(next) {
				t.Fatal("StatefulSet template did not follow the spec")
			}
			if field == "image" && bumped.Spec.Template.Spec.InitContainers[0].Image != string(next) {
				t.Fatal("kernel-preflight image did not follow the spec")
			}
			after := &corev1.ConfigMap{}
			f.get(f.g.Name+"-fresh", after)
			samePod := &corev1.Pod{}
			f.get(f.g.Name+"-0", samePod)
			if after.ResourceVersion != receipt.ResourceVersion || samePod.UID != oldPod.UID || bumped.UID != sts.UID {
				t.Fatal("update rewrote the receipt or replaced the Pod/StatefulSet")
			}
			rv := bumped.ResourceVersion
			f.reconcile("FreshRuntimeReady") // Idempotent: no further template writes.
			f.get(f.g.Name, bumped)
			if bumped.ResourceVersion != rv {
				t.Fatal("template writer looped")
			}
			rolePod(t, f)
			f.reconcile("FreshRuntimeReady")
			workload(t, f, metav1.ConditionTrue, "PodCurrent")
			f.assertMints(1)
		})
	}

	t.Run("static records flow live without touching the workload", func(t *testing.T) {
		f, _ := ready(t)
		sts := &appsv1.StatefulSet{}
		f.get(f.g.Name, sts)
		update(t, f, func(g *tnv1.TailnetGateway) {
			g.Spec.DNS.StaticRecords = []tnv1.GatewayStaticRecord{{Name: "printer", Address: "198.51.100.8"}}
		})
		f.reconcile("FreshRuntimeReady")
		cm := &corev1.ConfigMap{}
		f.get(f.g.Name+"-coredns", cm)
		if cm.Annotations["tsunaro.io/dns-serial"] != "2" || !strings.Contains(cm.Data["zone.db"], "printer") {
			t.Fatal("static record did not reach the derived zone")
		}
		if dns := meta.FindStatusCondition(f.g.Status.Conditions, "DNSReady"); dns == nil || dns.Status != metav1.ConditionTrue {
			t.Fatal("DNSReady is not True after a static record change")
		}
		again := &appsv1.StatefulSet{}
		f.get(f.g.Name, again)
		if again.ResourceVersion != sts.ResourceVersion {
			t.Fatal("DNS change touched the StatefulSet")
		}
	})

	t.Run("RoutesInSync reports approvals from the node (the fake Headscale fails on any unexpected write)", func(t *testing.T) {
		f, node := ready(t)
		routes := func() *metav1.Condition {
			gatewayWriterMust(t, admin.Get(ctx, client.ObjectKeyFromObject(f.g), f.g), "read gateway")
			return meta.FindStatusCondition(f.g.Status.Conditions, "RoutesInSync")
		}
		// Nothing approved, Tailnet without policy ownership: the hint names the manual path.
		c := routes()
		if c == nil || c.Status != metav1.ConditionFalse || c.Reason != "NotApproved" || !strings.Contains(c.Message, "192.0.2.0/24, 198.51.100.0/24") || !strings.Contains(c.Message, "approve-routes") {
			t.Fatalf("RoutesInSync = %+v", c)
		}
		// Only one of the two approved: the missing one is named, the approved one is not.
		node.ApprovedRoutes = []string{"198.51.100.0/24"}
		f.hs.setNodes([]headscale.Node{node})
		f.reconcile("FreshRuntimeReady")
		if c := routes(); c.Status != metav1.ConditionFalse || !strings.HasPrefix(c.Message, "Advertised but not approved: 192.0.2.0/24. ") {
			t.Fatalf("partial approval = %+v", c)
		}
		// Policy-owned Tailnet: the hint points at the policy controller instead.
		gatewayWriterMust(t, admin.Get(ctx, client.ObjectKeyFromObject(f.tn), f.tn), "read Tailnet")
		f.tn.Spec.Policy = tnv1.PolicySpec{BaseConfigMap: "policy", Mode: "Apply", TagOwners: []string{"group:operator"}, RouteApprovers: []string{"tag:fabric"}}
		gatewayWriterMust(t, admin.Update(ctx, f.tn), "make the Tailnet own its policy")
		f.reconcile("FreshRuntimeReady")
		if c := routes(); !strings.Contains(c.Message, "policy controller approves") {
			t.Fatalf("policy-owned hint = %+v", c)
		}
		node.ApprovedRoutes = []string{"192.0.2.0/24", "198.51.100.0/24"}
		f.hs.setNodes([]headscale.Node{node})
		f.reconcile("FreshRuntimeReady")
		if c := routes(); c.Status != metav1.ConditionTrue || c.Reason != "Approved" {
			t.Fatalf("all approved = %+v", c)
		}
	})

	stsRoutes := func(t *testing.T, f *gatewayWriterFixture) []string {
		t.Helper()
		sts := &appsv1.StatefulSet{}
		f.get(f.g.Name, sts)
		for _, c := range sts.Spec.Template.Spec.Containers {
			if c.Name == "tailscale" {
				for _, e := range c.Env {
					if e.Name == "TS_ROUTES" {
						return strings.Split(e.Value, ",")
					}
				}
			}
		}
		t.Fatal("StatefulSet has no TS_ROUTES")
		return nil
	}

	t.Run("routes follow the spec into the template, Pod untouched until it restarts", func(t *testing.T) {
		f, node := ready(t)
		oldPod := &corev1.Pod{}
		f.get(f.g.Name+"-0", oldPod)
		update(t, f, func(g *tnv1.TailnetGateway) { g.Spec.Routes.LAN = append(g.Spec.Routes.LAN, "10.9.0.0/16") })
		f.reconcile("FreshRuntimeReady") // The running Pod still advertises what it started with.
		workload(t, f, metav1.ConditionFalse, "PodTemplateStale")
		if c := meta.FindStatusCondition(f.g.Status.Conditions, "WorkloadCurrent"); !strings.Contains(c.Message, "10.9.0.0/16") {
			t.Fatalf("stale message does not name the route: %s", c.Message)
		}
		if got := stsRoutes(t, f); !slices.Contains(got, "10.9.0.0/16") || len(got) != 3 {
			t.Fatalf("template routes = %v", got)
		}
		samePod := &corev1.Pod{}
		f.get(f.g.Name+"-0", samePod)
		if samePod.UID != oldPod.UID {
			t.Fatal("route update replaced the Pod")
		}
		sts := &appsv1.StatefulSet{}
		f.get(f.g.Name, sts)
		f.reconcile("FreshRuntimeReady") // Idempotent.
		again := &appsv1.StatefulSet{}
		f.get(f.g.Name, again)
		if again.ResourceVersion != sts.ResourceVersion {
			t.Fatal("route writer looped")
		}
		// Fail closed: the node advertises the new set but the Pod was not restarted.
		node.AvailableRoutes = []string{"10.9.0.0/16", "192.0.2.0/24", "198.51.100.0/24"}
		f.hs.setNodes([]headscale.Node{node})
		f.reconcile("Provisioning")
		// The restarted Pod carries the new template; node and Pod agree again.
		rolePod(t, f)
		f.reconcile("FreshRuntimeReady")
		workload(t, f, metav1.ConditionTrue, "PodCurrent")
		f.assertMints(1)
		// Reverting the spec removes the route from the template; the Pod keeps it until restart.
		update(t, f, func(g *tnv1.TailnetGateway) { g.Spec.Routes.LAN = g.Spec.Routes.LAN[:1] })
		f.reconcile("FreshRuntimeReady")
		workload(t, f, metav1.ConditionFalse, "PodTemplateStale")
		if got := stsRoutes(t, f); len(got) != 2 {
			t.Fatalf("template routes after revert = %v", got)
		}
	})

	t.Run("egress targets are planned into the template and advertiseEgressTargets=false removes them", func(t *testing.T) {
		f, _ := ready(t)
		eg := &tnv1.TailnetEgress{ObjectMeta: metav1.ObjectMeta{Name: "db", Namespace: f.ns}, Spec: tnv1.TailnetEgressSpec{
			TailnetRef: tnv1.TailnetRef{Name: f.tn.Name}, ConsumerNamespaces: []string{f.ns}, Targets: []tnv1.Target{{Name: "db", Address: "203.0.113.8", Port: 5432}}}}
		gatewayWriterMust(t, admin.Create(ctx, eg), "create egress")
		f.reconcile("FreshRuntimeReady")
		workload(t, f, metav1.ConditionFalse, "PodTemplateStale")
		if got := stsRoutes(t, f); !slices.Contains(got, "203.0.113.8/32") {
			t.Fatalf("egress target not planned: %v", got)
		}
		update(t, f, func(g *tnv1.TailnetGateway) { g.Spec.Routes.AdvertiseEgressTargets = ptr.To(false) })
		f.reconcile("FreshRuntimeReady")
		if got := stsRoutes(t, f); slices.Contains(got, "203.0.113.8/32") || len(got) != 2 {
			t.Fatalf("egress target still planned: %v", got)
		}
		workload(t, f, metav1.ConditionTrue, "PodCurrent")
	})

	t.Run("poolLabels follow into the LB Service, same Service, foreign labels survive, collisions block", func(t *testing.T) {
		f, _ := ready(t)
		svc := &corev1.Service{}
		f.get(f.g.Name, svc)
		uid := svc.UID
		// Pick one of the operator's own base label keys, skipping any pool key the
		// gateway already owns (the fixture seeds one): hijacking a base key is a
		// render-time block, hijacking a pool key is a normal, allowed update.
		var baseKey string
		for k := range svc.Labels {
			if _, pool := f.g.Spec.Service.PoolLabels[k]; pool {
				continue
			}
			baseKey = k
			break
		}
		svc.Labels["foreign.example/keep"] = "yes"
		gatewayWriterMust(t, admin.Update(ctx, svc), "add a foreign label")
		check := func(want map[string]string) {
			t.Helper()
			got := &corev1.Service{}
			f.get(f.g.Name, got)
			if got.UID != uid || got.Labels["foreign.example/keep"] != "yes" {
				t.Fatal("Service was replaced or lost a foreign label")
			}
			for k, v := range want {
				if got.Labels[k] != v {
					t.Fatalf("label %s = %q, want %q", k, got.Labels[k], v)
				}
			}
			if _, ok := want["pool"]; !ok {
				if _, has := got.Labels["pool"]; has {
					t.Fatal("removed pool label is still set")
				}
			}
		}
		update(t, f, func(g *tnv1.TailnetGateway) {
			g.Spec.Service.PoolLabels = map[string]tnv1.GatewayLabelValue{"pool": "e2e"}
		})
		f.reconcile("FreshRuntimeReady")
		check(map[string]string{"pool": "e2e"})
		update(t, f, func(g *tnv1.TailnetGateway) {
			g.Spec.Service.PoolLabels = map[string]tnv1.GatewayLabelValue{"pool": "blue"}
		})
		f.reconcile("FreshRuntimeReady")
		check(map[string]string{"pool": "blue"})
		update(t, f, func(g *tnv1.TailnetGateway) { g.Spec.Service.PoolLabels = nil })
		f.reconcile("FreshRuntimeReady")
		check(nil)
		workload(t, f, metav1.ConditionTrue, "PodCurrent")
		// A pool key somebody else already put on the Service is refused, even with the same value,
		// and the refusal does not stall the template (routes still flow).
		update(t, f, func(g *tnv1.TailnetGateway) {
			g.Spec.Service.PoolLabels = map[string]tnv1.GatewayLabelValue{"foreign.example/keep": "yes"}
			g.Spec.Routes.LAN = append(g.Spec.Routes.LAN, "10.9.0.0/16")
		})
		before := &corev1.Service{}
		f.get(f.g.Name, before)
		f.reconcile("FreshRuntimeReady")
		workload(t, f, metav1.ConditionFalse, "ServiceUpdateBlocked")
		after := &corev1.Service{}
		f.get(f.g.Name, after)
		if after.ResourceVersion != before.ResourceVersion || after.Labels["foreign.example/keep"] != "yes" {
			t.Fatal("collision still wrote the Service")
		}
		if got := stsRoutes(t, f); !slices.Contains(got, "10.9.0.0/16") {
			t.Fatalf("blocked Service stalled the template: %v", got)
		}
		// A key of the operator's own base labels is refused when the plan is rendered.
		update(t, f, func(g *tnv1.TailnetGateway) {
			g.Spec.Service.PoolLabels = map[string]tnv1.GatewayLabelValue{baseKey: "hijack"}
		})
		f.reconcile("FreshBlocked")
		update(t, f, func(g *tnv1.TailnetGateway) {
			g.Spec.Service.PoolLabels, g.Spec.Routes.LAN = nil, g.Spec.Routes.LAN[:1]
		})
		f.reconcile("FreshRuntimeReady")
		workload(t, f, metav1.ConditionTrue, "PodCurrent")
		f.assertMints(1)
	})

	t.Run("tailnet side fields are tolerated, server is pinned", func(t *testing.T) {
		f, _ := ready(t)
		gatewayWriterMust(t, admin.Get(ctx, client.ObjectKeyFromObject(f.tn), f.tn), "read Tailnet")
		f.tn.Spec.APIKeyLifetime.Duration *= 2
		gatewayWriterMust(t, admin.Update(ctx, f.tn), "change unrelated Tailnet field")
		f.reconcile("FreshRuntimeReady")
		old := f.tn.Spec.Server
		f.tn.Spec.Server = "https://other.example"
		gatewayWriterMust(t, admin.Update(ctx, f.tn), "change pinned Tailnet server")
		f.reconcile("IdentityChanged")
		f.tn.Spec.Server = old
		gatewayWriterMust(t, admin.Update(ctx, f.tn), "restore Tailnet server")
		f.reconcile("FreshRuntimeReady")
	})

	t.Run("bound StatefulSet drift blocks without a write", func(t *testing.T) {
		// Fields outside spec.template (replicas, selector, service, strategy)
		// are bound by the completion receipt digest, so foreign drift there
		// blocks the fresh set. The Pod template itself is reconciled live
		// through UpdateWorkloadRevision which keys off an operator-written
		// annotation; a foreign actor that bypasses the annotation is out of
		// scope (receipt-bound fields are the trust boundary).
		f, _ := ready(t)
		sts := &appsv1.StatefulSet{}
		f.get(f.g.Name, sts)
		sts.Spec.Replicas = ptr.To(int32(2))
		gatewayWriterMust(t, admin.Update(ctx, sts), "drift bound StatefulSet replicas as a foreign actor")
		rv := sts.ResourceVersion
		f.reconcile("FreshBlocked")
		f.get(f.g.Name, sts)
		if sts.ResourceVersion != rv {
			t.Fatal("operator wrote a StatefulSet with replicas drift")
		}
	})

	for _, old := range []string{"1", "2"} {
		t.Run("a format "+old+" receipt is reported as IdentityChanged", func(t *testing.T) {
			f := newFixture(t, false)
			f.reconcile("Provisioning")
			f.assertComplete()
			cm := &corev1.ConfigMap{}
			f.get(f.g.Name+"-fresh", cm)
			var receipt map[string]any
			gatewayWriterMust(t, json.Unmarshal([]byte(cm.Data["receipt.json"]), &receipt), "decode receipt")
			receipt["scope"].(map[string]any)["format"] = old
			raw, err := json.Marshal(receipt)
			gatewayWriterMust(t, err, "encode legacy receipt")
			legacy := &corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Name: cm.Name, Namespace: cm.Namespace, Labels: cm.Labels}, Immutable: ptr.To(true), Data: map[string]string{"receipt.json": string(raw)}}
			gatewayWriterMust(t, admin.Delete(ctx, cm), "remove current receipt as test admin")
			gatewayWriterMust(t, admin.Create(ctx, legacy), "install legacy-format receipt")
			f.reconcile("IdentityChanged")
		})
	}
}
