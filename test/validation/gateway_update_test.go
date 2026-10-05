//go:build integration

package validation

import (
	"context"
	"encoding/json"
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
		if meta.FindStatusCondition(f.g.Status.Conditions, "WorkloadCurrent") != nil {
			t.Fatal("suspended gateway kept a stale WorkloadCurrent")
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

	t.Run("pinned routes report IdentityChanged and recover on revert", func(t *testing.T) {
		f, _ := ready(t)
		update(t, f, func(g *tnv1.TailnetGateway) { g.Spec.Routes.LAN = append(g.Spec.Routes.LAN, "10.9.0.0/16") })
		before, writes := f.snapshot(), f.writes.writes
		f.reconcile("IdentityChanged")
		f.reconcile("IdentityChanged")
		f.assertUnchanged(before, writes)
		update(t, f, func(g *tnv1.TailnetGateway) { g.Spec.Routes.LAN = g.Spec.Routes.LAN[:1] })
		f.reconcile("FreshRuntimeReady")
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

	t.Run("drift beyond images and bound StatefulSet drift both block without a write", func(t *testing.T) {
		for _, drift := range []string{"template env", "replicas"} {
			f, _ := ready(t)
			sts := &appsv1.StatefulSet{}
			f.get(f.g.Name, sts)
			if drift == "replicas" {
				sts.Spec.Replicas = ptr.To(int32(2))
			} else {
				sts.Spec.Template.Spec.Containers[0].Env[0].Value = "drifted"
			}
			gatewayWriterMust(t, admin.Update(ctx, sts), "drift the StatefulSet as a foreign actor")
			rv := sts.ResourceVersion
			f.reconcile("FreshBlocked")
			f.get(f.g.Name, sts)
			if sts.ResourceVersion != rv {
				t.Fatalf("operator wrote a StatefulSet with %s drift", drift)
			}
		}
	})

	t.Run("a format 1 receipt is reported as IdentityChanged", func(t *testing.T) {
		f := newFixture(t, false)
		f.reconcile("Provisioning")
		f.assertComplete()
		cm := &corev1.ConfigMap{}
		f.get(f.g.Name+"-fresh", cm)
		var receipt map[string]any
		gatewayWriterMust(t, json.Unmarshal([]byte(cm.Data["receipt.json"]), &receipt), "decode receipt")
		receipt["scope"].(map[string]any)["format"] = "1"
		raw, err := json.Marshal(receipt)
		gatewayWriterMust(t, err, "encode legacy receipt")
		legacy := &corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Name: cm.Name, Namespace: cm.Namespace, Labels: cm.Labels}, Immutable: ptr.To(true), Data: map[string]string{"receipt.json": string(raw)}}
		gatewayWriterMust(t, admin.Delete(ctx, cm), "remove current receipt as test admin")
		gatewayWriterMust(t, admin.Create(ctx, legacy), "install legacy-format receipt")
		f.reconcile("IdentityChanged")
	})
}
