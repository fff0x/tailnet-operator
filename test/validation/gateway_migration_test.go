//go:build integration

package validation

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"strings"
	"testing"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/utils/ptr"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"tsunaro.io/tailnet-operator/internal/headscale"
)

// v0100LegacyDigest is an INDEPENDENT reimplementation of the v0.10.0 receipt
// digest rule (blank container images + tailscale TS_ROUTES on the StatefulSet,
// blank only zone.db on the -coredns ConfigMap). It exists so the migration
// tests do not depend on the operator's own shim to produce the legacy input.
func v0100LegacyDigest(t *testing.T, obj client.Object) string {
	t.Helper()
	b, err := json.Marshal(obj)
	gatewayWriterMust(t, err, "marshal object for legacy digest")
	var data map[string]any
	gatewayWriterMust(t, json.Unmarshal(b, &data), "decode object for legacy digest")
	for _, k := range []string{"apiVersion", "kind", "metadata", "status"} {
		delete(data, k)
	}
	if _, ok := obj.(*appsv1.StatefulSet); ok {
		spec, _ := data["spec"].(map[string]any)
		template, _ := spec["template"].(map[string]any)
		podSpec, _ := template["spec"].(map[string]any)
		for _, key := range []string{"initContainers", "containers"} {
			list, _ := podSpec[key].([]any)
			for _, item := range list {
				c, ok := item.(map[string]any)
				if !ok {
					continue
				}
				delete(c, "image")
				if c["name"] != "tailscale" {
					continue
				}
				env, _ := c["env"].([]any)
				for _, e := range env {
					if v, ok := e.(map[string]any); ok && v["name"] == "TS_ROUTES" {
						delete(v, "value")
					}
				}
			}
		}
	}
	if cm, ok := obj.(*corev1.ConfigMap); ok && strings.HasSuffix(cm.Name, "-coredns") {
		if payload, ok := data["data"].(map[string]any); ok {
			delete(payload, "zone.db")
		}
	}
	b, err = json.Marshal(data)
	gatewayWriterMust(t, err, "re-encode object for legacy digest")
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:])
}

// rewriteReceiptDigests reads the live -fresh receipt and replaces the stored
// StatefulSet and -coredns digests with the supplied ones, then delete+creates
// the immutable receipt. It returns the receipt object the operator will observe.
func (f *gatewayWriterFixture) rewriteReceiptDigests(digest func(kind, name string) string) {
	f.t.Helper()
	cm := &corev1.ConfigMap{}
	f.get(f.g.Name+"-fresh", cm)
	var receipt map[string]any
	gatewayWriterMust(f.t, json.Unmarshal([]byte(cm.Data["receipt.json"]), &receipt), "decode receipt")
	for _, raw := range receipt["objects"].([]any) {
		o := raw.(map[string]any)
		if d := digest(o["kind"].(string), o["name"].(string)); d != "" {
			o["digest"] = d
		}
	}
	data, err := json.Marshal(receipt)
	gatewayWriterMust(f.t, err, "encode rewritten receipt")
	legacy := &corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Name: cm.Name, Namespace: cm.Namespace, Labels: cm.Labels}, Immutable: ptr.To(true), Data: map[string]string{"receipt.json": string(data)}}
	gatewayWriterMust(f.t, f.c.Delete(f.ctx, cm), "remove current receipt as test admin")
	gatewayWriterMust(f.t, f.c.Create(f.ctx, legacy), "install rewritten receipt")
}

// liveLegacyDigest computes the v0.10.0 digest for the live StatefulSet and
// -coredns ConfigMap, matching what a v0.10.0 operator would have stored.
func (f *gatewayWriterFixture) liveLegacyDigest(kind, name string) string {
	switch {
	case kind == "StatefulSet":
		sts := &appsv1.StatefulSet{}
		f.get(name, sts)
		return v0100LegacyDigest(f.t, sts)
	case kind == "ConfigMap" && strings.HasSuffix(name, "-coredns"):
		cm := &corev1.ConfigMap{}
		f.get(name, cm)
		return v0100LegacyDigest(f.t, cm)
	}
	return ""
}

// gatewayMigrationCases covers the in-place migration of a format-3 receipt
// written by v0.10.0 (old digest rule) to the current rule, and the crash-safe
// staging (-fresh-next) that backs it.
func gatewayMigrationCases(t *testing.T, newFixture func(*testing.T, bool) *gatewayWriterFixture, admin client.Client, ctx context.Context) {
	t.Run("v0.10.0 receipt migrates in place without recreate", func(t *testing.T) {
		f := newFixture(t, false)
		f.reconcile("Provisioning")
		f.assertComplete()
		original := &corev1.ConfigMap{}
		f.get(f.g.Name+"-fresh", original)
		f.rewriteReceiptDigests(f.liveLegacyDigest)
		// First reconcile recognises the legacy rule, verifies the full set and
		// rewrites the receipt; no Pod yet, so Ready stays Provisioning.
		f.reconcile("Provisioning")
		migrated := &corev1.ConfigMap{}
		f.get(f.g.Name+"-fresh", migrated)
		if migrated.UID == original.UID {
			t.Fatal("migration did not rewrite the completion receipt")
		}
		// The rewritten receipt must carry current-rule digests for every child
		// (assertComplete recomputes them independently), not the legacy ones.
		f.assertComplete()
		f.absent(f.g.Name+"-fresh-next", &corev1.ConfigMap{})
		// Idempotent: a second reconcile neither re-migrates nor blocks.
		before, writes := f.snapshot(), f.writes.writes
		f.reconcile("Provisioning")
		f.assertUnchanged(before, writes)
		// The migrated receipt drives a healthy runtime: a synthetic Pod reaches
		// Ready and an image bump still follows the spec into the template.
		node := f.seedSyntheticState()
		f.hs.setNodes([]headscale.Node{node})
		f.createSyntheticReadyPod()
		f.reconcile("FreshRuntimeReady")
		f.assertMints(1)
	})

	t.Run("legacy receipt with bound-field drift still blocks", func(t *testing.T) {
		f := newFixture(t, false)
		f.reconcile("Provisioning")
		f.assertComplete()
		// Drift a receipt-bound field (replicas) BEFORE recording the legacy digest
		// of the pre-drift object, so neither the current nor the legacy rule can
		// match the live StatefulSet.
		sts := &appsv1.StatefulSet{}
		f.get(f.g.Name, sts)
		preDrift := v0100LegacyDigest(t, sts)
		f.rewriteReceiptDigests(func(kind, name string) string {
			if kind == "StatefulSet" {
				return preDrift
			}
			return f.liveLegacyDigest(kind, name)
		})
		fresh := &corev1.ConfigMap{}
		f.get(f.g.Name+"-fresh", fresh)
		sts.Spec.Replicas = ptr.To(int32(2))
		gatewayWriterMust(t, admin.Update(ctx, sts), "drift bound replicas as a foreign actor")
		f.reconcile("FreshBlocked")
		after := &corev1.ConfigMap{}
		f.get(f.g.Name+"-fresh", after)
		if after.UID != fresh.UID || after.ResourceVersion != fresh.ResourceVersion {
			t.Fatal("blocked migration still rewrote the receipt")
		}
	})

	t.Run("crash between delete and recreate recovers from the stage", func(t *testing.T) {
		f := newFixture(t, false)
		f.reconcile("Provisioning")
		f.assertComplete()
		// Simulate the crash window: a valid staged -fresh-next exists, -fresh is gone.
		fresh := &corev1.ConfigMap{}
		f.get(f.g.Name+"-fresh", fresh)
		stage := &corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Name: f.g.Name + "-fresh-next", Namespace: f.ns, Labels: fresh.Labels}, Immutable: ptr.To(true), Data: map[string]string{"receipt.json": fresh.Data["receipt.json"]}}
		gatewayWriterMust(t, admin.Create(ctx, stage), "stage -fresh-next")
		gatewayWriterMust(t, admin.Delete(ctx, fresh), "simulate crashed -fresh delete")
		f.reconcile("Provisioning")
		restored := &corev1.ConfigMap{}
		f.get(f.g.Name+"-fresh", restored)
		if restored.Data["receipt.json"] != fresh.Data["receipt.json"] {
			t.Fatal("recovery did not restore the staged receipt payload")
		}
		f.absent(f.g.Name+"-fresh-next", &corev1.ConfigMap{})
	})

	t.Run("stale stage with -fresh present is cleared", func(t *testing.T) {
		f := newFixture(t, false)
		f.reconcile("Provisioning")
		f.assertComplete()
		fresh := &corev1.ConfigMap{}
		f.get(f.g.Name+"-fresh", fresh)
		stage := &corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Name: f.g.Name + "-fresh-next", Namespace: f.ns, Labels: fresh.Labels}, Immutable: ptr.To(true), Data: map[string]string{"receipt.json": fresh.Data["receipt.json"]}}
		gatewayWriterMust(t, admin.Create(ctx, stage), "leave a stale -fresh-next")
		f.reconcile("Provisioning")
		after := &corev1.ConfigMap{}
		f.get(f.g.Name+"-fresh", after)
		if after.UID != fresh.UID {
			t.Fatal("cleanup rewrote the live receipt")
		}
		f.absent(f.g.Name+"-fresh-next", &corev1.ConfigMap{})
	})

	t.Run("foreign stage with -fresh absent blocks, never adopts", func(t *testing.T) {
		f := newFixture(t, false)
		f.reconcile("Provisioning")
		f.assertComplete()
		fresh := &corev1.ConfigMap{}
		f.get(f.g.Name+"-fresh", fresh)
		foreignLabels := map[string]string{"tsunaro.io/gateway-uid": "foreign-gateway", "app.kubernetes.io/managed-by": "tailnet-operator"}
		stage := &corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Name: f.g.Name + "-fresh-next", Namespace: f.ns, Labels: foreignLabels}, Immutable: ptr.To(true), Data: map[string]string{"receipt.json": fresh.Data["receipt.json"]}}
		gatewayWriterMust(t, admin.Create(ctx, stage), "stage a foreign -fresh-next")
		gatewayWriterMust(t, admin.Delete(ctx, fresh), "remove -fresh as test admin")
		f.reconcile("FreshBlocked")
		f.absent(f.g.Name+"-fresh", &corev1.ConfigMap{})
		// The foreign stage is left untouched; the operator never adopts it.
		survivor := &corev1.ConfigMap{}
		f.get(f.g.Name+"-fresh-next", survivor)
		if survivor.UID != stage.UID {
			t.Fatal("operator mutated a foreign stage")
		}
	})
}
