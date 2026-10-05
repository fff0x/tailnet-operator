//go:build integration

package validation

import (
	"context"
	"strconv"
	"strings"
	"testing"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

// Teardown and DNS live reconcile share the writer fixture: the real API
// server, synthetic Headscale and a reconciler whose DNS writes land through
// the same CAS path.
func gatewayDNSLiveCases(t *testing.T, newFixture func(*testing.T, bool) *gatewayWriterFixture, admin client.Client, ctx context.Context) {
	t.Run("hosts change advances the serial once and reports DNSReady", func(t *testing.T) {
		f := newFixture(t, false)
		f.reconcile("Provisioning")
		f.assertComplete()
		cm := &corev1.ConfigMap{}
		f.get(f.g.Name+"-coredns", cm)
		if cm.Annotations["tsunaro.io/dns-serial"] != "1" || cm.Annotations["tsunaro.io/dns-content-sha256"] == "" {
			t.Fatal("initial render missing CAS annotations")
		}
		if !strings.Contains(cm.Data["zone.db"], "app.prod.example.internal") {
			t.Fatal("initial zone does not describe the hosts snapshot")
		}
		if dns := meta.FindStatusCondition(f.g.Status.Conditions, "DNSReady"); dns == nil || dns.Status != metav1.ConditionTrue || dns.Reason != "DNSInSync" {
			t.Fatal("DNSReady is not True after the first reconcile")
		}
		updateHosts(t, admin, ctx, f, "100.64.0.42 updated.prod.example.internal\n")
		f.reconcile("Provisioning")
		f.get(f.g.Name+"-coredns", cm)
		if cm.Annotations["tsunaro.io/dns-serial"] != "2" {
			t.Fatal("source change did not advance the serial")
		}
		if !strings.Contains(cm.Data["zone.db"], "updated.prod.example.internal") || strings.Contains(cm.Data["zone.db"], "app.prod.example.internal") {
			t.Fatal("zone was not re-rendered against the live source")
		}
		// A reconcile without a source change writes nothing new.
		rvAfterFirst := cm.ResourceVersion
		f.reconcile("Provisioning")
		f.get(f.g.Name+"-coredns", cm)
		if cm.ResourceVersion != rvAfterFirst || cm.Annotations["tsunaro.io/dns-serial"] != "2" {
			t.Fatal("DNS writer looped on an idempotent source")
		}
	})

	t.Run("cosmetic hosts rewrite leaves the serial", func(t *testing.T) {
		f := newFixture(t, false)
		f.reconcile("Provisioning")
		f.assertComplete()
		// Same records, different formatting: PlanDNSRevision canonicalises.
		updateHosts(t, admin, ctx, f, "  100.64.0.19   app.prod.example.internal   \n")
		f.reconcile("Provisioning")
		cm := &corev1.ConfigMap{}
		f.get(f.g.Name+"-coredns", cm)
		if cm.Annotations["tsunaro.io/dns-serial"] != "1" {
			t.Fatal("cosmetic rewrite advanced the serial")
		}
	})

	t.Run("corefile tamper is caught by the completion receipt", func(t *testing.T) {
		f := newFixture(t, false)
		f.reconcile("Provisioning")
		f.assertComplete()
		cm := &corev1.ConfigMap{}
		f.get(f.g.Name+"-coredns", cm)
		cm.Data["Corefile"] += "\n# synthetic drift\n"
		gatewayWriterMust(t, admin.Update(ctx, cm), "tamper with Corefile")
		f.reconcile("FreshBlocked")
	})

	t.Run("zone tamper without matching hash is not overwritten", func(t *testing.T) {
		f := newFixture(t, false)
		f.reconcile("Provisioning")
		f.assertComplete()
		cm := &corev1.ConfigMap{}
		f.get(f.g.Name+"-coredns", cm)
		cm.Data["zone.db"] = "poisoned\n"
		gatewayWriterMust(t, admin.Update(ctx, cm), "tamper with zone.db")
		before := cm.ResourceVersion
		f.reconcile("Provisioning")
		f.get(f.g.Name+"-coredns", cm)
		if cm.ResourceVersion != before || cm.Data["zone.db"] != "poisoned\n" {
			t.Fatal("DNS writer overwrote a mismatched zone instead of blocking")
		}
		if dns := meta.FindStatusCondition(f.g.Status.Conditions, "DNSReady"); dns == nil || dns.Status != metav1.ConditionFalse || dns.Reason != "DNSUpdateBlocked" {
			t.Fatal("DNSReady did not report the blocked state")
		}
	})

	t.Run("foreign hosts owner blocks live DNS", func(t *testing.T) {
		f := newFixture(t, false)
		f.reconcile("Provisioning")
		f.assertComplete()
		hosts := &corev1.ConfigMap{}
		gatewayWriterMust(t, admin.Get(ctx, client.ObjectKey{Namespace: f.ns, Name: "hosts"}, hosts), "read hosts")
		hosts.OwnerReferences[0].UID = "foreign-tailnet"
		gatewayWriterMust(t, admin.Update(ctx, hosts), "replace hosts owner")
		before := snapshotCoreDNS(t, admin, ctx, f)
		f.reconcile("Provisioning")
		if snapshotCoreDNS(t, admin, ctx, f) != before {
			t.Fatal("foreign hosts owner was accepted as the DNS source")
		}
		if dns := meta.FindStatusCondition(f.g.Status.Conditions, "DNSReady"); dns == nil || dns.Reason != "DNSUpdateBlocked" {
			t.Fatal("DNSReady did not report the blocked source")
		}
	})

	t.Run("suspended gateway writes no derived DNS", func(t *testing.T) {
		f := newFixture(t, true)
		f.reconcile("Suspended")
		// No fresh set exists, so the live writer has no state to touch.
		cm := &corev1.ConfigMap{}
		if admin.Get(ctx, client.ObjectKey{Namespace: f.ns, Name: f.g.Name + "-coredns"}, cm) == nil {
			t.Fatal("suspended gateway rendered a derived ConfigMap")
		}
		if f.writes.writes != 0 {
			t.Fatal("suspended gateway attempted a runtime write")
		}
	})

	t.Run("legacy ConfigMap without annotations blocks DNSReady only", func(t *testing.T) {
		f := newFixture(t, false)
		f.reconcile("Provisioning")
		f.assertComplete()
		cm := &corev1.ConfigMap{}
		f.get(f.g.Name+"-coredns", cm)
		// Simulate a v0.7.1 render: no DNS CAS annotations recorded.
		delete(cm.Annotations, "tsunaro.io/dns-serial")
		delete(cm.Annotations, "tsunaro.io/dns-content-sha256")
		gatewayWriterMust(t, admin.Update(ctx, cm), "simulate pre-live-DNS gateway")
		f.reconcile("Provisioning")
		if dns := meta.FindStatusCondition(f.g.Status.Conditions, "DNSReady"); dns == nil || dns.Status != metav1.ConditionFalse || dns.Reason != "DNSUpdateBlocked" {
			t.Fatal("legacy CM did not report DNSUpdateBlocked")
		}
		ready := meta.FindStatusCondition(f.g.Status.Conditions, "Ready")
		if ready == nil || ready.Reason != "Provisioning" {
			t.Fatal("legacy CM must not invalidate Ready")
		}
	})
}

func updateHosts(t *testing.T, admin client.Client, ctx context.Context, f *gatewayWriterFixture, data string) {
	t.Helper()
	hosts := &corev1.ConfigMap{}
	gatewayWriterMust(t, admin.Get(ctx, client.ObjectKey{Namespace: f.ns, Name: "hosts"}, hosts), "read hosts source")
	hosts.Data = map[string]string{"hosts": data}
	gatewayWriterMust(t, admin.Update(ctx, hosts), "update hosts source")
}

func snapshotCoreDNS(t *testing.T, admin client.Client, ctx context.Context, f *gatewayWriterFixture) string {
	t.Helper()
	cm := &corev1.ConfigMap{}
	gatewayWriterMust(t, admin.Get(ctx, client.ObjectKey{Namespace: f.ns, Name: f.g.Name + "-coredns"}, cm), "read -coredns")
	return cm.ResourceVersion + "/" + cm.Annotations["tsunaro.io/dns-serial"] + "/" + strconv.Itoa(len(cm.Data["zone.db"]))
}
