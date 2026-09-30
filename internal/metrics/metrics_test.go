package metrics

import (
	"sync"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	tnv1 "this-is-fine.io/tailnet-operator/api/v1alpha1"
)

func isolated(t *testing.T) (*Metrics, *prometheus.Registry) {
	t.Helper()
	reg := prometheus.NewPedanticRegistry()
	m, err := Register(reg)
	if err != nil {
		t.Fatal(err)
	}
	return m, reg
}
func samples(t *testing.T, reg *prometheus.Registry, name string) []*dto.Metric {
	t.Helper()
	families, err := reg.Gather()
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range families {
		if f.GetName() == name {
			return f.Metric
		}
	}
	return nil
}
func value(t *testing.T, reg *prometheus.Registry, name string, labels map[string]string, want float64) {
	t.Helper()
	for _, m := range samples(t, reg, name) {
		match := true
		for key, w := range labels {
			found := false
			for _, p := range m.Label {
				if p.GetName() == key && p.GetValue() == w {
					found = true
				}
			}
			match = match && found
		}
		if match {
			var got float64
			if m.Gauge != nil {
				got = m.Gauge.GetValue()
			} else {
				got = m.Counter.GetValue()
			}
			if got != want {
				t.Fatalf("%s %v = %v, want %v", name, labels, got, want)
			}
			return
		}
	}
	t.Fatalf("missing %s %v", name, labels)
}
func cond(typ, reason string, status metav1.ConditionStatus, generation int64) metav1.Condition {
	return metav1.Condition{Type: typ, Reason: reason, Status: status, ObservedGeneration: generation}
}
func TestConditionsAndLifecycle(t *testing.T) {
	m, reg := isolated(t)
	eg := &tnv1.TailnetEgress{ObjectMeta: metav1.ObjectMeta{Name: "eg", Namespace: "ns", UID: "first", Generation: 1}}
	eg.Spec.TailnetRef.Name = "tn"
	eg.Status.Conditions = []metav1.Condition{cond("Ready", "NoTailnet", metav1.ConditionFalse, 1)}
	m.Observe(eg)
	value(t, reg, "tailnet_resource_ready", map[string]string{"tailnet": "tn"}, 0)
	value(t, reg, "tailnet_resource_condition", map[string]string{"reason": "NoTailnet"}, 1)
	eg.Status.Conditions = []metav1.Condition{cond("Ready", "Ready", metav1.ConditionTrue, 1)}
	m.Observe(eg)
	value(t, reg, "tailnet_resource_ready", nil, 1)
	value(t, reg, "tailnet_resource_condition", map[string]string{"reason": "NoTailnet"}, 0)
	value(t, reg, "tailnet_resource_condition", map[string]string{"reason": "Ready"}, 1)
	eg.Generation = 2
	m.Observe(eg)
	if len(samples(t, reg, "tailnet_resource_ready")) != 0 {
		t.Fatal("stale Ready exported")
	}
	value(t, reg, "tailnet_resource_condition", map[string]string{"reason": "Ready"}, 0)
	eg.Status.Conditions = nil
	m.Observe(eg)
	value(t, reg, "tailnet_resource_condition", map[string]string{"reason": "Ready"}, 0)
	eg.Status.Conditions = []metav1.Condition{cond("Ready", "Ready", metav1.ConditionTrue, 2)}
	eg.Spec.TailnetRef.Name = "changed"
	m.Observe(eg)
	if got := len(samples(t, reg, "tailnet_resource_ready")); got != 1 {
		t.Fatalf("old tailnet label remained: %d", got)
	}
	if got := len(samples(t, reg, "tailnet_resource_condition")); got != 1 {
		t.Fatal("old ref history remained")
	}
	eg.UID = "second"
	eg.Status.Conditions = []metav1.Condition{cond("untrusted-type", "untrusted-reason", metav1.ConditionUnknown, 2)}
	m.Observe(eg)
	if got := len(samples(t, reg, "tailnet_resource_condition")); got != 1 {
		t.Fatal("recreated UID retained history")
	}
	value(t, reg, "tailnet_resource_condition", map[string]string{"type": "Other", "reason": "Other"}, 1)
	m.Delete("TailnetEgress", "ns", "eg")
	if len(samples(t, reg, "tailnet_resource_condition")) != 0 || len(m.objects) != 0 {
		t.Fatal("delete retained history")
	}
	eg.Status.Conditions = []metav1.Condition{cond("Ready", "NotReady", metav1.ConditionFalse, 2)}
	m.Observe(eg)
	if len(samples(t, reg, "tailnet_resource_condition")) != 1 {
		t.Fatal("recreation retained old reasons")
	}
}

func TestTargetsExposesAndLegacyCleanup(t *testing.T) {
	m, reg := isolated(t)
	exp := metav1.NewTime(time.Now().Add(time.Hour))
	eg := &tnv1.TailnetEgress{ObjectMeta: metav1.ObjectMeta{Name: "eg", Namespace: "ns", Generation: 1}}
	eg.Spec.Targets = []tnv1.Target{{Name: "keep"}, {Name: "remove"}}
	eg.Status.ObservedGeneration = 1
	eg.Status.AuthKeyExpiresAt = &exp
	eg.Status.Conditions = []metav1.Condition{cond("RoutesGranted", "RoutesMissing", metav1.ConditionFalse, 1)}
	eg.Status.Targets = []tnv1.TargetStatus{{Name: "keep", Reason: "NotApproved"}, {Name: "remove", Reason: "NoGrant"}}
	m.Observe(eg)
	value(t, reg, "tailnetegress_routes_missing", nil, 2)
	eg.Spec.Targets = eg.Spec.Targets[:1] // even stale status entries cannot recreate removed targets
	m.Observe(eg)
	if len(samples(t, reg, "tailnet_egress_target_state")) != 1 {
		t.Fatal("removed target retained")
	}
	value(t, reg, "tailnetegress_routes_missing", nil, 1)
	eg.Status.Targets[0].Present = true
	eg.Status.Targets[0].Reason = ""
	m.Observe(eg)
	value(t, reg, "tailnet_egress_target_state", map[string]string{"reason": "Present"}, 1)
	eg.Generation++
	m.Observe(eg)
	if len(samples(t, reg, "tailnet_egress_target_state")) != 0 {
		t.Fatal("stale target exported")
	}
	m.Delete("TailnetEgress", "ns", "eg")
	for _, name := range []string{"tailnetegress_authkey_expires_seconds", "tailnetegress_routes_missing", "tailnet_egress_target_state"} {
		if len(samples(t, reg, name)) != 0 {
			t.Fatal("delete retained", name)
		}
	}
	in := &tnv1.TailnetIngress{ObjectMeta: metav1.ObjectMeta{Name: "in", Namespace: "ns", Generation: 1}}
	in.Spec.Exposes = []tnv1.Expose{{Name: "keep"}, {Name: "remove"}}
	in.Status.ObservedGeneration = 1
	in.Status.AuthKeyExpiresAt = &exp
	in.Status.Conditions = []metav1.Condition{cond("BackendsReachable", "Unreachable", metav1.ConditionFalse, 1)}
	in.Status.Exposes = []tnv1.ExposeStatus{{Name: "keep", Reachable: true}, {Name: "remove"}}
	m.Observe(in)
	value(t, reg, "tailnetingress_backends_unreachable", nil, 1)
	value(t, reg, "tailnet_ingress_expose_reachable", map[string]string{"expose": "keep"}, 1)
	in.Spec.Exposes = in.Spec.Exposes[:1]
	m.Observe(in)
	if len(samples(t, reg, "tailnet_ingress_expose_reachable")) != 1 {
		t.Fatal("removed expose retained")
	}
	in.Generation++
	m.Observe(in)
	if len(samples(t, reg, "tailnet_ingress_expose_reachable")) != 0 {
		t.Fatal("stale expose exported")
	}
	m.Delete("TailnetIngress", "ns", "in")
	for _, name := range []string{"tailnetingress_authkey_expires_seconds", "tailnetingress_backends_unreachable", "tailnet_ingress_expose_reachable"} {
		if len(samples(t, reg, name)) != 0 {
			t.Fatal("delete retained", name)
		}
	}
}

func TestTailnetPolicyNoInventedReady(t *testing.T) {
	m, reg := isolated(t)
	now := metav1.Now()
	tn := &tnv1.Tailnet{ObjectMeta: metav1.ObjectMeta{Name: "tn", Generation: 2}}
	tn.Status.Conditions = []metav1.Condition{cond("PolicyRendered", "Rendered", metav1.ConditionTrue, 2)}
	tn.Status.APIKeyExpiresAt = &now
	tn.Status.Policy = &tnv1.PolicyStatus{Generated: tnv1.PolicyGenerated{Tags: 3, Grants: 4, Routes: 5}, AppliedAt: &now}
	m.Observe(tn)
	if len(samples(t, reg, "tailnet_resource_ready")) != 0 {
		t.Fatal("Tailnet has no Ready condition")
	}
	value(t, reg, "tailnet_policy_generated", map[string]string{"kind": "tags"}, 3)
	value(t, reg, "tailnet_policy_generated", map[string]string{"kind": "grants"}, 4)
	value(t, reg, "tailnet_policy_generated", map[string]string{"kind": "routes"}, 5)
	tn.Generation++
	m.Observe(tn)
	if len(samples(t, reg, "tailnet_policy_generated")) != 0 {
		t.Fatal("stale generation policy exported")
	}
	tn.Generation--
	tn.Status.Policy = nil
	m.Observe(tn)
	if len(samples(t, reg, "tailnet_policy_generated")) != 0 {
		t.Fatal("disabled policy retained")
	}
	m.Delete("Tailnet", "", "tn")
	for _, name := range []string{"tailnet_apikey_expires_seconds", "tailnet_policy_generated", "tailnet_policy_applied_timestamp_seconds", "tailnet_resource_condition"} {
		if len(samples(t, reg, name)) != 0 {
			t.Fatal("delete retained", name)
		}
	}
}

// Pending is a persisted desired/applied comparison, not an age-of-last-write alarm.
func TestPolicyPending(t *testing.T) {
	m, reg := isolated(t)
	old := metav1.NewTime(time.Now().Add(-24 * time.Hour))
	tn := &tnv1.Tailnet{ObjectMeta: metav1.ObjectMeta{Name: "tn", Generation: 1}}
	tn.Status.Conditions = []metav1.Condition{cond("PolicyApplied", "InSync", metav1.ConditionTrue, 1)}
	tn.Status.Policy = &tnv1.PolicyStatus{AppliedAt: &old}
	for _, tc := range []struct {
		name, mode, rendered, applied string
		want                          float64
	}{
		{"unchanged InSync", "Apply", "same", "same", 0},
		{"changed render", "Apply", "new", "old", 1},
		{"initial render", "Apply", "new", "", 1},
		{"DryRun", "DryRun", "new", "old", 0},
		{"empty render", "Apply", "", "old", 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			tn.Spec.Policy.Mode = tc.mode
			tn.Status.Policy.RenderedHash = tc.rendered
			tn.Status.Policy.AppliedHash = tc.applied
			m.Observe(tn)
			value(t, reg, "tailnet_policy_pending", map[string]string{"tailnet": "tn"}, tc.want)
		})
	}
	m.Delete("Tailnet", "", "tn")
	if len(samples(t, reg, "tailnet_policy_pending")) != 0 {
		t.Fatal("deleted Tailnet retains pending")
	}
	m.Observe(tn)
	tn.Status.Policy = nil
	m.Observe(tn)
	if len(samples(t, reg, "tailnet_policy_pending")) != 0 {
		t.Fatal("removed policy retains pending")
	}
}

func TestSharedManagerRegistrationAndOperations(t *testing.T) {
	m, reg := isolated(t)
	var wg sync.WaitGroup
	for range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			other, err := Register(reg)
			if err != nil || other != m {
				t.Error("duplicate manager registration", err)
			}
		}()
	}
	wg.Wait()
	observer := m.Headscale("tn")
	observer("GET", "/api/v1/policy", 200, time.Second)
	observer("PUT", "/api/v1/policy", 200, time.Second)
	observer("PUT", "/api/v1/policy", 0, time.Second)
	hist := samples(t, reg, "tailnet_policy_write_duration_seconds")
	if len(hist) != 1 || hist[0].Histogram.GetSampleCount() != 2 {
		t.Fatal("writes must include failures, not reads")
	}
	value(t, reg, "tailnet_headscale_api_requests_total", map[string]string{"method": "PUT", "code": "0"}, 1)
	m.Approved("tn", 2)
	value(t, reg, "tailnet_route_approvals_replayed_total", nil, 2)
	m.PolicyError("tn", false)
	m.PolicyError("tn", true)
	value(t, reg, "tailnet_policy_apply_errors_total", nil, 1)
	_, other := isolated(t)
	if len(samples(t, other, "tailnet_headscale_api_requests_total")) != 0 {
		t.Fatal("registry leaked state")
	}
}
