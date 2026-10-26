//go:build e2e

package e2e

import (
	"testing"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	tnv1 "tsunaro.io/tailnet-operator/api/v1alpha1"
)

func TestPreflight(t *testing.T) {
	for _, version := range versions {
		t.Run(version, func(t *testing.T) {
			for _, mode := range []string{"database", "file"} {
				t.Run(mode, func(t *testing.T) {
					ctx := testContext(t)
					hs := startHeadscale(t, ctx, version, mode, true)
					name := createTailnet(t, ctx, hs)
					// A deliberately wrong version hint must not override observed capabilities.
					updateTailnet(t, ctx, name, func(tn *tnv1.Tailnet) {
						tn.Spec.Headscale.Version = "999.0.0"
					})
					status, reason := metav1.ConditionFalse, "Incompatible"
					if version == "v0.29.6" && mode == "database" {
						status, reason = metav1.ConditionTrue, "Compatible"
					}
					waitCondition(t, ctx, name, "HeadscaleCompatible", status, reason)
					waitCondition(t, ctx, name, "ApiReachable", metav1.ConditionTrue, "Reachable")
					waitCondition(t, ctx, name, "SplitDNS", metav1.ConditionUnknown, "CannotVerify")
					if mode == "database" {
						waitCondition(t, ctx, name, "PolicyMode", metav1.ConditionTrue, "Database")
					} else {
						waitCondition(t, ctx, name, "PolicyMode", metav1.ConditionFalse, "File")
						enablePolicy(t, ctx, name, policyBase("accept", "192.0.2.1:443"), "Apply")
						waitCondition(t, ctx, name, "PolicyApplied", metav1.ConditionFalse, "PolicyModeFile")
						waitCondition(t, ctx, name, "PolicyRendered", metav1.ConditionTrue, "Rendered")
					}
					if writes := hs.policyWrites(); len(writes) != 0 {
						t.Fatalf("preflight/file-mode guard sent %d policy PUTs", len(writes))
					}
					live, err := hs.client().GetPolicy(ctx)
					if err != nil || live != "{}" {
						t.Fatal("non-persisting preflight or file-mode guard changed the seeded policy")
					}
				})
			}
		})
	}
}
