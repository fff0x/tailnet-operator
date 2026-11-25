//go:build e2e

package e2e

import (
	"context"
	"strings"
	"testing"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"

	tnv1 "tsunaro.io/tailnet-operator/api/v1alpha1"
)

// TestUndeclaredSourceDoesNotFreezePolicy is the regression for 2026-11-18: a TailnetIngress whose
// allowFrom names a tag that no tagOwner declares (a typo, or an egress not created yet) or a group
// the base does not declare must not make Headscale reject the whole policy. The renderer drops the
// undeclared source; the rest of the policy applies. Each case also proves the unsanitized form is
// genuinely rejected by real Headscale, so the drop is load-bearing and not a vacuous happy path.
func TestUndeclaredSourceDoesNotFreezePolicy(t *testing.T) {
	cases := []struct {
		name, source, reason, ghost string
	}{
		{"tag", "tag:does-not-exist", "SourceTagUnknown",
			`{"tagOwners":{"tag:known":[]},"grants":[{"src":["tag:ghost-source"],"dst":["tag:known"],"ip":["tcp:443"]}]}`},
		{"group", "group:does-not-exist", "SourceGroupUnknown",
			`{"tagOwners":{"tag:known":[]},"grants":[{"src":["group:ghost-source"],"dst":["tag:known"],"ip":["tcp:443"]}]}`},
	}
	for _, version := range versions {
		t.Run(version, func(t *testing.T) {
			if version != "v0.29.6" {
				t.Skip("unsupported capability row; covered by TestPreflight")
			}
			for _, tc := range cases {
				t.Run(tc.name, func(t *testing.T) {
					ctx, cancel := context.WithTimeout(testContext(t), 90*time.Second)
					defer cancel()
					hs := startHeadscale(t, ctx, version, "database", false)
					name := createTailnet(t, ctx, hs)
					base := `{"tagOwners":{"tag:fabric":[]},"acls":[{"action":"accept","src":["*"],"dst":["192.0.2.1:443"]}]}`
					enablePolicy(t, ctx, name, base, "Apply")
					// Permit an autogroup source and the undeclared one through the admin allowlist,
					// so it reaches the renderer rather than being refused as PolicyDenied.
					updateTailnet(t, ctx, name, func(tn *tnv1.Tailnet) {
						tn.Spec.Policy.IngressSourceAllowlist = []string{"autogroup:member", "tag:*", "group:*"}
					})
					waitApplied(t, ctx, name, "192.0.2.1:443", hs)

					in := &tnv1.TailnetIngress{
						ObjectMeta: metav1.ObjectMeta{Name: name + "-in", Namespace: namespace},
						Spec: tnv1.TailnetIngressSpec{
							TailnetRef: tnv1.TailnetRef{Name: name}, Tag: "tag:ingress-ghosted",
							AllowFrom: []string{"autogroup:member", tc.source},
							Exposes:   []tnv1.Expose{{Name: "https", Port: 443, Backend: tnv1.Backend{Service: "fixture-backend", Port: 443}}},
						},
					}
					if err := kube.Create(ctx, in); err != nil {
						t.Fatal(err)
					}
					t.Cleanup(func() {
						cl, cancel := context.WithTimeout(context.Background(), 10*time.Second)
						defer cancel()
						_ = client.IgnoreNotFound(kube.Delete(cl, in))
					})

					// The policy still applies — Headscale is not frozen — and the live document
					// carries the ingress tag and its real source, but not the undeclared one.
					waitCondition(t, ctx, name, "PolicyApplied", metav1.ConditionTrue, "InSync")
					eventually(t, ctx, "ingress tag granted without the ghost source", func() bool {
						live := livePolicy(t, ctx, hs)
						return strings.Contains(live, "tag:ingress-ghosted") &&
							strings.Contains(live, "autogroup:member") &&
							!strings.Contains(live, tc.source)
					})

					// Load-bearing: the same policy WITH the undeclared source is really rejected upstream.
					if err := hs.client().SetPolicy(ctx, tc.ghost); err == nil {
						t.Fatalf("real Headscale accepted an undeclared %s source; the drop is not load-bearing", tc.name)
					}
					// The ingress itself reports the gap rather than a full grant.
					eventually(t, ctx, "ingress PolicyGranted="+tc.reason, func() bool {
						var got tnv1.TailnetIngress
						if err := kube.Get(ctx, client.ObjectKeyFromObject(in), &got); err != nil {
							return false
						}
						for _, c := range got.Status.Conditions {
							if c.Type == "PolicyGranted" {
								return c.Status == metav1.ConditionFalse && c.Reason == tc.reason
							}
						}
						return false
					})
				})
			}
		})
	}
}
