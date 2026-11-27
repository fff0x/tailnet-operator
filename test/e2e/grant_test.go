//go:build e2e

package e2e

import (
	"context"
	"strings"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/util/retry"
	"sigs.k8s.io/controller-runtime/pkg/client"

	tnv1 "tsunaro.io/tailnet-operator/api/v1alpha1"
)

const grantBasePolicy = `{"tagOwners":{"tag:fabric":[]},"acls":[{"action":"accept","src":["*"],"dst":["192.0.2.1:443"]}]}`

// createGrant creates a TailnetGrant for one user reference. Headscale accepts a user it does not
// know, so the reference doubles as a unique marker in the live policy.
func createGrant(t *testing.T, ctx context.Context, name, tailnet, user string, target tnv1.GrantTarget, expires *time.Time, ports ...int32) *tnv1.TailnetGrant {
	t.Helper()
	g := &tnv1.TailnetGrant{ObjectMeta: metav1.ObjectMeta{Name: name}, Spec: tnv1.TailnetGrantSpec{
		TailnetRef: tnv1.TailnetRef{Name: tailnet}, Sources: []string{user}, Target: target, Ports: ports,
	}}
	if expires != nil {
		at := metav1.NewTime(*expires)
		g.Spec.ExpiresAt = &at
	}
	if err := kube.Create(ctx, g); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		cleanup, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if err := client.IgnoreNotFound(kube.Delete(cleanup, g)); err != nil {
			t.Errorf("delete TailnetGrant fixture: %v", err)
		}
	})
	return g
}

// grantIs reports whether the grant's current-generation Ready condition has the reason.
func grantIs(t *testing.T, ctx context.Context, name, reason string) bool {
	t.Helper()
	var g tnv1.TailnetGrant
	if err := kube.Get(ctx, types.NamespacedName{Name: name}, &g); err != nil {
		t.Fatal(err)
	}
	c := meta.FindStatusCondition(g.Status.Conditions, "Ready")
	return c != nil && c.Reason == reason && c.ObservedGeneration == g.Generation &&
		(c.Status == metav1.ConditionTrue) == (reason == "Granted")
}

func policyInSync(t *testing.T, ctx context.Context, name string) bool {
	t.Helper()
	tn := getTailnet(t, ctx, name)
	return conditionMatches(tn, "PolicyApplied", metav1.ConditionTrue, "InSync") || conditionMatches(tn, "PolicyApplied", metav1.ConditionTrue, "Applied")
}

func grantTailnet(t *testing.T, ctx context.Context, hs *headscaleProcess) string {
	t.Helper()
	name := createTailnet(t, ctx, hs)
	enablePolicy(t, ctx, name, grantBasePolicy, "Apply")
	updateTailnet(t, ctx, name, func(tn *tnv1.Tailnet) {
		tn.Spec.Policy.IngressSourceAllowlist = []string{"autogroup:member"}
	})
	waitApplied(t, ctx, name, "192.0.2.1:443", hs)
	return name
}

func onlyGrantVersion(t *testing.T, version string) {
	t.Helper()
	if version != "v0.29.6" {
		t.Skip("unsupported capability row; grants need Headscale 0.29")
	}
}

// TestGrantLifecycle: a grant on an ingress tag reaches the live policy, leaves it at expiresAt
// without any object being touched, comes back when extended, and reports TargetUnknown when the
// ingress goes away, without ever freezing the policy.
func TestGrantLifecycle(t *testing.T) {
	for _, version := range versions {
		t.Run(version, func(t *testing.T) {
			onlyGrantVersion(t, version)
			ctx := testContext(t)
			hs := startHeadscale(t, ctx, version, "database", false)
			name := grantTailnet(t, ctx, hs)
			in := &tnv1.TailnetIngress{
				ObjectMeta: metav1.ObjectMeta{Name: name + "-db", Namespace: namespace},
				Spec: tnv1.TailnetIngressSpec{
					TailnetRef: tnv1.TailnetRef{Name: name}, Tag: "tag:ingress-granted", AllowFrom: []string{"autogroup:member"},
					Exposes: []tnv1.Expose{{Name: "pg", Port: 5432, Backend: tnv1.Backend{Service: "fixture-backend", Port: 5432}}},
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
			eventually(t, ctx, "ingress tag in the live policy", func() bool {
				return strings.Contains(livePolicy(t, ctx, hs), "tag:ingress-granted")
			})

			const user = "grant-lifecycle@example.com"
			expires := time.Now().Add(20 * time.Second).Truncate(time.Second)
			g := createGrant(t, ctx, name+"-grant", name, user, tnv1.GrantTarget{Tag: "tag:ingress-granted"}, &expires, 5432)
			eventually(t, ctx, "grant in the live policy and Granted", func() bool {
				return strings.Contains(livePolicy(t, ctx, hs), user) && grantIs(t, ctx, g.Name, "Granted")
			})
			if !time.Now().Before(expires) {
				t.Fatal("fixture too slow: the grant expired before it was observed as granted")
			}

			// Expiry: nothing is written to any object; the operator's own requeue removes the grant.
			eventually(t, ctx, "grant gone from the live policy", func() bool {
				return !strings.Contains(livePolicy(t, ctx, hs), user)
			})
			gone := time.Now()
			if gone.Before(expires) {
				t.Fatalf("grant left the live policy %v before expiresAt", expires.Sub(gone))
			}
			if late := gone.Sub(expires); late > 15*time.Second {
				t.Fatalf("grant left the live policy %v after expiresAt, want at most 15s", late)
			}
			t.Logf("grant left the live policy %v after expiresAt", gone.Sub(expires).Round(100*time.Millisecond))
			eventually(t, ctx, "grant Expired", func() bool { return grantIs(t, ctx, g.Name, "Expired") })

			// Extension: a new expiresAt makes the same object active again.
			if err := retry.RetryOnConflict(retry.DefaultBackoff, func() error {
				var cur tnv1.TailnetGrant
				if err := kube.Get(ctx, client.ObjectKeyFromObject(g), &cur); err != nil {
					return err
				}
				at := metav1.NewTime(time.Now().Add(time.Hour))
				cur.Spec.ExpiresAt = &at
				return kube.Update(ctx, &cur)
			}); err != nil {
				t.Fatal(err)
			}
			eventually(t, ctx, "extended grant Granted again", func() bool {
				return strings.Contains(livePolicy(t, ctx, hs), user) && grantIs(t, ctx, g.Name, "Granted")
			})

			// The target goes away: the grant is no longer rendered and the policy still applies.
			if err := kube.Delete(ctx, in); err != nil {
				t.Fatal(err)
			}
			eventually(t, ctx, "grant TargetUnknown, policy still applied", func() bool {
				live := livePolicy(t, ctx, hs)
				return grantIs(t, ctx, g.Name, "TargetUnknown") && !strings.Contains(live, user) &&
					!strings.Contains(live, "tag:ingress-granted") && policyInSync(t, ctx, name)
			})
		})
	}
}

// TestGrantSiteTarget: a host inside a TailnetSite is granted; a host outside every site is not
// rendered and reports TargetOutsideSites.
func TestGrantSiteTarget(t *testing.T) {
	for _, version := range versions {
		t.Run(version, func(t *testing.T) {
			onlyGrantVersion(t, version)
			ctx := testContext(t)
			hs := startHeadscale(t, ctx, version, "database", false)
			name := grantTailnet(t, ctx, hs)
			site := &tnv1.TailnetSite{ObjectMeta: metav1.ObjectMeta{Name: name + "-branch"}}
			site.Spec.TailnetRef.Name = name
			site.Spec.Owner = "e2e"
			site.Spec.Prefixes = []tnv1.GatewayPrefix{"198.51.100.0/24"}
			if err := kube.Create(ctx, site); err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() {
				cl, cancel := context.WithTimeout(context.Background(), 10*time.Second)
				defer cancel()
				_ = client.IgnoreNotFound(kube.Delete(cl, site))
			})

			const inside, outside = "grant-inside@example.com", "grant-outside@example.com"
			in := createGrant(t, ctx, name+"-inside", name, inside, tnv1.GrantTarget{Prefixes: []tnv1.GatewayPrefix{"198.51.100.5/32"}}, nil, 22, 443)
			out := createGrant(t, ctx, name+"-outside", name, outside, tnv1.GrantTarget{Prefixes: []tnv1.GatewayPrefix{"203.0.113.5/32"}}, nil, 22)
			eventually(t, ctx, "site host granted, outside host not rendered", func() bool {
				live := livePolicy(t, ctx, hs)
				return strings.Contains(live, inside) && strings.Contains(live, `"198.51.100.5/32"`) &&
					grantIs(t, ctx, in.Name, "Granted") && grantIs(t, ctx, out.Name, "TargetOutsideSites") && policyInSync(t, ctx, name)
			})
			if live := livePolicy(t, ctx, hs); strings.Contains(live, outside) || strings.Contains(live, "203.0.113.5") {
				t.Fatal("a grant outside every site reached the live policy")
			}
		})
	}
}

// TestGrantSpokeTag: an ingress tag that a merged fragment grants to is a valid target. When the
// fragment stops declaring it the grant reports TargetUnknown and the policy still applies. The
// counter-check proves the guard is load-bearing: real Headscale rejects a policy whose grant names
// an undeclared tag as dst, and accepts the same policy with a declared one.
func TestGrantSpokeTag(t *testing.T) {
	for _, version := range versions {
		t.Run(version, func(t *testing.T) {
			onlyGrantVersion(t, version)
			ctx := testContext(t)
			hs := startHeadscale(t, ctx, version, "database", false)
			name := grantTailnet(t, ctx, hs)
			frag := &corev1.ConfigMap{
				ObjectMeta: metav1.ObjectMeta{Name: name + "-fragment", Namespace: namespace},
				Data:       map[string]string{"policy": `{"tagOwners":{"tag:spoke-api":["tag:fabric"]},"grants":[{"src":["tag:spoke-api"],"dst":["tag:spoke-api"],"ip":["tcp:443"]}]}`},
			}
			if err := kube.Create(ctx, frag); err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() {
				cl, cancel := context.WithTimeout(context.Background(), 10*time.Second)
				defer cancel()
				_ = client.IgnoreNotFound(kube.Delete(cl, frag))
			})
			updateTailnet(t, ctx, name, func(tn *tnv1.Tailnet) { tn.Spec.Policy.FragmentConfigMaps = []string{frag.Name} })
			eventually(t, ctx, "fragment tag in the live policy", func() bool {
				return strings.Contains(livePolicy(t, ctx, hs), "tag:spoke-api")
			})

			const user = "grant-spoke@example.com"
			g := createGrant(t, ctx, name+"-spoke", name, user, tnv1.GrantTarget{Tag: "tag:spoke-api"}, nil, 443)
			eventually(t, ctx, "grant on the spoke tag Granted", func() bool {
				return strings.Contains(livePolicy(t, ctx, hs), user) && grantIs(t, ctx, g.Name, "Granted")
			})

			// The fragment no longer declares the tag.
			if err := retry.RetryOnConflict(retry.DefaultBackoff, func() error {
				var cur corev1.ConfigMap
				if err := kube.Get(ctx, client.ObjectKeyFromObject(frag), &cur); err != nil {
					return err
				}
				cur.Data["policy"] = `{"tagOwners":{},"grants":[]}`
				return kube.Update(ctx, &cur)
			}); err != nil {
				t.Fatal(err)
			}
			eventually(t, ctx, "grant TargetUnknown, policy still applied", func() bool {
				live := livePolicy(t, ctx, hs)
				return grantIs(t, ctx, g.Name, "TargetUnknown") && !strings.Contains(live, user) &&
					!strings.Contains(live, "tag:spoke-api") && policyInSync(t, ctx, name)
			})

			// Load-bearing: without the guard this grant would have frozen the policy. The control
			// differs only in the dst tag, so the unknown user is not what Headscale objects to.
			const control = `{"tagOwners":{"tag:known":[]},"grants":[{"src":["grant-spoke@example.com"],"dst":["tag:known"],"ip":["tcp:443"]}]}`
			const ghost = `{"tagOwners":{"tag:known":[]},"grants":[{"src":["grant-spoke@example.com"],"dst":["tag:ghost-target"],"ip":["tcp:443"]}]}`
			if err := hs.client().SetPolicy(ctx, control); err != nil {
				t.Fatalf("control policy with a declared dst tag rejected: %v", err)
			}
			err := hs.client().SetPolicy(ctx, ghost)
			if err == nil {
				t.Fatal("real Headscale accepted a grant to an undeclared dst tag; TargetUnknown is not load-bearing")
			}
			t.Logf("counter-check: Headscale %s accepts dst tag:known and rejects the undeclared dst tag:ghost-target: %v", version, err)
		})
	}
}
