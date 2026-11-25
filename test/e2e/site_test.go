//go:build e2e

package e2e

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"

	tnv1 "tsunaro.io/tailnet-operator/api/v1alpha1"
)

func getSite(t *testing.T, ctx context.Context, name string) *tnv1.TailnetSite {
	t.Helper()
	var s tnv1.TailnetSite
	if err := kube.Get(ctx, types.NamespacedName{Name: name}, &s); err != nil {
		t.Fatal(err)
	}
	return &s
}

func siteCond(s *tnv1.TailnetSite, typ string, status metav1.ConditionStatus, reason string) bool {
	c := meta.FindStatusCondition(s.Status.Conditions, typ)
	return c != nil && c.Status == status && c.Reason == reason && c.ObservedGeneration == s.Generation
}

// TestSiteApprovalReplay: a TailnetSite advertised by a tagged node that is NOT operator-managed
// (white-box route fixture, like a tagged router in another cluster) gets its prefix rendered
// into autoApprovers and approved on that node; the site reports Ready. A younger overlapping
// site is blocked (RouteConflict) and never rendered; a node without the advertiser tag that
// advertises an overlapping route is reported, not blocked, and gets no approval.
func TestSiteApprovalReplay(t *testing.T) {
	for _, version := range versions {
		t.Run(version, func(t *testing.T) {
			if version != "v0.29.6" {
				t.Skip("unsupported capability row; route fixture is verified only on v0.29.6")
			}
			ctx := testContext(t)
			hs := startHeadscale(t, ctx, version, "database", false)
			const site, host, overlap, foreignRoute = "192.0.2.0/24", "198.51.100.9/32", "192.0.2.128/25", "192.0.2.0/26"
			const base = `{"tagOwners":{"tag:fabric":[],"tag:route-fixture":[],"tag:unmatched":[]},"acls":[{"action":"accept","src":["*"],"dst":["192.0.2.7:443"]}]}`
			if err := hs.client().SetPolicy(ctx, base); err != nil {
				t.Fatal(err)
			}
			hs.cli(t, ctx, "users", "create", "fixture", "--output", "json")
			router := hs.registerRouteNode(t, ctx, "router", "tag:route-fixture")
			foreign := hs.registerRouteNode(t, ctx, "foreign", "tag:unmatched")
			hs.seedAdvertisedRoutes(t, ctx, map[string][]string{router: {site, host}, foreign: {foreignRoute}})

			name := createTailnet(t, ctx, hs)
			updateTailnet(t, ctx, name, func(tn *tnv1.Tailnet) {
				tn.Spec.ReservedNetworks = []tnv1.ReservedNetwork{{Name: "nodes", Prefixes: []tnv1.GatewayPrefix{"100.64.0.0/10"}}}
			})
			enablePolicy(t, ctx, name, base, "Apply")
			waitApplied(t, ctx, name, "192.0.2.7:443", hs)
			if len(routeNode(t, ctx, hs, router).ApprovedRoutes) != 0 {
				t.Fatal("base without autoApprovers unexpectedly approved a route")
			}

			newSite := func(suffix string, prefixes ...string) *tnv1.TailnetSite {
				s := &tnv1.TailnetSite{ObjectMeta: metav1.ObjectMeta{Name: name + "-" + suffix}}
				s.Spec.TailnetRef.Name = name
				s.Spec.Owner = "e2e"
				s.Spec.AdvertisedBy.Tags = []string{"tag:route-fixture"}
				for _, p := range prefixes {
					s.Spec.Prefixes = append(s.Spec.Prefixes, tnv1.GatewayPrefix(p))
				}
				if err := kube.Create(ctx, s); err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() {
					cleanup, cancel := context.WithTimeout(context.Background(), 10*time.Second)
					defer cancel()
					if err := client.IgnoreNotFound(kube.Delete(cleanup, s)); err != nil {
						t.Errorf("delete TailnetSite fixture: %v", err)
					}
				})
				return s
			}
			older := newSite("branch", site)
			// Created after the first site is observed, so the ordering is unambiguous.
			eventually(t, ctx, "older site observed", func() bool {
				return getSite(t, ctx, older.Name).Status.ObservedGeneration == 1
			})
			younger := newSite("overlap", overlap)

			eventually(t, ctx, "site rendered, approved and Ready", func() bool {
				var doc struct {
					AutoApprovers struct {
						Routes map[string][]string `json:"routes"`
					} `json:"autoApprovers"`
				}
				if err := json.Unmarshal([]byte(livePolicy(t, ctx, hs)), &doc); err != nil {
					t.Fatal("decode live policy failed")
				}
				_, overlapRendered := doc.AutoApprovers.Routes[overlap]
				s := getSite(t, ctx, older.Name)
				return sameRoutes(doc.AutoApprovers.Routes[site], "tag:route-fixture") && !overlapRendered &&
					sameRoutes(routeNode(t, ctx, hs, router).ApprovedRoutes, site) &&
					siteCond(s, "Ready", metav1.ConditionTrue, "Ready") &&
					sameRoutes(s.Status.RoutesApproved, site) && sameRoutes(s.Status.RoutesAdvertised, site)
			})
			s := getSite(t, ctx, older.Name)
			if c := meta.FindStatusCondition(s.Status.Conditions, "UnmanagedOverlap"); c == nil || c.Status != metav1.ConditionTrue || !strings.Contains(c.Message, "foreign") {
				t.Fatalf("UnmanagedOverlap must name the foreign node: %+v", c)
			}
			if len(routeNode(t, ctx, hs, foreign).ApprovedRoutes) != 0 {
				t.Fatal("foreign node without the advertiser tag was approved")
			}
			eventually(t, ctx, "younger site blocked", func() bool {
				y := getSite(t, ctx, younger.Name)
				c := meta.FindStatusCondition(y.Status.Conditions, "RouteConflict")
				return siteCond(y, "Ready", metav1.ConditionFalse, "RouteConflict") && c != nil && c.Reason == "OverlapsSite" && strings.Contains(c.Message, older.Name)
			})
			tn := getTailnet(t, ctx, name)
			if c := meta.FindStatusCondition(tn.Status.Conditions, "PolicyRendered"); c == nil || !strings.Contains(c.Message, "site/"+younger.Name) {
				t.Fatalf("PolicyRendered must list the blocked site as skipped: %+v", c)
			}
			// The host route is not part of any site: advertised, never approved by the operator.
			if sameRoutes(routeNode(t, ctx, hs, router).ApprovedRoutes, site, host) {
				t.Fatal("unrelated host route was approved")
			}
		})
	}
}
