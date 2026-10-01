//go:build e2e

package e2e

import (
	"context"
	"encoding/json"
	"slices"
	"testing"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	tnv1 "tsunaro.io/tailnet-operator/api/v1alpha1"
	"tsunaro.io/tailnet-operator/internal/headscale"
	"tsunaro.io/tailnet-operator/internal/policy"
)

func routeNode(t *testing.T, ctx context.Context, hs *headscaleProcess, id string) headscale.Node {
	t.Helper()
	nodes, err := hs.client().ListNodes(ctx)
	if err != nil {
		t.Fatal(err)
	}
	for _, node := range nodes {
		if node.ID == id {
			return node
		}
	}
	t.Fatal("registered route fixture node missing from REST response")
	return headscale.Node{}
}

func sameRoutes(got []string, want ...string) bool {
	got = slices.Clone(got)
	slices.Sort(got)
	slices.Sort(want)
	return slices.Equal(got, want)
}

func TestApprovalReplay(t *testing.T) {
	for _, version := range versions {
		t.Run(version, func(t *testing.T) {
			if version != "v0.29.3" {
				t.Skip("unsupported capability row; route fixture and replay are verified only on v0.29.3")
			}
			ctx := testContext(t)
			hs := startHeadscale(t, ctx, version, "database", false)
			const desired = "192.0.2.7/32"
			const unrelated = "198.51.100.9/32"
			const base = `{"tagOwners":{"tag:route-fixture":[],"tag:unmatched":[]},"acls":[{"action":"accept","src":["*"],"dst":["192.0.2.7:443"]}]}`
			// Tags must be declared before assigning them. There are deliberately no autoApprovers.
			if err := hs.client().SetPolicy(ctx, base); err != nil {
				t.Fatal(err)
			}
			hs.cli(t, ctx, "users", "create", "fixture", "--output", "json")
			matching := hs.registerRouteNode(t, ctx, "matching", "tag:route-fixture")
			unmatched := hs.registerRouteNode(t, ctx, "unmatched", "tag:unmatched")
			// White-box setup only: v0.29.3's debug/auth flow loses advertised routes.
			// No tsnet client, packet forwarding, or control-protocol advertisement is tested here.
			hs.seedAdvertisedRoutes(t, ctx, map[string][]string{
				matching: {desired, unrelated}, unmatched: {desired},
			})
			for _, fixture := range []struct {
				id, tag string
				routes  []string
			}{
				{matching, "tag:route-fixture", []string{desired, unrelated}},
				{unmatched, "tag:unmatched", []string{desired}},
			} {
				node := routeNode(t, ctx, hs, fixture.id)
				if !sameRoutes(node.AvailableRoutes, fixture.routes...) || !sameRoutes(node.Tags, fixture.tag) || len(node.ApprovedRoutes) != 0 {
					t.Fatal("fixture must expose the advertised routes and tag, with no approvals")
				}
			}

			name := createTailnet(t, ctx, hs)
			enablePolicy(t, ctx, name, base, "Apply")
			waitApplied(t, ctx, name, "192.0.2.7:443", hs)
			if len(routeNode(t, ctx, hs, matching).ApprovedRoutes) != 0 || len(routeNode(t, ctx, hs, unmatched).ApprovedRoutes) != 0 {
				t.Fatal("base without autoApprovers unexpectedly approved a route")
			}
			const withApprover = `{"tagOwners":{"tag:route-fixture":[],"tag:unmatched":[]},"acls":[{"action":"accept","src":["*"],"dst":["192.0.2.7:443"]}],"autoApprovers":{"routes":{"192.0.2.7/32":["tag:route-fixture"]}}}`
			updateBase(t, ctx, name, withApprover)
			eventually(t, ctx, "autoApprovers policy applied", func() bool {
				live := livePolicy(t, ctx, hs)
				var doc struct {
					AutoApprovers struct {
						Routes map[string][]string `json:"routes"`
					} `json:"autoApprovers"`
				}
				if err := json.Unmarshal([]byte(live), &doc); err != nil {
					t.Fatal("decode normalized fixture policy failed")
				}
				tn := getTailnet(t, ctx, name)
				return sameRoutes(doc.AutoApprovers.Routes[desired], "tag:route-fixture") &&
					tn.Status.Policy != nil && tn.Status.Policy.AppliedHash == policy.Hash(live) &&
					tn.Status.Policy.RenderedHash == policy.Hash(live) &&
					sameRoutes(routeNode(t, ctx, hs, matching).ApprovedRoutes, desired)
			})
			// A policy PUT itself autoapproves existing routes in Headscale, even for identical
			// policy text. The approval above therefore proves setup, NOT operator replay.
			updateTailnet(t, ctx, name, func(tn *tnv1.Tailnet) { tn.Spec.Headscale.Version = version })
			waitCondition(t, ctx, name, "PolicyApplied", metav1.ConditionTrue, "InSync")
			before := getTailnet(t, ctx, name)
			writesBefore := len(hs.policyWrites())
			if err := hs.client().SetApprovedRoutes(ctx, matching, []string{unrelated}); err != nil {
				t.Fatal(err)
			}
			if !sameRoutes(routeNode(t, ctx, hs, matching).ApprovedRoutes, unrelated) {
				t.Fatal("replay precondition failed: desired route must be absent, unrelated approval retained")
			}

			// Normal watched generation change on an ALREADY InSync Tailnet, never direct Reconcile.
			updateTailnet(t, ctx, name, func(tn *tnv1.Tailnet) { tn.Spec.Headscale.Version = "0.29.3" })
			waitCondition(t, ctx, name, "PolicyApplied", metav1.ConditionTrue, "InSync")
			after := getTailnet(t, ctx, name)
			if after.Generation <= before.Generation || after.Status.Policy.AppliedHash != before.Status.Policy.AppliedHash {
				t.Fatal("replay must observe a new generation without changing the applied policy")
			}
			if !sameRoutes(routeNode(t, ctx, hs, matching).ApprovedRoutes, desired, unrelated) {
				t.Fatal("InSync replay did not restore the desired/unrelated route union")
			}
			if len(routeNode(t, ctx, hs, unmatched).ApprovedRoutes) != 0 {
				t.Fatal("replay approved a route for the unmatched tag")
			}
			if len(hs.policyWrites()) != writesBefore {
				t.Fatal("policy PUT occurred during replay; Headscale autoapproval would make this a false positive")
			}
		})
	}
}
