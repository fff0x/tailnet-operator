//go:build e2e

package e2e

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// TestTestsSrcResolution exercises tag-based policy tests against a registered real Headscale
// node. It proves upstream semantic validation survives the operator's render/apply path;
// it does not claim a regression-revert result for a historical fix outside this repository.
func TestTestsSrcResolution(t *testing.T) {
	for _, version := range versions {
		t.Run(version, func(t *testing.T) {
			if version != "v0.29.6" {
				t.Skip("unsupported capability row; covered by TestPreflight")
			}
			ctx, cancel := context.WithTimeout(testContext(t), 60*time.Second)
			defer cancel()
			hs := startHeadscale(t, ctx, version, "database", false)
			const base = `{"tagOwners":{"tag:source":[]},"acls":[{"action":"accept","src":["tag:source"],"dst":["192.0.2.7:443"]}]}`
			if err := hs.client().SetPolicy(ctx, base); err != nil {
				t.Fatal(err)
			}
			hs.cli(t, ctx, "users", "create", "fixture", "--output", "json")
			id := hs.registerRouteNode(t, ctx, "source", "tag:source")
			node := routeNode(t, ctx, hs, id)
			if !sameRoutes(node.Tags, "tag:source") || len(node.IPAddresses) == 0 {
				t.Fatal("source fixture needs a real registered, tagged IP identity")
			}
			withTest := func(accept string) string {
				var doc map[string]any
				if err := json.Unmarshal([]byte(base), &doc); err != nil {
					t.Fatal(err)
				}
				doc["tests"] = []any{map[string]any{"src": "tag:source", "accept": []string{accept}, "deny": []string{"192.0.2.7:80"}}}
				b, err := json.Marshal(doc)
				if err != nil {
					t.Fatal(err)
				}
				return string(b)
			}
			name := createTailnet(t, ctx, hs)
			enablePolicy(t, ctx, name, withTest("192.0.2.7:443"), "Apply")
			waitApplied(t, ctx, name, "192.0.2.7:443", hs)
			lastGood := livePolicy(t, ctx, hs)
			var live struct {
				Tests []struct {
					Src    string   `json:"src"`
					Accept []string `json:"accept"`
					Deny   []string `json:"deny"`
				} `json:"tests"`
			}
			if err := json.Unmarshal([]byte(lastGood), &live); err != nil || len(live.Tests) != 1 ||
				live.Tests[0].Src != "tag:source" || !sameRoutes(live.Tests[0].Accept, "192.0.2.7:443") ||
				!sameRoutes(live.Tests[0].Deny, "192.0.2.7:80") {
				t.Fatal("live policy did not preserve the source and assertions")
			}
			writesBefore := len(hs.policyWrites())
			// Same valid ACL and source identity, but an impossible assertion: port 22 is denied.
			// A render that drops tests or a validator that skips source expansion must fail this gate.
			updateBase(t, ctx, name, withTest("192.0.2.7:22"))
			waitCondition(t, ctx, name, "PolicyApplied", metav1.ConditionFalse, "PolicyRejected")
			writes := hs.policyWrites()
			if len(writes) <= writesBefore || writes[len(writes)-1].status/100 == 2 {
				t.Fatal("semantic policy test must reach and be rejected by real Headscale")
			}
			if livePolicy(t, ctx, hs) != lastGood {
				t.Fatal("rejected policy test replaced the last good live policy")
			}
			updateBase(t, ctx, name, withTest("192.0.2.7:443"))
			waitCondition(t, ctx, name, "PolicyApplied", metav1.ConditionTrue, "InSync")
		})
	}
}
