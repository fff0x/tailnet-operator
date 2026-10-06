//go:build e2e

package e2e

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/util/retry"
	"k8s.io/utils/ptr"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/yaml"

	tnv1 "tsunaro.io/tailnet-operator/api/v1alpha1"
	"tsunaro.io/tailnet-operator/internal/policy"
)

func policyBase(action, destination string) string {
	return fmt.Sprintf(`{"tagOwners":{},"acls":[{"action":%q,"src":["*"],"dst":[%q]}]}`, action, destination)
}

func livePolicy(t *testing.T, ctx context.Context, hs *headscaleProcess) string {
	t.Helper()
	live, err := hs.client().GetPolicy(ctx)
	if err != nil {
		t.Fatal(err)
	}
	canonical, err := policy.Normalize([]byte(live))
	if err != nil {
		t.Fatal(err)
	}
	return canonical
}

func waitApplied(t *testing.T, ctx context.Context, name, destination string, hs *headscaleProcess) {
	t.Helper()
	eventually(t, ctx, "applied policy for "+destination, func() bool {
		tn := getTailnet(t, ctx, name)
		if !conditionMatches(tn, "PolicyApplied", metav1.ConditionTrue, "Applied") &&
			!conditionMatches(tn, "PolicyApplied", metav1.ConditionTrue, "InSync") {
			return false
		}
		live := livePolicy(t, ctx, hs)
		var doc struct {
			ACLs []struct {
				Action string   `json:"action"`
				Dst    []string `json:"dst"`
			} `json:"acls"`
		}
		if err := json.Unmarshal([]byte(live), &doc); err != nil {
			t.Fatal(err)
		}
		return len(doc.ACLs) == 1 && doc.ACLs[0].Action == "accept" && len(doc.ACLs[0].Dst) == 1 && doc.ACLs[0].Dst[0] == destination &&
			tn.Status.Policy != nil && tn.Status.Policy.AppliedHash == policy.Hash(live) && tn.Status.Policy.RenderedHash == policy.Hash(live)
	})
}

// Disjoint intervals reject constant-delay regressions while tolerating scheduler/network jitter.
func increasingRetryDelays(first, second time.Duration) bool {
	return first >= 12*time.Second && first <= 22*time.Second &&
		second >= 25*time.Second && second <= 40*time.Second
}

func TestRetryTimingAssertion(t *testing.T) {
	for _, tt := range []struct {
		name          string
		first, second time.Duration
		want          bool
	}{
		{"expected", 15 * time.Second, 30 * time.Second, true},
		{"jitter", 20 * time.Second, 35 * time.Second, true},
		{"constant-30", 30 * time.Second, 30 * time.Second, false},
		{"constant-15", 15 * time.Second, 15 * time.Second, false},
		{"too-fast", time.Second, 30 * time.Second, false},
		{"too-slow", 15 * time.Second, time.Minute, false},
	} {
		t.Run(tt.name, func(t *testing.T) {
			if got := increasingRetryDelays(tt.first, tt.second); got != tt.want {
				t.Fatalf("timing verdict = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestPolicyLifecycle(t *testing.T) {
	for _, version := range versions {
		t.Run(version, func(t *testing.T) {
			if version == "v0.28.0" {
				t.Skip("unsupported capability row; covered by TestPreflight, not a positive lifecycle claim")
			}
			ctx := testContext(t)
			hs := startHeadscale(t, ctx, version, "database", false)
			name := createTailnet(t, ctx, hs)
			// Empty DB must not block key bootstrap. It also must not be mistaken for file mode.
			waitCondition(t, ctx, name, "PolicyMode", metav1.ConditionUnknown, "ProbeFailed")
			waitCondition(t, ctx, name, "HeadscaleCompatible", metav1.ConditionUnknown, "ProbeFailed")
			first := policyBase("accept", "192.0.2.1:443")
			enablePolicy(t, ctx, name, first, "Apply")
			waitApplied(t, ctx, name, "192.0.2.1:443", hs)

			// Trigger preflight after the first apply; no controller sleeps or test-only requeue knobs.
			// Switching DryRun/Apply also proves that rendering alone cannot change the server.
			second := policyBase("accept", "192.0.2.2:443")
			updateTailnet(t, ctx, name, func(tn *tnv1.Tailnet) { tn.Spec.Policy.Mode = "DryRun" })
			waitCondition(t, ctx, name, "HeadscaleCompatible", metav1.ConditionTrue, "Compatible")
			waitCondition(t, ctx, name, "PolicyApplied", metav1.ConditionFalse, "DryRun")
			before := livePolicy(t, ctx, hs)
			writesBefore := len(hs.policyWrites())
			updateBase(t, ctx, name, second)
			eventually(t, ctx, "new DryRun render", func() bool {
				tn := getTailnet(t, ctx, name)
				return tn.Status.Policy != nil && tn.Status.Policy.RenderedHash != policy.Hash(before)
			})
			if livePolicy(t, ctx, hs) != before || len(hs.policyWrites()) != writesBefore {
				t.Fatal("DryRun changed the live policy")
			}
			updateTailnet(t, ctx, name, func(tn *tnv1.Tailnet) { tn.Spec.Policy.Mode = "Apply" })
			waitApplied(t, ctx, name, "192.0.2.2:443", hs)
			good := livePolicy(t, ctx, hs)
			writesBefore = len(hs.policyWrites())

			updateBase(t, ctx, name, "{ broken")
			waitCondition(t, ctx, name, "PolicyRendered", metav1.ConditionFalse, "BaseInvalid")
			if livePolicy(t, ctx, hs) != good || len(hs.policyWrites()) != writesBefore {
				t.Fatal("invalid local render reached Headscale")
			}
			// This parses/renders locally but fails real Headscale validation.
			updateBase(t, ctx, name, policyBase("definitely-invalid-action", "192.0.2.3:443"))
			waitCondition(t, ctx, name, "PolicyApplied", metav1.ConditionFalse, "PolicyRejected")
			var rejected []policyWrite
			eventually(t, ctx, "three rejected policy writes", func() bool {
				rejected = nil
				for _, w := range hs.policyWrites()[writesBefore:] {
					if w.status >= 400 {
						rejected = append(rejected, w)
					}
				}
				return len(rejected) >= 3
			})
			// retryIn is currently a log field, not status. Observe the actual 15s/30s retries,
			// with scheduling tolerance, rather than adding an API field solely for the test.
			firstDelay, secondDelay := rejected[1].at.Sub(rejected[0].at), rejected[2].at.Sub(rejected[1].at)
			if !increasingRetryDelays(firstDelay, secondDelay) {
				t.Fatalf("rejected-write backoff = %s/%s, want approximately 15s/30s", firstDelay, secondDelay)
			}
			if livePolicy(t, ctx, hs) != good {
				t.Fatal("Headscale rejection changed the previously applied policy")
			}
			updateBase(t, ctx, name, second)
			waitApplied(t, ctx, name, "192.0.2.2:443", hs)
			waitCondition(t, ctx, name, "PolicyApplied", metav1.ConditionTrue, "InSync")
		})
	}
}

// A TailnetGateway of the Tailnet contributes its tags to tagOwners and its routes to
// autoApprovers.routes, and a gateway change re-renders. DryRun makes the render observable in the
// rendered ConfigMap while the real Headscale must see no write.
func TestPolicyGatewayRoutes(t *testing.T) {
	for _, version := range versions {
		t.Run(version, func(t *testing.T) {
			if version == "v0.28.0" {
				t.Skip("unsupported capability row; covered by TestPreflight")
			}
			ctx := testContext(t)
			hs := startHeadscale(t, ctx, version, "database", false)
			name := createTailnet(t, ctx, hs)
			enablePolicy(t, ctx, name, policyBase("accept", "192.0.2.1:443"), "DryRun")
			waitCondition(t, ctx, name, "PolicyApplied", metav1.ConditionFalse, "DryRun")
			writesBefore := len(hs.policyWrites())

			data, err := os.ReadFile(filepath.Join(root, "deploy", "examples", "tailnetgateway.yaml"))
			if err != nil {
				t.Fatal(err)
			}
			gw := &tnv1.TailnetGateway{}
			if err := yaml.Unmarshal(data, gw); err != nil {
				t.Fatal(err)
			}
			gw.Name = name + "-gw"
			gw.Spec.TailnetRef.Name = tnv1.GatewayName(name)
			gw.Spec.Tags = []string{"tag:e2e-site"}
			gw.Spec.Routes = tnv1.GatewayRoutes{LAN: []tnv1.GatewayPrefix{"10.77.0.0/24"}, AdvertiseEgressTargets: ptr.To(false)}
			if err := kube.Create(ctx, gw); err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() {
				cleanup, cancel := context.WithTimeout(context.Background(), 10*time.Second)
				defer cancel()
				_ = client.IgnoreNotFound(kube.Delete(cleanup, gw))
			})
			approvers := func(doc map[string]any, cidr string) string {
				routes, _ := doc["autoApprovers"].(map[string]any)["routes"].(map[string]any)
				b, _ := json.Marshal(routes[cidr])
				return string(b)
			}
			rendered := func() map[string]any {
				var cm corev1.ConfigMap
				if kube.Get(ctx, types.NamespacedName{Namespace: namespace, Name: name + "-base-rendered"}, &cm) != nil {
					return nil
				}
				var doc map[string]any
				if json.Unmarshal([]byte(cm.Data["policy"]), &doc) != nil {
					return nil
				}
				return doc
			}
			eventually(t, ctx, "gateway tag and routes rendered", func() bool {
				doc := rendered()
				if doc == nil {
					return false
				}
				owner, _ := json.Marshal(doc["tagOwners"].(map[string]any)["tag:e2e-site"])
				return string(owner) == `["autogroup:member"]` && approvers(doc, "10.77.0.0/24") == `["tag:e2e-site"]` && approvers(doc, "198.51.100.0/24") == `["tag:e2e-site"]`
			})
			if err := retry.RetryOnConflict(retry.DefaultBackoff, func() error {
				if err := kube.Get(ctx, client.ObjectKeyFromObject(gw), gw); err != nil {
					return err
				}
				gw.Spec.Routes.LAN = []tnv1.GatewayPrefix{"10.78.0.0/24"}
				return kube.Update(ctx, gw)
			}); err != nil {
				t.Fatal(err)
			}
			eventually(t, ctx, "gateway change re-rendered", func() bool {
				doc := rendered()
				return doc != nil && approvers(doc, "10.78.0.0/24") == `["tag:e2e-site"]` && approvers(doc, "10.77.0.0/24") == "null"
			})
			if len(hs.policyWrites()) != writesBefore {
				t.Fatal("DryRun gateway render reached Headscale")
			}
		})
	}
}
