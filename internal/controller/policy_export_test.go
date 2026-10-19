package controller

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	tnv1 "tsunaro.io/tailnet-operator/api/v1alpha1"
)

// a minimal valid hub base (tagOwners + one grant, so not ErrEmpty).
const hubBase = `{"tagOwners":{"tag:base":["group:admins"]},"groups":{"group:admins":["admin@"]},` +
	`"grants":[{"src":["group:admins"],"dst":["tag:base"],"ip":["*"]}]}`

// a valid spoke fragment: only the three additive blocks.
const spokeFragment = `{"tagOwners":{"tag:egress-spoke-db":["group:operator"]},` +
	`"autoApprovers":{"routes":{"10.9.0.5/32":["tag:fabric"]}},` +
	`"grants":[{"src":["tag:egress-spoke-db"],"dst":["10.9.0.5/32"],"ip":["tcp:5432"]}]}`

func exportScheme(t *testing.T) *runtime.Scheme {
	t.Helper()
	s := runtime.NewScheme()
	_ = clientgoscheme.AddToScheme(s)
	_ = tnv1.AddToScheme(s)
	return s
}

// TestPolicyExportSpoke: mode Export renders a fragment ConfigMap and never touches the server.
func TestPolicyExportSpoke(t *testing.T) {
	s := exportScheme(t)
	tn := &tnv1.Tailnet{ObjectMeta: metav1.ObjectMeta{Name: "corp", UID: "spoke-uid", Generation: 2},
		Spec: tnv1.TailnetSpec{TagTemplate: "tag:egress-{name}", IngressTagTemplate: "tag:ingress-{name}",
			Policy: tnv1.PolicySpec{Mode: "Export",
				TagOwners: []string{"group:operator"}, RouteApprovers: []string{"tag:fabric"},
				IngressSourceAllowlist: []string{"group:*"}}}}
	eg := &tnv1.TailnetEgress{ObjectMeta: metav1.ObjectMeta{Name: "spoke-db", Namespace: "operator"},
		Spec: tnv1.TailnetEgressSpec{TailnetRef: tnv1.TailnetRef{Name: "corp"},
			Targets: []tnv1.Target{{Name: "db", Address: "10.9.0.5", Port: 5432}}}}
	ing := &tnv1.TailnetIngress{ObjectMeta: metav1.ObjectMeta{Name: "spoke-api", Namespace: "apps"},
		Spec: tnv1.TailnetIngressSpec{TailnetRef: tnv1.TailnetRef{Name: "corp"},
			AllowFrom: []string{"group:ops"}, Exposes: []tnv1.Expose{{Name: "https", Port: 443}}}}
	c := fake.NewClientBuilder().WithScheme(s).WithObjects(tn, eg, ing).WithStatusSubresource(tn).Build()
	r := TailnetPolicyReconciler{Client: c, Scheme: s, OperatorNamespace: "operator"}
	if _, err := r.Reconcile(context.Background(), ctrl.Request{NamespacedName: types.NamespacedName{Name: "corp"}}); err != nil {
		t.Fatal(err)
	}
	if err := c.Get(context.Background(), types.NamespacedName{Name: "corp"}, tn); err != nil {
		t.Fatal(err)
	}
	if condReason(tn.Status.Conditions, "PolicyRendered") != "Rendered" || condReason(tn.Status.Conditions, "PolicyApplied") != "Export" {
		t.Fatalf("conditions = %+v", tn.Status.Conditions)
	}
	if tn.Status.Policy == nil || tn.Status.Policy.RenderedHash == "" || tn.Status.Policy.AppliedHash != "" {
		t.Fatalf("export must render without applying: %+v", tn.Status.Policy)
	}
	var cm corev1.ConfigMap
	if err := c.Get(context.Background(), types.NamespacedName{Namespace: "operator", Name: "corp-policy-fragment"}, &cm); err != nil {
		t.Fatal(err)
	}
	var doc map[string]any
	if err := json.Unmarshal([]byte(cm.Data[policyKey]), &doc); err != nil {
		t.Fatal(err)
	}
	if len(doc) != 3 || doc["acls"] != nil || doc["groups"] != nil {
		t.Fatalf("fragment carried non-additive keys: %s", cm.Data[policyKey])
	}
	owners := doc["tagOwners"].(map[string]any)
	if owners["tag:egress-spoke-db"] == nil || owners["tag:ingress-spoke-api"] == nil {
		t.Fatalf("fragment tagOwners = %v", owners)
	}
}

// TestPolicyHubFragments: a hub merges a listed fragment, and fails closed when it is absent or
// malformed — in both failure cases without writing the server.
func TestPolicyHubFragments(t *testing.T) {
	for _, tc := range []struct {
		name, fragData, reason string
		haveFragment           bool
		wantWrites             int
		wantGrant              bool
	}{
		{"merged", spokeFragment, "Applied", true, 1, true},
		{"missing", "", "FragmentMissing", false, 0, false},
		{"invalid", `{"acls":[{"action":"accept"}]}`, "FragmentInvalid", true, 0, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var written string
			reads, writes := 0, 0
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
				switch {
				case req.URL.Path == "/api/v1/policy" && req.Method == http.MethodGet:
					reads++
					_ = json.NewEncoder(w).Encode(map[string]any{"policy": "{}", "updatedAt": "2026-09-30T00:00:00Z"})
				case req.URL.Path == "/api/v1/policy" && req.Method == http.MethodPut:
					writes++
					var body struct {
						Policy string `json:"policy"`
					}
					_ = json.NewDecoder(req.Body).Decode(&body)
					written = body.Policy
					_, _ = w.Write([]byte(`{}`))
				case req.URL.Path == "/api/v1/node":
					_, _ = w.Write([]byte(`{"nodes":[]}`))
				default:
					http.NotFound(w, req)
				}
			}))
			defer srv.Close()

			s := exportScheme(t)
			tn := &tnv1.Tailnet{ObjectMeta: metav1.ObjectMeta{Name: "corp", UID: "hub-uid", Generation: 2},
				Spec: tnv1.TailnetSpec{Server: srv.URL, Policy: tnv1.PolicySpec{BaseConfigMap: "base", Mode: "Apply",
					TagOwners: []string{"group:admins"}, RouteApprovers: []string{"tag:fabric"},
					FragmentConfigMaps: []string{"spoke-frag"}}}}
			baseCM := &corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Name: "base", Namespace: "operator"}, Data: map[string]string{policyKey: hubBase}}
			secret := &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: workingSecretName("corp"), Namespace: "operator"}, Data: map[string][]byte{apiKeyData: []byte("key")}}
			b := fake.NewClientBuilder().WithScheme(s).WithObjects(tn, baseCM, secret).WithStatusSubresource(tn)
			if tc.haveFragment {
				b = b.WithObjects(&corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Name: "spoke-frag", Namespace: "operator"}, Data: map[string]string{policyKey: tc.fragData}})
			}
			c := b.Build()
			r := TailnetPolicyReconciler{Client: c, Scheme: s, OperatorNamespace: "operator"}
			if _, err := r.Reconcile(context.Background(), ctrl.Request{NamespacedName: types.NamespacedName{Name: "corp"}}); err != nil {
				t.Fatal(err)
			}
			if err := c.Get(context.Background(), types.NamespacedName{Name: "corp"}, tn); err != nil {
				t.Fatal(err)
			}
			if writes != tc.wantWrites {
				t.Fatalf("writes = %d, want %d", writes, tc.wantWrites)
			}
			if tc.wantGrant {
				if condReason(tn.Status.Conditions, "PolicyApplied") != tc.reason {
					t.Fatalf("PolicyApplied = %s, want %s", condReason(tn.Status.Conditions, "PolicyApplied"), tc.reason)
				}
				if !strings.Contains(written, "tag:egress-spoke-db") {
					t.Fatalf("spoke grant not written: %s", written)
				}
				if c := meta.FindStatusCondition(tn.Status.Conditions, "PolicyRendered"); c == nil || !strings.Contains(c.Message, "1 fragments merged") {
					t.Fatalf("PolicyRendered message lacks fragment count: %+v", c)
				}
			} else if condReason(tn.Status.Conditions, "PolicyRendered") != tc.reason {
				t.Fatalf("PolicyRendered = %s, want %s", condReason(tn.Status.Conditions, "PolicyRendered"), tc.reason)
			}
			_ = reads
		})
	}
}

// TestPolicyByConfigMap: a change to a base or a listed fragment ConfigMap wakes exactly the
// Tailnets that reference it; other namespaces and unrelated names wake none.
func TestPolicyByConfigMap(t *testing.T) {
	s := exportScheme(t)
	hub := &tnv1.Tailnet{ObjectMeta: metav1.ObjectMeta{Name: "hub"},
		Spec: tnv1.TailnetSpec{Policy: tnv1.PolicySpec{BaseConfigMap: "base", FragmentConfigMaps: []string{"frag-a", "frag-b"}}}}
	other := &tnv1.Tailnet{ObjectMeta: metav1.ObjectMeta{Name: "other"},
		Spec: tnv1.TailnetSpec{Policy: tnv1.PolicySpec{BaseConfigMap: "frag-a"}}}
	r := TailnetPolicyReconciler{Client: fake.NewClientBuilder().WithScheme(s).WithObjects(hub, other).Build(), Scheme: s, OperatorNamespace: "operator"}
	cm := func(ns, name string) *corev1.ConfigMap {
		return &corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Namespace: ns, Name: name}}
	}
	names := func(reqs []ctrl.Request) string {
		var out []string
		for _, q := range reqs {
			out = append(out, q.Name)
		}
		return strings.Join(out, ",")
	}
	ctx := context.Background()
	if got := names(r.byPolicyConfigMap(ctx, cm("operator", "base"))); got != "hub" {
		t.Fatalf("base → %q", got)
	}
	if got := names(r.byPolicyConfigMap(ctx, cm("operator", "frag-a"))); got != "hub,other" {
		t.Fatalf("frag-a (fragment of hub, base of other) → %q", got)
	}
	if got := names(r.byPolicyConfigMap(ctx, cm("operator", "frag-b"))); got != "hub" {
		t.Fatalf("frag-b → %q", got)
	}
	if got := r.byPolicyConfigMap(ctx, cm("tenant", "base")); got != nil {
		t.Fatalf("foreign namespace enqueued %v", got)
	}
	if got := r.byPolicyConfigMap(ctx, cm("operator", "unrelated")); got != nil {
		t.Fatalf("unrelated name enqueued %v", got)
	}
}

// TestPublishRenderAdoption: publishRender takes over an ownerRef-less render ConfigMap that still
// carries our role label, and refuses one labelled for something else.
func TestPublishRenderAdoption(t *testing.T) {
	s := exportScheme(t)
	tn := &tnv1.Tailnet{ObjectMeta: metav1.ObjectMeta{Name: "corp", UID: "corp-uid"}}
	for _, tc := range []struct {
		name         string
		labels       map[string]string
		wantConflict bool
	}{
		{"orphaned-ours", map[string]string{roleLabel: rolePolicyRender}, false},
		{"foreign-label", map[string]string{roleLabel: "something-else"}, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cm := &corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Name: "headscale-policy-rendered", Namespace: "operator", Labels: tc.labels},
				Data: map[string]string{policyKey: "# stale"}}
			c := fake.NewClientBuilder().WithScheme(s).WithObjects(tn, cm).Build()
			r := TailnetPolicyReconciler{Client: c, Scheme: s, OperatorNamespace: "operator"}
			conflict, err := r.publishRender(context.Background(), tn, "headscale-policy-rendered", "# new")
			if err != nil {
				t.Fatal(err)
			}
			if conflict != tc.wantConflict {
				t.Fatalf("conflict=%v want %v", conflict, tc.wantConflict)
			}
			var got corev1.ConfigMap
			if err := c.Get(context.Background(), types.NamespacedName{Namespace: "operator", Name: "headscale-policy-rendered"}, &got); err != nil {
				t.Fatal(err)
			}
			if tc.wantConflict {
				if got.Data[policyKey] != "# stale" || ownedBy(&got, tn.UID) {
					t.Fatal("foreign ConfigMap was adopted or overwritten")
				}
			} else if got.Data[policyKey] != "# new" || !ownedBy(&got, tn.UID) {
				t.Fatalf("orphaned ConfigMap not adopted: data=%q owners=%v", got.Data[policyKey], got.OwnerReferences)
			}
		})
	}
}

func TestPolicyOwnedExport(t *testing.T) {
	tn := &tnv1.Tailnet{Spec: tnv1.TailnetSpec{Policy: tnv1.PolicySpec{Mode: "Export",
		TagOwners: []string{"group:operator"}, RouteApprovers: []string{"tag:fabric"}}}}
	if policyOwned(tn) {
		t.Fatal("an Export spoke is not an Apply writer")
	}
}
