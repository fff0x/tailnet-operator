package controller

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/tools/record"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	tnv1 "tsunaro.io/tailnet-operator/api/v1alpha1"
	"tsunaro.io/tailnet-operator/internal/policy"
)

const spokeToken = "SECRET-SPOKE-TOKEN-0123456789"

// prod2 fragments: v1, v2 adds a grant and drops a route, bad carries a tag outside the pattern.
const (
	prod2V1 = `{"tagOwners":{"tag:egress-prod-2-db":["group:admins"]},` +
		`"autoApprovers":{"routes":{"10.9.0.5/32":["tag:fabric"],"10.9.0.6/32":["tag:fabric"]}},` +
		`"grants":[{"src":["tag:egress-prod-2-db"],"dst":["10.9.0.5/32"],"ip":["tcp:5432"]}]}`
	prod2V2 = `{"tagOwners":{"tag:egress-prod-2-db":["group:admins"]},` +
		`"autoApprovers":{"routes":{"10.9.0.5/32":["tag:fabric"]}},` +
		`"grants":[{"src":["tag:egress-prod-2-db"],"dst":["10.9.0.5/32"],"ip":["tcp:5432"]},` +
		`{"src":["tag:egress-prod-2-db"],"dst":["10.9.0.5/32"],"ip":["tcp:5433"]}]}`
	prod2Bad = `{"tagOwners":{"tag:egress-other-db":["group:admins"]}}`
)

// spokeAPI fakes the spoke's API server: one ConfigMap, switchable body and status code; it
// records whether the bearer token arrived.
type spokeAPI struct {
	srv      *httptest.Server
	body     atomic.Pointer[string]
	code     atomic.Int32
	sawToken atomic.Bool
}

func newSpokeAPI(t *testing.T, body string) *spokeAPI {
	t.Helper()
	s := &spokeAPI{}
	s.body.Store(&body)
	s.code.Store(200)
	// TLS: client-go sends a bearer token over TLS only; a plain http spoke endpoint would be
	// silently unauthenticated.
	s.srv = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") == "Bearer "+spokeToken {
			s.sawToken.Store(true)
		}
		w.Header().Set("Content-Type", "application/json")
		if r.URL.Path != "/api/v1/namespaces/tailnet-system/configmaps/prod-2-policy-fragment" {
			http.NotFound(w, r)
			return
		}
		if c := int(s.code.Load()); c != 200 {
			w.WriteHeader(c)
			_, _ = fmt.Fprintf(w, `{"kind":"Status","apiVersion":"v1","status":"Failure","message":"server body with %s","code":%d}`, spokeToken, c)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"apiVersion": "v1", "kind": "ConfigMap",
			"metadata": map[string]any{"name": "prod-2-policy-fragment", "namespace": "tailnet-system"},
			"data":     map[string]string{policyKey: *s.body.Load()}})
	}))
	t.Cleanup(s.srv.Close)
	return s
}

func (s *spokeAPI) kubeconfig(server string) string {
	ca := base64.StdEncoding.EncodeToString(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: s.srv.Certificate().Raw}))
	return fmt.Sprintf(`apiVersion: v1
kind: Config
clusters:
- name: spoke
  cluster:
    server: %s
    certificate-authority-data: %s
users:
- name: reader
  user:
    token: %s
contexts:
- name: spoke
  context:
    cluster: spoke
    user: reader
current-context: spoke
`, server, ca, spokeToken)
}

type spokeHarness struct {
	t       *testing.T
	c       client.Client
	r       *TailnetPolicyReconciler
	written *string
	events  *record.FakeRecorder
}

func newSpokeHarness(t *testing.T, api *spokeAPI, approval string, server string) *spokeHarness {
	t.Helper()
	var written string
	hs := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		switch {
		case req.URL.Path == "/api/v1/policy" && req.Method == http.MethodGet:
			_ = json.NewEncoder(w).Encode(map[string]any{"policy": "{}", "updatedAt": "2026-09-30T00:00:00Z"})
		case req.URL.Path == "/api/v1/policy" && req.Method == http.MethodPut:
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
	t.Cleanup(hs.Close)
	if server == "" {
		server = api.srv.URL
	}
	s := exportScheme(t)
	tn := &tnv1.Tailnet{ObjectMeta: metav1.ObjectMeta{Name: "corp", UID: "hub-uid", Generation: 2},
		Spec: tnv1.TailnetSpec{Server: hs.URL, Policy: tnv1.PolicySpec{BaseConfigMap: "base", Mode: "Apply",
			TagOwners: []string{"group:admins"}, RouteApprovers: []string{"tag:fabric"},
			Spokes: []tnv1.SpokeRef{{Name: "prod-2", KubeconfigSecretRef: tnv1.SpokeKubeconfigRef{Name: "prod-2-kubeconfig"},
				Namespace: "tailnet-system", Approval: approval}}}}}
	objs := []client.Object{tn,
		&corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Name: "base", Namespace: "operator"}, Data: map[string]string{policyKey: hubBase}},
		&corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: workingSecretName("corp"), Namespace: "operator"}, Data: map[string][]byte{apiKeyData: []byte("key")}},
		&corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: "prod-2-kubeconfig", Namespace: "operator"}, Data: map[string][]byte{"kubeconfig": []byte(api.kubeconfig(server))}},
	}
	c := fake.NewClientBuilder().WithScheme(s).WithObjects(objs...).WithStatusSubresource(tn).Build()
	ev := record.NewFakeRecorder(16)
	return &spokeHarness{t: t, c: c, written: &written, events: ev,
		r: &TailnetPolicyReconciler{Client: c, Scheme: s, OperatorNamespace: "operator", Recorder: ev}}
}

func (h *spokeHarness) reconcile() tnv1.Tailnet {
	h.t.Helper()
	*h.written = ""
	if _, err := h.r.Reconcile(context.Background(), ctrl.Request{NamespacedName: types.NamespacedName{Name: "corp"}}); err != nil {
		h.t.Fatal(err)
	}
	var tn tnv1.Tailnet
	if err := h.c.Get(context.Background(), types.NamespacedName{Name: "corp"}, &tn); err != nil {
		h.t.Fatal(err)
	}
	return tn
}

func (h *spokeHarness) spoke(tn tnv1.Tailnet) tnv1.SpokeStatus {
	h.t.Helper()
	if len(tn.Status.Spokes) != 1 {
		h.t.Fatalf("status.spokes = %+v", tn.Status.Spokes)
	}
	return tn.Status.Spokes[0]
}

func (h *spokeHarness) copyData(name string) (string, bool) {
	var cm corev1.ConfigMap
	if err := h.c.Get(context.Background(), types.NamespacedName{Namespace: "operator", Name: name}, &cm); err != nil {
		return "", false
	}
	return cm.Data[policyKey], true
}

func (h *spokeHarness) annotate(name, value string) {
	h.t.Helper()
	var tn tnv1.Tailnet
	if err := h.c.Get(context.Background(), types.NamespacedName{Name: "corp"}, &tn); err != nil {
		h.t.Fatal(err)
	}
	before := tn.DeepCopy()
	if tn.Annotations == nil {
		tn.Annotations = map[string]string{}
	}
	tn.Annotations[approveAnnotationPrefix+name] = value
	if err := h.c.Patch(context.Background(), &tn, client.MergeFrom(before)); err != nil {
		h.t.Fatal(err)
	}
}

func hashOf(t *testing.T, doc string) string {
	t.Helper()
	c, err := policy.Normalize([]byte(doc))
	if err != nil {
		t.Fatal(err)
	}
	return policy.Hash(c)
}

func condReasonOf(conds []metav1.Condition, typ string) string {
	if c := meta.FindStatusCondition(conds, typ); c != nil {
		return c.Reason
	}
	return ""
}

// The rule (Auto): a valid fetched fragment is merged at once, recorded as approved and copied to
// <spoke>-policy-fragment-approved; the Tailnet reports SpokesReady=True/AllMerged.
func TestSpokeAutoMerges(t *testing.T) {
	api := newSpokeAPI(t, prod2V1)
	h := newSpokeHarness(t, api, "Auto", "")
	tn := h.reconcile()
	st := h.spoke(tn)
	if !api.sawToken.Load() {
		t.Fatal("kubeconfig token not used")
	}
	if st.ApprovedHash != hashOf(t, prod2V1) || st.FetchedHash != st.ApprovedHash || st.PendingHash != "" || st.ApprovedAt == nil {
		t.Fatalf("status = %+v", st)
	}
	if !strings.Contains(*h.written, "tag:egress-prod-2-db") {
		t.Fatalf("spoke grant not written: %s", *h.written)
	}
	if d, ok := h.copyData("prod-2-policy-fragment-approved"); !ok || d != prod2V1 {
		t.Fatalf("approved copy = %q %v", d, ok)
	}
	if r := condReasonOf(tn.Status.Conditions, "SpokesReady"); r != "AllMerged" {
		t.Fatalf("SpokesReady = %s", r)
	}
	select {
	case e := <-h.events.Events:
		if !strings.Contains(e, "SpokeFragmentAdopted") {
			t.Fatalf("event = %s", e)
		}
	default:
		t.Fatal("no adoption event")
	}
	// A second identical reconcile changes nothing and emits no spoke event (the fake Headscale
	// always answers "{}", so the policy controller itself reports a drift rewrite).
	tn2 := h.reconcile()
	if !h.spoke(tn2).ApprovedAt.Equal(st.ApprovedAt) {
		t.Fatalf("idempotency: %+v", h.spoke(tn2))
	}
	for len(h.events.Events) > 0 {
		if e := <-h.events.Events; strings.Contains(e, "Spoke") {
			t.Fatalf("unexpected spoke event: %s", e)
		}
	}
}

// The rule (Manual): a first fetch is pending and nothing is merged; the approve annotation with
// the pending hash adopts it; a later changed fetch is pending again with its delta, and until it is
// approved the hub merges approved ∩ fetched — removals apply, additions wait. A stale annotation is
// reported, not honoured.
func TestSpokeManualGate(t *testing.T) {
	api := newSpokeAPI(t, prod2V1)
	h := newSpokeHarness(t, api, "Manual", "")
	tn := h.reconcile()
	st := h.spoke(tn)
	v1 := hashOf(t, prod2V1)
	if st.PendingHash != v1 || st.ApprovedHash != "" || st.PendingSince == nil || strings.Contains(*h.written, "prod-2") {
		t.Fatalf("first fetch must be pending and unmerged: %+v written=%s", st, *h.written)
	}
	if _, ok := h.copyData("prod-2-policy-fragment-pending"); !ok {
		t.Fatal("pending copy missing")
	}
	if r := condReasonOf(st.Conditions, "SpokeFragmentApproved"); r != "ApprovalPending" {
		t.Fatalf("SpokeFragmentApproved = %s", r)
	}
	if r := condReasonOf(tn.Status.Conditions, "SpokesReady"); r != "ApprovalPending" {
		t.Fatalf("SpokesReady = %s", r)
	}

	// Wrong hash: nothing happens, condition says stale.
	h.annotate("prod-2", "deadbeef")
	st = h.spoke(h.reconcile())
	if st.ApprovedHash != "" || condReasonOf(st.Conditions, "SpokeFragmentApproved") != "ApprovalStale" {
		t.Fatalf("stale annotation honoured: %+v", st)
	}

	h.annotate("prod-2", v1)
	st = h.spoke(h.reconcile())
	if st.ApprovedHash != v1 || st.PendingHash != "" || !strings.Contains(*h.written, "10.9.0.6/32") {
		t.Fatalf("approval not adopted: %+v written=%s", st, *h.written)
	}
	if _, ok := h.copyData("prod-2-policy-fragment-pending"); ok {
		t.Fatal("pending copy not removed after approval")
	}

	// Spoke changes its fragment: pending with delta, merge is the intersection.
	v2 := prod2V2
	api.body.Store(&v2)
	st = h.spoke(h.reconcile())
	if st.ApprovedHash != v1 || st.PendingHash != hashOf(t, prod2V2) {
		t.Fatalf("changed fetch not pending: %+v", st)
	}
	if d := st.PendingDelta; d == nil || *d != (tnv1.SpokeDelta{GrantsAdded: 1, RoutesRemoved: 1}) {
		t.Fatalf("delta = %+v", d)
	}
	if strings.Contains(*h.written, "10.9.0.6/32") || strings.Contains(*h.written, "tcp:5433") || !strings.Contains(*h.written, "tcp:5432") {
		t.Fatalf("intersection not merged: %s", *h.written)
	}
	if condReasonOf(st.Conditions, "SpokeFragmentApproved") != "ApprovalStale" { // v1 annotation still there
		t.Fatalf("SpokeFragmentApproved = %s", condReasonOf(st.Conditions, "SpokeFragmentApproved"))
	}
}

// The rule: an unreachable spoke, a forbidden read or an invalid fragment keeps the last approved
// fragment merged and never leaks the kubeconfig token or a server body into status or events.
func TestSpokeFailuresKeepApproved(t *testing.T) {
	api := newSpokeAPI(t, prod2V1)
	h := newSpokeHarness(t, api, "Auto", "")
	h.reconcile()
	for _, tc := range []struct {
		name, reachable, valid string
		arrange                func()
	}{
		{"forbidden", "Forbidden", "Unknown", func() { api.code.Store(403) }},
		{"invalid", "Reachable", "FragmentInvalid", func() { api.code.Store(200); b := prod2Bad; api.body.Store(&b) }},
		{"unreachable", "Unreachable", "Unknown", func() { api.srv.Close() }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			tc.arrange()
			tn := h.reconcile()
			st := h.spoke(tn)
			if condReasonOf(st.Conditions, "SpokeReachable") != tc.reachable || condReasonOf(st.Conditions, "SpokeFragmentValid") != tc.valid {
				t.Fatalf("conditions = %+v", st.Conditions)
			}
			if st.ApprovedHash != hashOf(t, prod2V1) || !strings.Contains(*h.written, "tag:egress-prod-2-db") {
				t.Fatalf("approved fragment dropped: %+v written=%s", st, *h.written)
			}
			if r := condReasonOf(tn.Status.Conditions, "SpokesReady"); r == "AllMerged" {
				t.Fatal("SpokesReady must report the failure")
			}
			blob, _ := json.Marshal(tn.Status)
			if strings.Contains(string(blob), spokeToken) || strings.Contains(string(blob), "server body") {
				t.Fatalf("status leaks: %s", blob)
			}
			if tc.name == "forbidden" && !strings.Contains(meta.FindStatusCondition(st.Conditions, "SpokeReachable").Message, "HTTP 403") {
				t.Fatalf("status code missing: %+v", st.Conditions)
			}
		})
	}
	for len(h.events.Events) > 0 {
		if e := <-h.events.Events; strings.Contains(e, spokeToken) {
			t.Fatalf("event leaks token: %s", e)
		}
	}
}

// The rule: a spoke removed from spec loses its copies and status; a kubeconfig Secret that is
// missing reports KubeconfigMissing without touching the approved copy.
func TestSpokeRemovalAndMissingKubeconfig(t *testing.T) {
	api := newSpokeAPI(t, prod2V1)
	h := newSpokeHarness(t, api, "Auto", "")
	h.reconcile()
	ctx := context.Background()
	if err := h.c.Delete(ctx, &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: "prod-2-kubeconfig", Namespace: "operator"}}); err != nil {
		t.Fatal(err)
	}
	st := h.spoke(h.reconcile())
	if condReasonOf(st.Conditions, "SpokeReachable") != "KubeconfigMissing" || st.ApprovedHash == "" {
		t.Fatalf("status = %+v", st)
	}

	var tn tnv1.Tailnet
	if err := h.c.Get(ctx, types.NamespacedName{Name: "corp"}, &tn); err != nil {
		t.Fatal(err)
	}
	before := tn.DeepCopy()
	tn.Spec.Policy.Spokes = nil
	if err := h.c.Patch(ctx, &tn, client.MergeFrom(before)); err != nil {
		t.Fatal(err)
	}
	tn = h.reconcile()
	if len(tn.Status.Spokes) != 0 || meta.FindStatusCondition(tn.Status.Conditions, "SpokesReady") != nil {
		t.Fatalf("spoke status not cleared: %+v", tn.Status)
	}
	if _, ok := h.copyData("prod-2-policy-fragment-approved"); ok {
		t.Fatal("approved copy not pruned")
	}
	if strings.Contains(*h.written, "prod-2") {
		t.Fatalf("removed spoke still merged: %s", *h.written)
	}
}

// The rule: the structural helpers count and intersect per entry.
func TestSpokeDeltaAndIntersection(t *testing.T) {
	d := spokeDelta([]byte(prod2V1), []byte(prod2V2))
	if *d != (tnv1.SpokeDelta{GrantsAdded: 1, RoutesRemoved: 1}) {
		t.Fatalf("delta = %+v", d)
	}
	got := string(intersectFragment([]byte(prod2V1), []byte(prod2V2)))
	if strings.Contains(got, "10.9.0.6/32") || strings.Contains(got, "tcp:5433") || !strings.Contains(got, "tcp:5432") || !strings.Contains(got, "tag:egress-prod-2-db") {
		t.Fatalf("intersection = %s", got)
	}
	if got := string(intersectFragment([]byte(prod2V1), []byte(`{}`))); strings.Contains(got, "grants") || strings.Contains(got, "autoApprovers") || strings.Contains(got, "tag:") {
		t.Fatalf("empty fetch must leave nothing: %s", got)
	}
}
