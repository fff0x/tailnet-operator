package controller

import (
	"context"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/go-logr/logr/funcr"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/log"

	tnv1 "tsunaro.io/tailnet-operator/api/v1alpha1"
	operatormetrics "tsunaro.io/tailnet-operator/internal/metrics"
)

var grantClock = time.Date(2026, 12, 1, 12, 0, 0, 0, time.UTC)

// grantUser stands for a personal reference; no status message or log line may carry it.
const grantUser = "https://id.example.com/59ac9125@"

func grantFixture(name string, expires time.Duration, mutate func(*tnv1.TailnetGrantSpec)) tnv1.TailnetGrant {
	g := tnv1.TailnetGrant{ObjectMeta: metav1.ObjectMeta{Name: name, Generation: 1, UID: types.UID(name)}}
	g.Spec.TailnetRef.Name = "corp"
	g.Spec.Sources = []string{grantUser}
	g.Spec.Target.Tag = "tag:ingress-db"
	g.Spec.Ports = []int32{5432}
	if expires != 0 {
		at := metav1.NewTime(grantClock.Add(expires))
		g.Spec.ExpiresAt = &at
	}
	if mutate != nil {
		mutate(&g.Spec)
	}
	return g
}

func prefixes(ps ...string) func(*tnv1.TailnetGrantSpec) {
	return func(s *tnv1.TailnetGrantSpec) {
		s.Target = tnv1.GrantTarget{}
		for _, p := range ps {
			s.Target.Prefixes = append(s.Target.Prefixes, tnv1.GatewayPrefix(p))
		}
	}
}

// The rule of grants.go, case by case: what is rendered, why not, and when the next grant expires.
func TestResolveGrants(t *testing.T) {
	tag := func(tag string) func(*tnv1.TailnetGrantSpec) {
		return func(s *tnv1.TailnetGrantSpec) { s.Target.Tag = tag }
	}
	// Only the shipped (unblocked) site prefixes reach resolveGrants; a blocked site is simply absent.
	sites := []string{"10.1.0.0/24", "2001:db8:1::/64", "not-a-prefix"}
	for _, tc := range []struct {
		name     string
		grant    tnv1.TailnetGrant
		rendered bool
		expired  bool
		reason   string
		dst      []string
	}{
		{name: "permanent", grant: grantFixture("g", 0, nil), rendered: true, dst: []string{"tag:ingress-db"}},
		{name: "active", grant: grantFixture("g", time.Second, nil), rendered: true, dst: []string{"tag:ingress-db"}},
		{name: "expires exactly now", grant: grantFixture("g", 0, func(s *tnv1.TailnetGrantSpec) { at := metav1.NewTime(grantClock); s.ExpiresAt = &at }), expired: true},
		{name: "expired", grant: grantFixture("g", -time.Hour, nil), expired: true},
		{name: "tag of an own ingress", grant: grantFixture("g", 0, tag("tag:ingress-db")), rendered: true, dst: []string{"tag:ingress-db"}},
		{name: "tag from a fragment", grant: grantFixture("g", 0, tag("tag:spoke-api")), rendered: true, dst: []string{"tag:spoke-api"}},
		{name: "unknown tag", grant: grantFixture("g", 0, tag("tag:nowhere")), reason: "TargetUnknown"},
		{name: "expired with unknown tag", grant: grantFixture("g", -time.Hour, tag("tag:nowhere")), expired: true, reason: "TargetUnknown"},
		{name: "host inside a site", grant: grantFixture("g", 0, prefixes("10.1.0.5/32")), rendered: true, dst: []string{"10.1.0.5/32"}},
		{name: "the site itself", grant: grantFixture("g", 0, prefixes("10.1.0.0/24")), rendered: true, dst: []string{"10.1.0.0/24"}},
		{name: "wider than the site", grant: grantFixture("g", 0, prefixes("10.1.0.0/16")), reason: "TargetOutsideSites"},
		{name: "outside every site", grant: grantFixture("g", 0, prefixes("10.2.0.5/32")), reason: "TargetOutsideSites"},
		{name: "one inside, one outside", grant: grantFixture("g", 0, prefixes("10.1.0.5/32", "10.2.0.5/32")), reason: "TargetOutsideSites"},
		{name: "blocked site is not shipped", grant: grantFixture("g", 0, prefixes("10.9.0.5/32")), reason: "TargetOutsideSites"},
		{name: "ipv6 host", grant: grantFixture("g", 0, prefixes("2001:db8:1::7/128")), rendered: true, dst: []string{"2001:db8:1::7/128"}},
		{name: "ipv6 outside", grant: grantFixture("g", 0, prefixes("2001:db8:2::7/128")), reason: "TargetOutsideSites"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			in, verdicts, _ := resolveGrants(grantClock, []tnv1.TailnetGrant{tc.grant}, []string{"tag:ingress-db"}, []string{"tag:spoke-api"}, sites)
			v := verdicts["g"]
			if v.expired != tc.expired || v.reason != tc.reason || (len(in) == 1) != tc.rendered {
				t.Fatalf("expired=%t reason=%q rendered=%d", v.expired, v.reason, len(in))
			}
			if tc.rendered && (!reflect.DeepEqual(in[0].Dst, tc.dst) || !reflect.DeepEqual(in[0].Sources, tc.grant.Spec.Sources) || !reflect.DeepEqual(in[0].Ports, tc.grant.Spec.Ports)) {
				t.Fatalf("rendered %+v", in[0])
			}
			if strings.Contains(v.message, grantUser) {
				t.Fatal("verdict message names a user reference")
			}
		})
	}

	grants := []tnv1.TailnetGrant{grantFixture("past", -time.Minute, nil), grantFixture("later", time.Hour, nil), grantFixture("soon", 90*time.Second, nil), grantFixture("never", 0, nil)}
	if _, _, next := resolveGrants(grantClock, grants, nil, nil, nil); !next.Equal(grantClock.Add(90 * time.Second)) {
		t.Fatalf("next expiry = %v", next)
	}
	if _, _, next := resolveGrants(grantClock, grants[:1], nil, nil, nil); !next.IsZero() {
		t.Fatalf("an expired grant has no next expiry, got %v", next)
	}
}

// The Ready reason follows the order of the rule for every stage a reconcile can end in.
func TestGrantReason(t *testing.T) {
	unknown := []string{"group:ghost", "tag:other"}
	withGroup := grantFixture("g", time.Hour, func(s *tnv1.TailnetGrantSpec) { s.Sources = []string{grantUser, "group:ghost", "group:ops"} })
	expired := grantFixture("g", -time.Hour, nil)
	confirmed := grantFixture("g", -time.Hour, nil)
	confirmed.Status.Conditions = []metav1.Condition{{Type: "Ready", Status: metav1.ConditionFalse, Reason: "Expired", ObservedGeneration: 1}}
	edited := *confirmed.DeepCopy()
	edited.Generation = 2
	badTarget := grantVerdict{reason: "TargetUnknown", message: "target"}
	for _, tc := range []struct {
		name  string
		grant tnv1.TailnetGrant
		v     grantVerdict
		stage grantStage
		want  string
	}{
		{"granted", grantFixture("g", time.Hour, nil), grantVerdict{}, grantsLive, "Granted"},
		{"permanent", grantFixture("g", 0, nil), grantVerdict{}, grantsLive, "Granted"},
		{"live policy differs", grantFixture("g", time.Hour, nil), grantVerdict{}, grantsRendered, "PolicyPending"},
		{"not the writer wins over everything", expired, grantVerdict{expired: true, reason: "TargetUnknown"}, grantsNotWriter, "NotPolicyWriter"},
		{"expired and dropped", expired, grantVerdict{expired: true}, grantsLive, "Expired"},
		{"expired wins over the target", expired, grantVerdict{expired: true, reason: "TargetUnknown"}, grantsLive, "Expired"},
		{"expired, write open", expired, grantVerdict{expired: true}, grantsRendered, "ExpiryPending"},
		{"expired, no render", expired, grantVerdict{expired: true}, grantsNotRendered, "ExpiryPending"},
		{"confirmed expiry survives a failed write", confirmed, grantVerdict{expired: true}, grantsRendered, "Expired"},
		{"confirmed expiry survives a missing base", confirmed, grantVerdict{expired: true}, grantsNotRendered, "Expired"},
		{"a new generation must be confirmed again", edited, grantVerdict{expired: true}, grantsRendered, "ExpiryPending"},
		{"target before sources", withGroup, badTarget, grantsLive, "TargetUnknown"},
		{"target before pending", grantFixture("g", time.Hour, nil), badTarget, grantsRendered, "TargetUnknown"},
		{"undeclared group", withGroup, grantVerdict{}, grantsLive, "SourceGroupUnknown"},
		{"undeclared group before pending", withGroup, grantVerdict{}, grantsRendered, "SourceGroupUnknown"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			reason, msg := grantReason(&tc.grant, tc.v, tc.stage, unknown)
			if reason != tc.want {
				t.Fatalf("reason %q, want %q (%s)", reason, tc.want, msg)
			}
			if strings.Contains(msg, grantUser) || strings.Contains(msg, "group:ops") {
				t.Fatalf("message names a source that is not an undeclared group: %s", msg)
			}
			if reason == "SourceGroupUnknown" && !strings.Contains(msg, "group:ghost") {
				t.Fatalf("message does not name the undeclared group: %s", msg)
			}
		})
	}
}

// TestGrantReasonNoSourceLeft: the message says what happens to the rest of the grant.
func TestGrantReasonNoSourceLeft(t *testing.T) {
	unknown := []string{"group:ghost"}
	for sources, want := range map[string]string{
		"group:ghost":              "nothing is rendered",
		"group:ghost," + grantUser: "the other sources stay granted",
	} {
		g := grantFixture("g", 0, func(s *tnv1.TailnetGrantSpec) { s.Sources = strings.Split(sources, ",") })
		if reason, msg := grantReason(&g, grantVerdict{}, grantsLive, unknown); reason != "SourceGroupUnknown" || !strings.Contains(msg, want) {
			t.Fatalf("sources %s: %s: %s, want %q in the message", sources, reason, msg, want)
		}
	}
}

type grantHarness struct {
	t    *testing.T
	c    client.Client
	r    *TailnetPolicyReconciler
	now  time.Time
	logs []string
}

const grantBase = `{"groups":{"group:ops":["ops@"]},"tagOwners":{"tag:fabric":["group:ops"]},"acls":[{"action":"accept","src":["group:ops"],"dst":["192.0.2.1:443"]}]}`

// newGrantHarness builds a Tailnet "corp" in the given policy mode with one ingress (tag:ingress-db)
// and the given grants. No working API key exists, so Apply ends at NoAPIKey: rendered, not live.
func newGrantHarness(t *testing.T, mode, baseConfigMap string, grants ...tnv1.TailnetGrant) *grantHarness {
	t.Helper()
	s := runtime.NewScheme()
	_ = clientgoscheme.AddToScheme(s)
	_ = tnv1.AddToScheme(s)
	tn := &tnv1.Tailnet{ObjectMeta: metav1.ObjectMeta{Name: "corp", Generation: 1}, Spec: tnv1.TailnetSpec{
		Server: "https://hs.example", IngressTagTemplate: "tag:ingress-{name}",
		Policy: tnv1.PolicySpec{BaseConfigMap: baseConfigMap, Mode: mode, TagOwners: []string{"group:ops"}, IngressSourceAllowlist: []string{"group:*"}},
	}}
	objs := []client.Object{tn,
		&corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Name: "base", Namespace: "operator"}, Data: map[string]string{policyKey: grantBase}},
		&tnv1.TailnetIngress{ObjectMeta: metav1.ObjectMeta{Name: "db", Namespace: "shop"}, Spec: tnv1.TailnetIngressSpec{
			TailnetRef: tnv1.TailnetRef{Name: "corp"}, AllowFrom: []string{"group:ops"},
			Exposes: []tnv1.Expose{{Name: "pg", Port: 5432, Backend: tnv1.Backend{Service: "db", Port: 5432}}},
		}},
	}
	for i := range grants {
		objs = append(objs, &grants[i])
	}
	c := fake.NewClientBuilder().WithScheme(s).WithObjects(objs...).WithStatusSubresource(&tnv1.Tailnet{}, &tnv1.TailnetGrant{}).Build()
	h := &grantHarness{t: t, c: c, now: grantClock}
	h.r = &TailnetPolicyReconciler{Client: c, Scheme: s, OperatorNamespace: "operator", Metrics: operatormetrics.New(), Now: func() time.Time { return h.now }}
	return h
}

func (h *grantHarness) reconcile() ctrl.Result {
	h.t.Helper()
	logger := funcr.New(func(prefix, args string) { h.logs = append(h.logs, prefix+args) }, funcr.Options{Verbosity: 10})
	res, err := h.r.Reconcile(log.IntoContext(context.Background(), logger), ctrl.Request{NamespacedName: types.NamespacedName{Name: "corp"}})
	if err != nil {
		h.t.Fatal(err)
	}
	return res
}

func (h *grantHarness) ready(name string) *metav1.Condition {
	h.t.Helper()
	var g tnv1.TailnetGrant
	if err := h.c.Get(context.Background(), types.NamespacedName{Name: name}, &g); err != nil {
		h.t.Fatal(err)
	}
	c := findCond(g.Status.Conditions, "Ready")
	if c != nil && (strings.Contains(c.Message, grantUser) || c.ObservedGeneration != g.Generation || g.Status.ObservedGeneration != g.Generation) {
		h.t.Fatalf("grant %s: condition names a user or lags the generation: %+v", name, c)
	}
	return c
}

func (h *grantHarness) rendered() string {
	h.t.Helper()
	var cm corev1.ConfigMap
	if err := h.c.Get(context.Background(), types.NamespacedName{Namespace: "operator", Name: "base-rendered"}, &cm); err != nil {
		h.t.Fatal(err)
	}
	return cm.Data[policyKey]
}

// DryRun renders the grant but never compares the live policy: PolicyPending, and the reconcile is
// due again when the first grant expires, not after the periodic five minutes.
func TestGrantsRenderedPendingAndRequeue(t *testing.T) {
	h := newGrantHarness(t, "DryRun", "base",
		grantFixture("soon", 90*time.Second, nil),
		grantFixture("later", time.Hour, nil),
		grantFixture("nowhere", 0, func(s *tnv1.TailnetGrantSpec) { s.Target.Tag = "tag:nowhere" }),
		grantFixture("ghost", 0, func(s *tnv1.TailnetGrantSpec) { s.Sources = []string{"group:ghost", grantUser} }),
		grantFixture("other-tailnet", 0, func(s *tnv1.TailnetGrantSpec) { s.TailnetRef.Name = "lab" }),
	)
	if res := h.reconcile(); res.RequeueAfter != 90*time.Second {
		t.Fatalf("requeue %v, want the next expiry in 90s", res.RequeueAfter)
	}
	for name, want := range map[string]string{"soon": "PolicyPending", "later": "PolicyPending", "nowhere": "TargetUnknown", "ghost": "SourceGroupUnknown"} {
		if c := h.ready(name); c == nil || c.Status != metav1.ConditionFalse || c.Reason != want {
			t.Fatalf("grant %s: %+v, want %s", name, c, want)
		}
	}
	if h.ready("other-tailnet") != nil {
		t.Fatal("a grant of another Tailnet got a status")
	}
	doc := h.rendered()
	var soon tnv1.TailnetGrant
	_ = h.c.Get(context.Background(), types.NamespacedName{Name: "soon"}, &soon)
	if !strings.Contains(doc, grantUser) || !strings.Contains(doc, "tcp:5432") || strings.Contains(doc, "tag:nowhere") || strings.Contains(doc, "group:ghost") {
		t.Fatalf("render:\n%s", doc)
	}
	// The Tailnet's own status names the undeclared group, never a user reference.
	var tn tnv1.Tailnet
	_ = h.c.Get(context.Background(), types.NamespacedName{Name: "corp"}, &tn)
	for _, c := range tn.Status.Conditions {
		if strings.Contains(c.Message, grantUser) {
			t.Fatalf("Tailnet condition %s names a user reference", c.Type)
		}
	}

	if strings.Contains(strings.Join(h.logs, "\n"), grantUser) {
		t.Fatal("a log line names a user reference")
	}

	// Unchanged input: the status is not rewritten (messages carry no remaining time).
	h.now = h.now.Add(30 * time.Second)
	if res := h.reconcile(); res.RequeueAfter != 60*time.Second {
		t.Fatalf("requeue %v, want 60s", res.RequeueAfter)
	}
	var again tnv1.TailnetGrant
	_ = h.c.Get(context.Background(), types.NamespacedName{Name: "soon"}, &again)
	if again.ResourceVersion != soon.ResourceVersion {
		t.Fatal("unchanged grant status was rewritten")
	}

	// At expiresAt the grant leaves the render without any change to an object. DryRun cannot
	// confirm the live policy, so the grant reports ExpiryPending. The requeue never drops below 1s.
	h.now = grantClock.Add(90 * time.Second)
	if res := h.reconcile(); res.RequeueAfter != policyRequeue {
		t.Fatalf("requeue %v, want the periodic %v", res.RequeueAfter, policyRequeue)
	}
	if c := h.ready("soon"); c.Reason != "ExpiryPending" {
		t.Fatalf("expired grant: %+v", c)
	}
	if strings.Count(h.rendered(), grantUser) != 1 { // only "later" is left
		t.Fatalf("expired grant still rendered:\n%s", h.rendered())
	}
	h.now = grantClock.Add(time.Hour - time.Millisecond)
	if res := h.reconcile(); res.RequeueAfter != time.Second {
		t.Fatalf("requeue %v, want the 1s floor", res.RequeueAfter)
	}
}

// A Tailnet that does not write the policy reports NotPolicyWriter and renders no grant, as a
// spoke (Export) and with the policy switched off.
func TestGrantsNotPolicyWriter(t *testing.T) {
	for _, tc := range []struct{ mode, base, out string }{{"Export", "", "corp-policy-fragment"}, {"", "", ""}} {
		h := newGrantHarness(t, tc.mode, tc.base, grantFixture("g", time.Minute, nil), grantFixture("old", -time.Hour, nil))
		if res := h.reconcile(); tc.mode == "" && res.RequeueAfter != 0 {
			t.Fatalf("mode %q: requeue %v for a Tailnet without policy", tc.mode, res.RequeueAfter)
		}
		for _, name := range []string{"g", "old"} {
			if c := h.ready(name); c == nil || c.Reason != "NotPolicyWriter" {
				t.Fatalf("mode %q grant %s: %+v", tc.mode, name, c)
			}
		}
		if tc.out != "" {
			var cm corev1.ConfigMap
			if err := h.c.Get(context.Background(), types.NamespacedName{Namespace: "operator", Name: tc.out}, &cm); err != nil {
				t.Fatal(err)
			}
			if strings.Contains(cm.Data[policyKey], grantUser) {
				t.Fatal("a spoke rendered a grant into its fragment")
			}
		}
	}
}

// A reconcile that stops before the render (the named base ConfigMap is missing) reports only what
// it knows: an expired grant is ExpiryPending, an active one is left untouched.
func TestGrantsExpiryPendingWithoutBase(t *testing.T) {
	h := newGrantHarness(t, "Apply", "missing", grantFixture("active", time.Hour, nil), grantFixture("old", -time.Hour, nil))
	h.reconcile()
	if c := h.ready("old"); c == nil || c.Reason != "ExpiryPending" {
		t.Fatalf("expired grant: %+v", c)
	}
	if c := h.ready("active"); c != nil {
		t.Fatalf("active grant touched before a render: %+v", c)
	}
}

// Apply without a working API key renders but cannot write: active grants are PolicyPending.
func TestGrantsApplyWithoutKey(t *testing.T) {
	h := newGrantHarness(t, "Apply", "base", grantFixture("active", time.Hour, nil))
	h.reconcile()
	if c := h.ready("active"); c == nil || c.Reason != "PolicyPending" {
		t.Fatalf("grant: %+v", c)
	}
}
