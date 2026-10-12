package controller

import (
	"context"
	"strings"
	"testing"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	tnv1 "tsunaro.io/tailnet-operator/api/v1alpha1"
	"tsunaro.io/tailnet-operator/internal/headscale"
	operatormetrics "tsunaro.io/tailnet-operator/internal/metrics"
	"tsunaro.io/tailnet-operator/internal/routes"
)

func siteFixture(name, tailnet string, created time.Time, tags []string, prefixes ...string) *tnv1.TailnetSite {
	s := &tnv1.TailnetSite{ObjectMeta: metav1.ObjectMeta{Name: name, CreationTimestamp: metav1.NewTime(created), Generation: 1}}
	s.Spec.TailnetRef.Name = tailnet
	s.Spec.Owner = "netops"
	s.Spec.AdvertisedBy.Tags = tags
	for _, p := range prefixes {
		s.Spec.Prefixes = append(s.Spec.Prefixes, tnv1.GatewayPrefix(p))
	}
	return s
}

// collect renders only unblocked sites bound to the Tailnet, with routeApprovers as the default
// advertiser, and lists blocked sites as skipped; siteStatus then writes the verdict on each CR,
// folding in the live node observation.
func TestPolicyCollectSitesAndStatus(t *testing.T) {
	s := runtime.NewScheme()
	_ = clientgoscheme.AddToScheme(s)
	_ = tnv1.AddToScheme(s)
	t0 := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	tn := &tnv1.Tailnet{
		ObjectMeta: metav1.ObjectMeta{Name: "corp"},
		Spec: tnv1.TailnetSpec{
			Policy:           tnv1.PolicySpec{BaseConfigMap: "policy", TagOwners: []string{"group:operator"}, RouteApprovers: []string{"tag:fabric"}},
			ReservedNetworks: []tnv1.ReservedNetwork{{Name: "nodes", Prefixes: []tnv1.GatewayPrefix{"100.64.0.0/16"}}},
		},
	}
	objs := []runtime.Object{
		siteFixture("branch-a", "corp", t0, nil, "10.1.1.0/24"),
		siteFixture("branch-b", "corp", t0.Add(time.Hour), []string{"tag:kc-router"}, "10.1.1.128/25"), // younger, overlaps a
		siteFixture("mgmt", "corp", t0, nil, "100.64.8.0/22"),                                          // reserved
		siteFixture("foreign", "lab", t0, nil, "10.7.0.0/24"),
	}
	r := &TailnetPolicyReconciler{Client: fake.NewClientBuilder().WithScheme(s).WithRuntimeObjects(objs...).WithStatusSubresource(&tnv1.TailnetSite{}).Build(),
		Scheme: s, OperatorNamespace: "tailnet-system", Metrics: operatormetrics.New()}
	ctx := context.Background()

	in, skipped, sites, err := r.collect(ctx, tn)
	if err != nil {
		t.Fatal(err)
	}
	if len(in.Sites) != 1 || in.Sites[0].Prefixes[0] != "10.1.1.0/24" || strings.Join(in.Sites[0].Approvers, ",") != "tag:fabric" {
		t.Fatalf("sites rendered = %+v", in.Sites)
	}
	if strings.Join(skipped, ",") != "site/branch-b,site/mgmt" {
		t.Fatalf("skipped = %v", skipped)
	}
	if len(sites) != 3 {
		t.Fatalf("bound sites = %d", len(sites))
	}

	// Not observed: verdicts written, observations Unknown.
	r.siteStatus(ctx, tn, sites, nil)
	get := func(name string) tnv1.TailnetSite {
		var out tnv1.TailnetSite
		if err := r.Get(ctx, types.NamespacedName{Name: name}, &out); err != nil {
			t.Fatal(err)
		}
		return out
	}
	cond := func(st tnv1.TailnetSite, typ string) metav1.Condition {
		if c := findCond(st.Status.Conditions, typ); c != nil {
			return *c
		}
		t.Fatalf("%s: condition %s missing", st.Name, typ)
		return metav1.Condition{}
	}
	a, b, m := get("branch-a"), get("branch-b"), get("mgmt")
	if c := cond(b, "RouteConflict"); c.Status != metav1.ConditionTrue || c.Reason != routes.OverlapsSite || !strings.Contains(c.Message, "older site branch-a") {
		t.Fatalf("branch-b RouteConflict = %+v", c)
	}
	if c := cond(b, "Ready"); c.Status != metav1.ConditionFalse || c.Reason != "RouteConflict" {
		t.Fatalf("branch-b Ready = %+v", c)
	}
	if c := cond(m, "RouteConflict"); c.Reason != routes.OverlapsReserved || !strings.Contains(c.Message, "reserved network nodes") {
		t.Fatalf("mgmt RouteConflict = %+v", c)
	}
	if c := cond(a, "Ready"); c.Status != metav1.ConditionUnknown || c.Reason != "NotObserved" {
		t.Fatalf("branch-a Ready without nodes = %+v", c)
	}
	if a.Status.ObservedGeneration != 1 {
		t.Fatalf("observedGeneration = %d", a.Status.ObservedGeneration)
	}

	// Observed: router advertises but nothing approved yet → NotApproved; a debug node overlapping
	// is reported, not blocking.
	nodes := []headscale.Node{
		{ID: "1", GivenName: "kc-router", Tags: []string{"tag:fabric"}, AvailableRoutes: []string{"10.1.1.0/24"}},
		{ID: "2", GivenName: "laptop", Tags: []string{"tag:debug"}, AvailableRoutes: []string{"10.1.1.0/26"}},
	}
	r.siteStatus(ctx, tn, sites, nodes)
	a = get("branch-a")
	if c := cond(a, "Advertised"); c.Status != metav1.ConditionTrue {
		t.Fatalf("Advertised = %+v", c)
	}
	if c := cond(a, "Approved"); c.Status != metav1.ConditionFalse || c.Reason != "NotApproved" || !strings.Contains(c.Message, "10.1.1.0/24") {
		t.Fatalf("Approved = %+v", c)
	}
	if c := cond(a, "Ready"); c.Status != metav1.ConditionFalse || c.Reason != "NotApproved" {
		t.Fatalf("Ready = %+v", c)
	}
	if c := cond(a, "UnmanagedOverlap"); c.Status != metav1.ConditionTrue || !strings.Contains(c.Message, "laptop") {
		t.Fatalf("UnmanagedOverlap = %+v", c)
	}
	if len(a.Status.RoutesAdvertised) != 1 || len(a.Status.RoutesApproved) != 0 {
		t.Fatalf("routes = %v / %v", a.Status.RoutesAdvertised, a.Status.RoutesApproved)
	}

	// Approved on the router → Ready; a second unchanged pass must not bump resourceVersion.
	nodes[0].ApprovedRoutes = []string{"10.1.1.0/24"}
	r.siteStatus(ctx, tn, sites, nodes)
	a = get("branch-a")
	if c := cond(a, "Ready"); c.Status != metav1.ConditionTrue {
		t.Fatalf("Ready = %+v", c)
	}
	rv := a.ResourceVersion
	r.siteStatus(ctx, tn, sites, nodes)
	if get("branch-a").ResourceVersion != rv {
		t.Fatal("unchanged site status was rewritten")
	}
}
