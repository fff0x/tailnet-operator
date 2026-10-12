package controller

import (
	"context"
	"fmt"
	"slices"
	"strings"

	"k8s.io/apimachinery/pkg/api/equality"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/util/retry"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/log"

	tnv1 "tsunaro.io/tailnet-operator/api/v1alpha1"
	"tsunaro.io/tailnet-operator/internal/headscale"
	"tsunaro.io/tailnet-operator/internal/routes"
)

// registryInputs turns the TailnetSite CRs bound to tn and its reserved networks into registry
// inputs. A site without advertisedBy.tags is advertised by the Tailnet's routeApprovers.
func registryInputs(tn *tnv1.Tailnet, sites []tnv1.TailnetSite) ([]routes.Site, []routes.Reserved) {
	rs := make([]routes.Site, 0, len(sites))
	for _, s := range sites {
		tags := s.Spec.AdvertisedBy.Tags
		if len(tags) == 0 {
			tags = tn.Spec.Policy.RouteApprovers
		}
		prefixes := make([]string, 0, len(s.Spec.Prefixes))
		for _, p := range s.Spec.Prefixes {
			prefixes = append(prefixes, string(p))
		}
		rs = append(rs, routes.Site{Name: s.Name, Created: s.CreationTimestamp.Time, Prefixes: prefixes, Tags: tags})
	}
	reserved := make([]routes.Reserved, 0, len(tn.Spec.ReservedNetworks))
	for _, r := range tn.Spec.ReservedNetworks {
		prefixes := make([]string, 0, len(r.Prefixes))
		for _, p := range r.Prefixes {
			prefixes = append(prefixes, string(p))
		}
		reserved = append(reserved, routes.Reserved{Name: r.Name, Prefixes: prefixes})
	}
	return rs, reserved
}

// registryNodes projects the control server's node list onto what the registry needs.
func registryNodes(nodes []headscale.Node) []routes.Node {
	out := make([]routes.Node, 0, len(nodes))
	for _, n := range nodes {
		out = append(out, routes.Node{Name: n.GivenName, Tags: n.Tags, Available: n.AvailableRoutes, Approved: n.ApprovedRoutes})
	}
	return out
}

// siteStatus writes the registry verdict into every bound TailnetSite. nodes == nil means the
// control server was not queried in this reconcile (DryRun without a key, API failure): the
// observation conditions become Unknown instead of flipping to False. Failures are logged;
// site status is observational and must never fail the policy reconcile.
func (r *TailnetPolicyReconciler) siteStatus(ctx context.Context, tn *tnv1.Tailnet, sites []tnv1.TailnetSite, nodes []headscale.Node) {
	if len(sites) == 0 {
		return
	}
	rs, reserved := registryInputs(tn, sites)
	var live []routes.Node
	if nodes != nil {
		live = registryNodes(nodes)
	}
	res := routes.Build(rs, reserved, live)
	for i := range sites {
		s := &sites[i]
		st := res.States[s.Name]
		if err := r.writeSiteStatus(ctx, s.Name, func(t *tnv1.TailnetSite) {
			applySiteState(t, st, nodes != nil)
		}); err != nil {
			log.FromContext(ctx).Error(err, "site status not written", "site", s.Name)
		}
	}
}

// applySiteState maps a registry verdict onto the site's status and conditions.
func applySiteState(t *tnv1.TailnetSite, st routes.SiteState, observed bool) {
	gen := t.Generation
	t.Status.ObservedGeneration = gen
	t.Status.RoutesAdvertised = st.Advertised
	t.Status.RoutesApproved = st.Approved
	conds := &t.Status.Conditions
	if st.Blocked != nil {
		setCond(conds, gen, "RouteConflict", metav1.ConditionTrue, st.Blocked.Reason, st.Blocked.Message()+"; nothing is rendered or approved for this site")
	} else {
		setCond(conds, gen, "RouteConflict", metav1.ConditionFalse, "None", "no overlap with reserved networks or older sites")
	}
	if len(st.Unmanaged) > 0 {
		setCond(conds, gen, "UnmanagedOverlap", metav1.ConditionTrue, "Unmanaged",
			"nodes without an advertiser tag advertise overlapping routes: "+joinMax(st.Unmanaged, 5))
	} else {
		setCond(conds, gen, "UnmanagedOverlap", metav1.ConditionFalse, "None", "no foreign node advertises an overlapping route")
	}
	want := len(t.Spec.Prefixes)
	observe := func(typ, trueReason, falseReason string, have []string) {
		if !observed {
			setCond(conds, gen, typ, metav1.ConditionUnknown, "NotObserved", "control server not queried in this reconcile")
			return
		}
		if len(have) == want {
			setCond(conds, gen, typ, metav1.ConditionTrue, trueReason, fmt.Sprintf("all %d prefixes", want))
			return
		}
		var missing []string
		for _, p := range t.Spec.Prefixes {
			if !slices.Contains(have, string(p)) {
				missing = append(missing, string(p))
			}
		}
		setCond(conds, gen, typ, metav1.ConditionFalse, falseReason,
			fmt.Sprintf("%d of %d prefixes; missing: %s", len(have), want, joinMax(missing, 5)))
	}
	observe("Advertised", "Advertised", "NotAdvertised", st.Advertised)
	observe("Approved", "Approved", "NotApproved", st.Approved)
	switch {
	case st.Blocked != nil:
		setCond(conds, gen, "Ready", metav1.ConditionFalse, "RouteConflict", st.Blocked.Message())
	case !observed:
		setCond(conds, gen, "Ready", metav1.ConditionUnknown, "NotObserved", "control server not queried in this reconcile")
	default:
		for _, typ := range []string{"Advertised", "Approved"} {
			if c := findCond(*conds, typ); c != nil && c.Status == metav1.ConditionFalse {
				setCond(conds, gen, "Ready", metav1.ConditionFalse, c.Reason, c.Message)
				return
			}
		}
		setCond(conds, gen, "Ready", metav1.ConditionTrue, "Ready", "all prefixes advertised and approved")
	}
}

func findCond(conds []metav1.Condition, t string) *metav1.Condition {
	if i := condIndex(conds, t); i >= 0 {
		return &conds[i]
	}
	return nil
}

func joinMax(ss []string, n int) string {
	if len(ss) <= n {
		return strings.Join(ss, ", ")
	}
	return strings.Join(ss[:n], ", ") + fmt.Sprintf(" (+%d more)", len(ss)-n)
}

// writeSiteStatus applies mutate to a fresh copy and persists it only when the status changed,
// so the periodic policy reconcile does not rewrite N unchanged sites.
func (r *TailnetPolicyReconciler) writeSiteStatus(ctx context.Context, name string, mutate func(*tnv1.TailnetSite)) error {
	return retry.RetryOnConflict(retry.DefaultBackoff, func() error {
		var s tnv1.TailnetSite
		if err := r.Get(ctx, types.NamespacedName{Name: name}, &s); err != nil {
			if apierrors.IsNotFound(err) {
				r.Metrics.Delete("TailnetSite", "", name)
			}
			return client.IgnoreNotFound(err)
		}
		before := s.Status.DeepCopy()
		mutate(&s)
		if equality.Semantic.DeepEqual(before, &s.Status) {
			r.Metrics.Observe(&s)
			return nil
		}
		return updateObservedStatus(ctx, r.Client, r.Metrics, &s)
	})
}
