package controller

import (
	"context"
	"net/netip"
	"slices"
	"strings"

	corev1 "k8s.io/api/core/v1"
	"sigs.k8s.io/controller-runtime/pkg/log"

	tnv1 "tsunaro.io/tailnet-operator/api/v1alpha1"
	"tsunaro.io/tailnet-operator/internal/headscale"
	"tsunaro.io/tailnet-operator/internal/policy"
)

// approvals replays what Headscale's autoApprovers would have done on a route-change event: for
// every node, every advertised-but-unapproved route that lies inside an approver prefix naming one
// of the node's tags gets approved. Returns, per node ID with a delta, the full sorted approved list
// (existing ∪ new, because the API replaces the list) and the newly added routes. Never removes an
// approval.
//
// ponytail: only tag: aliases are matched; user/group approvers are ignored (nodes carry tags, not
// users, in this operator's model). Upgrade path: resolve users via the node's user field.
type approval struct{ Routes, Added []string }

func approvals(nodes []headscale.Node, approvers map[string][]string) map[string]approval {
	type approver struct {
		prefix netip.Prefix
		tags   []string
	}
	var aps []approver
	for cidr, aliases := range approvers {
		p, err := netip.ParsePrefix(cidr)
		if err != nil {
			continue
		}
		var tags []string
		for _, a := range aliases {
			if strings.HasPrefix(a, "tag:") {
				tags = append(tags, a)
			}
		}
		if len(tags) > 0 {
			aps = append(aps, approver{p, tags})
		}
	}
	out := map[string]approval{}
	for _, n := range nodes {
		add := []string(nil)
		for _, r := range n.AvailableRoutes {
			if slices.Contains(n.ApprovedRoutes, r) {
				continue
			}
			rp, err := netip.ParsePrefix(r)
			if err != nil {
				continue
			}
			for _, a := range aps {
				if a.prefix.Bits() <= rp.Bits() && a.prefix.Contains(rp.Addr()) && slices.ContainsFunc(n.Tags, func(t string) bool { return slices.Contains(a.tags, t) }) {
					add = append(add, r)
					break
				}
			}
		}
		if len(add) > 0 {
			slices.Sort(add)
			add = slices.Compact(add)
			all := append(slices.Clone(n.ApprovedRoutes), add...)
			slices.Sort(all)
			out[n.ID] = approval{Routes: slices.Compact(all), Added: add}
		}
	}
	return out
}

// approveRoutes applies approvals for the rendered policy. Failures are logged and reported as
// events; they never fail the policy reconcile that called this. Returns the node list it worked
// from, with successful approvals folded in, so callers can observe routes without a second list;
// nil when the list failed.
func (r *TailnetPolicyReconciler) approveRoutes(ctx context.Context, hs *headscale.Client, tn *tnv1.Tailnet, rendered []byte) []headscale.Node {
	l := log.FromContext(ctx)
	aps, err := policy.Approvers(rendered)
	if err != nil {
		return nil // rendered by us; cannot happen
	}
	nodes, err := hs.ListNodes(ctx)
	if err != nil {
		l.Error(err, "route approval replay skipped: node list failed")
		return nil
	}
	for id, a := range approvals(nodes, aps) {
		if err := hs.SetApprovedRoutes(ctx, id, a.Routes); err != nil {
			l.Error(err, "route approval failed", "node", id, "routes", a.Added)
			if r.Recorder != nil {
				r.Recorder.Eventf(tn, corev1.EventTypeWarning, "RouteApprovalFailed", "node %s: %v", id, err)
			}
			continue
		}
		r.Metrics.Approved(tn.Name, len(a.Added))
		l.Info("routes approved (autoApprover replay)", "node", id, "routes", a.Added)
		if r.Recorder != nil {
			r.Recorder.Eventf(tn, corev1.EventTypeNormal, "RoutesApproved", "node %s: %s", id, strings.Join(a.Added, ", "))
		}
		for i := range nodes {
			if nodes[i].ID == id {
				nodes[i].ApprovedRoutes = a.Routes
			}
		}
	}
	return nodes
}
