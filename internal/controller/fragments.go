package controller

import (
	"net/netip"

	tnv1 "tsunaro.io/tailnet-operator/api/v1alpha1"
	"tsunaro.io/tailnet-operator/internal/policy"
)

// fragmentRules builds the hub-side limits a foreign fragment must respect. base is the hub's base
// document (its tagOwners are exempt from the tag patterns), in.Sites the unblocked TailnetSites
// (a non-host route must lie within one of them or within extra), reservedNetworks the protected
// space. patterns and contain distinguish a pulled spoke (its tag patterns, containment on) from a
// Git-reviewed fragmentConfigMaps entry ("tag:*", containment off).
func fragmentRules(tn *tnv1.Tailnet, base []byte, in policy.Inputs, patterns []string, extra []string, contain bool) policy.FragmentRules {
	r := policy.FragmentRules{
		TagPatterns:            patterns,
		BaseTags:               policy.BaseTags(base),
		TagOwners:              tn.Spec.Policy.TagOwners,
		RouteApprovers:         tn.Spec.Policy.RouteApprovers,
		IngressSourceAllowlist: tn.Spec.Policy.IngressSourceAllowlist,
		ContainRoutes:          contain,
	}
	for _, s := range in.Sites {
		for _, p := range s.Prefixes {
			if pf, err := netip.ParsePrefix(p); err == nil {
				r.Allowed = append(r.Allowed, pf)
			}
		}
	}
	for _, p := range extra {
		if pf, err := netip.ParsePrefix(p); err == nil {
			r.Allowed = append(r.Allowed, pf)
		}
	}
	for _, res := range tn.Spec.ReservedNetworks {
		for _, p := range res.Prefixes {
			if pf, err := netip.ParsePrefix(string(p)); err == nil {
				r.Reserved = append(r.Reserved, pf)
			}
		}
	}
	return r
}

// gitFragmentPatterns: a fragmentConfigMaps entry landed through Git review, so any tag is
// acceptable in principle — the structural rules (owners, approvers, grant shape, reserved space)
// still apply.
var gitFragmentPatterns = []string{"tag:*"}
