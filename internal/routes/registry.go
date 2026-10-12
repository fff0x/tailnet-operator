package routes

import (
	"net/netip"
	"slices"
	"sort"
	"strings"
	"time"
)

// Site is a TailnetSite as the registry sees it: its prefixes and the tags of the routers that
// advertise them. Created orders sites for conflict resolution (older wins).
type Site struct {
	Name     string
	Created  time.Time
	Prefixes []string
	Tags     []string
}

// Reserved is address space no site may overlap (node prefix, cluster LAN/pod/service/LB ranges).
type Reserved struct {
	Name     string
	Prefixes []string
}

// Node is the control server's view of one node: tags plus advertised and approved routes.
type Node struct {
	Name      string
	Tags      []string
	Available []string
	Approved  []string
}

// Conflict reasons. Both block the site: nothing is rendered or approved for it.
const (
	OverlapsReserved = "OverlapsReserved"
	OverlapsSite     = "OverlapsSite"
)

// Conflict names why a site is blocked: the reserved network or the older site, and the prefix.
type Conflict struct {
	Reason string
	Other  string
	Prefix string
}

// SiteState is what the controller writes into a site's status.
type SiteState struct {
	Blocked    *Conflict
	Unmanaged  []string // nodes advertising an overlapping route without carrying an advertiser tag
	Advertised []string // site prefixes some advertiser node offers (exact match)
	Approved   []string // site prefixes approved on some advertiser node (exact match)
}

// Result of Build. Shipped are the unblocked sites, oldest first.
type Result struct {
	Shipped []Site
	States  map[string]SiteState
}

// Build is the pure route registry, no I/O. Rules, in order:
//
//  1. A site prefix overlapping a reserved network blocks the site (OverlapsReserved).
//  2. A site prefix overlapping an older, unblocked site blocks the younger site (OverlapsSite);
//     the older one is untouched, so a conflict never flips an already-serving site. Two routers
//     carrying the same tag and advertising the same prefixes are ONE site (HA), not two.
//  3. A node without an advertiser tag that advertises a route overlapping a site prefix is
//     reported (Unmanaged), never blocked — the managed route still ships and the client's
//     longest-prefix match decides.
//
// Advertised/Approved compare exact prefixes against advertiser nodes: a site is advertised as-is.
//
// ponytail: host routes (/32 egress targets, gateway routes) covered by a site prefix are not
// de-duplicated out of any gateway's TS_ROUTES — Headscale resolves them by longest prefix.
// Upgrade path: thread Result into gateway.SpecRouteInputs when a gateway should drop covered /32s.
func Build(sites []Site, reserved []Reserved, nodes []Node) Result {
	ordered := slices.Clone(sites)
	sort.SliceStable(ordered, func(a, b int) bool {
		if !ordered[a].Created.Equal(ordered[b].Created) {
			return ordered[a].Created.Before(ordered[b].Created)
		}
		return ordered[a].Name < ordered[b].Name
	})
	res := Result{States: make(map[string]SiteState, len(ordered))}
	for _, s := range ordered {
		st := SiteState{}
		st.Blocked = reservedConflict(s, reserved)
		if st.Blocked == nil {
			st.Blocked = siteConflict(s, res.Shipped)
		}
		if st.Blocked == nil {
			res.Shipped = append(res.Shipped, s)
		}
		for _, n := range nodes {
			if hasAny(n.Tags, s.Tags) {
				st.Advertised = append(st.Advertised, intersect(s.Prefixes, n.Available)...)
				st.Approved = append(st.Approved, intersect(s.Prefixes, n.Approved)...)
			} else if overlapsAny(s.Prefixes, n.Available) {
				st.Unmanaged = append(st.Unmanaged, n.Name)
			}
		}
		st.Advertised = sortedSet(st.Advertised)
		st.Approved = sortedSet(st.Approved)
		st.Unmanaged = sortedSet(st.Unmanaged)
		res.States[s.Name] = st
	}
	return res
}

func reservedConflict(s Site, reserved []Reserved) *Conflict {
	for _, r := range reserved {
		for _, p := range s.Prefixes {
			if overlapsAny([]string{p}, r.Prefixes) {
				return &Conflict{Reason: OverlapsReserved, Other: r.Name, Prefix: p}
			}
		}
	}
	return nil
}

func siteConflict(s Site, older []Site) *Conflict {
	for _, o := range older {
		for _, p := range s.Prefixes {
			if overlapsAny([]string{p}, o.Prefixes) {
				return &Conflict{Reason: OverlapsSite, Other: o.Name, Prefix: p}
			}
		}
	}
	return nil
}

// overlapsAny reports whether any prefix in a shares an address with any prefix in b.
// Unparsable entries never overlap (the CRD guarantees canonical prefixes; live routes come
// from the control server and are trusted to be well-formed).
func overlapsAny(a, b []string) bool {
	for _, x := range a {
		px, err := netip.ParsePrefix(x)
		if err != nil {
			continue
		}
		for _, y := range b {
			py, err := netip.ParsePrefix(y)
			if err == nil && (px.Overlaps(py)) {
				return true
			}
		}
	}
	return false
}

func hasAny(have, want []string) bool {
	return slices.ContainsFunc(have, func(t string) bool { return slices.Contains(want, t) })
}

func intersect(a, b []string) []string {
	var out []string
	for _, x := range a {
		if slices.Contains(b, x) {
			out = append(out, x)
		}
	}
	return out
}

func sortedSet(ss []string) []string {
	if len(ss) == 0 {
		return nil
	}
	slices.Sort(ss)
	return slices.Compact(ss)
}

// Message formats a conflict for a condition message, e.g.
// "10.0.0.0/24 overlaps reserved network nodes" / "… overlaps older site branch-a".
func (c Conflict) Message() string {
	kind := "reserved network"
	if c.Reason == OverlapsSite {
		kind = "older site"
	}
	return strings.Join([]string{c.Prefix, "overlaps", kind, c.Other}, " ")
}
