package policy

import (
	"fmt"
	"net/netip"
	"strconv"
	"strings"
)

// FragmentRules is what a hub accepts from another cluster's policy fragment. The fragment is
// rendered by a spoke operator, but the hub cannot know that: a spoke administrator can hand-edit
// the ConfigMap, so every entry is checked against the hub's own limits before it is merged. The
// rules are structural — they bound WHAT a fragment may add, the question WHO reviewed it is the
// approval mode of the spoke.
type FragmentRules struct {
	// Globs (path.Match) the fragment's own tags must satisfy, e.g. "tag:*-prod-2-*". A tag the hub's
	// base already owns is exempt (the base entry wins at merge time, the fragment's is dropped).
	TagPatterns []string
	// Tags the hub's base policy owns (tagOwners keys). Exempt from TagPatterns.
	BaseTags map[string]bool
	// Allowed owner aliases of exported tags — the hub's policy.tagOwners.
	TagOwners []string
	// Allowed route approvers besides the fragment's own tags — the hub's policy.routeApprovers.
	RouteApprovers []string
	// Globs a grant's src may match besides the fragment's own tags — the hub's
	// ingressSourceAllowlist (the hub's list decides, not the spoke's).
	IngressSourceAllowlist []string
	// Prefixes a non-host route or destination must lie within (TailnetSite prefixes plus the
	// spoke's routeAllowlist). Only enforced when ContainRoutes is set.
	Allowed []netip.Prefix
	// Prefixes no route or destination may overlap — Tailnet.spec.reservedNetworks.
	Reserved []netip.Prefix
	// ContainRoutes requires every non-host (/32, /128) route and destination to be inside Allowed.
	// On for spokes pulled by the hub; off for Git-reviewed fragmentConfigMaps.
	ContainRoutes bool
}

// BaseTags returns the tagOwners keys of a base document — the tags a fragment may name without
// matching the spoke's patterns, because the base entry wins at merge time anyway.
func BaseTags(base []byte) map[string]bool {
	m, err := parse(base)
	if err != nil {
		return nil
	}
	owners, _ := m["tagOwners"].(map[string]any)
	out := make(map[string]bool, len(owners))
	for t := range owners {
		out[t] = true
	}
	return out
}

// ValidateFragment checks frag against r. Any violation is returned wrapped in ErrFragment with the
// offending path and value, so the status message names what to fix; values are policy aliases
// and prefixes, never credentials.
func ValidateFragment(frag []byte, r FragmentRules) error {
	m, err := parse(frag)
	if err != nil {
		return fmt.Errorf("%w: not valid policy HuJSON", ErrFragment)
	}
	for _, k := range sortedKeys(m) {
		switch k {
		case "tagOwners", "autoApprovers", "grants":
		default:
			return fmt.Errorf("%w: unexpected key %q", ErrFragment, k)
		}
	}

	own := map[string]bool{}
	if v, ok := m["tagOwners"]; ok {
		owners, ok := v.(map[string]any)
		if !ok {
			return fmt.Errorf("%w: tagOwners is not an object", ErrFragment)
		}
		for _, tag := range sortedKeys(owners) {
			if !strings.HasPrefix(tag, "tag:") {
				return fmt.Errorf("%w: tagOwners[%q] is not a tag", ErrFragment, tag)
			}
			if !r.BaseTags[tag] && !Allowed(tag, r.TagPatterns) {
				return fmt.Errorf("%w: tagOwners[%q] does not match the spoke's tag patterns", ErrFragment, tag)
			}
			vals := strs(owners[tag])
			if len(vals) == 0 || len(vals) != len(arr(owners[tag])) {
				return fmt.Errorf("%w: tagOwners[%q] must be a non-empty list of aliases", ErrFragment, tag)
			}
			for _, o := range vals {
				if !contains(r.TagOwners, o) {
					return fmt.Errorf("%w: tagOwners[%q] owner %q is not in the hub's tagOwners", ErrFragment, tag, o)
				}
			}
			own[tag] = true
		}
	}

	if v, ok := m["autoApprovers"]; ok {
		aa, ok := v.(map[string]any)
		if !ok {
			return fmt.Errorf("%w: autoApprovers is not an object", ErrFragment)
		}
		for _, k := range sortedKeys(aa) {
			if k != "routes" {
				return fmt.Errorf("%w: autoApprovers.%s is not allowed in a fragment", ErrFragment, k)
			}
		}
		routes, ok := aa["routes"].(map[string]any)
		if aa["routes"] != nil && !ok {
			return fmt.Errorf("%w: autoApprovers.routes is not an object", ErrFragment)
		}
		for _, cidr := range sortedKeys(routes) {
			if err := r.prefixOK(cidr, "autoApprovers.routes"); err != nil {
				return err
			}
			approvers := strs(routes[cidr])
			if len(approvers) == 0 || len(approvers) != len(arr(routes[cidr])) {
				return fmt.Errorf("%w: autoApprovers.routes[%q] must be a non-empty list of aliases", ErrFragment, cidr)
			}
			for _, a := range approvers {
				if !own[a] && !contains(r.RouteApprovers, a) {
					return fmt.Errorf("%w: autoApprovers.routes[%q] approver %q is neither a fragment tag nor a hub route approver", ErrFragment, cidr, a)
				}
			}
		}
	}

	if v, ok := m["grants"]; ok {
		grants, ok := v.([]any)
		if !ok {
			return fmt.Errorf("%w: grants is not a list", ErrFragment)
		}
		for i, gv := range grants {
			g, ok := gv.(map[string]any)
			if !ok {
				return fmt.Errorf("%w: grants[%d] is not an object", ErrFragment, i)
			}
			for _, k := range sortedKeys(g) {
				switch k {
				case "src", "dst", "ip":
				default:
					return fmt.Errorf("%w: grants[%d].%s is not allowed in a fragment", ErrFragment, i, k)
				}
			}
			src := strs(g["src"])
			if len(src) == 0 || len(src) != len(arr(g["src"])) {
				return fmt.Errorf("%w: grants[%d].src must be a non-empty list", ErrFragment, i)
			}
			for _, s := range src {
				if !own[s] && !Allowed(s, r.IngressSourceAllowlist) {
					return fmt.Errorf("%w: grants[%d].src %q is neither a fragment tag nor allowed by the hub's ingressSourceAllowlist", ErrFragment, i, s)
				}
			}
			dst := strs(g["dst"])
			if len(dst) == 0 || len(dst) != len(arr(g["dst"])) {
				return fmt.Errorf("%w: grants[%d].dst must be a non-empty list", ErrFragment, i)
			}
			for _, d := range dst {
				if own[d] {
					continue
				}
				if strings.HasPrefix(d, "tag:") || strings.HasPrefix(d, "group:") || strings.HasPrefix(d, "autogroup:") || d == "*" {
					return fmt.Errorf("%w: grants[%d].dst %q is not a fragment tag or a prefix", ErrFragment, i, d)
				}
				if err := r.prefixOK(d, fmt.Sprintf("grants[%d].dst", i)); err != nil {
					return err
				}
			}
			ports := strs(g["ip"])
			if len(ports) == 0 || len(ports) != len(arr(g["ip"])) {
				return fmt.Errorf("%w: grants[%d].ip must be a non-empty list", ErrFragment, i)
			}
			for _, p := range ports {
				if !tcpPort(p) {
					return fmt.Errorf("%w: grants[%d].ip %q is not tcp:<port>", ErrFragment, i, p)
				}
			}
		}
	}
	return nil
}

// prefixOK applies the route/destination rules: a canonical prefix, never the default route, never
// inside a reserved network and — with ContainRoutes — a host route or inside an allowed prefix.
func (r FragmentRules) prefixOK(s, where string) error {
	p, err := netip.ParsePrefix(s)
	if err != nil || p.Masked() != p {
		return fmt.Errorf("%w: %s %q is not a canonical prefix", ErrFragment, where, s)
	}
	if p.Bits() == 0 {
		return fmt.Errorf("%w: %s %q: the default route is never approved through a fragment", ErrFragment, where, s)
	}
	for _, res := range r.Reserved {
		if p.Overlaps(res) {
			return fmt.Errorf("%w: %s %q overlaps reserved network %s", ErrFragment, where, s, res)
		}
	}
	if r.ContainRoutes && !p.IsSingleIP() {
		inside := false
		for _, a := range r.Allowed {
			if a.Bits() <= p.Bits() && a.Contains(p.Addr()) {
				inside = true
				break
			}
		}
		if !inside {
			return fmt.Errorf("%w: %s %q is not a host route and lies in no TailnetSite or routeAllowlist prefix", ErrFragment, where, s)
		}
	}
	return nil
}

func tcpPort(s string) bool {
	n, ok := strings.CutPrefix(s, "tcp:")
	if !ok {
		return false
	}
	port, err := strconv.Atoi(n)
	return err == nil && port >= 1 && port <= 65535 && strconv.Itoa(port) == n
}

func contains(ss []string, s string) bool {
	for _, x := range ss {
		if x == s {
			return true
		}
	}
	return false
}
