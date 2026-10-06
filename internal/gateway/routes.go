package gateway

import (
	"errors"
	"fmt"
	"net/netip"
	"slices"
	"strings"

	tnv1 "tsunaro.io/tailnet-operator/api/v1alpha1"
)

// RouteInputs describes explicit gateway routes and optional automatic host routes.
// LAN must contain at least one prefix; LoadBalancerCIDR is always required.
// EgressTargets is ignored entirely when AdvertiseEgressTargets is false.
type RouteInputs struct {
	LAN                    []string
	LoadBalancerCIDR       string
	AdvertiseEgressTargets bool
	EgressTargets          []string
}

// SpecRouteInputs builds the RouteInputs a Gateway wants from its spec: LAN, the tailnet
// LB CIDR and, unless advertiseEgressTargets is false, the targets of the non-deleting
// TailnetEgress CRs of this operator namespace and Tailnet. egresses may contain other
// scopes. RenderFresh, the route reconciler and the policy render all use it, so the
// advertised set and the approved set cannot drift apart.
func SpecRouteInputs(g *tnv1.TailnetGateway, tailnet, namespace string, egresses []tnv1.TailnetEgress) RouteInputs {
	ri := RouteInputs{LoadBalancerCIDR: string(g.Spec.Service.TailnetLBCIDR), AdvertiseEgressTargets: g.Spec.Routes.AdvertiseEgressTargets == nil || *g.Spec.Routes.AdvertiseEgressTargets}
	for _, prefix := range g.Spec.Routes.LAN {
		ri.LAN = append(ri.LAN, string(prefix))
	}
	if ri.AdvertiseEgressTargets {
		for _, eg := range egresses {
			if eg.Namespace != namespace || eg.Spec.TailnetRef.Name != tailnet || !eg.DeletionTimestamp.IsZero() {
				continue
			}
			for _, target := range eg.Spec.Targets {
				ri.EgressTargets = append(ri.EgressTargets, target.Address)
			}
		}
	}
	return ri
}

// RoutePlan contains canonical routes sorted by netip address, then prefix bits.
// Only identical prefixes are deduplicated: covered host routes remain explicit.
// SkippedDNS contains unique, lexically sorted DNS targets; none are resolved.
type RoutePlan struct {
	Routes     []string
	SkippedDNS []string
}

// ErrInvalidRoutes identifies invalid route configuration. Wrapped errors name
// only a field and, where applicable, its zero-based index, never supplied values.
var ErrInvalidRoutes = errors.New("invalid gateway routes")

// PlanRoutes validates and plans routes without I/O or modifying its inputs.
// Explicit CIDRs must use netip's canonical text, be masked and non-default, and
// not intersect IPv4/IPv6 multicast, loopback or unspecified address ranges.
// IPv4-mapped prefixes are rejected. The unspecified ranges here are the exact
// addresses 0.0.0.0/32 and ::/128, not all of 0.0.0.0/8. Explicit link-local
// prefixes are not excluded; the caller must assess their routability. No fixed
// Tailscale pool is excluded because Headscale can use custom address prefixes.
//
// Automatic targets accept usable IP literals (mapped IPv4 is unmapped), or
// lowercase ASCII DNS hostnames with no trailing dot, matching the Egress API.
// All-numeric dotted names are rejected rather than treating malformed IPv4 as
// DNS. Other DNS names, including hexadecimal-looking labels, are only skipped;
// they are never interpreted as legacy numeric addresses. Automatic IPs
// cannot be loopback, multicast, unspecified, link-local, broadcast or zoned.
//
// Any error returns a zero RoutePlan, never partial routes. The returned slices
// are newly allocated and do not alias the input slices.
func PlanRoutes(in RouteInputs) (RoutePlan, error) {
	if len(in.LAN) == 0 {
		return RoutePlan{}, fmt.Errorf("%w: LAN", ErrInvalidRoutes)
	}
	prefixes := make(map[netip.Prefix]struct{}, len(in.LAN)+1)
	for i, value := range in.LAN {
		p, ok := routePrefix(value)
		if !ok {
			return RoutePlan{}, fmt.Errorf("%w: LAN[%d]", ErrInvalidRoutes, i)
		}
		prefixes[p] = struct{}{}
	}
	lb, ok := routePrefix(in.LoadBalancerCIDR)
	if !ok {
		return RoutePlan{}, fmt.Errorf("%w: LoadBalancerCIDR", ErrInvalidRoutes)
	}
	prefixes[lb] = struct{}{}

	dns := make(map[string]struct{})
	if in.AdvertiseEgressTargets {
		for i, value := range in.EgressTargets {
			if addr, err := netip.ParseAddr(value); err == nil {
				zoned := addr.Zone() != ""
				addr = addr.Unmap()
				if zoned || !addr.IsGlobalUnicast() || addr.IsLinkLocalUnicast() {
					return RoutePlan{}, fmt.Errorf("%w: EgressTargets[%d]", ErrInvalidRoutes, i)
				}
				prefixes[netip.PrefixFrom(addr, addr.BitLen())] = struct{}{}
			} else if dnsTarget(value) {
				dns[value] = struct{}{}
			} else {
				return RoutePlan{}, fmt.Errorf("%w: EgressTargets[%d]", ErrInvalidRoutes, i)
			}
		}
	}

	ordered := make([]netip.Prefix, 0, len(prefixes))
	for p := range prefixes {
		ordered = append(ordered, p)
	}
	slices.SortFunc(ordered, comparePrefixes)
	plan := RoutePlan{Routes: make([]string, 0, len(ordered))}
	for _, p := range ordered {
		plan.Routes = append(plan.Routes, p.String())
	}
	for name := range dns {
		plan.SkippedDNS = append(plan.SkippedDNS, name)
	}
	slices.Sort(plan.SkippedDNS)
	return plan, nil
}

func comparePrefixes(a, b netip.Prefix) int {
	if cmp := a.Addr().Compare(b.Addr()); cmp != 0 {
		return cmp
	}
	return a.Bits() - b.Bits()
}

func routePrefix(value string) (netip.Prefix, bool) {
	p, err := netip.ParsePrefix(value)
	if err != nil || p.Bits() == 0 || p.Addr().Is4In6() || p.Addr().Zone() != "" ||
		p != p.Masked() || p.String() != value {
		return netip.Prefix{}, false
	}
	// Check overlap, not just the base address: e.g. 126.0.0.0/7 contains
	// loopback, and fe00::/7 contains multicast despite its unicast base.
	for _, reserved := range [...]netip.Prefix{
		netip.MustParsePrefix("0.0.0.0/32"),
		netip.MustParsePrefix("127.0.0.0/8"),
		netip.MustParsePrefix("224.0.0.0/4"),
		netip.MustParsePrefix("::/128"),
		netip.MustParsePrefix("::1/128"),
		netip.MustParsePrefix("ff00::/8"),
	} {
		if p.Overlaps(reserved) {
			return netip.Prefix{}, false
		}
	}
	return p, true
}

func dnsTarget(value string) bool {
	if len(value) == 0 || len(value) > 253 {
		return false
	}
	labels := strings.Split(value, ".")
	for _, label := range labels {
		if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for _, c := range label {
			if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-') {
				return false
			}
		}
	}
	return strings.Trim(value, "0123456789.") != ""
}
