// Package routes turns "the route my target needs is missing from the netmap" into a cause. This is
// the operator's whole diagnostic value: the two silent failures of the manual pilot — a route
// advertised before its approver existed, and the wrong assumption that Headscale distributes routes
// like Tailscale SaaS — both surface here as a named reason instead of a hanging connection.
package routes

// Reason is why a target route is (not) usable. Empty means present.
type Reason string

const (
	// Present: the route is in this node's netmap; nothing is wrong.
	Present Reason = ""
	// NotAdvertised: no node in the tailnet offers this prefix. The site gateway is not
	// advertising it (missing CLUSTER_SITE_ROUTES, or the gateway is down).
	NotAdvertised Reason = "NotAdvertised"
	// NotApproved: some node advertises it, but it is not approved anywhere. autoApprovers did not
	// fire (it only fires on a route *change*) or nobody approved it manually.
	NotApproved Reason = "NotApproved"
	// NoGrant: advertised and approved, yet absent from this node's netmap. Headscale filters the
	// netmap per node by policy; this node's tag has no grant reaching the prefix.
	NoGrant Reason = "NoGrant"
)

// Classify decides why route is or is not usable by a node.
//
//	netmap     — routes actually present in this node's netmap (its filtered view)
//	advertised — union of availableRoutes across all nodes (offered to the control plane)
//	approved   — union of approvedRoutes across all nodes
//
// The order matters: a prefix can be advertised without being approved, and approved without
// reaching a given node's netmap. Each check rules out the cause below it.
func Classify(route string, netmap, advertised, approved map[string]bool) Reason {
	if netmap[route] {
		return Present
	}
	if !advertised[route] {
		return NotAdvertised
	}
	if !approved[route] {
		return NotApproved
	}
	return NoGrant
}
