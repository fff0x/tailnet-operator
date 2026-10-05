// Package gateway contains planning and a create-only fresh writer for a
// persistent kernel subnet router. Suspension is the default; explicit activation
// connects the pure planners to uncached Kubernetes and Headscale operations.
//
// Route planning keeps the LAN and LoadBalancer prefixes and can add literal
// IPv4/IPv6 egress host routes. DNS names are not resolved into advertised routes.
// Callers must check Tailnet/namespace scope, local reachability, and conflicts
// with control-plane and peer networks before applying a route set. A desired
// route is not evidence of its advertisement, approval or data-plane reachability.
//
// Adoption is explicitly UID-bound and requires identical, API-defaulted payloads
// with a settled singleton StatefulSet. State remains externally owned; resource
// retention requires avoiding garbage-collection owner references to the gateway.
// The planner neither mutates Secret contents nor calls Headscale. A controller
// still needs a verified persistent-node binding and a concurrency-safe takeover
// protocol before it can act on these plans.
//
// Fresh DNS rendering compiles a bounded hosts snapshot and static records into
// one authoritative file zone, preserving NODATA for known names. Forward zones
// are not implemented; they fail closed. Callers must verify source ownership,
// persist SOA serial progression and publish complete configuration snapshots.
// The pure DNS revision transition computes a canonical content hash and expected
// target resourceVersion, but neither persists them nor performs an API CAS.
// This renderer is not a projection for adopting an existing CoreDNS instance.
//
// Fresh resource rendering models initial retained Kubernetes objects only. It
// scopes automatic routes, limits state access and checks kernel prerequisites
// without changing sysctls. The active fresh writer captures independent Create
// UIDs, persistent auth provenance and exclusive names. Kernel/image compatibility
// remains a deployment prerequisite. There is no adoption or resource-update path.
// The separate read-only fresh snapshot inspection validates necessary state,
// hosts ownership and inventory, but always blocks on unverified auth/node
// provenance; it is not permission to create anything.
//
// The ephemeral ingress/egress lifecycle (key minting, duplicate deletion, node
// renaming) is not suitable for these persistent gateways and must not be reused.
package gateway
