// Package gateway contains side-effect-free planning for a persistent kernel
// subnet router. It performs no Kubernetes or Headscale operations. The separate
// gateway controller currently reports suspension only.
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
// without changing sysctls. A future writer must independently prove fresh state,
// persistent auth provenance, exclusive names, image and network compatibility.
// Neither the suspension controller nor the adoption planner invokes this model.
// The separate read-only fresh snapshot inspection validates necessary state,
// hosts ownership and inventory, but always blocks on unverified auth/node
// provenance; it is not permission to create anything.
//
// The ephemeral ingress/egress lifecycle (key minting, duplicate deletion, node
// renaming) is not suitable for these persistent gateways and must not be reused.
package gateway
