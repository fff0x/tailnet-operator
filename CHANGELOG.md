# Changelog

Notable changes are recorded here using [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [Unreleased]

### Added

- `TailnetGateway` conditions are exported through `tailnet_resource_ready`/`tailnet_resource_condition`
  (suspended gateways are withdrawn), and the chart alert `TailnetGatewayFreshBlocked` (warning, 5 min)
  pages when the fresh writer blocks — follow-up to the 2026-10-07 expired-key incident (Issue `cdcfb19`).

### Changed

- `task e2e-full` runs the CI gate (`hack/ci-test.sh`) followed by every Tier-2 kind suite; the
  dev shell now ships `govulncheck`, and `hack/ci-test.sh`/`hack/e2e-kind.sh` honour a pre-set
  `GOTOOLCHAIN` (CI keeps `local`). No runtime change.

## [0.14.1] - 2026-10-13

### Fixed

- `TailnetSite`: an exit node's default routes (`0.0.0.0/0`, `::/0`) no longer count as an
  `UnmanagedOverlap` — they offer the internet, not a subnet. Before, every site on a tailnet
  with an exit node reported `Unmanaged` and `TailnetUnmanagedRouteOverlap` fired after 30 min.
- Metrics: `Ready` with reason `RouteConflict` is exported as such instead of `Other`.
- `PolicyRendered` names blocked sites (`site/<name>`) in its skipped list wording.

## [0.14.0] - 2026-10-12

### Added

- `TailnetSite` (cluster-scoped): declare a remote network — branch `/24`, management range or a
  single host as `/32` — advertised by routers identified **by tag** (`advertisedBy.tags`, default
  `policy.routeApprovers`). The policy controller appends `autoApprovers.routes` for the prefixes,
  the existing replay approves them on every node carrying an advertiser tag (including a hand-built
  router in another cluster), and the site reports `Advertised`, `Approved`, `Ready` from the node
  list. Grants are not rendered: who may reach a site stays in the base policy.
- `Tailnet.spec.reservedNetworks[]`: address space no site may overlap (node prefix, each
  cluster's LAN/pod/service/LB ranges). The pure registry `internal/routes.Build` blocks a site that
  overlaps a reserved network (`RouteConflict/OverlapsReserved`) or an **older** site
  (`OverlapsSite`; the older site is never affected), and reports — never blocks — a node without
  an advertiser tag that advertises an overlapping route (`UnmanagedOverlap`). Blocked sites are
  listed as `site/<name>` in `PolicyRendered`'s skipped inputs.
- Alerts `TailnetRouteConflict` (warning, 15 min) and `TailnetUnmanagedRouteOverlap` (info,
  30 min); dashboard row "8. Routes"; `tailnet_resource_ready`/`_condition` carry
  `kind="TailnetSite"`. Runbooks in USAGE §9a and §14. RBAC: read `tailnetsites`, write their status.
- Without `TailnetSite` CRs the rendered policy is byte-identical to before, so upgrading never
  triggers a policy write.

### Changed

- Pre-auth keys are bound to the identity they were minted for: the authkey Secret carries
  `tsunaro.io/server`, `tsunaro.io/tag` and `tsunaro.io/tailnet-uid`. A key is reused only while
  its server and effective tag match the CR; a changed server or tag mints a new key at once and the
  agent pod restarts so the node re-registers with the new identity (the tag is now a pod-template
  annotation; the Tailnet UID is recorded only). Legacy and transferred Secrets without a binding
  keep their key and are labelled in place — `TestTransferredKeysReuseCredentials` still holds.
  Upgrading rolls every agent pod once because the pod template changed.

### Fixed

- After `PolicyApplied=False/PolicyRejected` the write is retried at most every minute (was: up to
  5 min). The blocker typically clears on the Headscale side — duplicate users deleted, a
  short-lived test `src` re-registered — without any Kubernetes event, so only the retry cadence
  decides how fast the live policy catches up. Transport failures (`ApplyFailed`) keep the 5-min cap.

- Test flake `TestVirtualHostReloadFencesDelayedSNIMetrics` (cmd/agent): the metric
  snapshot could race the new generation's own byte accounting, which the HTTP
  listener records after `Conn.Write` returns. The test now closes its keep-alive
  connection and waits for the connection gauge to drop before snapshotting; the
  fencing assertion itself is unchanged. No runtime change.

## [0.13.0] - 2026-10-09

### Added

- `Tailnet` condition `UsersUnique` and gauge `tailnet_headscale_user_conflicts`
  (`status.userConflicts`): the operator lists Headscale users every reconcile
  and reports names shared by more than one user. Headscale rejects every policy
  write while such a collision exists (`multiple users found`), which used to
  surface only as `PolicyApplied=False/PolicyRejected` with a bare HTTP status;
  that message now points at `UsersUnique`. Only the count and the user IDs are
  published, never a name. The check is informational and does not block writes.
- Dashboard: row 2 gains a stacked bar chart of resources per active `Ready`
  reason, row 3 a history of egress targets in `NotApproved`.

### Changed

- `Ready=False` on `TailnetEgress` and `TailnetIngress` now repeats the reason
  and message of the first blocking condition (egress: `Registered`,
  `RoutesGranted`, `TargetsReachable`; ingress: `Registered`, `PolicyGranted`,
  `BackendsReachable`) instead of the generic `NotReady`, so the
  `TailnetResourceNotReady` alert label and the dashboard name the failure class.
  `NotReady` remains only before the first complete reconcile.
- `TailnetGateway` keeps `WorkloadCurrent` as `Unknown/Suspended`,
  `Unknown/RuntimeUnavailable` or `Unknown/TearingDown` instead of removing the
  condition; a suspended or draining gateway now shows seven conditions.
- The agent no longer defaults `AGENT_MODE` to `egress`. An unset or unknown
  value is a startup error, and the egress Deployment now sets `AGENT_MODE=egress`
  explicitly, as the ingress Deployment always did. An ingress agent that lost the
  variable used to come up silently as an egress; it now fails loudly. Upgrade
  the operator before or together with the agent image: an older operator renders
  egress Deployments without the variable, and this agent refuses to start from
  them. The chart ships both at matching versions.
- The post-publication image audit (`hack/audit-image.sh`) pins the tools the CI
  broker v1.4.1 ships: syft 1.54.1, trivy 0.75.0, and `cosign-legacy` v2.5.0 for
  every signature and attestation operation. The broker now dual-signs with
  cosign v3 (OCI referrers bundles) and the legacy tag form; the audit stays on
  the legacy binary because that is the form the registry's trust extension and
  Kyverno verify. Every `main` build since 2026-10-08 had failed at the audit's
  tool preflight after the broker upgrade; those commits were published without
  SBOM or provenance attestations. The same broker also writes `artifactType`
  (image config) and empty base-image annotations into every index descriptor;
  the audit's index contract now accepts exactly that and still rejects any
  other artifact type or key.

### Security

- Go 1.26.9 and `golang.org/x/net` v0.60.0: `govulncheck` reported ten reachable
  `net/http`, `net/textproto` and `crypto/tls` advisories (GO-2026-6603 … 6617)
  against Go 1.26.7 / x/net v0.58.0, on the agent's TLS and health paths among
  others. The module now requires Go 1.26.9, the CI test image is pinned to it,
  and the scan is clean with the fixed toolchain. The single remaining finding
  is the unfixed `x/crypto/openpgp` advisory (GO-2026-5932) in a module we
  require but never import.

### Documentation

- Gateway reference: when to set `routes.advertiseEgressTargets: false`, why
  the DNS zone's `NS`/SOA primary point at the apex itself, and that container
  images are the only mutable part of the gateway Pod template.
- `status.dnsName`/`status.hosts` are gateway-zone names rendered from the CR
  name and do not follow `spec.hostname`; `status.hostname` is the MagicDNS
  identity. INSTALL and USAGE now state that the `ingressNameTemplate` zone must
  differ from the MagicDNS `base_domain`, and the Kind rename test pins the
  invariant instead of recording it as a divergence.

## [0.12.1] - 2026-10-07

### Fixed

- A fresh `TailnetGateway` fell into permanent `Ready=False/FreshBlocked` exactly
  24 hours after creation: completed-set observation re-validated the minted
  pre-auth key's expiry (`gatewayKeyLifetime`) and rejected the spent key. While
  blocked, the live DNS reconciler (`UpdateDNSRevision`) did not run, so the
  gateway's zone kept stale agent addresses after ingress restarts. Expiry is now
  enforced only on the bootstrap paths (mint, record write, record recovery);
  observation of a set with a completion receipt still binds Secret name, UID,
  resourceVersion, key ID and the recorded expiry value, but no longer compares
  that value against the clock. No re-mint, no Headscale write, no CRD change.

## [0.12.0] - 2026-10-07

### Release notes

The generated ingress agent is now named `ingress-<CR name>` (Deployment and
NetworkPolicy), matching its Headscale host. A `TailnetIngress` may therefore share
its name with a user workload in the same namespace; before, such a CR stopped with
`HTTPTransitionBlocked`. On upgrade the operator drains and deletes the legacy
Deployment and NetworkPolicy named like the CR (only if the CR controls them; a
foreign object of that name is left alone) before the new agent starts, so every
ingress restarts once (`Ready=False/WorkloadMigrating`, normally under a minute).
Pod labels, ConfigMap, Secrets and the Headscale node identity are unchanged.

A TLS Secret that cert-manager issued for this CR's own Certificate name and that
nothing owns any more (the leftover of a deleted CR) is taken over instead of
blocking the new CR with `TLSSecretConflict`.

The `DNS` printer column of `TailnetIngress` is replaced by `HOSTS`
(`status.hosts`), the names the agent actually serves: HTTP expose names and
aliases, or the node name for L4-only ingresses. `status.dnsName` stays the node's
identity and first certificate name; it is not a route once every HTTP expose has a
`dnsLabel`. A request to a certificate name without a route now completes the TLS
handshake instead of ending in an alert and gets `308` to the only served host or
`404` listing the served hosts (SNI and `Host` must still agree; unknown names are
still rejected).

`monitoring.podMonitor.scrapeFrom` (NetworkPolicy peers) is passed to the operator as
`AGENT_SCRAPE_PEERS` and adds one ingress rule on the agents' health/metrics port to
every generated ingress and egress NetworkPolicy, replacing site-owned,
CNI-specific policies for Prometheus. Default: none.

### Added

- `TailnetIngress.status.hosts` and the `HOSTS` printer column (replaces `DNS`).
- `TailnetGateway` condition `ServiceReady` (`True/LoadBalancerAssigned`,
  `False/LBPending`); `Ready` does not wait for it.
- Event `GatewayTeardownFinished` when a gateway teardown releases its finalizer.
- Chart value `monitoring.podMonitor.scrapeFrom`, env `AGENT_SCRAPE_PEERS`.

### Changed

- Ingress agent Deployment and NetworkPolicy are named `ingress-<CR>`; the legacy
  objects are retired automatically (`WorkloadMigrating`, `WorkloadMigrationBlocked`).
- Orphaned cert-manager TLS Secrets of the same Certificate name are adopted.
- The agent answers certificate names without a route with 308/404 instead of a TLS alert.

## [0.11.0] - 2026-10-06

### Release notes

A `TailnetGateway` static DNS record can now be a CNAME inside the same zone:
`dns.staticRecords[]` admits an optional `target` FQDN as a mutually exclusive
alternative to `address`. The target must lie within `dns.zone` (equal to the
zone or ending in `.<zone>`) and must differ from the record's own FQDN. The
rendered Corefile also enables the CoreDNS `prometheus :9153` listener and a
global `reload` plugin so that Corefile changes land without a Pod restart,
and the tailscale sidecar is now started with `TS_ENABLE_METRICS=true` on the
existing `TS_LOCAL_ADDR_PORT` (tcp/8080). The default chart's `PodMonitor`
scrapes both ports. The completion receipt remains format 3; the Pod template
and the derived `Corefile` are now reconciled live, keyed off the operator-
written `tsunaro.io/template-sha256` annotation on the `StatefulSet`
(StatefulSet fields outside the template, like `replicas`, `selector`,
`serviceName` and `updateStrategy`, are still bound). Existing fresh gateways
upgrade in place. A v0.10.0 completion receipt stores the `StatefulSet` and
`Corefile` digests under the old rule; on the first reconcile after upgrade the
operator recognises the old rule, re-verifies the whole retained set and rewrites
the immutable `-fresh` receipt to the new digests. The rewrite is crash-safe
through a transient `-fresh-next` staging `ConfigMap`: if the operator dies
between deleting and recreating `-fresh`, the next reconcile recovers from the
stage instead of minting a new identity. Afterwards the operator (idempotently)
rewrites the Pod template with the new metrics env/port; the running Pod picks up
the new `Corefile` via `reload 1s`, and you delete `Pod <name>-0` once to also
roll the sidecar onto `TS_ENABLE_METRICS`. A format-1/2 receipt still reports
`IdentityChanged` and must be recreated.
No CRD, RBAC or chart contract change beyond the additive `target` field.

### Added

- `GatewayStaticRecord.target`: mutually exclusive with `address`, admits an
  FQDN inside the same `dns.zone` and renders a CNAME in `zone.db`. CRD CEL
  rejects both-set, neither-set, out-of-zone and self-FQDN targets at admission.
- Operator metrics coverage for `TailnetGateway` pods: Tailscale sidecar
  Prometheus endpoint on tcp/8080 (`TS_ENABLE_METRICS=true`), CoreDNS
  Prometheus endpoint on tcp/9153, both scraped by the default `PodMonitor`.

### Changed

- The completion receipt no longer binds the `StatefulSet` Pod template or the
  derived `Corefile`; both are reconciled live. Template drift is tracked
  through a `tsunaro.io/template-sha256` annotation on the `StatefulSet`
  (annotation-keyed CAS), `Corefile` drift through the existing
  `tsunaro.io/dns-content-sha256` annotation on the `-coredns` `ConfigMap`.
  `WorkloadCurrent` now reads `pod.labels[controller-revision-hash]` against
  `sts.Status.UpdateRevision` instead of comparing container images.
- A v0.10.0 (format-3) completion receipt is migrated to the new digest rule in
  place on the first reconcile, via a crash-safe `-fresh-next` staging ConfigMap;
  no gateway identity is reminted. Teardown also removes a leftover `-fresh-next`.

## [0.10.0] - 2026-10-06

### Release notes

A running fresh `TailnetGateway` now reconciles its route set and LoadBalancer pool
labels: changes to `routes.lan`, `routes.advertiseEgressTargets`, `service.tailnetLBCIDR`,
the targets of the Tailnet's `TailnetEgress` objects and `service.poolLabels` reach the
StatefulSet template (`TS_ROUTES`) and the Service without reporting `IdentityChanged`.
The Pod is never restarted (`OnDelete`); `WorkloadCurrent=False/PodTemplateStale` names
the routes it does not advertise yet, and `Ready` binds to the running Pod's own
`TS_ROUTES`. With an operator-owned policy, every gateway's tags and advertised routes
are merged into `tagOwners`/`autoApprovers.routes`, so `RoutesInSync` turns `True/Approved`
without a manual `headscale nodes approve-routes`. The completion receipt is now format 3;
gateways with a format-1 or format-2 receipt report `IdentityChanged` and must be deleted
(`spec.deletionPolicy: Delete`) and recreated. The CRD remains experimental; `spec.suspend`
still defaults to `true`. No CRD, RBAC or chart contract change (Services and StatefulSets
already carry `update`).

### Added

- With an operator-owned policy (`policy.baseConfigMap` set; `Apply` writes and replays approvals, `DryRun` only renders), every fresh
  `TailnetGateway` of the Tailnet contributes its tags to `tagOwners` and its advertised
  routes (LAN, `tailnetLBCIDR`, egress host routes) to `autoApprovers.routes`, approved for
  the gateway's own tags. The existing route-approval replay therefore approves gateway
  routes without a manual `headscale nodes approve-routes`. Gateway create, change and
  delete trigger a re-render. Base `autoApprovers` entries stay and are merged by union.

- A running fresh `TailnetGateway` now follows `routes.lan`, `routes.advertiseEgressTargets`,
  `service.tailnetLBCIDR` and the targets of the Tailnet's `TailnetEgress` objects into
  `TS_ROUTES` of the StatefulSet template, and `service.poolLabels` onto the LoadBalancer
  Service. The Pod is never restarted (`OnDelete`); `WorkloadCurrent=False/PodTemplateStale`
  names the routes it does not advertise yet. New reasons `ServiceUpdateBlocked` and
  `ServiceUpdateConflict`. The policy controller plans the same routes from the spec.

### Changed

- The `TailnetGateway` completion receipt is now format 3: routes, `tailnetLBCIDR` and
  `poolLabels` are no longer pinned, and `Ready` binds to the running Pod's own
  `TS_ROUTES`. Gateways with a format-1 or format-2 receipt report `IdentityChanged`;
  delete (`deletionPolicy: Delete`) and recreate them.
- `TailnetGateway` `RoutesInSync` now reports `True/Approved` or `False/NotApproved`
  (missing prefixes named) for a Ready fresh gateway instead of
  `Unknown/ExternallyManaged`. It is read-only.

## [0.9.0] - 2026-10-06

### Release notes

A completed fresh `TailnetGateway` now tolerates spec updates: the completion
receipt (format 2) pins identity fields only, `image`/`dns.image` flow into the
StatefulSet template without a Pod restart (`WorkloadCurrent` reports staleness),
and a changed identity field reports `Ready=False/IdentityChanged`. The operator
Role gains `update` on `statefulsets`. Gateways created by 0.8.0 or earlier carry a
format-1 receipt and must be deleted (`spec.deletionPolicy: Delete`) and recreated.
The CRD remains experimental; `spec.suspend` still defaults to `true`.

### Changed

- The `TailnetGateway` completion receipt is now format 2 and pins identity fields
  instead of generations and full spec hashes. `deletionPolicy`, `suspend` (including
  a suspend/resume round trip), `dns.staticRecords`, `dns.wildcardAddress`, container
  images and Tailnet fields other than `server` and `dns.hostsConfigMap` no longer
  block a running gateway. A changed identity field reports
  `Ready=False/IdentityChanged` instead of `FreshBlocked`. Gateways created by 0.8.0
  or earlier must be deleted (`deletionPolicy: Delete`) and recreated.
- The operator Role gains `update` on `statefulsets` (operator namespace only).
  The StatefulSet digest in the receipt now excludes container images.

### Added

- `image` and `dns.image` changes are written into the StatefulSet Pod template.
  The `OnDelete` strategy is kept, so the operator never restarts the Pod; the new
  `WorkloadCurrent` condition reports `PodCurrent` or `PodTemplateStale` (delete
  Pod `<gateway>-0` to apply).
- Teardown completion is logged at `info` level with the gateway name and outcome.

## [0.8.0] - 2026-10-05

### Release notes

Experimental fresh-only `TailnetGateway` continues from 0.7.1 with two steps toward
production use: an explicit teardown contract and a live DNS reconcile. The
`TailnetGateway` CRD remains experimental; `spec.suspend` still defaults to `true`
and existing gateways are not adopted. Gateways rendered by 0.7.x carry no DNS CAS
annotations and permanently report `DNSReady=False/DNSUpdateBlocked`; migrate by
deleting with `spec.deletionPolicy: Delete` and recreating.

### Added

- Live DNS reconcile for a fresh `TailnetGateway`: once the completion receipt is
  verified, the controller re-renders the derived `-coredns` ConfigMap from the
  Tailnet hosts source on every reconcile, advancing the SOA serial only on
  semantic change and writing with a resourceVersion CAS. The initial render
  carries the `tsunaro.io/dns-serial` and `tsunaro.io/dns-content-sha256`
  annotations; `zone.db` is excluded from the completion fingerprint while
  `Corefile` and every other key remain digest-bound. The `DNSReady` condition
  reports `DNSInSync`, `DNSUpdateBlocked` or `DNSUpdateConflict` and is
  independent of `Ready`. Gateways rendered by 0.7.x carry no annotations and
  permanently report `DNSUpdateBlocked` until deleted and recreated with
  `deletionPolicy: Delete`.
- `TailnetGateway.spec.deletionPolicy: Delete` tears down the operator-created fresh
  resources on CR deletion: StatefulSet first, then the Headscale node and the minted
  bootstrap key, then the receipt children by recorded UID and the state/auth Secrets
  and receipts last. Every delete is UID-preconditioned; foreign objects or Headscale
  errors block with `Ready=False/TeardownBlocked` and nothing further is removed.
  Switching back to `Retain` releases the finalizer. `Retain` stays the default and
  still deletes nothing.

### Changed

- Chart RBAC: namespace-local `delete` on StatefulSets, PodDisruptionBudgets,
  ServiceAccounts, Roles and RoleBindings, and `patch` on `tailnetgateways` for the
  teardown finalizer.

### Fixed

- Headscale client: expire pre-auth keys by numeric ID as Headscale 0.26+ requires;
  the previous `key` field was silently ignored and expired nothing.

## [0.7.1] - 2026-10-05

### Fixed

- Isolate fixed DNS Service IPs from automatic LoadBalancer Service ClusterIP allocation
  in the Gateway API test fixture. A deterministic regression checks that separation;
  production reconciliation and provenance checks are unchanged.

### Release notes

This release includes the experimental fresh-only Gateway described in 0.7.0 below.
All experimental limits remain unchanged. The v0.7.0 tag is retained, but its failed
release build published no image or chart; use 0.7.1 for installation.

## [0.7.0] - 2026-10-05

### Added

- **Experimental, fresh-only `TailnetGateway`** for a persistent IPv4 kernel subnet router
  with a local authoritative DNS snapshot. `spec.suspend` defaults to `true`; explicit
  `false` enables create-only reconciliation. Existing gateways are never adopted.
- Independently retained State/auth/child provenance, exclusive resource creation and
  runtime Ready checks against the persistent state and online Headscale identity.
  Partial or uncertain creation is retained and blocked, not reminted or repaired.
- Namespace-local `get/create` for StatefulSets, PDBs, ServiceAccounts, Roles and
  RoleBindings. No new update/delete, escalation or binding grants for these resources.
- Real Kubernetes API tests and a controller-driven Kind proof with Headscale 0.29.3,
  Tailscale 1.102.4 and CoreDNS 1.14.6 on Linux amd64: fresh TCP /32 forwarding and local
  UDP/TCP DNS before and after StatefulSet Pod recreation, retaining node/IP/State UID.
  Backend socket-source checks distinguish forwarding from native Kubernetes reachability.
  Route absence before approval/after revocation is not packet-level ACL-denial evidence.

### Experimental limits

Deliberately no adoption, IPv6, update or rollback path. Spec/generation changes and
expired bootstrap keys keep blocking reconciliation.

In detail: no adoption, IPv6 writer, dynamic DNS/route updates, rollback/compensating cleanup, automatic key renewal, arbitrary topology proof, arm64 runtime or live deployment. Initial DNS stays at serial 1 and is never reset/reapplied. Expired auth blocks observation even if a retained router remains running. Spec/generation changes, including suspend/resume, invalidate completion evidence; general resume/lifecycle support is not implemented. Suspension freezes reconciliation, not the running workload. The immutable receipts are privileged Kubernetes trust anchors, not signatures or a transaction. No CR-deletion/GC execution proof is claimed.

Without update/delete permissions for the new workload and RBAC resources, a created
Gateway is effectively immutable. Even an API-admitted spec change invalidates its
completion receipt and blocks reconciliation; the controller cannot update or replace
the retained runtime.

Ready proves bounded bootstrap/runtime health, not route approval, LoadBalancer allocation,
DNS queries or cluster DNS forwarding. The Kind fixture invokes the production reconciler
in-process; it does not prove a separately deployed operator or leader failover. Deployment
compatibility on Talos/Cilium remains unverified. Keep an existing gateway and its state,
routes and split DNS untouched; this release is not a cutover or migration mechanism.
See the [gateway reference](docs/reference/gateway.md) for prerequisites and evidence bounds.

## [0.6.0] - 2026-10-03

### Added

- Virtual hosts: a `TailnetIngress` may publish several `mode: http` exposes behind one node. Each
  expose gets its own DNS name (`spec.exposes[].dnsLabel`, rendered through
  `Tailnet.spec.dns.ingressNameTemplate`); at most one HTTP expose may omit the label. The agent
  terminates TLS on a single certificate covering every name, routes by SNI, and requires the HTTP
  `Host` to equal the SNI. Resolved names appear in `status.exposes[].dnsName`.
- Optional short alias per HTTP expose (`spec.exposes[].alias`) rendered from
  `Tailnet.spec.dns.ingressAliasTemplate`. The alias must resolve in the same DNS zone as
  `ingressNameTemplate`; it becomes an extra certificate SAN and SNI route, reported in
  `status.exposes[].dnsAliases`.
- DNS names and egress aliases are arbitrated oldest-owner-wins across one Tailnet. A younger CR that
  claims a name already held by an older one reports `Ready=False/DNSNameConflict` and is not
  published, replacing the previous lexical hosts-file de-duplication.
- Chart `agent.resources` defaults for ingress and egress: requests CPU `10m` and memory `32Mi`,
  memory limit `128Mi`, no CPU limit. Precedence selects one whole block:
  CR `spec.resources` > `Tailnet.spec.proxy.resources` > chart default, without per-key merging.
  `agent.resources: null` disables the chart fallback; `{}` retains Helm's merged defaults.
  Direct binary runs without `AGENT_RESOURCES` retain the zero default.

### Changed

- Upgrading to v0.6.0 retires every existing HTTP ingress agent once, including single-expose
  v1 and v2 ingresses, because the resolved TLS-source marker is absent. The operator scales the
  Deployment to zero and waits for its Pods to disappear before installing the current configuration.
  All exposes on that CR are briefly interrupted; L4-only ingresses do not use this HTTP barrier.
- Agents that inherit the new defaults restart once per CR with `Recreate` when their effective
  resources change. Ephemeral nodes re-register; expect a brief interruption. Higher-tier overrides
  are preserved.

## [0.5.1] - 2026-10-02

### Fixed

- HTTP ingress no longer negotiates gzip or decompresses backend responses on the client's behalf.
  Stored object bytes, content-encoding metadata and explicit client `Accept-Encoding` are preserved.

## [0.5.0] - 2026-10-02

### Added

- Verified HTTP-ingress backend TLS through `exposes[].backend.tls`: explicit SNI/verification name
  and namespace-local CA ConfigMap key, TLS 1.2 minimum, no system-root or plaintext fallback.
  Backend readiness requires a fresh verified handshake and matching projected trust.
- HTTP expose `timeouts.request` and `timeouts.backendRequest`, with explicit `0s` to disable each
  timer. Omission preserves unlimited whole-response duration and the 30-second backend-header wait.
- Agent configuration envelope v2 and `http-v2` Pod protocol annotation for extended ingresses.
  Older agents reject it; new agents retain legacy L4 and v1 HTTP support.

### Changed

- Backend CA updates replace transports and close idle connections without interrupting established
  streams. Missing or invalid projected trust blocks new backend traffic and readiness.

## [0.4.0] - 2026-10-02

### Changed

- Product name: **Tsunaro**. Go module `tsunaro.io/tailnet-operator`. Chart name, image repository
  and binary names are unchanged.
- **Breaking:** API group `tailnet.this-is-fine.io` → `tsunaro.io`; annotation/label keys become
  `tsunaro.io/<key>`; the leader Lease is `tailnet-operator.tsunaro.io`. There is no conversion:
  install the new CRDs, re-create the CRs under the new group, then delete the old CRDs.
- Agent containers use a read-only root filesystem and no longer mount a ServiceAccount token.
- Headscale error bodies are withheld from logs, Events and status because they can echo credentials.

### Added

- Helm chart (`charts/tailnet-operator`) with generated standalone manifests under `deploy/`,
  configurable agent image and namespace-local image-pull Secret references.
- Leader election (default on), PodDisruptionBudget for `replicas > 1`, topology spread settings.
- Optional ServiceMonitor, PodMonitor, bundled Prometheus alerts and a Grafana dashboard
  (Grafana Operator or ConfigMap).
- `TailnetIngress` HTTP mode: one `mode: http` expose on port 443 terminates TLS on the agent with a
  `kubernetes.io/tls` Secret (`spec.tls.secretName`), a cert-manager issuer (`spec.tls.issuerRef`) or
  the Tailnet-wide default (`Tailnet.spec.defaults.tls.issuerRef`). SNI and Host are bound to the
  ingress DNS name; the backend receives plain HTTP; certificates reload without a restart.
  New condition `TLSReady`, status fields `tlsSecretName`, `tlsNotAfter`, `exposes[].tlsReady`.
- Metrics: per-target/per-expose state, Headscale request duration/count, policy write duration,
  `tailnet_policy_pending`, `tailnet_policy_generated`, node online/last-seen, route replay counter,
  agent connection/byte/dial families.
- RBAC: `Certificate` get/create/patch/delete; `finalizers` update on the managed CRs.
- Signed multi-arch images with SPDX SBOM and SLSA v1 provenance attestations; `govulncheck` in CI.
- `internal/migration`: library helpers for explicit child ownership transfer (not wired into the controllers).
- Security policy, RBAC reference, Renovate configuration.

## [0.3.0]

- Headscale capability preflight: conditions `HeadscaleCompatible`, `PolicyMode`, `SplitDNS`;
  `COMPAT`/`DNS` columns; optional `headscale.version` hint. File mode blocks policy writes and
  route-approval replay; bootstrap works against an empty policy database.
- **Breaking admission rules:** Kubernetes ≥ 1.31; `spec` required; non-empty ingress `allowFrom`;
  stricter names, addresses and templates; unique target/expose names and expose ports; bounded
  list sizes and lifetimes. Validate existing CRs with `task test-validation` before upgrading.

## [0.2.3]

- `ApiReachable` follows Headscale `/health` (new reason `Unhealthy`); `ApiKeyValid` follows a live
  authenticated call (new reason `Rejected`); both re-checked at least every 5 min.

## [0.2.2]

- The policy controller no longer re-reconciles on its own rendered ConfigMap write.

## [0.2.1]

- Missed `autoApprovers` approvals are replayed after every successful policy write/InSync check
  (event `RoutesApproved`). Rejected or failed policy writes retry with backoff (15 s doubling to
  5 min); `TailnetPolicyApplyErrors` therefore counts more increments per outage.

## [0.2.0]

- **Breaking:** API group `tailnet.fr0st.dev` → `tailnet.this-is-fine.io` without conversion.
- Reason `ProbeFailed`; `status.tag` and `TAG` column; ingress DNS names publish IPv4 only;
  MagicDNS name restored after a duplicate; transient `ApplyFailed` logged at info; status-only
  updates no longer re-trigger reconciles.

## [0.1.1]

- Route diagnosis is prefix-aware: a target covered by an aggregate advertised route is `Present`.

## [0.1.0]

- `Tailnet.spec.policy` (operator-owned policy, `DryRun`/`Apply`), `TailnetIngress.spec.allowFrom`,
  conditions `PolicyRendered`/`PolicyApplied`/`PolicyGranted`, reasons `PolicyPending`/`PolicyDenied`.

## [0.0.6]

- `Tailnet.spec.dns`, `TailnetEgress.spec.targets[].aliases`, `TailnetIngress.status.dnsName`,
  `Backend.namespace`.
