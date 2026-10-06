# Changelog

Notable changes are recorded here using [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [Unreleased]

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
