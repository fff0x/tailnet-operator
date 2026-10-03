# Changelog

Notable changes are recorded here using [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [Unreleased]

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
