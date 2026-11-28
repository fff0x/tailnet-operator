# Changelog

Notable changes are recorded here using [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [Unreleased]

## [0.28.2] - 2026-11-28

### Fixed

- Console: the **Ports** and **Matched by** columns of the My Access table no longer break a value
  across lines.

## [0.28.1] - 2026-11-28

### Security

- `github.com/go-jose/go-jose/v4` 4.1.9 (CVE-2026-116587, reachable through the console's OIDC
  sign-in). The v0.28.0 image carries the affected version and failed the release audit; it is
  not accepted for use. Use v0.28.1.

### Added

- **Web console (`console.enabled`).** A third program in the operator image,
  `/tailnet-console`, shows Tailnets, spokes, TailnetIngresses and TailnetSites in four tables. It
  signs people in with OIDC (authorization code with PKCE S256, `state` and `nonce`) and takes the
  role from the `groups` claim: members of `console.oidc.adminGroup` are admins, members of
  `console.oidc.userGroup` (or every signed-in person when it is empty) are users. The session is
  a sealed cookie (AES-256-GCM, one hour, key generated at every start); no tokens are kept. User
  references in `allowFrom` appear only as a count, and logs carry no identity. The chart renders
  a Deployment, a Service, a ServiceAccount and a ClusterRole with `get`, `list` and `watch` on
  Tailnets, TailnetIngresses, TailnetSites and TailnetGrants, all named `<name>-console`; publish
  the console with a `TailnetIngress` in `mode: http` ([Console](docs/how-to/console.md)). Off by
  default.
  - **My access.** A page with two lists per Tailnet from the live policy: rules whose `src` names
    the person (e-mail, user name or provider identifier, built as Headscale builds it) or one of
    their policy groups, and rules for `autogroup:member` or `*`. Each row names the destination,
    the matching source, the origin (`TailnetGrant`, `TailnetIngress` or `Policy`, by comparison)
    and a grant's remaining time.
  - **Operator console API.** With `console.enabled` every operator replica serves
    `GET /v1/tailnets/<name>/{users,nodes,policy}` on port 8082 (Service `<name>-console-api`). It
    reads Headscale with the working key and admits only the console's ServiceAccount, checked by a
    `TokenReview` for the audience `tailnet-operator` (ClusterRole `<name>-console-api`). Nodes are
    tagged nodes only.
  - **Map.** The overview draws one server-rendered SVG map per Tailnet: the hub with its
    ingresses and sites, one box per spoke with its conditions and the tags it owns, each entry
    with `Ready` and node state. A list shows up to 12 entries and then `+N more`; the map carries
    no user references, node names or rule sources.
  - **Live updates.** The overview fetches itself every 10 seconds with the console's only script,
    `/static/console.js`, and shows a sign-in notice when the session has expired. The Content
    Security Policy now allows `script-src 'self'` and `connect-src 'self'`.
  - **Console network policy.** With `networkPolicy.enabled` the chart isolates the console pod
    for both providers and admits it on the operator's port 8082; `console.networkPolicy.idpCIDRs`
    is then required. Under `cilium` the console admits only `ingressPeers` and the node, and the
    operator's policy gains an ingress section: the console on 8082, everybody on metrics and
    health.
  - **Grant management (`console.accessManagement.enabled`, off by default).** Admins list all
    TailnetGrants and create, extend and revoke their own: one target (an ingress tag, a spoke
    tag or addresses inside a TailnetSite of a policy-owning Tailnet), ports prefilled from the
    target, recipients from the Headscale users with a provider identifier and the live policy's
    groups, and a fixed duration from 1 hour to 30 days or permanent. Revoking sets `expiresAt` to
    now; the console changes only grants labelled
    `app.kubernetes.io/managed-by: tailnet-console`. Users get 403; without the switch the pages
    do not exist. The chart adds `create`, `update` and `patch` on TailnetGrants, a
    PersistentVolumeClaim and a ConfigMap `<name>-console-audit` (both kept on uninstall), and a
    Role on exactly that ConfigMap.
  - **Audit log.** Every change is appended and synced to `audit.jsonl` on that volume before it
    is made, one JSON line with actor, grant, details and the SHA-256 of the previous line. The
    head goes to the ConfigMap and to the pod log (without identity); without both writes the
    change is refused (503), and a write the API server rejects is followed by `grant.failed`. The
    console checks the chain at start and on every view of the audit page, records each new break
    once and continues; nothing is rotated.
  - **Access requests.** New cluster-scoped kind `TailnetAccessRequest` (`tnar`), read only by the
    console; its `spec` is immutable. With access management every signed-in person requests a
    grant for themselves, on a tailnet whose Headscale knows them, or the extension of a console
    grant that names them alone; admins approve or reject on **Requests**. Nobody decides their own
    request; one rejection ends it, the requester may withdraw it. The last approval checks the
    request against the current targets, ports and recipients, records `grant.create` or
    `grant.extend` with requester and approvers, and the duration counts from then. The request's
    status names nobody: approvals are counted from the audit log, and only admins see who
    decided. A request whose grant was written but whose status was not counts as decided; only
    **Approve** closes it (`request.close`). Apply the CRD before upgrading (`task crd-upgrade`).
  - **Observed changes and cleanup.** Every minute the console compares all TailnetGrants with
    its log and records changes made outside it as `grant.observed`, without a person, and an
    expiry the operator confirmed as `grant.expired`. With `console.accessManagement.retentionDays`
    (default 30, 0 turns it off) it deletes its own grants that the operator reports `Expired`
    and decided requests that many days later, and lets pending requests expire (phase
    `Expired`); each step is in the log first. The chart grants `delete` only with a retention
    above 0. A user revokes a console grant that names them alone, at once; a grant that expired
    already cannot be revoked (409).
  - **Four-eyes approval (`console.accessManagement.fourEyes`, off by default).** An admin's new
    grant or extension becomes a request that another admin approves, and a user's request needs
    two admins; revoking acts at once.
  - **Console metrics and alerts.** With access management the console serves
    `tailnet_console_access_requests_pending{tailnet}` and `tailnet_console_audit_chain_breaks` on
    port 8081 (ServiceMonitor `<name>-console`, network policies for the port), checks its audit
    chain every 10 minutes, and the bundled rules add `TailnetConsoleAccessRequestPending` (info)
    and `TailnetConsoleAuditChainBroken` (warning).
  - The Headscale client decodes `displayName` and `providerId` of users.
- **`TailnetGrant`: time-bound TCP access for people and policy groups.** A cluster-scoped kind in
  the policy-owning cluster (`policy.mode: Apply`). It grants user references or base-policy groups
  access to the tag of a `TailnetIngress`, to an ingress tag of a merged spoke fragment or to
  prefixes inside a `TailnetSite`, on 1 to 16 TCP ports. With `expiresAt` the operator removes the
  grant from the policy by its own clock and reports `Ready=False/Expired`; the object stays. A
  grant with an invalid target is not rendered (`TargetUnknown`, `TargetOutsideSites`), so it
  cannot make Headscale reject the policy. The kind is administrative: a grant bypasses `allowFrom`
  and the spoke allowlist. After the expiry new connections are refused, and the agent closes
  the established connections to an ingress. An established connection to a host inside a
  `TailnetSite` is not closed ([Grants](docs/how-to/grants.md#expiry)).
  **Upgrade:** apply the new CRD before the operator (`task crd-upgrade`, or `CreateReplace` on a
  Flux `HelmRelease`). Without the `TailnetGrant` CRD the policy controller cannot
  start its watch, and the operator exits after the cache sync timeout (2 minutes) and restarts in
  a loop.

### Changed

- **The ingress agent closes open connections that the policy no longer permits.** Until now a
  policy change refused new connections only; a session that was open before continued while the
  two nodes stayed peers. Once per second the agent now compares each open connection of a
  `TailnetIngress` (`mode: l4` and `mode: http`, including WebSockets) with its packet filter and
  closes it, with the connection to the backend, when the filter would not admit it again. This
  applies to every policy change: an expired or deleted `TailnetGrant`, a changed `allowFrom`, a
  changed base policy. Measured with an L4 ingress: the connection failed 0.7 to 2.5 seconds
  after the revocation. Sessions that survived a revocation before now end;
  connections of peers that stay permitted are not touched. Not covered: a target inside a
  `TailnetSite` (no agent in the path) and an agent that has no contact to Headscale
  ([Grants](docs/how-to/grants.md#expiry)). The change is in the agent image: with a pinned
  `agentImage`, move the pin to get it.
- **A generated grant that loses an undeclared source is rendered once.** When the drop of an
  undeclared tag or group makes a generated or spoke grant equal to another grant of the rendered
  policy, the operator no longer renders the duplicate. Base grants stay unchanged.

## [0.28.0] - 2026-11-28

Tagged but not released: the image failed the release audit (see 0.28.1, *Security*). All of its
changes are listed under 0.28.1.

## [0.27.1] - 2026-11-25

### Changed

- **Local tests and the CI test image use Helm v4.3.2** instead of v3.19.0. The projection runner
  now requires Helm 4.
- **The kind suites run on kind v0.33.0 with Kubernetes v1.37.0** (node image pinned by digest)
  instead of kind v0.32.0 with v1.36.1.

### Fixed

- **The transition failure reasons survive as metric labels.** `Ready=False/WorkloadMigrationBlocked`
  and `HTTPTransitionBlocked` reached `tailnet_resource_condition` as `reason="Other"`. Both are
  now in the allowlist, and the drift test also scans the reasons passed to `fail()` and returned
  by the condition helpers, so the next one cannot collapse silently either.
- **An undeclared group in `allowFrom` no longer freezes the policy.** Headscale 0.29 rejects the
  whole policy when a grant names a group the policy does not define. The operator now drops an
  `allowFrom` `group:` source that the base `groups` do not declare from generated and spoke
  grants, as it does for undeclared tags; base grants stay unchanged. The ingress reports
  `PolicyGranted=False/SourceGroupUnknown` and `Ready=False` until the base declares the group;
  with an undeclared tag as well it reports `SourceTagUnknown` and names both. The `PolicyApplied`
  message now reads `skipped undeclared sources: …`.
- **`ReadyChanged` events name the right from-reason.** `TailnetIngress` and `TailnetEgress` take
  it from the Ready reason the operator last determined for the object, not from the informer
  cache, which can still hold the status from before the last write. A stale cache no longer
  produces a wrong from-reason, a duplicate event or a missed flip. Deleting a resource emits no
  event.
- **Local kind suites: the L4 denial check uses the HTTP ACL categories.** The L4 peer probe
  now reports the same dial-error category as the HTTP ACL probe, and a denial counts only for
  `timeout`, `noRoute` or `unreachable`; refused, reset, canceled and unclassified dials fail the
  check.
- **Local kind suites: projected files reach running pods in time.** The HTTP kind cluster syncs
  the kubelet every 10 s, so rotated ConfigMaps and Secrets arrive inside the 90 s wait budget.
- **Local kind suites: the startup gate release is decided by the pod state.** A release exec that
  the exiting gate container kills (exit 137) no longer fails the test; the same gate container
  must still exit 0 and the application must start.

## [0.27.0] - 2026-11-25

### Added

- **`TailnetGateway` `spec.dns.aliasZones`** ([Gateway](docs/how-to/gateway.md#alias-zones-for-names-of-another-cluster),
  [reference](docs/reference/gateway.md#alias-zones-dnsaliaszones)). Up to 16 zones that the
  gateway answers only from the Tailnet hosts source, without an upstream — typically another
  cluster's tailnet zone whose names this cluster reaches through `TailnetEgress` aliases. The
  entries are rendered inline into the `Corefile`, so the field is live DNS: it can change at any
  time without a Pod restart. Unknown names in such a zone answer SERVFAIL. Gateways without the
  field render byte-identical to earlier releases.

### Changed

- **Docs: reach a spoke service from a pod on the hub** ([Connect a second cluster § 3a](docs/how-to/second-cluster.md#3a-reach-a-spoke-service-from-a-pod-on-the-hub)).
  The standard path for hub workloads without a tailnet client: the spoke ingress admits the hub
  egress tag, a hub `TailnetEgress` targets the ingress node by MagicDNS name with the ingress
  name as alias, and the hub gateway serves the spoke zone through `dns.aliasZones`. The egress
  guide and the limitations table point there.

### Fixed

- **Docs and the local CoreDNS gate describe CoreDNS 1.15.** In a `dns.extraZones` zone, CoreDNS
  1.15 answers a non-address query for a name the hosts source overrides with NODATA; 1.14
  forwarded it to the upstream. The reference still described the 1.14 behaviour, and two tests
  of `task test-gateway-dns` failed against 1.15.0, the release the gateways pin. The operator's
  rendering is unchanged.

## [0.26.1] - 2026-11-20

### Changed

- **Docs: first contact with a spoke API** ([Connect a second cluster](docs/how-to/second-cluster.md)).
  The hub declares the spoke's network as a `TailnetSite` before the first fetch, the egress targets
  the API server's private address, and `routeAllowlist` carries the spoke gateway's tailnet-LB
  range. New troubleshooting rows for the hub egress, and a note that the approval annotation is
  read once.
- **Docs and examples: what `reservedNetworks` holds.** Only address space that must never become
  a tailnet route: the node prefix and each cluster's pod and service ranges. The site guide, the
  field description and two examples also listed the LAN and the tailnet-LB range, which blocks
  the gateway's own site and every spoke fragment with a route in them. A network a router
  advertises is declared as a `TailnetSite` or through the gateway, never reserved. Behaviour is
  unchanged; the CRD description text changes.
- **`task ci-local`** runs the CI gate in the CI test container (the `Dockerfile` `TEST` stage)
  with Podman, so a local run uses the toolchain the CI broker uses.
- **`shell.nix` pins kind v0.32.0 and Helm v3.19.0**, the releases the kind runners require (Helm
  as in the CI test image), so `task e2e-full` runs from the dev shell again after nixpkgs moved to
  a newer kind and to Helm 4. The runner contract test follows the rest selection again; it had
  kept `hack/e2e-kind.sh` from reaching a cluster test.

### Fixed

- **`TailnetEgress` route diagnosis ignores default routes.** An exit node's `0.0.0.0/0` or `::/0`
  no longer counts as covering a target. A target that only a default route reaches reports
  `NotAdvertised` instead of `NoGrant`, and a default route in the agent's netmap no longer makes
  such a target look routed.
- **`TailnetSite` on an Export tailnet reports its observed state.** A site on a spoke stayed
  `Advertised`/`Approved`/`Ready` = `Unknown/NotObserved` forever. It now reads the control
  server's node list like a site in Apply mode: `NotApproved` until the hub has merged the
  fragment, then `Ready`. The spoke still never approves a route, and an unreadable node list
  stays `NotObserved`.

## [0.26.0] - 2026-11-20

### Added

- **Status reason `TailnetIngress` `PolicyGranted=False/SourceTagUnknown`.** When an `allowFrom`
  `tag:` source is not declared in the live tailnet policy, that one source is left out of the
  grant while the other sources stay granted; the ingress reports `SourceTagUnknown` and
  `Ready=False` until the tag exists, instead of the policy freezing. Skipped sources are named in
  the `Tailnet` `PolicyApplied` message (`skipped undeclared source tags: …`).
- **Status reason `TailnetIngress` `TLSReady=False/TLSChainInvalid`** (`mode: http`). When the TLS
  Secret carries a `ca.crt`, the controller verifies the served leaf against it (issuer and the
  CA's name constraints). A leaf that does not verify reports `TLSChainInvalid`; the agent keeps
  serving the leaf — the check is report-only. Without `ca.crt`, no chain check runs.
- **Status reason `TailnetEgress` `TargetsReachable=False/NameUnresolved`** and per-target
  `status.targets[].reason=NameUnresolved`, distinguishing a target name that did not resolve (use
  the MagicDNS name, or grant the egress tag `:53` to the split-DNS zone) from a plain `Unreachable`
  dial failure.
- **`ReadyChanged` events.** `TailnetIngress` and `TailnetEgress` emit a `ReadyChanged` event on
  every Ready-reason transition, visible in `kubectl describe`.

### Changed

- **`kubectl get` columns.** The `READY` column now shows the Ready **reason** instead of
  `True`/`False`; `TailnetEgress` gains an `ADDRESS` column and `TailnetGateway` an `AGE` column
  (both in `-o wide`). Scripts that parsed `READY=True`/`False` must read
  `.status.conditions[?(@.type=="Ready")].status` instead. Apply the v0.26.0 CRDs
  (`task crd-upgrade`) to refresh the columns.
- **Metrics reason labels.** The exported `reason` label now covers every condition reason the
  controllers emit; previously a dozen reasons (including the TLS-backend, gateway-workload and
  spoke `HubMerged` reasons) collapsed silently to `Other`. A regression test guards the allowlist
  against drift.
- Grant rendering is now independent of the order the API server lists objects in, so two ingresses
  sharing a source tag no longer flap the policy between reconciles.

## [0.25.0] - 2026-11-18

### Added

- **Bridge names: `TailnetIngress.spec.exposes[].bridgeNames`.** An HTTP expose may serve up to
  four names outside the tailnet zone — the names a site's own DNS gives a
  [bridge](docs/how-to/legacy-bridge.md), so that LAN clients without a tailnet client dial the
  ingress by the site name and the agent still finds a matching SNI route and certificate SAN.
  Bridge names are SANs and routes only: never rendered into the hosts file, never claimed across
  CRs, never MagicDNS. Accepted names appear in `status.exposes[].bridgeNames` and `status.hosts`.
- **`Tailnet.spec.bridgeNameAllowlist`** — the admin's veto: a bridge name must be a proper
  subdomain of a listed zone and must not lie in the `ingressNameTemplate`/`ingressAliasTemplate`
  zone; otherwise `TLSReady=False/BridgeNameDenied` (new bounded reason). Empty list denies.
- Admission: `bridgeNames` require `mode: http`, are lowercase multi-label DNS names (no IP
  literals, no trailing dot), unique per expose; `bridgeNameAllowlist` entries are zones of the
  same shape (max 16).

### Changed

- The agent config and certificate name bound grows from 51 to 301 names (base + per HTTP expose
  its name, one alias and four bridge names). Ingresses without `bridgeNames` render identical
  targets and do not roll.

## [0.24.0] - 2026-11-13

### Added

- **Bridge: `TailnetEgress.spec.expose`.** Hosts on the site LAN without a tailnet client reach a
  service published on the tailnet through the site cluster. With `expose`, every target Service
  is rendered as `type: LoadBalancer` with `externalTrafficPolicy: Local` (fixed), no NodePorts and
  the given `loadBalancer.class`/`annotations`/`labels` passed through — address assignment stays
  with the cluster's LB implementation. The agent NetworkPolicy gains an `ipBlock` rule admitting
  exactly `expose.allowFrom` to the proxy listen ports. `allowFrom` is required and bounded at
  admission (canonical CIDR, no default route, at most `/16` IPv4 or `/48` IPv6); user labels may
  not set `app.kubernetes.io/*`. Status: condition `Exposed` (`AddressAssigned`, `PendingAddress`,
  `Denied`) and `status.expose.addresses`; a `False` `Exposed` blocks `Ready`.
- **`Tailnet.spec.exposeSourceAllowlist`** — the admin's veto: every `expose.allowFrom` prefix must
  lie inside one of these prefixes, otherwise the egress is rendered *without* the expose
  (ClusterIP, no `ipBlock`) and reports `Exposed=False/Denied`. Empty denies all; shrinking the
  list closes running bridges on the next reconcile.
- How-to [Bridge: let a legacy network reach the tailnet](docs/how-to/legacy-bridge.md) with the
  two-sided consent model, DNS/firewall hand-offs, the security properties and their limits
  (client-address preservation), the proxy-box fallback for sites without a cluster and why a NAT
  subnet router is the wrong tool. Example `deploy/examples/tailnetegress-bridge.yaml`.

### Fixed

- A **MagicDNS-named egress target** (e.g. the name of a `TailnetIngress` in another cluster) no
  longer waits for a `/32` route it can never get: `status.targets[].route` is empty, `present`
  is true, and the target's `Ready` hinges on reachability only. A missing grant on the far
  ingress now shows as `TargetsReachable=False/Unreachable` instead of a standing
  `RoutesGranted=False/RoutesMissing`.

### Changed

- Egress target Services carry an explicit `type: ClusterIP` (API default; no behavioural change).

### Security

- Go 1.26.11 (GO-2026-6859, `net/http` MaxBytesReader header race). The module and the CI test
  image now require 1.26.11; the scan is clean.

## [0.23.1] - 2026-11-08

### Security

- `golang.org/x/net` 0.62.0 (CVE-2026-78661). The v0.23.0 image carries the affected version and
  failed the release audit; it is not accepted for use. Use v0.23.1.

## [0.23.0] - 2026-11-08

### Changed

- **`TailnetIngress` nodes keep their identity across Pod restarts.** The agent stores its `tsnet`
  state in a Secret of the ingress namespace (`ingress-<name>-state-<hash>`), written through a
  ServiceAccount, Role and RoleBinding named `ingress-<name>` that the operator renders per CR; the
  pre-auth key is reusable and non-ephemeral. A restarted Pod is the same Headscale node with the
  same tailnet IP. A changed tag, server or hostname is a new identity: new Secret, fresh
  registration, the previous node deleted by the operator; deleting the CR deletes its node. On
  upgrade every ingress rolls once; operator and agent images must move together (an older agent
  ignores `TS_STATE_SECRET`). The `tailnet-operator-workloads` ClusterRole gains `get`/`create`/`patch` on
  `serviceaccounts`, `roles` and `rolebindings`. Egress agents stay ephemeral.
- A spoke (`policy.mode: Export`) reads the live policy with its working API key and reports
  `PolicyApplied=True/HubMerged` (with `status.policy.appliedHash`) once the hub carries every
  exported tag, route approver and grant, `False/HubPending` listing what is still missing, and
  the former `False/Export` only while the control server is not readable.
- *Upgrade and roll back* documents pinning `agentImage` separately so an operator bump does not
  roll agents; *Compatibility* names the releases that require new agent images.

### Security

- `github.com/klauspost/compress` 1.20.2 (GO-2026-6865, reachable through `tsnet` and the metrics
  registry).

## [0.22.3] - 2026-10-31

### Fixed

- The `TailnetGateway` StatefulSet carries its `tsunaro.io/template-sha256` annotation from
  creation, so the first reconcile no longer rewrites the Pod template. Before, a create-time
  admission mutation of the template (sysctls, pull policy, sidecars) left the running Pod one
  revision behind with `WorkloadCurrent=False/PodTemplateStale` and nothing to clear it. Gateways
  created by earlier releases already carry the annotation after their first rewrite.

### Changed

- The Kind gateway fixture, the `TailnetGateway` example and the gateway how-to pin Tailscale
  1.104.4 and CoreDNS 1.15.0 (previously 1.102.4 and 1.14.x); the fixture passes with both images.

## [0.22.2] - 2026-10-30

### Fixed

- The `TailnetGateway` PodDisruptionBudget now sets `maxUnavailable: 1` instead of
  `minAvailable: 1`. With a single replica the old budget forbade every voluntary eviction and
  stalled node drains until the PDB was patched by hand. Gateways created by earlier releases keep
  their recorded PDB until recreated with `deletionPolicy: Delete`.

### Changed

- `Tailnet.status.spokes[].fetchedAt` is described as the time the fetched hash last changed, not a
  heartbeat; `SpokeReachable` and `tailnet_spoke_reachable` report every reconcile. The how-to
  *Connect a second cluster* shows the hub reaching the spoke API server through a `TailnetEgress`
  (section 2a) instead of a directly reachable endpoint.

## [0.22.1] - 2026-10-27

### Added

- Chart `networkPolicy.spokePeers`, `networkPolicy.spokeCIDRs` and `networkPolicy.spokePorts`
  (default `[443, 6443]`): with `networkPolicy.enabled` the operator's NetworkPolicy /
  CiliumNetworkPolicy now has a rule for the `Tailnet.spec.policy.spokes[]` fetch — the egress
  agent pod a spoke API server is reached through (label peers on its listen port) or the spoke
  API address itself. Both default to empty, so existing renders are unchanged; before, a hub with
  isolation enabled needed a hand-maintained extra rule and otherwise reported
  `SpokeReachable=False/Unreachable`.

## [0.22.0] - 2026-10-26

### Added

- `Tailnet.spec.policy.spokes[]`: the hub pulls a spoke's exported policy fragment from the
  spoke cluster itself, through a kubeconfig Secret (`kubeconfigSecretRef`) scoped to that one
  ConfigMap, instead of waiting for the fragment to be committed into the hub repository. Each
  fetch is validated like a committed fragment and additionally bounded by the spoke's
  `tagPatterns` (default `tag:*-<spoke>-*`) and `routeAllowlist`. `approval: Auto` (default)
  merges every valid fetch; `Manual` keeps the last approved fragment merged, publishes a changed
  fetch as `<spoke>-policy-fragment-pending` with `status.spokes[].pendingDelta`, and adopts it
  once the Tailnet carries `tsunaro.io/approve-spoke.<spoke>: <pendingHash>` — until then the hub
  merges approved ∩ fetched, so a spoke's removals land without approval and its additions wait.
  An unreachable spoke, a forbidden read or an invalid fetch keeps the last approved fragment.
  New: Tailnet condition `SpokesReady` and printer column `SPOKES`, `status.spokes[]` with
  `SpokeReachable` / `SpokeFragmentValid` / `SpokeFragmentApproved`, events `SpokeFragmentAdopted`
  and `SpokeFragmentApproved`, gauges `tailnet_spoke_reachable`, `tailnet_spoke_fragment_valid`,
  `tailnet_spoke_fragment_pending`, alerts `TailnetSpokeUnreachable`, `TailnetSpokeFragmentInvalid`,
  `TailnetSpokeApprovalPending`, dashboard row "Spokes", example
  `deploy/examples/tailnet-hub-spokes.yaml`.
- Chart `policy.fragmentReader`: on a spoke, renders the ServiceAccount, a Role limited to
  `get/list/watch` on the named fragment ConfigMaps, the RoleBinding and a token Secret
  `<release>-fragment-reader-token` from which the hub's spoke kubeconfig is built.

### Changed

- The spoke's `PolicyApplied=False/Export` message now names both ways the hub can take the
  fragment (`policy.spokes` pull or a committed `fragmentConfigMaps` entry).
- The Headscale test matrix row 0.29.3 is now 0.29.6 (Tier 1 binaries, the kind image pinned by
  digest, the projection runner's fixture). 0.29.4–0.29.6 change nothing the operator depends on
  (release notes: rejected policies no longer pass the filter, re-authentication after key expiry,
  long-poll shutdown for deleted nodes, Go 1.27.3 / x/net security fixes); the capability matrix
  stays `0.29.x`.

### Security

- Hub `policy.fragmentConfigMaps`: a fragment is now validated against the hub's limits before
  it is merged, not only for unexpected top-level blocks — tag owners must come from the hub's
  `policy.tagOwners`, route approvers from the fragment's own tags or `policy.routeApprovers`,
  grant sources from its own tags or `policy.ingressSourceAllowlist`, destinations are own tags or
  canonical CIDRs, ports `tcp:<n>` only, and nothing may touch `spec.reservedNetworks`. A fragment
  that breaks a limit fails the render closed with `PolicyRendered=False/FragmentInvalid` naming
  the ConfigMap and the offending path.
- Agent pre-auth keys are expired on Headscale when they are superseded (half-life rotation,
  changed tag or server) and when their `TailnetEgress`/`TailnetIngress` is deleted. The authkey
  Secret records the key's Headscale ID (`tsunaro.io/authkey-id`); a finalizer `tsunaro.io/authkey`
  performs the delete-time expiry best-effort — an unreachable Headscale never blocks the delete.
  The operator gains `patch` on `tailnetegresses` and `tailnetingresses` for that finalizer; keys
  minted by earlier releases carry no ID and age out at their own expiry as before.

## [0.21.1] - 2026-10-22

### Security

- SBOM and provenance attestations are uploaded to the public Rekor transparency log, and the
  post-publication audit (`hack/audit-image.sh`) now requires log evidence for the signature and
  every attestation instead of passing `--insecure-ignore-tlog`. Image and chart signatures were
  already logged by the CI publisher; plain `cosign verify` / `verify-attestation` therefore work
  without the flag from this release on. Attestations of earlier releases remain unlogged.

## [0.21.0] - 2026-10-22

### Added

- Docs: [Connect a second cluster](docs/how-to/second-cluster.md) — hub and spokes on one Headscale
  in one walk-through (per-cluster names, exported fragments, grants between clusters, one DNS zone
  per cluster, repository layout); [Limitations](docs/reference/limitations.md) — the functional
  boundaries in one table per area, each checked against the code.

### Changed

- `Tailnet` condition `SplitDNS` is verified instead of permanently `Unknown/CannotVerify`. The
  agent exposes the split-DNS routes of its netmap on the health port (`/dns`); the operator reads
  them from one running ingress or egress agent of the Tailnet and compares the zone from
  `dns.ingressNameTemplate` with the `loadBalancerIP` of every bound `TailnetGateway`:
  `True/Configured`, `False/Missing` (zone absent), `False/Mismatch` (other resolver). `CannotVerify`
  remains only while no gateway or no online agent binds the Tailnet. Agents of the previous image
  answer `/dns` with 404 and keep `CannotVerify` until rolled.
- `Tailnet.spec.apiUrl` no longer participates in the HTTP ingress agent identity. Agents dial
  `server`, never `apiUrl`, so switching the operator's API endpoint (for example `http` → `https`)
  keeps every agent running. One-time effect: the first upgrade to this version re-rolls the HTTP
  ingress agents once, together with the image rollout that upgrade performs anyway.

### Removed

- `TailnetGateway.spec.adoption` (types `GatewayAdoption`/`GatewayAdoptionObject`, their CEL rules
  and the internal `PlanAdoption` planner). The field was never wired to a controller — every
  reconcile path refused a gateway that set it — and the hand-built routers it was meant to take over
  are gone; all known gateways are fresh. The operator is fresh-only by design; a lost state Secret
  or receipt is a new node ([no adoption](docs/reference/gateway.md#no-adoption)). CRD upgrade: a
  stored object that set the field loses it on the next write and, since the field blocked
  bootstrap, starts its fresh bootstrap afterwards — none is known to exist.

### Security

- Go 1.26.10: `govulncheck` reported the reachable `crypto/x509` advisory GO-2026-6809 against
  Go 1.26.9. The module and the CI test image now require 1.26.10; the scan is clean again.

### Fixed

- Gateway bootstrap survives status and metadata writes on the Gateway and Tailnet CRs. The mint
  guard and the `-auth-receipt` record (now format 2) pin UID, generation and spec, not
  `resourceVersion`: the Tailnet controller re-rendering the policy for the new gateway's tags used
  to land inside the mint window and strand the set in `Ready=False/FreshBlocked`. A gateway already
  stranded that way is still cleared the documented way (`deletionPolicy: Delete`, delete, recreate).
  [Gateway reference](docs/reference/gateway.md#minimal-fresh-lifecycle)

### Documentation

- Ephemeral agent identity spelled out: a restarted agent is a new node with a new tailnet IP, names
  are the stable handle, records carry a 30 s TTL ([Limitations](docs/reference/limitations.md),
  [Troubleshooting](docs/how-to/troubleshooting.md#clients-time-out-right-after-an-agent-restart),
  [Model](docs/explanation/model.md)).

## [0.20.0] - 2026-10-19

### Added

- `TailnetEgress`/`TailnetIngress` report `Registered=False/WorkloadBlocked` with the admission
  message when the agent pod is refused (LimitRange, ResourceQuota, PodSecurity), instead of the
  generic "no online node yet". [Agent resources](docs/how-to/install-operator.md#namespaces-with-a-limitrange)
  shows how to clear it.
- Chart value `headscale.caConfigMapRef` mounts a PEM bundle from a ConfigMap and sets
  `SSL_CERT_DIR`, so an `https://` `apiUrl` signed by a site CA verifies next to the public
  roots. No Go change: Go merges `SSL_CERT_DIR` with `SSL_CERT_FILE`. Unset, the Deployment is
  byte-identical to before. [Prepare Headscale § API over TLS](docs/how-to/install-headscale.md#api-over-tls)
  explains the Headscale side; the security model names the clear-text hop that `http://` leaves.
- Docs: [Architecture by scenario](docs/explanation/architecture.md) — a diagram per scenario
  (egress, ingress, HTTPS ingress, gateway, policy and key flow) and a table of every object a CR
  creates; [Reach the Kubernetes API over the tailnet](docs/how-to/kubernetes-api.md); the
  documentation index opens with what the operator lets you do.
- Second-cluster policy without hand-copied grants: `policy.mode: Export` renders a spoke's own
  tagOwners, route approvals and grants into a fragment ConfigMap, and the hub's
  `policy.fragmentConfigMaps` merges reviewed fragments after its base and own CRs (base and hub win,
  fragments only add; a non-additive block is `FragmentInvalid`, a missing fragment is
  `FragmentMissing` — both fail the render closed). New reasons `Export`, `FragmentMissing`,
  `FragmentInvalid`. [Policy § Second cluster](docs/how-to/policy.md#second-cluster-export-on-the-spoke-merge-on-the-hub).

### Fixed

- An ownerRef-less operator ConfigMap (hosts, rendered or fragment — e.g. left behind when a Tailnet
  is re-created) is now re-adopted instead of refused forever: the guard recognises our own
  `tsunaro.io/role` label on a ConfigMap with no controller and takes it back over on the next
  reconcile. A ConfigMap controlled by another resource, or without that label, stays refused and now
  surfaces as a `ConfigMapNotOwned` warning event instead of an operator log line only.

## [0.19.0] - 2026-10-19

### Changed

- Gateway bootstrap no longer freezes the *content* of its sources: between the first Create and
  the completion receipt the writer re-checks the Gateway/Tailnet snapshots and the hosts
  ConfigMap's identity (UID, liveness), not its `resourceVersion` or the TailnetEgress revisions.
  Agents registering during the bootstrap (which rewrite the hosts file) therefore no longer turn
  the mint into `Ready=False/FreshBlocked`; the live DNS and route reconcilers converge the zone
  and routes after completion, as they already did for every later change.

### Fixed

- Gateway teardown of a bootstrap that stopped halfway (no `<gateway>-fresh` receipt) now removes
  the children that bootstrap wrote — ServiceAccount, Role, RoleBinding, Services,
  PodDisruptionBudget, `-coredns` ConfigMap and StatefulSet — by the operator's own
  `tsunaro.io/gateway-uid` label, each with a UID precondition. Previously only the state/auth
  Secrets and receipts went, and the leftovers blocked every further attempt until deleted by
  hand. Unlabelled objects, even under the gateway's names, are still never touched.

### Docs

- `how-to/gateway.md`: *Cloud load-balancer controllers* (`service.loadBalancerClass` when a cloud
  controller manager would claim the gateway's LoadBalancer Service) and *Replace a hand-built
  gateway* (side-by-side bootstrap, resolver flips, retiring the old router with immediate route
  failover).
- `how-to/ingress-tcp.md`, `how-to/ingress-https.md`: *Tailnet without a policy writer (spoke
  cluster)* — pin `spec.tag`/`hostname` and declare `tagOwners` + grant in the hub base policy;
  cross-referenced from `how-to/policy.md`.
- Gateway reference and FreshBlocked runbook state the recovery path for a partial bootstrap
  (`deletionPolicy: Delete`, delete, recreate).

### Removed

- The `docs/{INSTALL,USAGE,SECURITY,COMPATIBILITY}.md` redirect stubs, as announced in 0.17.0 and
  0.18.0; the Diátaxis pages under `docs/how-to`, `docs/reference` and `docs/explanation` are the
  only locations.

## [0.18.0] - 2026-10-17

### Added

- Chart: the operator Deployment sets `GOMEMLIMIT` from its own `resources.limits.memory` through
  the Downward API, so the Go runtime collects before the cgroup limit instead of being OOM-killed
  at it. Asserted in `test/chart`.

### Changed

- Chart: default operator `resources.limits.memory` 128Mi → 192Mi (requests unchanged). Operators
  with a few dozen CRs settled a few MiB below the old limit. The agent default block is unchanged;
  its comment states that tenant LimitRanges must admit these values.
- Docs, examples and test fixtures use RFC 2606/5737 names and addresses throughout
  (`corp.example`, `partner.example`, `prod-1.tailnet.example.internal`, `198.51.100.0/24`, …).
  The gateway reference drops the "Verified platforms" table; `compatibility.md` lists
  `linux/amd64` and `linux/arm64`, and the preflight note states that the image is multi-arch.
- Docs describe the `TailnetGateway` as the operator-managed router and resolver; "bring your own
  resolver" ([Serve DNS names with CoreDNS](docs/how-to/dns-coredns.md#serve-the-file)) remains a
  documented option. `TailnetSite.spec.advertisedBy` is described as "any tagged router" — CRD
  description only, no schema change.

### Known issues

- Ingress agents take a new tailnet identity on every restart (new IP, stale client DNS until the
  30 s record TTL expires); tracked as issue `6929f01`.

The `docs/{INSTALL,USAGE,SECURITY,COMPATIBILITY}.md` redirect stubs are removed in 0.19.0, as
announced in 0.17.0.

## [0.17.0] - 2026-10-16

### Changed

- Docs restructured along [Diátaxis](https://diataxis.fr/): `docs/tutorials` (getting started),
  `docs/how-to` (one task per page, split from `INSTALL.md`/`USAGE.md`), `docs/reference`
  (generated `crds.md` and `values.md` via `task docs`, `rbac.md`, `compatibility.md`, `gateway.md`,
  curated `metrics.md`/`alerts.md`/`reasons.md`), `docs/explanation` (`model.md`,
  `security-model.md`), `docs/operations` (keys, state and backup, validation). `docs/OPERATIONS.md`
  keeps the alert runbooks under unchanged anchors (alert `runbook_url`s stay valid). The README CRD
  field tables moved to `docs/reference/crds.md`. `docs/{INSTALL,USAGE,SECURITY,COMPATIBILITY}.md`
  remain as redirect stubs and are removed in the release after next. Documentation is licensed
  CC BY 4.0 (`docs/LICENSE`); the code stays Apache-2.0.
- `deploy/examples/*.yaml`: comments wrapped to 72 columns and their `USAGE §`/`INSTALL §`/README
  pointers replaced by the Diátaxis how-to pages. The YAML documents are unchanged.

## [0.16.0] - 2026-10-14

### Added

- Chart: `networkPolicy.cilium.headscalePeers` and `networkPolicy.headscaleCIDRs` may now coexist
  under `provider: cilium`. The template adds a `toCIDR` egress for `headscaleCIDRs` on
  `headscalePorts`, so a cluster whose Headscale control plane lives outside the cluster
  (shared/spoke clusters) is covered by the chart's own CiliumNetworkPolicy and no longer needs a
  side-car CNP. A fail guard rejects `provider: cilium` with both blocks empty. Default values keep
  the in-cluster label peer and `headscaleCIDRs: []`, so existing hub clusters render byte-identical
  specs on upgrade — verified in `test/chart`.

### Fixed

- Gateway metrics stay observable across an operator restart. `Metrics.Observe` is now called on
  every reconcile (not only when the status actually changed), so after a fresh Prometheus registry
  the `tailnet_resource_ready{kind="TailnetGateway",…}` and `tailnet_resource_condition{…}` gauges
  reappear without waiting for the next real status event. Observe is idempotent under the Metrics
  mutex, and suspended gateways still withdraw their series. Covered by the unit test
  `TestGatewayMetricsSurviveRestart` and the envtest subtest
  `TestGatewayFreshWriter/metrics survive operator restart in fresh path` (both red before, green
  after).

## [0.15.1] - 2026-10-14

### Changed

- `TailnetGateway.spec.routes.lan[]` accepts up to 128 prefixes (was 32), so a single gateway can
  advertise a LAN plus the dozens of single-host site routes a corporate fabric fans out, without
  route aggregation the Headscale policy forbids.

## [0.15.0] - 2026-10-14

### Added

- `TailnetGateway.spec.dns.extraZones[]` is rendered: each zone becomes a CoreDNS `hosts … { fallthrough }`
  + `cache 30` + `forward . <upstreams>` block next to the strict primary zone, for legacy networks whose
  internal resolvers carry authoritative overrides. Hosts-source names inside an extra zone are written
  to a third `-coredns` ConfigMap key `hosts` (live-reconciled and fingerprint-excluded like `zone.db`)
  and answered locally (A/AAAA); everything else, including non-address types for a known name, is
  forwarded — the documented weaker hosts+forward contract, opted into per zone. The renderer enforces
  non-overlapping zones, 1–8 unique canonical unicast upstreams and never the gateway's LB IP. A
  Gateway without extra zones renders byte-identical to 0.14.x (same keys, content hash and Pod
  template), so upgrading does not touch its ConfigMap or serial. `task test-gateway-dns` covers the
  rendered block against real CoreDNS 1.14.6 (local override, forward, NXDOMAIN, TXT fallthrough,
  hosts reload without restart, strict primary zone).

### Changed

- Alert `runbook_url` annotations point to `docs/OPERATIONS.md#monitoring-*`; USAGE §10–14 (keys, diagnosis,
  upgrade, state and backup, validation, alert runbooks) moved there unchanged.

### Documentation

- `TailnetGateway` is documented end to end: README model bullet, field table and status row; INSTALL §7a
  (prerequisites, order, afterwards); USAGE §9b worked example (gateway, LB pool, iBGP, split-DNS, cluster
  CoreDNS forward, `TailnetSite`, checks, change classes, fields the writer rejects). `deploy/examples/tailnetgateway.yaml`
  is that manifest with `suspend: true`; gateway.md drops its planning-phase wording.
- `docs/README.md` indexes every page with reading paths by role; USAGE §12a lists what the operator
  persists, what must be backed up and what happens while the operator is down.
- The chart README's permissions paragraph describes the shipped RBAC (no CR spec writes, gateway `patch`
  only for the teardown finalizer) instead of a planned DNS claim history; stale `0.7.1` version pins
  updated; the gateway is described by its scope (fresh-only, no adoption, IPv4) rather than as
  "experimental".

## [0.14.2] - 2026-10-13

### Added

- `networkPolicy.provider: cilium` renders an egress-only `CiliumNetworkPolicy` (`toEntities: kube-apiserver`,
  label peers, no CIDRs) in place of the ipBlock-based NetworkPolicy; `kubernetes` stays the default.

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
