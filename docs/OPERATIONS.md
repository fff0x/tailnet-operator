---
title: "Monitoring and alert runbooks"
weight: 40
description: "Opt-in Prometheus/Grafana objects, metric interpretation, and one runbook per bundled alert (the alerts' runbook_url annotations point here)."
---

Monitoring is opt-in. Install the Prometheus Operator (and, for the dashboard, Grafana Operator v5)
CRDs first, then enable what you need:

```yaml
monitoring:
  serviceMonitor: { enabled: true }          # operator metrics, TCP 8080
  podMonitor: { enabled: true }              # agent /metrics, TCP 9080
  rules: { enabled: true }                   # the 13 alerts below
  dashboard: { enabled: true, kind: GrafanaDashboard, datasourceName: Prometheus }
```

The agent `PodMonitor` also covers `TailnetGateway` pods: it scrapes the Tailscale
sidecar's Prometheus endpoint on tcp/8080 (`TS_ENABLE_METRICS=true` is wired by
the operator) and the CoreDNS Prometheus endpoint on tcp/9153.

The default Grafana selector is `grafana.internal/instance: grafana`; `kind: ConfigMap` serves
sidecar setups. Non-empty `rules.groups` or `dashboard.json` replace the bundled content.
A PodMonitor grants no network access: agent NetworkPolicies allow TCP 9080 from the operator
namespace only. Admit your Prometheus with `monitoring.podMonitor.scrapeFrom`, a list of
NetworkPolicy peers (`namespaceSelector`/`podSelector`/`ipBlock`) that the operator adds to every
agent NetworkPolicy for TCP 9080; with operator isolation on, list the same scraper in
`networkPolicy.metricsPeers` for the operator's own metrics:

```yaml
monitoring:
  podMonitor:
    enabled: true
    scrapeFrom:
      - namespaceSelector: { matchLabels: { kubernetes.io/metadata.name: monitoring } }
        podSelector: { matchLabels: { app.kubernetes.io/name: prometheus } }
```

### Metric interpretation

- `tailnet_resource_ready` exists only for the current-generation `Ready` condition; `Tailnet` has none, suspended `TailnetGateway`s are withdrawn.
- `tailnet_resource_condition` is 1 for the active reason and 0 for previously seen reasons — read type and reason, not the value as a boolean.
- `tailnet_policy_pending` is 1 only in `Apply` mode while `renderedHash != appliedHash`; an old `appliedAt` alone is healthy.
- `tailnet_headscale_user_conflicts` mirrors `status.userConflicts` (shared Headscale user names); anything above 0 blocks policy writes.
- `tailnet_node_online` reflects the last successful Headscale node list; `tailnet_node_last_seen_seconds` is a Unix timestamp (`time() - …` for the age).
- Headscale request labels are bounded method/path templates and status codes; code 0 means no HTTP response.
- `tailnet_route_approvals_replayed_total` counts routes, so one batch can add several.
- Agent families (`tailnet_agent_connections_active`, `_bytes_total`, `_dial_duration_seconds`) carry target/expose names, never peers or IPs; bytes include TLS bytes.
- `tailnetegress_routes_missing` and `tailnetingress_backends_unreachable` stay through v0.4.x; prefer `tailnet_egress_target_state` and `tailnet_ingress_expose_reachable`.

## Monitoring: operator down

`TailnetOperatorDown`: no healthy operator endpoint for 5 min. Check pods, Service endpoints and
ServiceMonitor selection. Agents keep forwarding while the operator is down.

## Monitoring: reconcile errors

`TailnetReconcileErrors`: more than 0.1 controller-runtime errors/s for 10 min. Read the CR conditions
and the operator log; usual causes are API availability, RBAC and resource conflicts.

## Monitoring: Headscale API

`TailnetHeadscaleAPIErrors`: more than 5 % HTTP 5xx over 10 min. Check Headscale readiness and its
database. Transport failures are code 0, not 5xx. Do not rotate keys because a server is down.

## Monitoring: resource not ready

`TailnetResourceNotReady`: a CR has been `Ready=False` for 10 min; the alert carries the active
reason. `Ready=False` never says just "not ready": it repeats the reason of the first blocking
condition — egress in the order `Registered`, `RoutesGranted`, `TargetsReachable`; ingress in the
order `Registered`, `PolicyGranted`, `TLSReady`, `BackendsReachable` — so the label distinguishes
`NotRegistered`, `RoutesMissing`, `ProbeFailed`, `Unreachable`, `PolicyDenied` and the `TLS*` reasons
directly. Use the reason tables in [Egress](how-to/egress.md), [Ingress: TCP](how-to/ingress-tcp.md) and [Ingress: HTTPS](how-to/ingress-https.md) for the remedy per reason.

## Monitoring: policy stale

`TailnetPolicyStale`: `tailnet_policy_pending == 1` for 15 min. Compare the hashes and read
`PolicyRendered`, `PolicyApplied`, `PolicyMode`. `DryRun` does not trigger it.

## Monitoring: policy rejected

`TailnetPolicyRejected`: Headscale refused the render for 5 min; the previous policy is still live.
Inspect the rendered ConfigMap, fix the base in Git. Never replace the live policy by hand.

## Monitoring: policy apply errors

`TailnetPolicyApplyErrors`: at least 6 failed writes in 30 min. Distinguish rejection from
transport/database failure via the conditions and the API metrics; the controller retries with
backoff on its own.

## Monitoring: policy generated drop

`TailnetPolicyGeneratedDrop`: generated tags, grants or routes fell by more than half within 10 min.
Compare with recent CR deletions and base changes; intended deletions trigger it too.

## Monitoring: route replays

`TailnetApprovalReplays`: more than three routes re-approved within an hour. Check Headscale
restarts and advertised routes; a legitimate batch after a router restart can trigger it.

## Monitoring: route conflict

`TailnetRouteConflict`: a `TailnetSite` has been blocked for 15 min — its prefix overlaps a
reserved network (`OverlapsReserved`) or an older site (`OverlapsSite`); the condition message
names both. Nothing is rendered or approved for the blocked site; the older site and the live
policy are untouched. Fix the prefix or `reservedNetworks` in Git. Section 9a has the table.

## Monitoring: unmanaged route overlap

`TailnetUnmanagedRouteOverlap` (info): for 30 min a node that does not carry one of the site's
advertiser tags has advertised a route overlapping the site (e.g. a laptop running
`--advertise-routes` for debugging). The managed route still ships and clients pick the longest
prefix. Find the node in the `UnmanagedOverlap` message and withdraw its route, or add the tag if it
is a legitimate second router.

## Monitoring: gateway fresh blocked

`TailnetGatewayFreshBlocked`: a `TailnetGateway` has reported `Ready=False/FreshBlocked` for 5 min.
The fresh writer found an expired or drifted bootstrap key, unverified provenance or template
drift and writes nothing; the derived zone keeps its last state. The `Ready` message names the
check that failed — see the gateway reference for each case. A bootstrap that stopped halfway
leaves labelled children that block the next attempt: set `deletionPolicy: Delete`, delete the CR
and recreate it; the teardown removes everything carrying the Gateway's own label and nothing
else. Suspended gateways are absent from
`tailnet_resource_ready`/`tailnet_resource_condition` and never raise this or
`TailnetResourceNotReady`.

## Monitoring: key expiry

`TailnetAPIKeyExpiringSoon` (7 days) and `Tailnet{Egress,Ingress}AuthKeyExpiringSoon` (1 day):
a key is close to expiry and has not been rotated. Check `ApiKeyValid` and the agent Secrets; tune
`monitoring.rules.apiKeyExpiryWarningSeconds` / `authKeyExpiryWarningSeconds` to below half the
lifetime for short lifetimes. Bootstrap recovery needs a valid bootstrap key.

## Monitoring: node offline

`TailnetNodeOffline`: Headscale has listed the node as offline for 5 min. Check the agent pod,
registration and control-server connectivity. Offline is not the same as a failed scrape or an
unreachable backend.

## Monitoring: spoke unreachable

`TailnetSpokeUnreachable`: for 1 h the hub could not read a `policy.spokes[]` fragment. The
`SpokeReachable` condition in `status.spokes[]` names the cause: `KubeconfigMissing` (Secret or key
absent in the operator namespace), `KubeconfigInvalid` (does not parse, or names a plain `http://`
server), `Forbidden` (`HTTP 401/403` — token revoked or the reader Role no longer names the
ConfigMap), `Unreachable` (dial or timeout against the spoke API server). The last approved fragment
stays merged, so nothing breaks immediately; the spoke's newer grants are simply not applied. Re-mint
the reader token on the spoke (`policy.fragmentReader`) and replace the hub Secret.

## Monitoring: spoke fragment invalid

`TailnetSpokeFragmentInvalid`: for 15 min the fetched fragment failed the hub's validation; the
`SpokeFragmentValid` message names the path (a tag outside `tagPatterns`, a route or destination
outside `routeAllowlist` and the hub's `TailnetSite`s, a foreign owner, a non-tcp port, a reserved
network, or a block other than `tagOwners` / `autoApprovers.routes` / `grants`). The last approved
fragment stays merged. Fix the spoke CR that produced the entry, or widen the spoke's allowlist on
the hub deliberately.

## Monitoring: spoke approval pending

`TailnetSpokeApprovalPending` (info): a `Manual` spoke's fetched fragment has differed from the
approved one for 4 h. Review `<spoke>-policy-fragment-pending` in the operator namespace and
`status.spokes[].pendingDelta`, then
`kubectl annotate tailnet <hub> tsunaro.io/approve-spoke.<spoke>=<pendingHash>`. Until then the hub
merges the approved fragment minus anything the spoke removed, so removals land without approval and
additions wait — a long-pending fetch means a spoke change nobody has looked at.
