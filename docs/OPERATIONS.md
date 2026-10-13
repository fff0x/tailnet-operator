# Operations

Day-2 reference for whoever runs the operator: credentials and their rotation, diagnosis, upgrade,
what to back up, admission rules to check before a CRD upgrade, and one runbook per bundled alert
(the alerts' `runbook_url` annotations point here). Installation is in [INSTALL.md](INSTALL.md),
tenant and policy recipes in [USAGE.md](USAGE.md); placeholders (`corp`, `tailnet-system`, …) are the
same as there.

1. [Keys and expiry](#1-keys-and-expiry)
2. [Diagnosis cheat sheet](#2-diagnosis-cheat-sheet)
3. [Upgrade the operator](#3-upgrade-the-operator)
4. [State, backup and loss](#4-state-backup-and-loss)
5. [Validation](#5-validation)
6. [Monitoring and alert runbooks](#6-monitoring-and-alert-runbooks)

---
## 1. Keys and expiry

| Key | Where | Lifetime | Rotation |
| --- | --- | --- | --- |
| Bootstrap API key | Secret `headscale-bootstrap` (yours) | as created | manual — replace the Secret before it expires; the operator only reads it |
| Working API key | Secret `corp-apikey` (operator) | `apiKeyLifetime` (720h) | automatic at half-life, verified before the old one is expired |
| Pre-auth key per CR | Secret `<cr>-authkey` (operator) | `authKeyLifetime` (168h) | automatic at half-life, immediately when the control server or the effective tag changes (the agent pod restarts and re-registers); a restarted agent re-registers with it |

```sh
kubectl get tailnet corp -o jsonpath='{.status.apiKeyExpiresAt}'      # working key
# 2026-10-28T12:00:00Z
```

Metrics: `tailnet_apikey_expires_seconds`, `tailnetegress_authkey_expires_seconds`,
`tailnetingress_authkey_expires_seconds` — alert when they stop rising after a rotation was due. An
expired **bootstrap** key prevents recovery when the working key is absent or expired.
Ordinary half-life rotation uses the still-valid working key, not the bootstrap key.

## 2. Diagnosis cheat sheet

| Question | Command | Healthy output |
| --- | --- | --- |
| Is the control server reachable? | `kubectl describe tailnet corp` | `ApiReachable=True`, `ApiKeyValid=True` |
| Does preflight pass? | `kubectl get tailnet corp`, `kubectl describe tailnet corp` | `COMPAT=Compatible`, `PolicyMode=True/Database`; `DNS=CannotVerify` is a manual split-DNS configuration hint |
| Why is an egress not ready? | `kubectl -n tailnet-system get tailnetegress X -o jsonpath='{range .status.targets[*]}{.name} {.present} {.reachable} {.reason}{"\n"}{end}'` | `true true` per target, empty reason |
| Is the route on the router? | `kubectl -n tailnet-system exec deploy/headscale -- headscale nodes list-routes` | the target's `/32` or a covering subnet under the router's approved routes |
| Does the agent reach the host? | `kubectl -n tailnet-system logs deploy/X \| grep target` | no `dial …: context deadline exceeded` |
| What does the agent probe say? | `wget -qO- http://<agent-pod-ip>:9080/targets` from any pod | `"reachable":true` per target |
| Does an alias resolve? | `kubectl -n <tenant> exec deploy/app -- getent hosts api.corp.example` | the Service ClusterIP |
| Is the hosts file current? | `kubectl -n tailnet-system get cm tailnet-dns-hosts -o jsonpath='{.data.hosts}'` | one line per alias / ingress name |
| Resolver errors? | `kubectl -n <resolver-ns> logs <coredns-pod> \| grep -i error` | none; `i/o timeout` = upstream unreachable |
| What did the policy render? | `kubectl get tailnet corp -o jsonpath='{.status.policy}'`, ConfigMap `headscale-policy-rendered` | hashes equal, `PolicyApplied=True` |
| Who is on the tailnet? | `kubectl -n tailnet-system exec deploy/headscale -- headscale nodes list` | egress/ingress nodes online with their tags |

### Known CNI behavior: ICMP errors

Kubernetes NetworkPolicy specifies TCP, UDP and SCTP; ICMP handling is up to the CNI, and some
implementations drop node-generated ICMP errors (unreachable, fragmentation-needed) to
policy-selected pods. A timeout on an agent is therefore not proof of reachability, and path-MTU
discovery may not work; `Tailnet.spec.proxy.mtu` (default 1200) sidesteps the latter.

## 3. Upgrade the operator

1. Apply the new CRDs, then the Deployment (image + `OPERATOR_IMAGE`).
2. The operator re-rolls agent Deployments whose image changed.
3. Verify:

```sh
kubectl -n tailnet-system rollout status deploy/tailnet-operator
kubectl get tailnetegress,tailnetingress -A
# every row READY=True
kubectl get tailnet corp          # COMPAT=Compatible; POLICY=Applied/InSync; DNS=CannotVerify (manual)
```

Full procedure incl. CRD validation: [INSTALL §8](INSTALL.md#8-upgrade); breaking changes per version: [CHANGELOG](../CHANGELOG.md).

## 4. State, backup and loss

Everything the operator owns is either declarative (re-derived from the CRs on the next reconcile) or
one of the objects below. Back up the **must back up** rows with the rest of the cluster; nothing else
in the operator namespace needs a backup.

| Object | Owner | Loss means | Backup |
| --- | --- | --- | --- |
| CRs (`Tailnet`, `TailnetEgress`, `TailnetIngress`, `TailnetSite`, `TailnetGateway`) | you (Git) | nothing — redeploy from Git | Git is the backup |
| Secret `headscale-bootstrap` (bootstrap API key) | you | no new working key can be minted; running agents keep working until their pre-auth key expires | **must back up** (or be able to mint a new key on Headscale) |
| Secret `<tailnet>-apikey` (working key) | operator | re-minted from the bootstrap key at the next reconcile | no |
| Secret `<cr>-authkey` (agent pre-auth key) | operator | re-minted; the agent pod restarts and re-registers as the same node name | no |
| ConfigMaps `tailnet-dns-hosts`, `<base>-rendered` | operator | rewritten at the next reconcile | no |
| Headscale policy (live document) | operator in `Apply`, you in `DryRun` | base policy lives in Git/ConfigMap; the render is deterministic | base ConfigMap source in Git |
| Secret `<gateway>-state` (tsnet node state) and ConfigMaps `<gateway>-auth-receipt`, `<gateway>-fresh` | operator, written once | gateway node identity is gone: delete the CR (`deletionPolicy: Delete` removes the Headscale node) and create it again | **must back up** together, see [gateway reference](reference/gateway.md#key-and-expiry-lifecycle) |
| Headscale database | Headscale | out of scope here; every operator-managed node, key and the applied policy live in it | per your Headscale runbook |

Behaviour when the operator itself is down: agent pods keep forwarding, Services and NetworkPolicies
stay in place, the CoreDNS hosts file keeps resolving, and the live policy stays applied. What stops
is change: no key rotation (alert on `tailnet_*_expires_seconds` flat-lining), no new CRs, no status
updates. Restore the Deployment before the shortest key lifetime elapses (`authKeyLifetime`, default
168h) and nothing else needs attention.

Restore after a lost namespace: install the chart, recreate `headscale-bootstrap`, apply the CRs. Egress
and ingress agents register as new Headscale nodes with the same names; delete the stale nodes with
`headscale nodes delete` once the new ones are online (the old ones also age out as ephemeral nodes).
A gateway without its `-state` Secret is a new node and needs the full fresh bootstrap; see the
[rollback table](reference/gateway.md#rollback).

## 5. Validation

Kubernetes **1.31 or later** is required. The API server validates these rules before storing a CR:

| Object / field | Rule |
| --- | --- |
| All three kinds | `spec` is required |
| Egress / ingress CR name | Lowercase DNS label, at most 40 characters; no dots |
| Egress `targets` | 1–50 entries; unique names, each a DNS-1035 label of at most 63 characters, starting with a letter (Service compatibility with Kubernetes 1.31) |
| Target `address` | Single IPv4/IPv6 address or lowercase DNS name (≤253 characters, labels ≤63); no CIDR, URL, host:port, IPv6 zone ID or malformed numeric IP |
| Target `aliases` | Each a lowercase DNS name of at most **63 characters** (a product limit, not the DNS FQDN maximum) |
| Egress `consumerNamespaces` | At least one namespace; each a DNS label of at most 63 characters |
| Ingress `allowFrom` | Required, at least one non-empty entry; the Tailnet's source allowlist still controls authorization |
| Ingress `exposes` | 1–50 entries; unique names and listener ports; names are DNS labels of at most 63 characters |
| Backend `service` / optional `namespace` | DNS labels of at most 63 characters |
| Ingress expose `mode` | Omitted or `l4` preserves TCP forwarding; `http` requires port 443 and at most one HTTP expose |
| Ingress `tls` | HTTP only; optional Secret name or Issuer reference, never both; an omitted source may inherit the Tailnet issuer default |
| Expose `backend.tls` | HTTP only; explicit DNS verification name and namespace-local ConfigMap name/key; no insecure or system-root fallback |
| Expose `timeouts` | HTTP only; optional `request` and `backendRequest` durations; `0s` disables the named timer |
| TLS issuer reference | Name is a DNS subdomain of at most 253 characters; kind defaults to `Issuer`, also permits `ClusterIssuer`; group defaults to and must equal `cert-manager.io` |
| Target, listener and backend ports | 1–65535 |
| Tailnet `server` | HTTPS scheme and a non-empty remainder; `apiUrl` may still use an internal HTTP endpoint |
| Tailnet `apiKeyLifetime` | Valid duration ≥1h, at most 32 characters; omitted defaults to 720h |
| Tailnet `policy.mode` | `DryRun` or `Apply` |
| Tailnet `dns.ingressNameTemplate` | Empty disables ingress DNS names; otherwise contains `{name}`, uses only `{name}`/`{namespace}`, and ends in a literal lowercase zone with at least two labels; at most 253 characters |
| Tailnet `policy.ingressSourceAllowlist` | Each entry begins with `group:`, `tag:` or `autogroup:` plus a non-empty suffix, or is an email-shaped pattern; at most 253 characters; bare `*` is rejected |
| Tailnet `headscale.ref` | Reserved; only empty is accepted |

Admission checks shape, not existence: a backend Service, Headscale group or DNS delegation may
still be missing. Rendered ingress DNS names are validated at reconcile time (`InvalidDNSName`)
because each label — including `{name}-{namespace}` — must fit 63 characters.

### Test without a cluster

```sh
export KUBEBUILDER_ASSETS=/path/to/envtest/binaries      # kube-apiserver, etcd, kubectl for Kubernetes >= 1.31
task test-validation
```

This starts a disposable API server with the generated CRDs and checks the valid examples, the
boundaries and every file in `deploy/examples/invalid/`. Before a CRD upgrade, add a fresh export of
the live CRs — each spec is submitted as a new object, so legacy fields cannot slip through ratcheting:

```sh
live=$(mktemp); kubectl get tailnet,tailnetegress,tailnetingress -A -o json > "$live"
LIVE_CR_FILE="$live" task test-validation; rm -f -- "$live"
```

Against an installed schema in a test cluster, `task validate-examples -- --context <ctx> --namespace <ns>`
runs the same negative fixtures as server-side dry-run creates.

## 6. Monitoring and alert runbooks

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

### Monitoring: operator down

`TailnetOperatorDown`: no healthy operator endpoint for 5 min. Check pods, Service endpoints and
ServiceMonitor selection. Agents keep forwarding while the operator is down.

### Monitoring: reconcile errors

`TailnetReconcileErrors`: more than 0.1 controller-runtime errors/s for 10 min. Read the CR conditions
and the operator log; usual causes are API availability, RBAC and resource conflicts.

### Monitoring: Headscale API

`TailnetHeadscaleAPIErrors`: more than 5 % HTTP 5xx over 10 min. Check Headscale readiness and its
database. Transport failures are code 0, not 5xx. Do not rotate keys because a server is down.

### Monitoring: resource not ready

`TailnetResourceNotReady`: a CR has been `Ready=False` for 10 min; the alert carries the active
reason. `Ready=False` never says just "not ready": it repeats the reason of the first blocking
condition — egress in the order `Registered`, `RoutesGranted`, `TargetsReachable`; ingress in the
order `Registered`, `PolicyGranted`, `TLSReady`, `BackendsReachable` — so the label distinguishes
`NotRegistered`, `RoutesMissing`, `ProbeFailed`, `Unreachable`, `PolicyDenied` and the `TLS*` reasons
directly. Use the tables in §1, §5 and §6 for the remedy per reason.

### Monitoring: policy stale

`TailnetPolicyStale`: `tailnet_policy_pending == 1` for 15 min. Compare the hashes and read
`PolicyRendered`, `PolicyApplied`, `PolicyMode`. `DryRun` does not trigger it.

### Monitoring: policy rejected

`TailnetPolicyRejected`: Headscale refused the render for 5 min; the previous policy is still live.
Inspect the rendered ConfigMap, fix the base in Git. Never replace the live policy by hand.

### Monitoring: policy apply errors

`TailnetPolicyApplyErrors`: at least 6 failed writes in 30 min. Distinguish rejection from
transport/database failure via the conditions and the API metrics; the controller retries with
backoff on its own.

### Monitoring: policy generated drop

`TailnetPolicyGeneratedDrop`: generated tags, grants or routes fell by more than half within 10 min.
Compare with recent CR deletions and base changes; intended deletions trigger it too.

### Monitoring: route replays

`TailnetApprovalReplays`: more than three routes re-approved within an hour. Check Headscale
restarts and advertised routes; a legitimate batch after a router restart can trigger it.

### Monitoring: route conflict

`TailnetRouteConflict`: a `TailnetSite` has been blocked for 15 min — its prefix overlaps a
reserved network (`OverlapsReserved`) or an older site (`OverlapsSite`); the condition message
names both. Nothing is rendered or approved for the blocked site; the older site and the live
policy are untouched. Fix the prefix or `reservedNetworks` in Git. Section 9a has the table.

### Monitoring: unmanaged route overlap

`TailnetUnmanagedRouteOverlap` (info): for 30 min a node that does not carry one of the site's
advertiser tags has advertised a route overlapping the site (e.g. a laptop running
`--advertise-routes` for debugging). The managed route still ships and clients pick the longest
prefix. Find the node in the `UnmanagedOverlap` message and withdraw its route, or add the tag if it
is a legitimate second router.

### Monitoring: gateway fresh blocked

`TailnetGatewayFreshBlocked`: a `TailnetGateway` has reported `Ready=False/FreshBlocked` for 5 min.
The fresh writer found an expired or drifted bootstrap key, unverified provenance or template
drift and writes nothing; the derived zone keeps its last state. The `Ready` message names the
check that failed — see the gateway reference for each case. Suspended gateways are absent from
`tailnet_resource_ready`/`tailnet_resource_condition` and never raise this or
`TailnetResourceNotReady`.

### Monitoring: key expiry

`TailnetAPIKeyExpiringSoon` (7 days) and `Tailnet{Egress,Ingress}AuthKeyExpiringSoon` (1 day):
a key is close to expiry and has not been rotated. Check `ApiKeyValid` and the agent Secrets; tune
`monitoring.rules.apiKeyExpiryWarningSeconds` / `authKeyExpiryWarningSeconds` to below half the
lifetime for short lifetimes. Bootstrap recovery needs a valid bootstrap key.

### Monitoring: node offline

`TailnetNodeOffline`: Headscale has listed the node as offline for 5 min. Check the agent pod,
registration and control-server connectivity. Offline is not the same as a failed scrape or an
unreachable backend.
