# Installation

This guide takes an empty cluster and a Headscale server to a working operator: keys, policy,
DNS, HTTPS ingress and — optionally — an operator-owned policy. Day-2 tasks (adding targets,
exposing services, reading conditions) are in [USAGE.md](USAGE.md); the CRD reference is in the
[README](../README.md#crd-reference).

All names below are placeholders: Tailnet `corp`, cluster `prod-1`, domain
`tailnet.example.internal`, site network `10.0.0.0/8`, tenant namespace `billing-dev`.

1. [Prerequisites](#1-prerequisites)
2. [Headscale](#2-headscale)
3. [Operator](#3-operator)
4. [First egress](#4-first-egress)
5. [DNS (CoreDNS)](#5-dns-coredns)
6. [Ingress and HTTPS](#6-ingress-and-https)
7. [Operator-owned policy](#7-operator-owned-policy)
8. [Upgrade](#8-upgrade)
9. [Rollback](#9-rollback)
10. [Troubleshooting](#10-troubleshooting)

## 1. Prerequisites

| Component | Requirement | Why |
| --- | --- | --- |
| Kubernetes | ≥ 1.29 | CEL validation on the CRDs |
| CNI | NetworkPolicy support | `consumerNamespaces` isolation is a NetworkPolicy |
| Headscale | 0.29.x, reachable from the cluster over HTTP(S) | REST API for nodes, keys and (optionally) the policy |
| Subnet router | a node tagged e.g. `tag:fabric` advertising the site routes | egress targets are reached through it |
| CoreDNS | the cluster's, plus (optionally) a resolver you control for your tailnet zone | DNS aliases and ingress names ([§5](#5-dns-coredns)) |
| Gateway | optional: Envoy/Gateway API with a wildcard certificate for `*.prod-1.tailnet.example.internal` | HTTPS through a `TailnetIngress` ([§6](#6-ingress-and-https)) |

The operator needs no privileges on the nodes: agents are userspace
[tsnet](https://tailscale.com/kb/1244/tsnet) pods without `NET_ADMIN` or `/dev/net/tun`.

## 2. Headscale

### 2.1 Bootstrap API key

The operator authenticates with a **bootstrap** key it only reads; from it it mints its own working
key (rotated at half-life) into the Secret `<tailnet>-apikey`. Create the bootstrap key with a long
life and store it once:

```sh
headscale apikeys create --expiration 8760h
kubectl -n tailnet-system create secret generic headscale-bootstrap --from-literal=apiKey=<key>
```

### 2.2 Policy: what must exist

Every egress/ingress node carries a **tag**, and the tag is the authorization. For each CR the policy
must contain:

| Block | Entry | Example |
| --- | --- | --- |
| `tagOwners` | the CR's tag | `"tag:egress-billing-dev": ["group:operator"]` |
| `autoApprovers.routes` | each egress target as `/32`, approved for the router's tag | `"10.0.10.20/32": ["tag:fabric"]` |
| `grants` | tag → target `/32` on the target port | `{ "src": ["tag:egress-billing-dev"], "dst": ["10.0.10.20/32"], "ip": ["tcp:1521"] }` |
| `grants` | who may reach an ingress | `{ "src": ["group:shop"], "dst": ["tag:ingress-shop"], "ip": ["tcp:5432"] }` |

You can maintain these by hand (policy mode `file`, the operator only *reads* the policy and reports
`NoGrant`/`NotApproved`) or let the operator generate them ([§7](#7-operator-owned-policy)).
[`deploy/examples/policy-base.jsonc`](../deploy/examples/policy-base.jsonc) is a minimal base that
works for both.

Two things always stay outside the policy: the router must **advertise** the target route
(`--advertise-routes=10.0.10.20/32,…` on the subnet router), and the site firewall must allow the
router's address to the target port.

### 2.3 Policy mode

| Mode | Where the policy lives | Who writes it |
| --- | --- | --- |
| `file` (default) | `policy.path`, e.g. a ConfigMap mounted at `/acl/policy` | you, via Git; Headscale reloads on SIGHUP/restart |
| `database` | the Headscale database | `headscale policy set -f …` or `PUT /api/v1/policy` — the operator in [§7](#7-operator-owned-policy) |

Switching to `database` is described in [§7.3](#73-migrating-from-file-mode).

## 3. Operator

```sh
kubectl apply -k deploy        # namespace tailnet-system, CRDs, RBAC, Deployment, ServiceMonitor
kubectl -n tailnet-system rollout status deploy/tailnet-operator
```

`deploy/` is organisation-free. In your own overlay set the image (both the container image and
`OPERATOR_IMAGE`, which the agents use), and add a NetworkPolicy for the operator: it needs the
kube-apiserver, cluster DNS and the Headscale API. Run **one replica** — the operator holds no
lease, and two would race the key rotation (and, in [§7](#7-operator-owned-policy), the policy).

Then bind the cluster to your control server:

```yaml
apiVersion: tailnet.fr0st.dev/v1alpha1
kind: Tailnet
metadata:
  name: corp
spec:
  server: https://ts.example.com                    # agents' ControlURL
  apiUrl: http://headscale.tailnet-system.svc:8080  # in-cluster REST endpoint
  apiSecretRef: { name: headscale-bootstrap, key: apiKey }
  proxy: { mtu: 1200, probeInterval: 5m }
```

```sh
kubectl get tailnet corp
# NAME   SERVER                   APIKEY   EXPIRES                POLICY   AGE
# corp   https://ts.example.com   True     2026-10-28T12:00:00Z            1m
```

`ApiReachable=True` and `ApiKeyValid=True` in `kubectl describe tailnet corp` mean the working key
exists and the API answers. The `POLICY` column stays empty until [§7](#7-operator-owned-policy).

## 4. First egress

1. Advertise the target on the subnet router and approve it (or rely on `autoApprovers`).
2. Declare tag, route approval and grant in the policy ([§2.2](#22-policy-what-must-exist)) — skip
   when the operator owns the policy.
3. Apply the CR **in the operator namespace** (egress CRs are admin resources):

```yaml
apiVersion: tailnet.fr0st.dev/v1alpha1
kind: TailnetEgress
metadata:
  name: billing-dev
  namespace: tailnet-system
spec:
  tailnetRef: { name: corp }
  consumerNamespaces: [billing-dev]
  targets:
    - { name: db-1, address: 10.0.10.20, port: 1521 }
```

```sh
kubectl -n tailnet-system get tailnetegress billing-dev
# NAME          TAG                      HOSTNAME             READY   AGE
# billing-dev   tag:egress-billing-dev   egress-billing-dev   True    2m
```

A pod in `billing-dev` now dials `db-1.tailnet-system.svc:1521`. If `READY` is `False`, the
per-target `reason` in `status.targets[]` names the missing step — see
[USAGE.md](USAGE.md#1-egress-reach-a-database-at-the-site).

## 5. DNS (CoreDNS)

Needed for two things: egress **aliases** (a client must dial `api.corp.example`, not
`api.tailnet-system.svc`, when the far end routes by TLS SNI / HTTP Host) and **ingress names**
(`shop-shop-dev.prod-1.tailnet.example.internal` for a `TailnetIngress`). The operator serves no DNS.
It renders a CoreDNS [`hosts`](https://coredns.io/plugins/hosts/) file into a ConfigMap; you mount it
into the resolver that is authoritative for those zones.

### 5.1 Enable rendering

```yaml
kind: Tailnet
spec:
  dns:
    hostsConfigMap: tailnet-dns-hosts   # operator namespace, key "hosts"
    ingressNameTemplate: "{name}-{namespace}.prod-1.tailnet.example.internal"
```

```sh
kubectl -n tailnet-system get cm tailnet-dns-hosts -o jsonpath='{.data.hosts}'
# # managed by tailnet-operator (Tailnet corp) — do not edit
# 10.43.12.7    api.corp.example
# 100.64.0.42   shop-shop-dev.prod-1.tailnet.example.internal
```

Keep the ingress template **one label** below your gateway's wildcard certificate: `*.prod-1.<domain>`
covers `shop-shop-dev.prod-1.<domain>`, not `shop.shop-dev.prod-1.<domain>`.

### 5.2 Serve the file

Mount the ConfigMap into the resolver for your tailnet zone (in a Headscale setup: the resolver your
split-DNS entry delegates `prod-1.tailnet.example.internal` to), `optional: true` so it starts before
the first render:

```yaml
volumes:
  - name: dns-hosts
    configMap: { name: tailnet-dns-hosts, optional: true }
containers:
  - name: coredns
    volumeMounts: [{ name: dns-hosts, mountPath: /etc/tailnet-dns, readOnly: true }]
```

```corefile
prod-1.tailnet.example.internal:53 {
    hosts /etc/tailnet-dns/hosts { fallthrough }                 # operator records win …
    template IN A { answer "{{ .Name }} 30 IN A 10.0.0.80" }     # … the gateway wildcard catches the rest
    cache 30
    reload
}
corp.example:53 {                                                # zones with egress aliases
    hosts /etc/tailnet-dns/hosts { fallthrough }
    cache 30
    forward . 10.0.0.53 { max_concurrent 1000 }                  # everything else: the site's DNS
    reload
}
```

### 5.3 Wire the cluster CoreDNS

Pods ask the cluster CoreDNS (`kube-system`). Forward the alias zones to your resolver first, with
the site DNS as sequential fallback so real corporate names keep resolving when the resolver is down:

```corefile
corp.example:53 {
    errors
    cache 30
    forward . 10.96.0.54 10.0.0.53 {       # 10.96.0.54 = ClusterIP of your resolver Service
        policy sequential
        max_concurrent 1000
    }
}
```

Two details worth knowing: `forward` treats SERVFAIL as an answer (no failover, only unreachable
upstreams fail over), and a resolver without a route into the site network cannot use the site DNS
as upstream — forward that zone to a peer resolver *inside* the site over the tailnet instead
(`forward . 100.64.0.3`, a subnet router's tailnet IP running the same block).

Freshness is ConfigMap propagation (≤ ~1 min) plus the `hosts` reload (5 s). If the operator dies,
the last file stays valid — the data path never depends on it.

## 6. Ingress and HTTPS

A `TailnetIngress` is a plain-TCP node on the tailnet. For TCP services nothing else is needed:

```yaml
apiVersion: tailnet.fr0st.dev/v1alpha1
kind: TailnetIngress
metadata:
  name: shop
  namespace: shop-dev
spec:
  tailnetRef: { name: corp }
  allowFrom: [group:shop]           # used when the operator owns the policy (§7)
  exposes:
    - { name: postgres, port: 5432, backend: { service: shop-db-rw, port: 5432 } }
```

Peers dial `ingress-shop:5432` (MagicDNS) or `shop-shop-dev.prod-1.tailnet.example.internal:5432`
([§5](#5-dns-coredns)).

**HTTPS** keeps terminating at your shared gateway; the ingress adds a per-app tailnet identity. Point
an expose at the gateway's Service (in its namespace) and give the tenant's HTTPRoute the rendered
name:

```yaml
kind: TailnetIngress                      # tenant namespace
spec:
  exposes:
    - name: https
      port: 443
      backend: { service: envoy-prod-1-tailnet, namespace: envoy-gateway-system, port: 443 }
---
kind: HTTPRoute
spec:
  parentRefs: [{ name: shared-gateway-tailnet, namespace: envoy-gateway-system, sectionName: prod-1-https }]
  hostnames: ["shop-shop-dev.prod-1.tailnet.example.internal"]   # = status.dnsName
```

Peer → name → node IP (grant `dst = tag:ingress-shop`) → Envoy (SNI matches the wildcard, route by
Host) → app. Authorization is the tailnet policy's job, not Envoy's. In-cluster pods usually cannot
route `100.x` — ingress names are for tailnet peers.

## 7. Operator-owned policy

Without this section every new target means four policy edits plus a route. With it, the CR is the
only input: the operator renders your **base** document plus what the CRs imply and writes the result
to Headscale.

### 7.1 What is generated

| From | Into | Entry |
| --- | --- | --- |
| every egress/ingress tag | `tagOwners` | `tag: policy.tagOwners` (base entry wins if present) |
| every egress target with an IP address | `autoApprovers.routes` | `/32: policy.routeApprovers` (merged into an existing list) |
| every egress, per port | `grants` | `{src: [tag], dst: [/32…], ip: ["tcp:port"]}` |
| every ingress with `allowFrom` | `grants` | `{src: allowFrom, dst: [tag], ip: ["tcp:port"…]}` — only if every source matches `ingressSourceAllowlist` |

Nothing is ever removed from the base; identical grants are not duplicated; unknown blocks (`ssh`,
`tests`, `nodeAttrs`, …) pass through. Targets addressed by **name** get no grant (a policy cannot
route a name) and are listed in the `PolicyRendered` message.

### 7.2 Enable in DryRun

Put the base policy into a ConfigMap in the operator namespace (Git-managed; the example works):

```sh
kubectl -n tailnet-system create configmap headscale-policy --from-file=policy=deploy/examples/policy-base.jsonc
```

```yaml
kind: Tailnet
spec:
  policy:
    baseConfigMap: headscale-policy         # key "policy"
    mode: DryRun                            # render only
    tagOwners: [group:operator]
    routeApprovers: [tag:fabric]
    ingressSourceAllowlist: ["group:*"]     # what tenants may put into allowFrom
```

```sh
kubectl describe tailnet corp | grep -A1 Policy
#   PolicyRendered  True   Rendered   2 tags, 2 grants, 1 routes generated
#   PolicyApplied   False  DryRun     mode DryRun: review ConfigMap tailnet-system/headscale-policy-rendered
kubectl -n tailnet-system get cm headscale-policy-rendered -o jsonpath='{.data.policy}' \
  | kubectl -n tailnet-system exec -i deploy/headscale -- headscale policy check -f /dev/stdin
# Policy is valid
```

### 7.3 Migrating from file mode

Headscale accepts `PUT /api/v1/policy` only in `database` mode. Switch and import in **one** step —
with an empty policy table Headscale answers `GET /api/v1/policy` with 500 and applies no policy:

1. Add a `tests` block to the base (see the example) — Headscale rejects any write whose tests fail.
2. Set `policy.mode: database` in the Headscale config (`HEADSCALE_POLICY_MODE=database`); keep the
   file mounted for the import and for rollback.
3. Restart Headscale and import immediately:

   ```sh
   kubectl -n tailnet-system exec deploy/headscale -- sh -c 'headscale policy set -f /acl/policy && headscale policy get | head -3'
   ```

4. Check that members still reach what they should (your own device → Kubernetes API is a good probe).

### 7.4 Apply

```yaml
spec:
  policy:
    mode: Apply
```

```sh
kubectl get tailnet corp
# NAME   SERVER                   APIKEY   EXPIRES                POLICY    AGE
# corp   https://ts.example.com   True     2026-10-28T12:00:00Z   Applied   3d
```

From now on: **never run `headscale policy set` by hand.** The operator compares the live document
with its render every 5 minutes (and on every CR change) and rewrites it when they differ — a manual
change is overwritten and reported as event `PolicyDriftOverwritten`. Change the base ConfigMap
in Git instead. Once the operator generates the tenant blocks, delete them from the base; the render
does not change (the union is the same), but the base gets shorter and cannot drift.

`status.policy` carries `renderedHash`, `appliedHash`, `appliedAt` and `generated{tags,grants,routes}`;
metrics `tailnet_policy_applied_timestamp_seconds` and `tailnet_policy_apply_errors_total` back an
alert (`time() - applied > 900` while `renderedHash != appliedHash`).

## 8. Upgrade

1. Apply the new CRDs first (`deploy/crds/`), then the Deployment with the new image (operator and
   `OPERATOR_IMAGE`; agent pods are re-rolled by the operator).
2. `kubectl get tailnetegress,tailnetingress -A` — everything back to `READY=True`.

Version notes:

| Version | Notes |
| --- | --- |
| v0.1.0 | `Tailnet.spec.policy` (operator-owned policy, DryRun/Apply), `TailnetIngress.spec.allowFrom`, new conditions `PolicyRendered`/`PolicyApplied`/`PolicyGranted`, reasons `PolicyPending`/`PolicyDenied`. Existing clusters are unaffected until `policy.baseConfigMap` is set. |
| v0.0.6 | `Tailnet.spec.dns`, `TailnetEgress.spec.targets[].aliases`, `TailnetIngress.status.dnsName`, `Backend.namespace`. |

## 9. Rollback

| Situation | Action |
| --- | --- |
| A render is wrong but not yet applied (`DryRun`) | fix the base or the CR; nothing reached Headscale |
| Headscale rejected the render (`PolicyApplied=False/PolicyRejected`) | the previous policy is still active; read the message, fix, the next reconcile retries |
| The operator must stop writing | `policy.mode: DryRun` — the operator only renders from now on |
| Restore the Git policy on the server | `kubectl -n tailnet-system exec deploy/headscale -- headscale policy set -f /acl/policy` (mode DryRun first, or it is overwritten within 5 min) |
| Leave database mode | `HEADSCALE_POLICY_MODE=file`, restart; the mounted file is authoritative again |
| Downgrade the operator | apply the previous image; CRDs are backwards compatible (new fields are optional) |

## 10. Troubleshooting

| Symptom | Look at | Typical cause |
| --- | --- | --- |
| `Tailnet` `ApiReachable=False` | condition message | `apiUrl` wrong, NetworkPolicy blocks the operator, bootstrap key expired |
| Egress `TagKnown=False/Unknown` | `kubectl describe tailnetegress` | tag missing in `tagOwners` (file mode) |
| Egress `TagKnown=False/PolicyPending` | `kubectl describe tailnet` → `PolicyApplied` | policy not applied yet / rejected |
| `status.targets[].reason=NotAdvertised` | router `--advertise-routes` | route not advertised |
| `… NotApproved` | `headscale nodes list-routes` | route not approved; `autoApprovers` missing or router tag differs |
| `… NoGrant` | policy `grants` | no grant tag → /32:port (file mode) |
| `TargetsReachable=False` | agent log `dial …: context deadline exceeded` | site firewall, target down |
| Alias does not resolve in a pod | `kubectl -n tailnet-system get cm tailnet-dns-hosts`, resolver log | zone not forwarded, ConfigMap not mounted, Service not created yet |
| Ingress `PolicyGranted=False/PolicyDenied` | condition message | `allowFrom` entry not covered by `ingressSourceAllowlist` |
| `PolicyRendered=False/PolicyEmpty` | base ConfigMap | base has no `tagOwners` or no `acls`/`grants` — refused to avoid a lock-out |
| `PolicyApplied=False/ApplyFailed` | condition message (`read: …; write: …`) | Headscale still in file mode, empty policy table, API unreachable |
| Event `PolicyDriftOverwritten` | `kubectl get events -A --field-selector reason=PolicyDriftOverwritten` | someone ran `headscale policy set` |
