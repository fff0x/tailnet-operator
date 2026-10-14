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
7a. [Gateway (subnet router + split-DNS)](#7a-gateway-subnet-router--split-dns)
8. [Upgrade](#8-upgrade)
9. [Rollback](#9-rollback)
10. [Troubleshooting](#10-troubleshooting)

## 1. Prerequisites

| Component | Requirement | Why |
| --- | --- | --- |
| Kubernetes | ≥ 1.31 | CRD admission uses the CEL IP library (`isIP`) |
| CNI | NetworkPolicy support | `consumerNamespaces` isolation is a NetworkPolicy |
| Headscale | 0.29.x, reachable from the cluster over HTTP(S) | REST API for nodes, keys and (optionally) the policy |
| Subnet router | a node tagged e.g. `tag:fabric` advertising the site routes — hand-built, or the operator-managed `TailnetGateway` ([§7a](#7a-gateway-subnet-router--split-dns)) | egress targets are reached through it |
| CoreDNS | the cluster's, plus (optionally) a resolver you control for your tailnet zone | DNS aliases and ingress names ([§5](#5-dns-coredns)) |
| cert-manager | optional | issues the certificate for a `mode: http` ingress ([§6](#6-ingress-and-https)) |
| Gateway | optional: Envoy/Gateway API with a wildcard certificate for `*.prod-1.tailnet.example.internal` | HTTPS through a shared gateway instead ([§6](#6-ingress-and-https)) |

Ingress and egress agents are userspace
[tsnet](https://tailscale.com/kb/1244/tsnet) pods without `NET_ADMIN` or `/dev/net/tun`.
The opt-in `TailnetGateway` instead needs a kernel-mode workload with
`NET_ADMIN`, `/dev/net/tun` and verified forwarding prerequisites. It is fresh-only,
not a migration mechanism; read its [limits and prerequisites](reference/gateway.md)
before activation. Installing the chart alone does not create a Gateway.

## 2. Headscale

### 2.1 Bootstrap API key

The operator authenticates with a **bootstrap** key it only reads; from it it mints its own working
key (rotated at half-life) into the Secret `<tailnet>-apikey`. Create the bootstrap key with a long
life and store it once:

```sh
headscale apikeys create --expiration 8760h
```

Create the Kubernetes Secret after installing the operator namespace in §3. Do not commit the plaintext key.

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

Two things always stay outside the policy: the router must **advertise** a route covering the
target (`--advertise-routes=10.0.10.20/32,…` per host, or an aggregate such as `10.0.10.0/24`; the
generated `/32` approval is then redundant but harmless), and the site firewall must allow the
router's address to the target port.

### 2.3 Policy mode

| Mode | Where the policy lives | Who writes it |
| --- | --- | --- |
| `file` (default) | `policy.path`, e.g. a ConfigMap mounted at `/acl/policy` | you, via Git; Headscale reloads on SIGHUP/restart |
| `database` | the Headscale database | `headscale policy set -f …` or `PUT /api/v1/policy` — the operator in [§7](#7-operator-owned-policy) |

Switching to `database` is described in [§7.3](#73-migrating-from-file-mode).

### 2.4 PostgreSQL TLS

If Headscale uses PostgreSQL, set `HEADSCALE_DATABASE_POSTGRES_SSL=verify-full`, mount the server
CA and point `PGSSLROOTCERT` at it (with CloudNativePG: the generated server CA and the `-rw`
Service FQDN). Select the intended kube-context and the current database primary. Adjust the database
role filter if the deployment does not use `headscale`:

```sh
kubectl --context <context> -n <headscale-ns> exec <db-primary> -c postgres -- \
  psql -X --no-password -v ON_ERROR_STOP=1 -qtAc \
  "select host(a.client_addr), s.ssl, s.version, s.cipher from pg_stat_activity a left join pg_stat_ssl s using (pid) where a.usename='headscale'"
```

Require at least one row and `ssl=t` in every row. An empty result is inconclusive, not a pass;
`false` or `NULL` fails the transport check. Correlate client addresses with the running Headscale pods.

This proves encryption for the observed connections, not certificate-name or CA validation by itself.
Check the live pod's selected SSL mode, database hostname and CA mount without dumping credentials.
Absence of TLS errors in logs is not a negative validation test; retained logs might omit startup.
Test rejection of a wrong CA or hostname only in an isolated fixture, not by breaking a production database connection.

### 2.5 Preflight

The Tailnet controller probes the server's capabilities on every reconcile (at least every five
minutes; a failed probe retries after one minute). `kubectl get tailnet` shows the `COMPAT`, `POLICY`
and `DNS` reasons, `kubectl describe tailnet` the messages. Detection uses the API response shape,
not a version string; `spec.headscale.version` is an optional hint for diagnostics only.

| Condition | Meaning |
| --- | --- |
| `HeadscaleCompatible=True/Compatible` | Database policy mode and `POST /api/v1/policy/check` are available |
| `HeadscaleCompatible=False/Incompatible` | File policy mode, or no `policy/check` endpoint (Headscale < 0.29) |
| `PolicyMode=True/Database` | `GET /api/v1/policy` carries an `updatedAt` timestamp |
| `PolicyMode=False/File` | `updatedAt` is `null`; `Apply` skips policy writes and route approvals (`PolicyApplied=False/PolicyModeFile`) |
| `PolicyMode=Unknown/CannotVerify` | The response omits `updatedAt` |
| `…=Unknown/ProbeFailed` | A request failed or returned an invalid body; check reachability, credentials and Headscale logs |
| `SplitDNS=Unknown/CannotVerify` | Headscale has no DNS API; configure the displayed split zone yourself |
| `UsersUnique=False/Duplicate` | Two Headscale users share a name (`status.userConflicts`, IDs in the message); Headscale rejects every policy write until one is removed (`headscale users destroy -i <id>`) |

The split-DNS hint is the literal zone after the last placeholder label of `dns.ingressNameTemplate`:
`{name}-{namespace}.prod-1.tailnet.example.com` → `prod-1.tailnet.example.com`. That zone must not
be the MagicDNS `base_domain`: the gateway serves it from the CR names (`status.dnsName`,
`status.hosts`), while MagicDNS serves `<hostname>.<base_domain>` from the node name
(`status.hostname`) — the two stay in sync only by accident and diverge on the first
`spec.hostname` change. An empty policy
database does not block bootstrap (key validation uses the API-key listing); `DryRun` publishes
the rendered policy even in file mode.

## 3. Operator

### Helm

```sh
helm install tailnet-operator oci://oci.this-is-fine.io/charts/tailnet-operator \
  --version 0.15.0 --namespace tailnet-system --create-namespace

kubectl -n tailnet-system create secret generic headscale-bootstrap --from-literal=apiKey='<key>'

kubectl apply -f - <<'EOF'
apiVersion: tsunaro.io/v1alpha1
kind: Tailnet
metadata:
  name: corp
spec:
  server: https://ts.example.com
  apiUrl: http://headscale.tailnet-system.svc:8080
  apiSecretRef: { name: headscale-bootstrap, key: apiKey }
  proxy: { mtu: 1200, probeInterval: 5m }
EOF
```

Use your secret manager instead of `--from-literal` in production. From a source checkout, replace
the OCI URL with `./charts/tailnet-operator` and set `image.repository`/`image.tag` to your build.
Helm 3 and 4 are supported; the default chart needs no Prometheus or Grafana CRDs.

To inspect or vendor the chart, pull it and verify its signature first (see
[SECURITY.md](SECURITY.md) for the key and the Radicle release record):

```sh
helm pull oci://oci.this-is-fine.io/charts/tailnet-operator --version 0.15.0
cosign verify --key deploy/cosign.pub --insecure-ignore-tlog \
  oci.this-is-fine.io/charts/tailnet-operator:0.15.0
```

```sh
kubectl -n tailnet-system rollout status deploy/tailnet-operator
kubectl get tailnet corp
kubectl describe tailnet corp
```

`ApiReachable=True` and `ApiKeyValid=True` mean the working key exists and the API answers. The
`POLICY` column stays empty until [§7](#7-operator-owned-policy). The Tailnet reports missing
credentials and retries until the Secret appears.

Run **one operator release per cluster**. Leader election is on by default; `replicas > 1` adds a
PodDisruptionBudget and all replicas share the Lease `tailnet-operator.tsunaro.io` in the operator
namespace. With `leaderElection.enabled: false` only one replica is allowed and the Deployment uses
`Recreate`. Chart values are documented in the [chart README](../charts/tailnet-operator/README.md#values).

### Images and private registries

`image.digest` wins over `image.tag`. An empty `agentImage` inherits the operator image. Image-pull
Secrets are referenced by **name** and must exist in each agent namespace (operator namespace for
egress, tenant namespace for ingress): `imagePullSecrets` for the operator pod,
`agent.imagePullSecrets` as the default for agents, `Tailnet.spec.proxy.imagePullSecrets` to replace
that default per Tailnet (`[]` clears it). The operator never copies registry credentials.

### Agent resources

The chart supplies agent requests of CPU `10m` and memory `32Mi`, and a memory limit of `128Mi`.
There is no CPU limit. Both ingress and egress select a **whole block** in this order:
`CR.spec.resources` > `Tailnet.spec.proxy.resources` > chart `agent.resources`.
Missing keys are not filled from lower tiers. A CR/Tailnet block with both requests and limits unset
falls through; either non-nil map selects the block, even if empty in memory.
Kubernetes serialization may omit empty maps, so do not rely on them to disable the fallback in a stored CR.

Helm merges supplied values with its defaults: `agent.resources: {}` does **not** disable resources.
Set `agent.resources: null` to disable the chart fallback; this renders `AGENT_RESOURCES='{}'`.
Use null for individual chart keys to remove them. A direct binary run with `AGENT_RESOURCES` absent,
empty, or `{}` retains the zero default. Non-empty input must be one non-null ResourceRequirements
JSON object with known fields and valid, nonnegative quantities; requests cannot exceed matching limits.

Installing these defaults or changing effective resources restarts each affected agent with `Recreate`.
Its ephemeral node re-registers, causing a brief interruption. CRs with higher-tier overrides keep their resources.
The generated standalone bundle includes the same defaults; customize its operator environment in an overlay.

### Network isolation

`networkPolicy.enabled` isolates the operator pod; `networkPolicy.provider` picks the dialect.

`kubernetes` (default) renders a NetworkPolicy for ingress and egress. Set the Kubernetes API and
Headscale CIDRs and ports for your site first — NetworkPolicy cannot select a hostname — and list
scrapers in `networkPolicy.metricsPeers`, otherwise metrics ingress is denied.

`cilium` renders an egress-only `CiliumNetworkPolicy` instead: `ipBlock` rules do not match
cluster/node identities on Cilium, so the API server is `toEntities: kube-apiserver`, DNS and
Headscale are label selectors (`dnsPeers`, `cilium.headscalePeers`; a peer without
`namespaceSelector` is scoped to the operator namespace) and no CIDRs are needed. Ingress stays
open (metrics :8080, health :8081). The `cilium.io/v2` CRDs must exist; `ipBlock` peers are rejected
at render time.

Both providers allow the same four destinations — API server, cluster DNS, Headscale, agent status
on TCP 9080 in every namespace. Agent pods get their own generated policies regardless of provider.

### Kustomize

```sh
kubectl apply -k deploy
```

`deploy/operator.yaml` is generated from the default chart values (`task deploy-gen`) and contains
Namespace, RBAC, ServiceAccount, Deployment and metrics Service; the CRDs are in `deploy/crds/`.
Use an overlay for namespace, images and site policies.

### What the chart ships and what the site provides

| Component | Chart default | Turn off | Site provides |
| --- | --- | --- | --- |
| CRDs (`crds/`) | installed with `helm install`, never upgraded by Helm | `--skip-crds` | upgrades per [§8](#8-upgrade) (`task crd-upgrade` or Flux `crds: CreateReplace`) |
| Deployment, RBAC, ServiceAccount, metrics Service, PDB | on; PDB only with `replicas > 1` | — (that is the operator) | one release per cluster, the namespace |
| ServiceMonitor, PrometheusRule, dashboard | off | `monitoring.serviceMonitor/rules/dashboard.enabled` | Prometheus and Grafana Operator CRDs, a Prometheus that selects them |
| PodMonitor for agents and gateways | off | `monitoring.podMonitor.enabled` | PodMonitor CRD; `scrapeFrom` peers, otherwise the agent policy blocks the scrape |
| Operator NetworkPolicy | off | `networkPolicy.enabled` | `provider: kubernetes` needs `kubeAPICIDRs`, `headscaleCIDRs`, `metricsPeers`; `provider: cilium` needs the Cilium CRDs and label peers |
| Agent NetworkPolicies | always generated by the operator (not the chart) | — | `consumerNamespaces` on the CR; a CNI that enforces NetworkPolicy |
| Headscale | not shipped | — | 0.29.x reachable from the cluster, bootstrap API key Secret, policy base per [§2](#2-headscale) |
| PKI for `mode: http` ingress | not shipped | — | cert-manager and an issuer, or a TLS Secret; the ingress name must resolve to the agent |
| Image-pull Secrets | none referenced | — | Secrets by name in operator and tenant namespaces (`imagePullSecrets`, `agent.imagePullSecrets`) |
| LoadBalancer IPs for gateways | not shipped | — | an LB implementation and pool matching `tailnetLBCIDR` / `service.poolLabels` ([§7a](#7a-gateway-subnet-router--split-dns)) |
| Cluster CoreDNS forward | not touched | — | the `forward` stanza for the alias zones ([§5.3](#53-wire-the-cluster-coredns)) |
| Flux/cosign verification | public key in `deploy/cosign.pub` | — | the `verify` block on `OCIRepository`/`HelmRelease` ([SECURITY.md](SECURITY.md)) |
| `Tailnet`, `TailnetEgress`, `TailnetIngress`, `TailnetSite`, `TailnetGateway` | none created | — | every CR; the chart installs only the schemas |

## 4. First egress

1. Advertise the target on the subnet router and approve it (or rely on `autoApprovers`).
2. Declare tag, route approval and grant in the policy ([§2.2](#22-policy-what-must-exist)) — skip
   when the operator owns the policy.
3. Apply the CR **in the operator namespace** (egress CRs are admin resources):

```yaml
apiVersion: tsunaro.io/v1alpha1
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
(`shop-shop-dev.prod-1.tailnet.example.internal` for a `TailnetIngress`). The operator itself serves
no DNS. It renders a CoreDNS [`hosts`](https://coredns.io/plugins/hosts/) file into a ConfigMap; either
a `TailnetGateway` serves it as the zone ([§7a](#7a-gateway-subnet-router--split-dns); skip §5.2) or
you mount it into the resolver that is authoritative for those zones.

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
apiVersion: tsunaro.io/v1alpha1
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

**HTTPS** has two shapes. With `mode: http` the agent terminates TLS itself using a `kubernetes.io/tls`
Secret or a cert-manager issuer. It forwards HTTP, or verified HTTPS with `backend.tls`, to one backend without a shared gateway
([USAGE §6.1](USAGE.md#61-ingress-terminate-tls-on-the-agent)). Or TLS keeps terminating at a shared
gateway and the ingress adds a per-app tailnet identity: point an expose at the gateway's Service
(in its namespace) and give the tenant's HTTPRoute the rendered name:

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
| every `TailnetGateway` tag of this Tailnet | `tagOwners` | `tag: policy.tagOwners` (base entry wins if present) |
| every route of a `TailnetGateway` of this Tailnet (LAN, `tailnetLBCIDR`, egress host routes) | `autoApprovers.routes` | `prefix: the gateway's own spec.tags` (merged into an existing list) |
| every egress, per port | `grants` | `{src: [tag], dst: [/32…], ip: ["tcp:port"]}` |
| every ingress with `allowFrom` | `grants` | `{src: allowFrom, dst: [tag], ip: ["tcp:port"…]}` — only if every source matches `ingressSourceAllowlist` |

Nothing is ever removed from the base; identical grants are not duplicated; unknown blocks (`ssh`,
`tests`, `nodeAttrs`, …) pass through. Targets addressed by **name** get no grant (a policy cannot
route a name) and are listed in the `PolicyRendered` message.

**Route approval replay.** Headscale's `autoApprovers` act only on a route *change* event, so a route
advertised before its approver existed stays "available, not approved". After every successful write
(and every `InSync` check) the operator lists the nodes and approves each advertised route that lies
inside an `autoApprovers.routes` prefix of the rendered policy naming one of the node's tags —
exactly what the event would have done, nothing more. Approvals are never removed. Events
`RoutesApproved` / `RouteApprovalFailed` on the `Tailnet` show what happened.

A fresh `TailnetGateway` is covered by the same replay: its tags and the routes it advertises are
rendered into the policy, so its node gets them approved without a manual `approve-routes`. The
gateway's `RoutesInSync` condition reports the result and never writes an approval. Caveat: a
prefix approved for the gateway's tag is also approvable for any other node carrying that tag.
Gateways whose routes do not plan are left out and named in the `PolicyRendered` message
(`gateway/<name>`).

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
   file mounted for the import and for rollback. If Stakater Reloader (or similar) restarts Headscale
   on ConfigMap changes, exclude the policy ConfigMap (`configmap.reloader.stakater.com/reload` with
   an explicit list instead of `reloader.stakater.com/auto`) — in database mode a base edit needs no
   restart, and every restart is a policy-less window plus `ApplyFailed` noise.
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
# NAME   SERVER                   APIKEY   EXPIRES                COMPAT       POLICY    DNS            AGE
# corp   https://ts.example.com   True     2026-10-28T12:00:00Z   Compatible   Applied   CannotVerify   3d
```

From now on: **never run `headscale policy set` by hand.** The operator compares the live document
with its render every 5 minutes (and on every CR change) and rewrites it when they differ — a manual
change is overwritten and reported as event `PolicyDriftOverwritten`. Change the base ConfigMap
in Git instead. Once the operator generates the tenant blocks, delete them from the base; the render
does not change (the union is the same), but the base gets shorter and cannot drift.

`status.policy` carries `renderedHash`, `appliedHash`, `appliedAt` and `generated{tags,grants,routes}`;
metrics `tailnet_policy_applied_timestamp_seconds` and `tailnet_policy_apply_errors_total` back an
alert (`time() - applied > 900` while `renderedHash != appliedHash`).

### 7.5 Base `tests` — what they can and cannot assert

Headscale evaluates the base's `tests` on every write, including the operator's `PUT`. A failing
test rejects the whole document (`PolicyApplied=False/PolicyRejected`) and the previous policy
stays live. Rules found on Headscale v0.29:

- `dst` must be a single host or IP (`"site-dns:53"`), no CIDR.
- `src` must resolve to **existing nodes** — a generated tag has no node until the operator applied
  the tag, so it deadlocks as `src`. Use long-lived tagged nodes (a router, a bot).
- A member `src` (`alice@`) evaluates as ALLOWED for every `dst` and discriminates nothing.
- The base must pass `headscale policy check -f` **on its own** (that is also the rollback import), so
  tests cannot assert generated grants — only that the base never widens what a tenant proxy may do.

```sh
kubectl -n tailnet-system exec -i deploy/headscale -c headscale -- headscale policy check -f /dev/stdin < policy.jsonc
```

## 7a. Gateway (subnet router + split-DNS)

Optional. A `TailnetGateway` replaces the hand-built subnet router and the hand-built resolver of
[§5.2](#52-serve-the-file) with one operator-managed Pod: kernel Tailscale advertising
`routes.lan ∪ service.tailnetLBCIDR ∪ {egress targets}/32`, and a CoreDNS serving the hosts file of
§5 as the authoritative zone. It is fresh-only — a new node with a persistent identity; an existing
router is never adopted. The complete worked example (manifest, LB pool, iBGP, split-DNS, site) is
[USAGE §9b](USAGE.md#9b-gateway-run-the-subnet-router-and-split-dns-as-a-cr); the contract
(receipts, immutability, deletion) is the [gateway reference](reference/gateway.md).

### 7a.1 Prerequisites

| Requirement | Why | Check |
| --- | --- | --- |
| `/dev/net/tun` on the nodes and `net.ipv4.ip_forward=1` visible in the Pod network namespace (Talos inherits it from the host; elsewhere allow the namespaced `net.ipv4.ip_forward` unsafe sysctl) | kernel Tailscale; an unprivileged init container only *checks* and fails startup otherwise | `kubectl -n tailnet-system logs prod-1-gw-0 -c kernel-preflight` after the first start |
| Pod Security admission in the operator namespace permits `NET_ADMIN` (level `privileged`, or an exemption) | the Tailscale container needs exactly that capability, no host network, no privilege escalation | `kubectl get ns tailnet-system -o jsonpath='{.metadata.labels}'` |
| A LoadBalancer implementation with a pool whose selector matches `service.poolLabels` and whose CIDR contains `service.loadBalancerIP` | the LB IP is the split-DNS nameserver peers dial; `tailnetLBCIDR` is advertised so peers reach every IP of the pool | `kubectl -n tailnet-system get svc prod-1-gw` shows an `EXTERNAL-IP` |
| A free, stable ClusterIP for `dns.serviceClusterIP` | the cluster CoreDNS forwards the zone to it; immutable | `kubectl get svc -A -o jsonpath='{.items[*].spec.clusterIP}' \| tr ' ' '\n' \| grep 10.96.0.54` prints nothing before creation |
| `Tailnet.spec.policy.mode: Apply` with the gateway tag in `routeApprovers` and `tagOwners` set — or a hand-maintained policy with matching `tagOwners` and `autoApprovers.routes` | routes are approved automatically only when the operator owns the policy | `kubectl get tailnet corp` shows `POLICY=Applied` |
| Headscale `dns.nameservers.split` for the zone → the LB IP (manual; Headscale has no DNS API) | peers must ask the gateway for `*.<zone>` | `Tailnet` reports `SplitDNS=Unknown/CannotVerify`, by design |
| Backup of the state Secret and the receipt ConfigMaps | the node identity lives there; without them the gateway is a new node | [OPERATIONS §4](OPERATIONS.md#4-state-backup-and-loss) |

### 7a.2 Order

1. Pool and (if used) BGP for the tailnet LB range exist and announce.
2. `Tailnet.spec.policy` is `Apply` (§7.4) or the policy carries the tag and routes by hand.
3. Apply the `TailnetGateway` with `suspend: false` (USAGE §9b). Within about a minute:
   `kubectl get tailnetgateway` → `READY=True`; `RoutesInSync=True/Approved` after the next policy
   reconcile (≤ 5 min).
4. Set the Headscale split-DNS entry; add the cluster CoreDNS `forward` for the zone to
   `dns.serviceClusterIP` (§5.3 form, upstream = the gateway's DNS Service). Repeat both for
   every `dns.extraZones[]` zone the gateway serves for a legacy network (USAGE §9b, "Extra zones").
5. Declare the LAN as a `TailnetSite` (USAGE §9a) so overlaps are blocked and the site has a status.
6. Verify from both sides: a Pod resolves `api.<zone>` through the cluster CoreDNS; a tailnet peer
   resolves `router.<zone>` through split-DNS and reaches `192.0.2.1` through the gateway.

Done when `Ready=True`, `RoutesInSync=True/Approved`, `ServiceReady=True/LoadBalancerAssigned`,
`WorkloadCurrent=True/PodCurrent`, and the alert `TailnetGatewayFreshBlocked` is silent.
`ClusterDNSForward` and `StaleNodes` stay `Unknown/ExternallyManaged`: they are yours.

### 7a.3 Afterwards

The operator never restarts the gateway Pod. Image and route changes are written into the
StatefulSet template and applied when *you* delete `prod-1-gw-0` (`WorkloadCurrent=False/PodTemplateStale`
until then). Rollback of the operator keeps the gateway running — see the
[rollback table](reference/gateway.md#rollback); a downgrade below 0.11.0 is not supported for an
existing gateway. Deleting the CR with the default `deletionPolicy: Retain` keeps node, Secret and
resources; `Delete` is the explicit teardown ([deletion](reference/gateway.md#deletion)).

## 8. Upgrade

Validate existing CRs against the new schema **before** installing new CRDs — admission rules
tighten between releases and the check is offline ([OPERATIONS §5](OPERATIONS.md#5-validation)):

```sh
live=$(mktemp); kubectl get tailnet,tailnetegress,tailnetingress -A -o json > "$live"
LIVE_CR_FILE="$live" task test-validation; rm -f -- "$live"
```

1. Apply the new CRDs. Helm installs CRDs from `crds/` but never upgrades them: run
   `task crd-upgrade KUBE_CONTEXT=<context>` for a manual installation, or set
   `install.crds: CreateReplace` and `upgrade.crds: CreateReplace` on a Flux `HelmRelease`.
2. `helm upgrade` (or apply the new `deploy/`). The operator re-rolls every agent whose image changed;
   agent Deployments use `Recreate`, so each affected CR's data path is interrupted for the restart.
3. `kubectl get tailnet` — `COMPAT=Compatible`, `POLICY=InSync` or `Applied`, `DNS=CannotVerify`.
4. `kubectl get tailnetegress,tailnetingress -A` — every row `READY=True`; test one egress and one
   ingress connection.

A pure operator restart with unchanged desired state does not restart agents; a `Ready=False` during
an agent image change is a real interruption, not a status flap. Breaking changes per version are
listed in the [CHANGELOG](../CHANGELOG.md).

## 9. Rollback

| Situation | Action |
| --- | --- |
| A render is wrong but not yet applied (`DryRun`) | fix the base or the CR; nothing reached Headscale |
| Headscale rejected the render (`PolicyApplied=False/PolicyRejected`) | the previous policy is still active; read the message, fix — the write is retried with backoff (15 s doubling to 1 min; transport failures to 5 min), a base/CR change retries at once |
| The operator must stop writing | `policy.mode: DryRun` — the operator only renders from now on |
| Restore the Git policy on the server | `kubectl -n tailnet-system exec deploy/headscale -- headscale policy set -f /acl/policy` (mode DryRun first, or it is overwritten within 5 min) |
| Leave database mode | `HEADSCALE_POLICY_MODE=file`, restart; the mounted file is authoritative again |
| Downgrade the operator | restore both the previous container image and `OPERATOR_IMAGE` (agents also roll back); the newer CRDs and their admission rules remain installed |
| Relax the v0.3.0 admission rules | restore the previous `deploy/crds/` manifests through the same deployment mechanism; never delete the CRDs, which also deletes their CRs |

Neither rollback restores a previously applied Headscale policy — switch to `DryRun` first if writes
must stop. Keep the desired CR manifests in Git: an older schema prunes newer optional fields on write.

## 10. Troubleshooting

| Symptom | Look at | Typical cause |
| --- | --- | --- |
| `Tailnet` `ApiReachable=False/Unreachable` | condition message | `apiUrl` wrong, NetworkPolicy blocks the operator |
| `Tailnet` `ApiReachable=False/Unhealthy` | Headscale `/health`, its database | Headscale answers but cannot reach its database (it then returns 401 on every API call) |
| `Tailnet` `ApiKeyValid=False/Rejected` | Headscale `apikeys list` | working key expired or deleted on the server; `Error` = rotation failed (bootstrap key expired) |
| `HeadscaleCompatible=False/Incompatible` | condition message | missing policy/check endpoint (requires ≥ 0.29), or file policy mode |
| `PolicyMode=False/File`, `PolicyApplied=False/PolicyModeFile` | Headscale `policy.mode` | switch to database mode using §7.3; writes are skipped until mode detection changes |
| Preflight `Unknown/ProbeFailed` | API/key conditions and Headscale logs | failed requests or invalid response shape; not proof of file mode |
| `SplitDNS=Unknown/CannotVerify` | condition message and Headscale DNS config | manually configure the named split zone; external Headscale has no DNS API |
| `UsersUnique=False/Duplicate`, `PolicyApplied=False/PolicyRejected` | `headscale users list` | duplicate user names (typically OIDC plus a CLI-created user); destroy the surplus user, the next reconcile clears both |
| Egress `TagKnown=False/Unknown` | `kubectl describe tailnetegress` | tag missing in `tagOwners` (file mode) |
| Egress `TagKnown=False/PolicyPending` | `kubectl describe tailnet` → `PolicyApplied` | policy not applied yet / rejected |
| `status.targets[].reason=NotAdvertised` | router `--advertise-routes` | route not advertised |
| `… NotApproved` | `headscale nodes list-routes`, `kubectl describe tailnet` events | route not approved; with operator-owned policy it is re-approved on the next policy reconcile — persists → `autoApprovers` entry missing or router tag differs |
| `… NoGrant` | policy `grants` | no grant tag → /32:port (file mode) |
| `TargetsReachable=False` | agent log `dial …: context deadline exceeded` | site firewall, target down |
| Alias does not resolve in a pod | `kubectl -n tailnet-system get cm tailnet-dns-hosts`, resolver log | zone not forwarded, ConfigMap not mounted, Service not created yet |
| Ingress `PolicyGranted=False/PolicyDenied` | condition message | `allowFrom` entry not covered by `ingressSourceAllowlist` |
| `PolicyRendered=False/PolicyEmpty` | base ConfigMap | base has no `tagOwners` or no `acls`/`grants` — refused to avoid a lock-out |
| `PolicyApplied=False/ApplyFailed` | condition message (`read: …; write: …`) | Headscale still in file mode, empty policy table, API unreachable |
| Event `PolicyDriftOverwritten` | `kubectl get events -A --field-selector reason=PolicyDriftOverwritten` | someone ran `headscale policy set` |
