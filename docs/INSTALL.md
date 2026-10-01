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
| Kubernetes | ≥ 1.31 | CRD admission uses the CEL IP library (`isIP`) |
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

For PostgreSQL deployments, use `HEADSCALE_DATABASE_POSTGRES_SSL=verify-full` and mount the database server's CA certificate.
Set `PGSSLROOTCERT` to the mounted certificate path, for example `/etc/headscale/postgres-ca/ca.crt`.
The database hostname must match a certificate SAN. With CloudNativePG, use its generated server CA and the `-rw` Service FQDN.
Restart Headscale when the mounted CA changes.

Check active connections on the database primary:

```sh
kubectl -n <headscale-namespace> exec <database-primary-pod> -c postgres -- \
  psql -qtAc "select a.usename, s.ssl, s.version, s.cipher from pg_stat_ssl s join pg_stat_activity a using (pid) where a.usename='headscale'"
```

Every returned connection must have `ssl=t`; no rows means there is no active connection to verify.
This query proves transport encryption, not certificate verification.
Also check the running Headscale container's `verify-full` setting, CA mount and connection errors.
A Git manifest alone does not prove that TLS is active.

### 2.5 Preflight

The Tailnet controller probes capabilities on each reconcile, normally at least every five minutes.
`kubectl get tailnet` shows `COMPAT`, `POLICY` and `DNS` reasons; `kubectl describe tailnet` shows the details.
A probe error retries after one minute. The operator does not claim to detect the server's version.
Optional `spec.headscale.version` supplies a diagnostic hint only; `spec.headscale.ref` is reserved and must remain empty.

| Condition | Meaning |
| --- | --- |
| `HeadscaleCompatible=True/Compatible` | Database policy mode and the non-mutating `POST /api/v1/policy/check` probe are available |
| `HeadscaleCompatible=False/Incompatible` | File policy mode, or the policy/check endpoint is absent (requires Headscale ≥ 0.29) |
| `PolicyMode=True/Database` | GET policy includes an `updatedAt` timestamp |
| `PolicyMode=False/File` | GET policy includes an explicit `updatedAt: null`; Apply skips policy writes and route approvals (`PolicyApplied=False/PolicyModeFile`) |
| `PolicyMode=Unknown/CannotVerify` | The response omits `updatedAt`; mode cannot be established |
| `…=Unknown/ProbeFailed` | A request failed or its response was invalid; check reachability, credentials and Headscale logs |
| `SplitDNS=Unknown/CannotVerify` | No DNS API exists; configure the displayed split zone to point at your gateway DNS Service IP |

Mode detection follows the response shape in Headscale
[0.28.0](https://github.com/juanfont/headscale/blob/v0.28.0/hscontrol/grpcv1.go#L658-L692) and
[0.29.3](https://github.com/juanfont/headscale/blob/v0.29.3/hscontrol/grpcv1.go#L687-L721).
HTTP 200 alone does not prove database mode. A 401, a server error, or an empty policy database is not evidence of file mode.
Key validation uses the API-key listing endpoint, so an initially empty policy database does not prevent bootstrap.
The authenticated health endpoint reports `databaseConnectivity`; a missing endpoint gives no database-health verdict.

Split-DNS hints use the literal suffix after the last placeholder-containing label in `dns.ingressNameTemplate`.
For example, `{name}-{namespace}.prod-1.tailnet.example.com` requires the split zone `prod-1.tailnet.example.com`.
An empty template produces no hint. New manifests require `{name}` and a literal zone with at least two labels.
The operator cannot verify DNS delegation or infer the gateway IP yet.
Preflight does not change Headscale configuration. DryRun still publishes the rendered policy in file mode.

## 3. Operator

### Helm installation

**Release preparation:** this checkout prepares chart `0.4.0` and image `v0.4.0`; it does not prove publication.
Existing installations must read the [API-group migration warning](#80-v040-api-group-migration) before upgrading.
First, release and deploy a broker with `mixed-helm-v1`, `image-result-v1` and the pinned audit tools.
Configure its immutable `CI_BUILDER_IMAGE` identity.
The prepared consumer CI rejects missing capabilities or audit prerequisites before publication.
See [security gates](SECURITY.md#build-and-verification-gates).
Verify actual chart publication and signatures before using the OCI command below.
Verify chart/image availability, registry authentication and signatures first; a private build does not prove Docker Hub mirror availability.
Use Helm 3 or 4. The default chart needs no Prometheus or Grafana CRDs.

After the release is available, configure the placeholders and run these three commands:

```sh
helm install tailnet-operator oci://oci.this-is-fine.io/charts/tailnet-operator \
  --version 0.4.0 --namespace tailnet-system --create-namespace

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

kubectl -n tailnet-system create secret generic headscale-bootstrap --from-literal=apiKey='<key>'
```

Use your secret manager for the last command in production; avoid storing the key in shell history.
The Tailnet initially reports missing credentials and retries after the Secret appears.
For a source installation, replace the OCI URL with `./charts/tailnet-operator` and supply a built image through values.

Check the result:

```sh
kubectl -n tailnet-system rollout status deploy/tailnet-operator
kubectl get tailnet corp
kubectl describe tailnet corp
```

`ApiReachable=True` and `ApiKeyValid=True` mean the working key exists and the API answers.
The `POLICY` column stays empty until [§7](#7-operator-owned-policy).
Run **one operator installation per cluster**, with all replicas in the same operator namespace.
The chart defaults to leader election and rolling updates; `replicas > 1` requires election and adds a PDB.
The shared Lease is `tailnet-operator.tsunaro.io`; changing namespace creates a different election domain.
Election does not fence in-flight external writes. Isolated failover passed; production handover and soak acceptance remain open.
With election disabled, only one replica and `Recreate` are allowed.

When upgrading a pre-election installation or changing election mode, stop the old operator before starting the new one.
Do not rely on `RollingUpdate` to prevent overlap with an instance that does not participate in the same Lease.
Use a reviewed stop-first GitOps handover; agents keep their existing state while the control plane is stopped.
See the [chart migration guidance](../charts/tailnet-operator/README.md) before rollout.

### Images, private registries and isolation

See the [chart values](../charts/tailnet-operator/README.md#values) for configuration.
`image.digest` wins over the image tag. An empty `agentImage` inherits the complete operator image.
`imagePullSecrets` takes Kubernetes reference objects, for example `[{name: dockerconfig}]`, for the operator pod.
`agent.imagePullSecrets` takes Secret names, for example `[dockerconfig]`, as the default for agents.
`Tailnet.spec.proxy.imagePullSecrets` replaces that list; omitted means inherit, `[]` means no operator-supplied references.
ServiceAccount admission can still add that namespace's pull secrets. Token automounting does not control this inheritance.
Secrets must exist in each agent namespace; the operator does not replicate credentials.
Prefer a verified public agent mirror for tenant namespaces.

Enable `networkPolicy.enabled` only after setting Kubernetes API and Headscale CIDRs/ports for your CNI.
The policy also permits cluster DNS and agent status traffic on **TCP 9080** across namespaces.
Configure `networkPolicy.metricsPeers` for scraping; an empty list denies metrics ingress when isolation is enabled.
Standard NetworkPolicy cannot select a Headscale URL by hostname. DNS changes, Service DNAT and NodeLocal DNS need site-specific handling.
With Cilium custom policies, `toEndpoints` selectors are namespace-scoped; add
`k8s:io.kubernetes.pod.namespace: {operator: Exists}` to the selector for tenant agents.

### Kustomize alternative

```sh
kubectl apply -k deploy
```

`deploy/operator.yaml` is generated by `task deploy-gen` from default chart values; edit the chart, not the generated bundle.
It contains the Namespace, RBAC, ServiceAccount, Deployment and metrics Service. The three CRDs remain under `deploy/crds/`.
The old separate `deploy/rbac.yaml` and `deploy/servicemonitor.yaml` files are replaced by this bundle.
ServiceMonitor is now opt-in through Helm; plain Kubernetes needs no monitoring CRDs.
Use an overlay for namespace/images and site-specific policies when using Kustomize.

### Existing GitOps installations

Do not replace copied manifests with a HelmRelease by simply removing their files.
First protect CRDs from Flux pruning, preserve CRs and credentials, and plan Helm ownership adoption for existing names.
Avoid overlapping operator instances. Test the handover in lab first; production migration is a separate step.
Configure Flux HelmRelease `install.crds: CreateReplace` and `upgrade.crds: CreateReplace` after the CRD ownership handover.
Do not let the old Kustomization and Helm independently manage the same CRDs.
A Git revert alone does not reverse Helm ownership or CRD schema changes; never delete CRDs to force adoption.

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

**Route approval replay.** Headscale's `autoApprovers` act only on a route *change* event, so a route
advertised before its approver existed stays "available, not approved". After every successful write
(and every `InSync` check) the operator lists the nodes and approves each advertised route that lies
inside an `autoApprovers.routes` prefix of the rendered policy naming one of the node's tags —
exactly what the event would have done, nothing more. Approvals are never removed. Events
`RoutesApproved` / `RouteApprovalFailed` on the `Tailnet` show what happened.

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

## 8. Upgrade

The in-place steps below apply only within the same API group.
For a pre-v0.4.0 installation, read [§8.0](#80-v040-api-group-migration) first.

**Validate existing CRs before upgrading the CRDs.** The stricter schema requires Kubernetes ≥ 1.31,
non-empty ingress `allowFrom`, DNS-label CR names of at most 40 characters, unique target/expose names
and expose ports, at most 50 targets/exposes, and aliases of at most 63 characters.
Target names must start with a letter because they become Services (Kubernetes 1.31 compatibility).
Rendered ingress DNS names must also keep each label within 63 characters; combining long names and namespaces can exceed this limit.
Non-empty ingress DNS templates must contain `{name}` and end in a literal lowercase zone with at least two labels.
See [validation rules and the isolated live-export check](USAGE.md#13-validation).
Do not install stricter CRDs until existing objects pass that check; it does not modify the cluster.

1. Verify that the release image exists in your registry before changing the Deployment.
   `deploy/operator.yaml` uses the Docker Hub mirror; a successful private-registry build does not prove mirror availability.
2. Apply the new CRDs first (`deploy/crds/`), then the Deployment with the new image (operator and
   `OPERATOR_IMAGE`; agent pods are re-rolled by the operator). With GitOps, make these changes in the source repository.
3. `kubectl get tailnet` — expect `COMPAT=Compatible`, `POLICY=InSync` (or `Applied`) and `DNS=CannotVerify`
   for a database-mode server with policy generation and an ingress DNS template enabled.
   `DNS=CannotVerify` is a manual configuration hint, not proof that DNS is broken or working.
4. `kubectl get tailnetegress,tailnetingress -A` — everything back to `READY=True`.
   Verify an actual egress connection and ingress connection after the rollout.

### 8.0. v0.4.0 API-group migration

**Upgrade blocker:** the API-group/child-ownership migration has not been rehearsed.
Do not treat this as an ordinary image bump or let Flux prune the old CRDs in a single replacement commit.
Fresh-install tests do not establish upgrade safety.

The API group changes from `tailnet.this-is-fine.io` to `tsunaro.io` without conversion.
Recreated CRs have new UIDs even when their names and namespaces stay unchanged.
Existing child owner references still point at the old CRs.
Deleting an old CRD deletes its CRs and can garbage-collect their children, including generated Secrets and Services.
The chart name, image repository and binary names do not change.

Before a rollout, prepare and rehearse a cluster-specific handover that meets these requirements:

1. Protect old CRDs and dependent resources from GitOps pruning. Preserve desired CR manifests,
   resource identities, Service IPs, policy state and recoverable credentials in secure storage.
   Do not put Secret exports in logs or Git.
2. Stop every old operator replica before starting a new one. The Lease changes from
   `tailnet-operator.this-is-fine.io` to `tailnet-operator.tsunaro.io`; these are independent locks.
   A rolling update cannot prevent concurrent old/new policy and key writers.
3. Inventory child owner references and old-domain labels/annotations. Plan explicit ownership and
   metadata transfer for preserved children, or deliberate recreation where downtime and identity changes are acceptable.
   Recreating CRs alone does not safely adopt all children or translate key-expiry metadata.
   Migrate role labels together with ownership: cleanup distinguishes DNS and rendered-policy ConfigMaps using `tsunaro.io/role`.
   A preserved working Secret with only the old expiry annotation triggers bootstrap, even if its working key is still valid.
   Verify the case where bootstrap has expired; do not assume preservation succeeds because the Secret name is unchanged.
4. Install the new CRDs and validate all recreated CR manifests against them.
   Complete the reviewed child handover before the new operator reconciles them.
   Keep each migrated Tailnet's policy in `DryRun` while rebuilding the full CR inventory.
   The new operator collects only new-group CRs; early `Apply` can replace the live policy with an incomplete fleet render.
   Review the complete rendered-policy diff before restoring `Apply`.
   Prove working/preauth-key behavior and retain secure recovery credentials.
5. Verify policy convergence, all CR conditions, DNS answers, Service IPs and actual egress/ingress connections.
   Record agent node identities and any intentional replacements. Do not promise a fixed downtime bound.
6. Remove old-group CRs and CRDs only after every retained child's owner reference has been accounted for.
   Keep CRD pruning disabled until this check is complete. Use fully qualified resource names while both groups exist.

A tested rollback must restore compatible CRs, ownership, metadata and images without overlapping operators.
An image downgrade or Git revert alone cannot undo this migration. Retain the shared ingress gateway until
application migration has separate acceptance. The detailed handover and its rehearsal remain release prerequisites.

#### Inventory and metadata-transfer primitives (development only)

`internal/migration` contains a read-only inventory planner and an explicit per-child handover primitive, not a live migration command.
It is not called by the controllers and does not loosen their ownership guards.
It requires existing old/new CRs with matching names, namespaces and specs; an enabled destination policy must be `DryRun`.
Permitted spec differences are the Tailnet policy transition to `DryRun` and admission adding an explicit ingress `mode: l4`.
Changing an L4 expose to HTTP is a separate migration, not part of this handover.

The primitive transfers the exact controller owner reference and known top-level metadata together.
It translates key expiry and ConfigMap role metadata. Legacy prefix annotations are removed, not copied:
older versions could store a full token there. The working-key controller reconstructs the canonical prefix from Secret data.
Conflicting metadata, unknown legacy keys, deleting resources and legacy pod-template keys require manual review.

Planning is read-only. Server-side dry-run validates a patch without persisting it.
Application tests the child's UID and resourceVersion, checks parent snapshots and verifies the returned post-state.
A retry with the same in-memory plan accepts only its exact post-state, apart from resourceVersion and managedFields.
Plans cannot be serialized for crash recovery. API failures stop the transfer without printing response bodies or credentials.

`PlanInventory` discovers and lists every advertised listable top-level resource type across namespaces, without label selectors.
It requires exact old/new CR pairs, including CRs without children, and rejects unsupported or ambiguous direct dependencies.
Partial discovery, denied or incomplete lists, already-transferred children and changed parent/catalog snapshots stop the entire plan.
Tailnet children and egress CRs must belong to the explicitly supplied operator namespace.
The scan requires broad read permissions and reads Secret data into memory; it returns only an opaque plan with redacted formatting and counts.
It does not report unowned name collisions or provide a cluster-wide atomic snapshot. Writers and pruning must already be stopped.

Neither primitive creates CRs, deletes resources, changes specs or contacts Headscale.
They do not fence parent deletion or concurrent writers. Successful per-object patches cannot prove a safe fleet migration.
Unowned-resource collision checks, durable partial-run recovery, garbage-collection/rollback rehearsal and real connectivity checks remain required.
Do not use the library as a shortcut around the stop-first procedure above.

### Helm and Flux CRD upgrades

Helm CLI installs missing files from `crds/` but does not upgrade, roll back or uninstall those CRDs.
After validating existing objects, use `task crd-upgrade KUBE_CONTEXT=<reviewed-context>` for a manually managed installation,
then `helm upgrade` to the new chart version. This task changes the selected cluster; it is not a validation command.
Flux HelmRelease can upgrade CRDs with `install.crds: CreateReplace` and `upgrade.crds: CreateReplace`.
Keep schema changes and their rollback manifests in Git. CRD retention is intentional; there is no deletion-based rollback.

### Operator restart versus agent upgrade

Restarting the operator with the same image and unchanged desired state does not itself require an agent rollout.
Changing `OPERATOR_IMAGE` also changes the agent image unless `spec.image` on the CR or `Tailnet.spec.proxy.image` overrides it.
Agent Deployments use `Recreate` to avoid two pods competing for one tailnet identity.
An agent image change therefore interrupts that CR's data path while the replacement registers and starts serving.
A temporary `Ready=False` during this replacement can indicate a real interruption, not a status-only flap.

When diagnosing a restart-related status change, watch the CR conditions and agent pod UIDs together.
Distinguish a pure operator restart from an agent replacement before suppressing readiness failures.

Version notes:

| Version | Notes |
| --- | --- |
| v0.4.0 (unreleased) | Agent HTTP/TLS termination, Helm chart, leader election, monitoring and security gates; see [CHANGELOG](../CHANGELOG.md). **Breaking:** API group `tailnet.this-is-fine.io` → `tsunaro.io`, metadata keys and leader Lease change. No conversion or coordinated child-adoption migration. Requires a rehearsed stop-first ownership/credential migration; do not use a single Flux swap-and-prune commit. See [§8.0](#80-v040-api-group-migration). Chart name, image repository and binary names are unchanged. |
| v0.3.0 | Headscale capability preflight (`HeadscaleCompatible`, `PolicyMode`, `SplitDNS`), `COMPAT`/`DNS` columns and optional `headscale.version` hint. Proven file mode blocks policy writes and route-approval replay; empty-database bootstrap remains possible. **Breaking admission changes:** Kubernetes ≥1.31, required `spec`/non-empty ingress `allowFrom`, stricter names/addresses/templates, unique target/expose names and expose ports, bounded lists and lifetimes. Validate existing CRs against the new schema before upgrading; see [all validation rules](USAGE.md#13-validation). |
| v0.2.0 | **Breaking:** API group `tailnet.fr0st.dev` → `tailnet.this-is-fine.io` (CRDs, RBAC, every CR). No conversion: apply new CRDs + RBAC + image and re-create the CRs under the new group, then delete the old CRDs — children (agents, keys, Services, hosts ConfigMap) are owned by the CR and are rebuilt, agents re-register (1–2 min). With Flux: one commit that swaps CRD files, RBAC, image and CRs; prune removes the old CRDs; tenant CRs follow in a second commit. Also: `ProbeFailed` reason, `status.tag` (TAG column), ingress DNS names publish IPv4 only, MagicDNS name restored to the hostname after a duplicate, transient `ApplyFailed` logged at info, status-only updates no longer re-trigger reconciles. |
| v0.2.1 | Missed `autoApprovers` approvals are replayed after every successful policy write/InSync check (routes inside a rendered approver prefix, router tag listed there; events `RoutesApproved`) — no manual `approve-routes` needed. Rejected/failed policy writes are retried with backoff (15 s doubling to 5 min) instead of a fixed 5 min — a base test whose `src` is momentarily unresolvable (node re-registering) heals in seconds. `tailnet_policy_apply_errors_total` therefore counts more increments per outage: raise `TailnetPolicyApplyErrors` to `>= 6` per 30 min (a permanent failure gets there in ~8 min, a hiccup under 4 min stays at ≤ 5). |
| v0.2.3 | `ApiReachable` is taken from Headscale `/health` (new reason `Unhealthy`: server up, database down) and `ApiKeyValid` from a live authenticated call (new reason `Rejected`); both are re-checked at least every 5 min instead of once per key half-life. |
| v0.2.2 | The policy controller no longer re-reconciles when it writes its own rendered ConfigMap (one policy write per change instead of a second no-op run; rejected writes are counted once). |
| v0.1.1 | Route diagnosis is prefix-aware: a target covered by an aggregate advertised route (`10.0.0.0/24` for `10.0.10.20`) is `Present`, no longer `NotAdvertised`. |
| v0.1.0 | `Tailnet.spec.policy` (operator-owned policy, DryRun/Apply), `TailnetIngress.spec.allowFrom`, new conditions `PolicyRendered`/`PolicyApplied`/`PolicyGranted`, reasons `PolicyPending`/`PolicyDenied`. Existing clusters are unaffected until `policy.baseConfigMap` is set. |
| v0.0.6 | `Tailnet.spec.dns`, `TailnetEgress.spec.targets[].aliases`, `TailnetIngress.status.dnsName`, `Backend.namespace`. |

## 9. Rollback

| Situation | Action |
| --- | --- |
| A render is wrong but not yet applied (`DryRun`) | fix the base or the CR; nothing reached Headscale |
| Headscale rejected the render (`PolicyApplied=False/PolicyRejected`) | the previous policy is still active; read the message, fix — the write is retried with backoff (15 s doubling to 5 min), a base/CR change retries at once |
| The operator must stop writing | `policy.mode: DryRun` — the operator only renders from now on |
| Restore the Git policy on the server | `kubectl -n tailnet-system exec deploy/headscale -- headscale policy set -f /acl/policy` (mode DryRun first, or it is overwritten within 5 min) |
| Leave database mode | `HEADSCALE_POLICY_MODE=file`, restart; the mounted file is authoritative again |
| Downgrade the operator | restore both the previous container image and `OPERATOR_IMAGE` (agents also roll back); the newer CRDs and their admission rules remain installed |
| Relax the v0.3.0 admission rules | restore the previous `deploy/crds/` manifests through the same deployment mechanism; never delete the CRDs, which also deletes their CRs |

For a v0.3.0 → v0.2.3 rollback, restore the v0.2.3 CRD manifests and both image pins in Git when using GitOps.
An image-only rollback does not undo schema validation or remove stored preflight conditions.
Older schemas can prune newer optional fields on subsequent writes; keep the desired CR manifests in Git.
Neither rollback restores a previously applied Headscale policy. Use `DryRun` first if policy writes must stop.
Agent replacement can interrupt connections during a downgrade just as during an upgrade.

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
