# tailnet-operator

[![CI](https://img.shields.io/endpoint?url=https%3A%2F%2Fci.this-is-fine.io%2Fbadge%2Ftailnet-operator.json)](https://ci.this-is-fine.io/)

**Per-namespace egress into a [Headscale](https://headscale.net) tailnet, as a CRD.** Give a
namespace stable in-cluster Services that tunnel out to off-cluster hosts — a remote site's
databases, message brokers, anything reachable through a tailnet subnet router — without a
per-workload `tailscale`+`socat` sidecar and without touching `NET_ADMIN` or `/dev/net/tun`.

Go · [controller-runtime](https://github.com/kubernetes-sigs/controller-runtime) ·
[tsnet](https://tailscale.com/kb/1244/tsnet) · MIT

- **`Tailnet`** (cluster-scoped) — one per Headscale control server. Holds the login URL, the
  in-cluster API endpoint and a bootstrap API key; the operator mints and **rotates its own working
  API key** from it (half-life rotation, verified before the old key is expired). Shared by every
  `TailnetEgress`.
- **`TailnetEgress`** (namespaced) — one egress identity: a tag, a reusable ephemeral pre-auth key,
  a userspace agent pod and one Service per target. Consumers dial `<target>.<namespace>:<port>`.
  The operator **reports** a missing route/grant as status — it never writes tailnet policy.
- **`TailnetIngress`** (namespaced) — the mirror: expose in-cluster **L4** Services *on* the tailnet
  as one userspace node with a MagicDNS name. A tenant self-serves a database, broker or any TCP
  service to tailnet peers (`<hostname>:<port>`) without an Envoy route, a subnet router or a
  certificate — complementing, not replacing, the HTTP shared gateway.

## Quickstart

```sh
kubectl apply -k deploy   # CRDs + operator (namespace tailnet-system)
```

Point the operator at your Headscale, using a bootstrap API key stored in a Secret:

```yaml
apiVersion: tailnet.fr0st.dev/v1alpha1
kind: Tailnet
metadata:
  name: corp
spec:
  server: https://ts.example.com                    # the agents' ControlURL
  apiUrl: http://headscale.tailnet-system.svc:8080  # in-cluster REST endpoint
  apiSecretRef: { name: headscale-bootstrap, key: apiKey }
  proxy: { mtu: 1200, probeInterval: 5m }
```

Give a namespace egress to a few off-cluster hosts. The `tag` must already be declared **with
grants** in the tailnet policy — the operator refuses to mint a key for an unknown tag, and surfaces
a missing grant as a status reason rather than editing policy:

```yaml
apiVersion: tailnet.fr0st.dev/v1alpha1
kind: TailnetEgress
metadata:
  name: billing-dev
  namespace: tailnet-system
spec:
  tailnetRef: { name: corp }
  # tag: tag:ns-billing-dev       # default: tag:egress-{name} from the Tailnet template
  consumerNamespaces: [billing-dev]
  targets:
    - { name: oracle-db-1, address: 10.0.10.20, port: 1521 }
    - { name: broker-1,       address: 10.0.20.10,  port: 5672 }
```

A workload in `billing-dev` then connects to `oracle-db-1.tailnet-system.svc:1521` — plain TCP in,
tailnet out.

```sh
kubectl get tailnetegress billing-dev
# NAME      TAG              HOSTNAME         READY   AGE
# billing-dev   tag:ns-billing-dev   egress-billing-dev   true    2m
```

Expose the other direction — an in-cluster Service *on* the tailnet — with a `TailnetIngress` in the
tenant's own namespace. Each expose is a plain-TCP listener on the node; the `tag`'s grants (with the
tag as `dst`) decide which peers may dial it:

```yaml
apiVersion: tailnet.fr0st.dev/v1alpha1
kind: TailnetIngress
metadata:
  name: shop
  namespace: shop-dev
spec:
  tailnetRef: { name: corp }
  # tag: tag:ingress-shop     # default: tag:ingress-{name} from the Tailnet template
  exposes:
    - { name: postgres, port: 5432, backend: { service: shop-db-rw, port: 5432 } }
    - { name: redis,    port: 6379, backend: { service: shop-redis, port: 6379 } }
```

A tailnet peer then reaches the database at `ingress-shop:5432` (the node's MagicDNS name + the expose
port) — any TCP protocol, no HTTP route and no certificate needed (WireGuard is the transport).

```sh
kubectl -n shop-dev get tailnetingress shop
# NAME   TAG               HOSTNAME       DNS                                        READY   AGE
# shop   tag:ingress-shop  ingress-shop   shop-shop-dev.prod-1.tailnet.example.internal   true    2m
```

The `DNS` column is filled once the `Tailnet` has a `dns.ingressNameTemplate` — see [DNS names](#dns-names).

## Status

Every kind reports readiness as Kubernetes conditions, so `kubectl describe` tells you exactly what
is (not) working — including the two silent failures of a hand-built proxy (a route advertised
before its approver existed, and Headscale not distributing routes like Tailscale SaaS), which here
surface as a named reason per target instead of a hanging connection:

| Kind             | Conditions                                                                       |
| ---------------- | -------------------------------------------------------------------------------- |
| `Tailnet`        | `ApiReachable`, `ApiKeyValid` (+ `status.apiKeyExpiresAt`)                        |
| `TailnetEgress`  | `TagKnown`, `Registered`, `RoutesGranted`, `TargetsReachable`, `Ready`           |
| `TailnetIngress` | `TagKnown`, `Registered`, `BackendsReachable`, `Ready`                            |

`TailnetEgress.status.targets[]` carries a per-target `present`/`reachable` pair and a `reason` when
a route is missing — `NotAdvertised`, `NotApproved` or `NoGrant` — pinpointing which of the four
manual steps was skipped. `TailnetIngress.status.exposes[]` carries a per-expose `reachable` flag and
an `Unreachable` reason when the in-cluster backend does not answer; `status.dnsName` is the
rendered DNS name (empty without a template), `InvalidDNSName` the reason when the template renders
something that is not a DNS name.

Metrics (controller-runtime registry): `tailnet_apikey_expires_seconds`,
`tailnetegress_authkey_expires_seconds`, `tailnetegress_routes_missing`,
`tailnetingress_authkey_expires_seconds`, `tailnetingress_backends_unreachable`.

## DNS names

An L4 tunnel carries TLS untouched — so whatever name the client dials becomes the SNI/Host the far
end sees. `db.tailnet-system.svc` is fine for a database; it is wrong for `api.corp.example`
behind a name-routing reverse proxy. Likewise a `TailnetIngress` node is only an IP until something
gives it a name. Both get one declaratively; the operator **serves no DNS** — it renders a CoreDNS
[`hosts`](https://coredns.io/plugins/hosts/) file into a ConfigMap, and the cluster mounts it into a
resolver that is already authoritative for the zones:

```yaml
kind: Tailnet
spec:
  dns:
    hostsConfigMap: tailnet-dns-hosts   # operator namespace, key "hosts"; empty → feature off
    ingressNameTemplate: "{name}-{namespace}.prod-1.tailnet.example.internal"
```

| Source                                 | Record                                        |
| -------------------------------------- | --------------------------------------------- |
| `TailnetEgress.spec.targets[].aliases` | alias → the target Service's ClusterIP        |
| `TailnetIngress` (template rendered)   | `status.dnsName` → the node's tailnet IPs     |

```
# managed by tailnet-operator (Tailnet corp) — do not edit
10.43.12.7    api.corp.example
100.64.0.42   shop-shop-dev.prod-1.tailnet.example.internal
```

Wire it into the CoreDNS that answers for those zones (in a Headscale setup typically the sidecar
your split-DNS entry delegates `<cluster>.<domain>` to); mount the ConfigMap `optional: true` so
the resolver starts before the operator has rendered anything:

```corefile
prod-1.tailnet.example.internal:53 {
    hosts /etc/tailnet-dns/hosts { fallthrough }   # operator records win …
    template IN A { answer "{{ .Name }} 30 IN A 10.0.0.80" }   # … the wildcard catches the rest
}
corp.example:53 {
    hosts /etc/tailnet-dns/hosts { fallthrough }
    forward . 10.0.0.53                           # everything else: the site's DNS
}
```

Freshness is ConfigMap propagation (≤ ~1 min) plus the `hosts` reload (5 s). A name claimed by two
CRs keeps the first (sorted by kind/namespace/name) and logs the loser. If the operator dies, the
last file stays valid — the data path never depends on it.

**Why one label.** A gateway's wildcard certificate `*.prod-1.<domain>` covers exactly one label,
so `{name}-{namespace}.prod-1.<domain>` works with the certificate you already have, while
`{name}.{namespace}.prod-1.<domain>` would need one per namespace. Which brings us to HTTPS:

**HTTPS through a `TailnetIngress`.** The node is L4 and has no certificate — TLS still terminates
at the shared gateway. What the ingress adds is a **per-app tailnet identity**: its own node, its own
tag, its own grant, instead of every HTTP app hiding behind the gateway's single IP. Point an expose
at the gateway's Service and give the tenant's HTTPRoute the rendered name:

```yaml
kind: TailnetIngress                      # in the tenant namespace
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

Peer → name → node IP (Headscale grant `dst = tag:ingress-shop`) → Envoy (SNI matches the wildcard,
route by Host) → app. Envoy sees the agent pod as the client; authorisation is the tailnet policy's
job here, not Envoy's. For plain TCP exposes the name simply resolves to the node and the peer dials
`<dnsName>:<port>`. Note that in-cluster pods usually cannot route tailnet `100.x` addresses — ingress
names are for tailnet peers, pods use the Service.

## How it works

The operator's control plane turns each `TailnetEgress` into a **desired state** and applies it via
server-side apply — no per-CR restart to add or remove a target:

- **Keys.** A reusable, ephemeral pre-auth key per CR (default 7 days, rotated at half-life) lets a
  restarted pod re-register on its own; a deleted CR's node ages out by itself. The working API key
  is minted from the bootstrap key and rotated automatically.
- **Data plane.** One agent pod per CR is a userspace [tsnet](https://tailscale.com/kb/1244/tsnet)
  node. `AGENT_MODE` sets the direction: **egress** takes `--accept-routes`, opens a local listener
  and `Dial`s the off-cluster address over the tailnet; **ingress** listens *on* the tailnet and
  `Dial`s an in-cluster backend through the pod's own netns. Same binary, `io.Copy` with half-close,
  no SOCKS5, no second container. State is in-memory and ephemeral by design.
- **Services & isolation.** One Service per target (named after the target) gives consumers a stable
  `host:port`; a NetworkPolicy restricts the proxy to `consumerNamespaces` (and lets the operator
  scrape its health port). Identity is per CR because **the tag is the authorization** — sharing a
  node between namespaces would collapse both grants onto it.
- **Names.** A fourth reconciler folds egress aliases and ingress names into one CoreDNS `hosts`
  ConfigMap per `Tailnet` (see [DNS names](#dns-names)); the resolver is the cluster's, not the
  operator's.
- **Policy stays in Git.** The operator reads the policy to pre-check the tag and to diagnose routes,
  but never writes it: a missing grant is a status line, an event and a metric.

A single image carries both binaries; the operator runs `/tailnet-operator`, each agent pod runs
`/tailnet-agent`.

## Develop

```sh
nix-shell          # go toolchain + go-task + kubectl + kustomize
task lint test     # gofmt + go vet + unit tests
task crds          # regenerate deploy/crds/ from the Go types
task image         # build the combined bundle image locally
```

CI is radicle-native: `.radicle/native.yaml` runs `ci-build`, which cross-compiles both binaries for
`linux/amd64` + `linux/arm64`, publishes a cosign-signed multi-arch index at
`oci.<domain>/tailnet/operator` (private) and mirrors it to `docker.io/ff0x/tailnet-operator`
(public).

| Path                  | What                                                                 |
| --------------------- | -------------------------------------------------------------------- |
| `api/v1alpha1`        | `Tailnet` + `TailnetEgress` + `TailnetIngress` CRD types             |
| `cmd/operator`        | control plane: reconcilers, key rotation, resource builders          |
| `cmd/agent`           | `tailnet-agent`: tsnet node, egress/ingress TCP forwarders, health/probe |
| `internal/headscale`  | Headscale REST client (Bearer)                                       |
| `internal/{keys,ports,routes,naming}` | pure functions: key rotation, port assignment, route diagnosis, templating (all tested) |
| `deploy/`             | generated CRDs, RBAC, manager Deployment (kustomize)                 |
