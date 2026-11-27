# Tsunaro — tailnet-operator

[![CI](https://img.shields.io/endpoint?url=https%3A%2F%2Fci.this-is-fine.io%2Fbadge%2Ftailnet-operator.json)](https://ci.this-is-fine.io/)

**Per-namespace egress into a [Headscale](https://headscale.net) tailnet, ingress out of it, and the
policy that binds them — as CRDs.** Give a namespace stable in-cluster Services that tunnel to
off-cluster hosts (a remote site's databases, brokers, HTTPS APIs behind a subnet router), publish
in-cluster services to tailnet peers, and let the operator derive tags, route approvals and grants
from those CRs — without a per-workload `tailscale`+`socat` sidecar, without `NET_ADMIN` or
`/dev/net/tun`, and without hand-editing the policy for every target.

Go · [controller-runtime](https://github.com/kubernetes-sigs/controller-runtime) ·
[tsnet](https://tailscale.com/kb/1244/tsnet) · [Apache-2.0](https://app.radicle.xyz/nodes/seed.this-is-fine.io/rad:z46fGxuhyvDV57psA8s6Q6PdHJrsX/tree/LICENSE) · © 2026 Max 'ff0x' Reineke

| | |
| --- | --- |
| **Tutorial** — Headscale to first egress and ingress in about thirty minutes | [docs/tutorials](docs/tutorials/getting-started.md) |
| **How-to guides** — install, egress, ingress, Kubernetes API, DNS, policy, site, gateway, upgrade, troubleshoot | [docs/how-to](docs/how-to/README.md) |
| **Reference** — CRD fields, chart values, RBAC, metrics, alerts, conditions and reasons | [docs/reference](docs/reference/README.md) |
| **Explanation & operations** — model, security model; keys, state, validation, runbooks | [docs/explanation](docs/explanation/README.md) · [docs/operations](docs/operations/README.md) |
| **All docs by role** — evaluator, installer, SRE, tenant, policy admin, auditor, contributor | [docs/README.md](docs/README.md) |

## Model

- **`Tailnet`** (cluster-scoped) — one per Headscale control server: login URL, in-cluster API
  endpoint, a read-only bootstrap API key from which the operator mints and **rotates its own working
  key**. Optionally owns the **DNS hosts file** and the **policy** for everything below.
- **`TailnetEgress`** (operator namespace) — one egress identity: a tag, a reusable ephemeral
  pre-auth key, a userspace agent pod and one Service per target. Consumers in `consumerNamespaces`
  dial `<target>.<operator-ns>.svc:<port>`; **aliases** let them dial the real hostname when the far
  end routes by SNI/Host.
- **`TailnetIngress`** (tenant namespace) — the mirror: expose in-cluster Services *on* the tailnet
  as one node with a MagicDNS name and, with a template, a DNS name under your zone. L4 exposes
  forward TCP; one or more `mode: http` exposes (virtual hosts, each with its own name, optional
  short alias and admin-allowed **bridge names** from a site's own zone) terminate TLS on the agent
  with a Secret or cert-manager certificate and forward HTTP or explicitly verified HTTPS to the
  app, routed by SNI — no shared gateway needed.
- **`TailnetSite`** (cluster-scoped) — a remote network behind a subnet router: a branch `/24`, a
  management range, a single host as `/32`. Declared once in the policy-owning cluster; the router
  is identified **by tag**, so any tagged router, in this or another cluster, qualifies. The operator renders
  the `autoApprovers`, replays approvals, blocks overlaps with `reservedNetworks` or older sites and
  reports `Advertised`/`Approved`/`Ready`. Who may *reach* the site is a grant in the base policy or a
  `TailnetGrant`.
- **`TailnetGrant`** (cluster-scoped) — TCP access for people or policy groups to one target: an
  ingress tag, also of a spoke cluster, or hosts inside a `TailnetSite`. Declared in the
  policy-owning cluster. The operator renders one grant and removes it at `expiresAt` by its own
  clock. The kind is administrative: a grant bypasses `allowFrom`.
- **`TailnetGateway`** (cluster-scoped) — the subnet router and split-DNS resolver as a CR: one
  kernel-mode Tailscale Pod advertising the site LAN, the tailnet LoadBalancer range and every
  egress target, plus a CoreDNS that serves the hosts file as the authoritative zone. Identity is
  pinned in a state Secret and immutable receipts; **fresh-only** — it creates a new node and never
  adopts, restarts or replaces one. Suspended by default.
- **`TailnetAccessRequest`** (cluster-scoped) — a request for a `TailnetGrant` or its extension,
  written and decided in the [console](docs/how-to/console.md); the operator ignores it.
- **The tag is the authorization.** Each CR is its own node with its own tag; the policy's grants for
  that tag decide what it may reach (egress) or who may reach it (ingress). Without
  `Tailnet.spec.policy` the operator only *reads* the policy and reports what is missing; with it, the
  operator renders your base policy plus the CR-derived entries and writes the result to Headscale.

## Quickstart

Installation (Helm chart, Headscale key, CoreDNS; `kubectl apply -k deploy` alternative) is in
[docs/how-to](docs/how-to/README.md); chart values in the [chart README](docs/reference/values.md).
With that in place, three manifests:

```yaml
apiVersion: tsunaro.io/v1alpha1
kind: Tailnet
metadata:
  name: corp
spec:
  server: https://ts.example.com
  apiUrl: http://headscale.tailnet-system.svc:8080
  apiSecretRef: { name: headscale-bootstrap, key: apiKey }
  dns:
    hostsConfigMap: tailnet-dns-hosts
    ingressNameTemplate: "{name}-{namespace}.prod-1.tailnet.example.internal"
  policy:                                   # optional: operator-owned policy
    baseConfigMap: headscale-policy
    mode: Apply
    tagOwners: [group:operator]
    routeApprovers: [tag:fabric]
    ingressSourceAllowlist: ["group:*"]
---
apiVersion: tsunaro.io/v1alpha1
kind: TailnetEgress
metadata:
  name: billing-dev
  namespace: tailnet-system
spec:
  tailnetRef: { name: corp }
  consumerNamespaces: [billing-dev]
  targets:
    - { name: db-1,     address: 10.0.10.20, port: 1521 }
    - { name: api-corp, address: 10.0.30.10, port: 443, aliases: [api.corp.example] }
---
apiVersion: tsunaro.io/v1alpha1
kind: TailnetIngress
metadata:
  name: shop
  namespace: shop-dev
spec:
  tailnetRef: { name: corp }
  allowFrom: [group:shop]
  exposes:
    - { name: postgres, port: 5432, backend: { service: shop-db-rw, port: 5432 } }
```

```sh
kubectl get tailnet,tailnetegress,tailnetingress -A
# NAME                             SERVER                   APIKEY   EXPIRES                COMPAT       POLICY    DNS            AGE
# tailnet.tsunaro.io/corp   https://ts.example.com   True     2026-10-28T12:00:00Z   Compatible   Applied   CannotVerify   3d
#
# NAMESPACE        NAME                                          TAG                      HOSTNAME             READY   AGE
# tailnet-system   tailnetegress.tsunaro.io/billing-dev   tag:egress-billing-dev   egress-billing-dev   True    2m
#
# NAMESPACE   NAME                                    TAG                HOSTNAME       HOSTS                                             READY   AGE
# shop-dev    tailnetingress.tsunaro.io/shop   tag:ingress-shop   ingress-shop   [shop-shop-dev.prod-1.tailnet.example.internal]   True    2m
```

A pod in `billing-dev` dials `db-1.tailnet-system.svc:1521` or `https://api.corp.example`; a tailnet
peer in `group:shop` dials `shop-shop-dev.prod-1.tailnet.example.internal:5432`. The policy behind
it (tagOwners, `/32` approvals, grants) was generated from the two CRs. In production, serve the
Headscale API over TLS and give the chart the issuer CA
([API over TLS](docs/how-to/install-headscale.md#api-over-tls)).

## CRD reference

Every `spec` and `status` field of the seven kinds, with types, defaults and constraints:
[CRD reference](docs/reference/crds.md) (generated from the CRDs). Worked examples for every kind:
[how-to guides](docs/how-to/README.md). Condition types and reasons per kind, as shown by
`kubectl get` and `describe`: [Conditions and reasons](docs/reference/reasons.md).

The `TailnetGateway` is fresh-only and suspended by default; the image is multi-arch
(`linux/amd64`, `linux/arm64`, [compatibility](docs/reference/compatibility.md)) — wiring in
[Run the gateway](docs/how-to/gateway.md), scope and migration boundary in
[Compatibility](docs/reference/compatibility.md#gateway-api-scope). Kubernetes ≥1.31 is required;
CR names, addresses, ports, list sizes and policy inputs are checked at admission
([validation](docs/operations/validation.md)).

Metrics (operator TCP 8080, agents TCP 9080) and the bundled alerts with their runbooks:
[Metrics](docs/reference/metrics.md), [Alerts](docs/reference/alerts.md),
[Monitoring and alert runbooks](docs/OPERATIONS.md).

## How it works

Six reconcilers (Tailnet, Egress, Ingress, Gateway, DNS, Policy) turn CRs into desired state
applied with server-side apply; one agent pod per CR is a userspace tsnet node, the same image
carrying `/tailnet-operator` and `/tailnet-agent`. The optional
[console](docs/how-to/console.md) (`/tailnet-console`), read-only unless its admins manage
TailnetGrants and access requests behind an audit log, is in that image too. The full walk-through — key rotation, route
diagnosis, policy rendering and replay, the data plane — is
[Model and how it works](docs/explanation/model.md#how-it-works).

## Develop

```sh
nix-shell            # Go, Task, kubectl, kustomize, Helm, helm-docs, kubeconform
task lint test       # gofmt, go vet, unit tests
task chart           # helm-docs, lint, kubeconform, drift and contract checks (no cluster)
task crds deploy-gen # regenerate CRDs and deploy/operator.yaml from their sources
task test-validation # admission tests on envtest (KUBEBUILDER_ASSETS)
task e2e             # manager against envtest + real Headscale (pinned downloads)
task e2e-kind        # rootless kind: install, failover, HTTP ingress with cert-manager
task e2e-full        # CI gate + every kind suite in one run (~75 min, delegated scope; see CONTRIBUTING)
task image           # build the combined image locally
```

CI runs the same gates in a fresh container, then publishes a cosign-signed multi-arch image and the
chart; see [CONTRIBUTING](https://app.radicle.xyz/nodes/seed.this-is-fine.io/rad:z46fGxuhyvDV57psA8s6Q6PdHJrsX/tree/CONTRIBUTING.md), [COMPATIBILITY](docs/reference/compatibility.md) and
[SECURITY](docs/explanation/security-model.md#supply-chain).

| Path | What |
| --- | --- |
| `api/v1alpha1` | `Tailnet`, `TailnetEgress`, `TailnetIngress`, `TailnetSite`, `TailnetGrant`, `TailnetAccessRequest`, `TailnetGateway` CRD types |
| `cmd/operator`, `cmd/agent` | control plane; `tailnet-agent`: tsnet node, TCP/HTTP forwarders, health and probe endpoints |
| `cmd/console`, `internal/console` | `tailnet-console`: web console with OIDC sign-in; optional grant management with a hash-chained audit log |
| `internal/controller` | reconcilers (tailnet, egress, ingress, gateway, dns, policy) and resource builders |
| `internal/gateway` | gateway renderer, route planner, DNS zone, receipts and the fresh writer |
| `internal/{headscale,policy,certificates}` | Headscale REST client; base + CR → rendered policy; TLS serving and certificate validation |
| `internal/{keys,ports,routes,naming,metrics,manager}` | key rotation, port assignment, route diagnosis, templating, metrics, controller wiring |
| `charts/tailnet-operator/` | Helm chart, copied CRDs, alerts, dashboard |
| `deploy/` | generated default bundle and CRDs (kustomize); `examples/` incl. a base policy and admission fixtures |
| `test/{validation,chart,security}` | envtest admission tests, chart contracts, image-audit tests |
| `test/e2e/`, `test/e2e-kind/` | Headscale integration suite; rootless kind cluster suite |
| `docs/` | [Diátaxis](https://diataxis.fr/) tree: [tutorials](docs/tutorials/README.md), [how-to](docs/how-to/README.md), [reference](docs/reference/README.md) (generated pages via `task docs` / `task rbac-gen`), [explanation](docs/explanation/README.md), [operations](docs/operations/README.md); [docs/README.md](docs/README.md) for paths by role |
