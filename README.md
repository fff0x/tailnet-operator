# tailnet-operator

[![CI](https://img.shields.io/endpoint?url=https%3A%2F%2Fci.this-is-fine.io%2Fbadge%2Ftailnet-operator.json)](https://ci.this-is-fine.io/)

**Per-namespace egress into a [Headscale](https://headscale.net) tailnet, ingress out of it, and the
policy that binds them — as CRDs.** Give a namespace stable in-cluster Services that tunnel to
off-cluster hosts (a remote site's databases, brokers, HTTPS APIs behind a subnet router), publish
in-cluster services to tailnet peers, and let the operator derive tags, route approvals and grants
from those CRs — without a per-workload `tailscale`+`socat` sidecar, without `NET_ADMIN` or
`/dev/net/tun`, and without hand-editing the policy for every target.

Go · [controller-runtime](https://github.com/kubernetes-sigs/controller-runtime) ·
[tsnet](https://tailscale.com/kb/1244/tsnet) · [Apache-2.0](LICENSE) · © 2026 Max 'ff0x' Reineke

| | |
| --- | --- |
| **Install** — Headscale, operator, CoreDNS, gateway, policy mode, upgrade, rollback | [docs/INSTALL.md](docs/INSTALL.md) |
| **Use & operate** — recipes for egress, ingress, policy, keys, diagnosis | [docs/USAGE.md](docs/USAGE.md) |
| **Reference** — CRD fields, conditions, metrics | [below](#crd-reference) |

## Model

- **`Tailnet`** (cluster-scoped) — one per Headscale control server: login URL, in-cluster API
  endpoint, a read-only bootstrap API key from which the operator mints and **rotates its own working
  key**. Optionally owns the **DNS hosts file** and the **policy** for everything below.
- **`TailnetEgress`** (operator namespace) — one egress identity: a tag, a reusable ephemeral
  pre-auth key, a userspace agent pod and one Service per target. Consumers in `consumerNamespaces`
  dial `<target>.<operator-ns>.svc:<port>`; **aliases** let them dial the real hostname when the far
  end routes by SNI/Host.
- **`TailnetIngress`** (tenant namespace) — the mirror: expose in-cluster **L4** Services *on* the
  tailnet as one node with a MagicDNS name and, with a template, a DNS name under your zone. HTTPS
  keeps terminating at your shared gateway; the ingress adds a per-app tailnet identity.
- **The tag is the authorization.** Each CR is its own node with its own tag; the policy's grants for
  that tag decide what it may reach (egress) or who may reach it (ingress). Without
  `Tailnet.spec.policy` the operator only *reads* the policy and reports what is missing; with it, the
  operator renders your base policy plus the CR-derived entries and writes the result to Headscale.

## Quickstart

Installation (Helm chart, Headscale key, CoreDNS; `kubectl apply -k deploy` alternative) is in
[docs/INSTALL.md](docs/INSTALL.md). Chart `0.3.1` is prepared but not yet published; see its
[values and release prerequisites](charts/tailnet-operator/README.md). With that in place, three manifests:

```yaml
apiVersion: tailnet.this-is-fine.io/v1alpha1
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
apiVersion: tailnet.this-is-fine.io/v1alpha1
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
apiVersion: tailnet.this-is-fine.io/v1alpha1
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
# tailnet.tailnet.this-is-fine.io/corp   https://ts.example.com   True     2026-10-28T12:00:00Z   Compatible   Applied   CannotVerify   3d
#
# NAMESPACE        NAME                                          TAG                      HOSTNAME             READY   AGE
# tailnet-system   tailnetegress.tailnet.this-is-fine.io/billing-dev   tag:egress-billing-dev   egress-billing-dev   True    2m
#
# NAMESPACE   NAME                                    TAG                HOSTNAME       DNS                                             READY   AGE
# shop-dev    tailnetingress.tailnet.this-is-fine.io/shop   tag:ingress-shop   ingress-shop   shop-shop-dev.prod-1.tailnet.example.internal   True    2m
```

A pod in `billing-dev` dials `db-1.tailnet-system.svc:1521` or `https://api.corp.example`; a tailnet
peer in `group:shop` dials `shop-shop-dev.prod-1.tailnet.example.internal:5432`. The policy behind
it (tagOwners, `/32` approvals, grants) was generated from the two CRs.

## CRD reference

### Tailnet

| Field | Default | Meaning |
| --- | --- | --- |
| `server` | — | login/control URL, the agents' ControlURL |
| `apiUrl` | `server` | in-cluster REST endpoint |
| `headscale.version` | none | optional version hint for diagnostics; does not bypass capability probes |
| `headscale.ref` | empty | reserved for managed Headscale; non-empty values are rejected |
| `apiSecretRef.{name,key}` | key `apiKey` | Secret (operator namespace) with the read-only bootstrap API key |
| `apiKeyLifetime` / `authKeyLifetime` | `720h` / `168h` | working API key (minimum 1h) / per-CR pre-auth key; both rotated at half-life |
| `proxy.{image,resources,mtu,probeInterval}` | operator image, –, `1200`, `5m` | agent pod defaults |
| `proxy.imagePullSecrets` | operator default | registry Secret names in each agent namespace; omitted inherits `AGENT_IMAGE_PULL_SECRETS` (JSON array), `[]` clears the operator-supplied list; credentials are never copied |
| `tagTemplate` / `hostnameTemplate` | `tag:egress-{name}` / `egress-{name}` | egress tag and MagicDNS name when the CR sets none |
| `ingressTagTemplate` / `ingressHostnameTemplate` | `tag:ingress-{name}` / `ingress-{name}` | same for ingress |
| `dns.hostsConfigMap` | off | ConfigMap (key `hosts`) receiving the rendered CoreDNS hosts file |
| `dns.ingressNameTemplate` | off | `{name}`, `{namespace}` → `TailnetIngress.status.dnsName`; keep it one label below your wildcard cert |
| `policy.baseConfigMap` | off | ConfigMap (key `policy`) with the human-written base policy (HuJSON) |
| `policy.renderedConfigMap` | `<base>-rendered` | where the render is published for review |
| `policy.mode` | `DryRun` | `DryRun` renders only; `Apply` also writes Headscale when live ≠ render |
| `policy.tagOwners` | required when on | owners of generated tags, e.g. `[group:operator]` |
| `policy.routeApprovers` | required when on | approvers of generated `/32` routes, e.g. `[tag:fabric]` |
| `policy.ingressSourceAllowlist` | none | globs an ingress `allowFrom` entry must match, e.g. `["group:*"]` |

### TailnetEgress (operator namespace)

| Field | Default | Meaning |
| --- | --- | --- |
| `tailnetRef.name` | — | the Tailnet |
| `tag` / `hostname` | from templates | node tag / MagicDNS name |
| `consumerNamespaces[]` | — | namespaces whose pods may reach the target Services (NetworkPolicy) |
| `targets[].name` | — | Service name starting with a letter, ≤63 characters; unique within the CR and operator namespace; 1–50 targets |
| `targets[].address`, `.port` | — | off-cluster host (IP or MagicDNS name) and TCP port |
| `targets[].aliases[]` | none | lowercase DNS names, each ≤63 characters, resolving to the target Service (needs `dns.hostsConfigMap`) |
| `image`, `resources` | Tailnet defaults | agent overrides |

### TailnetIngress (tenant namespace)

| Field | Default | Meaning |
| --- | --- | --- |
| `tailnetRef.name` | — | the Tailnet |
| `tag` / `hostname` | from templates | node tag / MagicDNS name |
| `allowFrom[]` | required | at least one non-empty peer source (policy `src`); each must match `ingressSourceAllowlist` when policy generation is enabled |
| `exposes[].name`, `.port` | — | listener on the tailnet node; 1–50 exposes, unique names and ports |
| `exposes[].backend.{service,namespace,port}` | namespace = CR's | in-cluster backend; another namespace only to funnel through a shared gateway |
| `image`, `resources` | Tailnet defaults | agent overrides |

Kubernetes ≥1.31 is required. CR names, addresses, ports, list sizes and policy inputs are checked
at admission. See [validation rules and tests](docs/USAGE.md#13-validation) before upgrading CRDs.

### Status and conditions

| Kind | Conditions | Notable reasons |
| --- | --- | --- |
| `Tailnet` | `ApiReachable`, `ApiKeyValid`, `HeadscaleCompatible`, `PolicyMode`, `SplitDNS`, `PolicyRendered`, `PolicyApplied` | `Reachable` / `Unreachable` / `Unhealthy` (database down); `Valid` / `Rejected` / `Error`; `Compatible` / `Incompatible` / `CannotVerify` / `ProbeFailed`; `Database` / `File`; `SplitDNS=Unknown/CannotVerify` (manual configuration required); `Rendered`, `BaseMissing`, `BaseInvalid`, `PolicyEmpty` (refused: would lock everyone out); `DryRun`, `InSync`, `Applied`, `PolicyModeFile` (write skipped), `PolicyRejected` (Headscale refused; old policy stays), `ApplyFailed`, `NoAPIKey` |
| `TailnetEgress` | `TagKnown`, `Registered`, `RoutesGranted`, `TargetsReachable`, `ServiceConflict`, `Ready` | `Known` / `Unknown` / `PolicyPending` (tag not in live policy yet); `Registered` / `NotRegistered`; `RoutesMissing`, `Unreachable`, `ProbeFailed` (agent not scraped — NetworkPolicy or pod down; nothing is known about routes/dials); `Conflict` (target name taken by a foreign Service); `Ready` false with `NoTailnet`, `NoAPIKey`, `TagUnknown`; per target `status.targets[].reason` ∈ `NotAdvertised`, `NotApproved` (re-approved by the operator on the next policy reconcile), `NoGrant`, `ProbeFailed` |
| `TailnetIngress` | `TagKnown`, `PolicyGranted`, `Registered`, `BackendsReachable`, `Ready` | as egress, plus `Granted` / `PolicyDenied` (`allowFrom` outside the allowlist) and `InvalidDNSName` |

`Tailnet.status.policy` = `{renderedHash, appliedHash, appliedAt, generated{tags,grants,routes}}`;
`TailnetIngress.status.dnsName` is the rendered DNS name (published as A record only — the IPv4 node
address; `status.tag` is the effective tag). `kubectl get tailnet` includes `COMPAT` and `DNS` reason columns.
Preflight uses the API response shape, not a reported server version: database policy mode and a
successful non-mutating `policy/check` probe are required for `Compatible`. Missing or failed
observations stay `Unknown`. See [preflight details](docs/INSTALL.md#25-preflight).
Event `PolicyDriftOverwritten` fires when
the live policy was changed behind the operator's back and rewritten.

Metrics (controller-runtime registry): `tailnet_apikey_expires_seconds`,
`tailnet_policy_applied_timestamp_seconds`, `tailnet_policy_apply_errors_total`,
`tailnetegress_authkey_expires_seconds`, `tailnetegress_routes_missing`,
`tailnetingress_authkey_expires_seconds`, `tailnetingress_backends_unreachable`.

## How it works

Five reconcilers, each turning CRs into desired state applied with server-side apply — no per-CR
restart to add or remove a target:

- **Tailnet** — mints the working API key from the bootstrap key, rotates it at half-life (new key
  verified before the old one is expired), reports reachability.
- **Egress / Ingress** — per CR: tag pre-check against the live policy, a reusable ephemeral pre-auth
  key (rotated at half-life; a restarted pod re-registers on its own, a deleted CR's node ages out),
  one agent Deployment, one Service per target, a NetworkPolicy scoped to `consumerNamespaces`, and a
  status that classifies every target route (`NotAdvertised` / `NotApproved` / `NoGrant`) from the
  node's netmap and the router's advertised/approved sets — the two silent failures of a hand-built
  proxy, named.
- **DNS** — folds egress aliases and ingress names into one CoreDNS `hosts` ConfigMap per Tailnet.
  The resolver is the cluster's, not the operator's; if the operator dies the last file stays valid.
- **Policy** — parses the base HuJSON generically, appends tagOwners / `/32` approvals / grants
  derived from the CRs (base wins, nothing removed, unknown blocks pass through), publishes the render
  in a ConfigMap and, in `Apply`, writes it when the live document differs. Headscale validates
  (including the base's `tests`) before storing, so a rejected render never becomes active. After a
  successful write it replays missed `autoApprovers` approvals (a route advertised before its
  approver existed) on the routers, so `NotApproved` heals without `headscale nodes approve-routes`.
- **Data plane** — one agent pod per CR is a userspace tsnet node. `AGENT_MODE` sets the direction:
  egress takes `--accept-routes` and `Dial`s the off-cluster address over the tailnet; ingress listens
  on the tailnet and `Dial`s an in-cluster backend. Same binary, `io.Copy` with half-close, no
  SOCKS5, no second container; state is in-memory and ephemeral by design.

A single image carries both binaries; the operator runs `/tailnet-operator`, each agent pod runs
`/tailnet-agent`.

## Develop

```sh
nix-shell          # Go, Task, kubectl, kustomize, Helm, helm-docs, kubeconform
task lint test     # gofmt + go vet + unit tests
task crds          # regenerate deploy/crds/ and chart CRD copies from Go types
task deploy-gen    # regenerate deploy/operator.yaml from default chart values
task chart         # chart docs, lint, render, drift and contract checks (no cluster)
# With KUBEBUILDER_ASSETS pointing to local envtest binaries (Kubernetes >=1.31):
task test-validation # real API-server admission tests; optional LIVE_CR_FILE export
task e2e           # isolated API server + real Headscale; downloads pinned public assets
task e2e-kind      # disposable installation + leader failover; rootless Podman/kind delegation
task image         # build the combined bundle image locally
```

The prepared `.radicle/native.yaml` runs the portable chart lint/render/drift gate before tests.
It then builds the native Dockerfile `TEST` target and runs `hack/ci-test.sh` in a fresh Buildah container.
The test gate includes formatting, vet, uncached unit/chart tests, admission and real Headscale Tier 1.
No signing credentials or host mounts enter the test container; test results are never cached in an image layer.
Only after success does `ci-build` cross-compile both binaries for `linux/amd64` + `linux/arm64` and publish a
cosign-signed multi-arch index at `oci.<domain>/tailnet/operator` (private).
Docker Hub mirroring to `docker.io/ff0x/tailnet-operator` is a separate publication step.
The prepared broker needs `mixed-helm-v1`, `image-result-v1`, Syft 1.52.0, Trivy 0.74.0 and Cosign 2.5.0.
Deploy it and configure `CI_BUILDER_IMAGE` with its immutable image reference before publishing this repo.
Native CI checks capabilities and audit configuration before building; it rejects older brokers.
After publication, `hack/audit-image.sh` consumes the publisher's private JSON report, not log output.
It verifies the signed index, scans both immutable platform children, then signs and verifies SPDX and SLSA-v1 predicates.
HIGH/CRITICAL findings warn on main and reject versioned releases; operational failures always fail.
This is post-publication acceptance, not a transaction or rollback. Existing releases do not gain this evidence retroactively.
See [the security policy](docs/SECURITY.md#build-and-verification-gates) for limits.
Local `task chart` additionally generates helm-docs and runs Go-based Helm contract tests.
Tier 1 covers preflight, policy lifecycle, working-key rotation and metadata repair,
InSync approval replay, tag-sourced policy tests, IPv4-only hosts output and credential redaction.
See [the compatibility matrix and remaining gates](docs/COMPATIBILITY.md).
The new CI gate still requires deployment and a successful broker run on main.
The [Tier-2 tests](test/e2e-kind/README.md) have passed installation and two-replica leader failover in a delegated rootless user scope.
The combined RBAC/metrics run converged in 16.884 seconds against a 30-second bound (previously 17.935 seconds).
One of the initial four integrated runs failed during early Helm installation; its cause remains unknown.
The subsequent combined run passed after the readiness-timing correction.
A later independently exported index passed with 17.393-second policy convergence and verified cleanup.
This is local control-plane evidence, not HTTP-ingress, data-plane, nightly or week-long HA acceptance.

| Path | What |
| --- | --- |
| `api/v1alpha1` | `Tailnet`, `TailnetEgress`, `TailnetIngress` CRD types |
| `cmd/operator` | control plane entry point |
| `cmd/agent` | `tailnet-agent`: tsnet node, egress/ingress TCP forwarders, health/probe |
| `internal/manager` | shared production/test controller wiring and cache scopes |
| `internal/controller` | reconcilers (tailnet, egress, ingress, dns, policy) and resource builders |
| `internal/headscale` | Headscale REST client (Bearer): nodes, keys, policy |
| `internal/policy` | base + CR → rendered policy, normalisation, hashing (tested) |
| `internal/{keys,ports,routes,naming}` | pure functions: key rotation, port assignment, route diagnosis, templating (tested) |
| `charts/tailnet-operator/` | Helm chart, copied CRDs, documented values and optional monitoring/network isolation |
| `deploy/` | generated default chart bundle and CRDs (kustomize); `examples/` incl. a base policy |
| `test/e2e/` | isolated Tier-1 manager + real Headscale tests and pinned asset hashes |
| `test/e2e-kind/` | rootless kind installation, leader failover and owned-kubeconfig safety tests |
| `docs/` | [INSTALL.md](docs/INSTALL.md), [USAGE.md](docs/USAGE.md), [COMPATIBILITY.md](docs/COMPATIBILITY.md) |
