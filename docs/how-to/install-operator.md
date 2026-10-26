---
title: "Install the operator"
weight: 30
description: "Prerequisites, Helm and kustomize installation, images and private registries, agent resources, network isolation, and what the chart ships versus what the site provides."
---

## Prerequisites


| Component | Requirement | Why |
| --- | --- | --- |
| Kubernetes | ≥ 1.31 | CRD admission uses the CEL IP library (`isIP`) |
| CNI | NetworkPolicy support | `consumerNamespaces` isolation is a NetworkPolicy |
| Headscale | 0.29.x, reachable from the cluster over HTTP(S) | REST API for nodes, keys and (optionally) the policy |
| Subnet router | a node tagged e.g. `tag:fabric` advertising the site routes — the operator-managed `TailnetGateway` ([Run the gateway](gateway.md)), or any node you tag yourself | egress targets are reached through it |
| CoreDNS | the cluster's, plus (optionally) a resolver you control for your tailnet zone | DNS aliases and ingress names ([DNS with CoreDNS](dns-coredns.md)) |
| cert-manager | optional | issues the certificate for a `mode: http` ingress ([Ingress over HTTPS](ingress-https.md)) |
| Gateway | optional: Envoy/Gateway API with a wildcard certificate for `*.prod-1.tailnet.example.internal` | HTTPS through a shared gateway instead ([Ingress over HTTPS](ingress-https.md)) |

Ingress and egress agents are userspace
[tsnet](https://tailscale.com/kb/1244/tsnet) pods without `NET_ADMIN` or `/dev/net/tun`.
The opt-in `TailnetGateway` instead needs a kernel-mode workload with
`NET_ADMIN`, `/dev/net/tun` and verified forwarding prerequisites. It is fresh-only,
not a migration mechanism; read its [limits and prerequisites](../reference/gateway.md)
before activation. Installing the chart alone does not create a Gateway.

## Helm

```sh
helm install tailnet-operator oci://oci.this-is-fine.io/charts/tailnet-operator \
  --version 0.22.0 --namespace tailnet-system --create-namespace

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

Use your secret manager instead of `--from-literal` in production. The `http://` `apiUrl` sends the
working key in clear across the cluster network; serve the API over TLS and set
`headscale.caConfigMapRef` ([API over TLS](install-headscale.md#api-over-tls)). From a source checkout, replace
the OCI URL with `./charts/tailnet-operator` and set `image.repository`/`image.tag` to your build.
Helm 3 and 4 are supported; the default chart needs no Prometheus or Grafana CRDs.

To inspect or vendor the chart, pull it and verify its signature first (see
[SECURITY.md](../explanation/security-model.md) for the key and the Radicle release record):

```sh
helm pull oci://oci.this-is-fine.io/charts/tailnet-operator --version 0.22.0
cosign verify --key deploy/cosign.pub oci.this-is-fine.io/charts/tailnet-operator:0.22.0
```

```sh
kubectl -n tailnet-system rollout status deploy/tailnet-operator
kubectl get tailnet corp
kubectl describe tailnet corp
```

`ApiReachable=True` and `ApiKeyValid=True` mean the working key exists and the API answers. The
`POLICY` column stays empty until [Operator-owned policy](policy.md). The Tailnet reports missing
credentials and retries until the Secret appears.

Run **one operator release per cluster**. Leader election is on by default; `replicas > 1` adds a
PodDisruptionBudget and all replicas share the Lease `tailnet-operator.tsunaro.io` in the operator
namespace. With `leaderElection.enabled: false` only one replica is allowed and the Deployment uses
`Recreate`. Chart values are documented in the [chart README](../reference/values.md#values).

## Images and private registries

`image.digest` wins over `image.tag`. An empty `agentImage` inherits the operator image. Image-pull
Secrets are referenced by **name** and must exist in each agent namespace (operator namespace for
egress, tenant namespace for ingress): `imagePullSecrets` for the operator pod,
`agent.imagePullSecrets` as the default for agents, `Tailnet.spec.proxy.imagePullSecrets` to replace
that default per Tailnet (`[]` clears it). The operator never copies registry credentials.

## Agent resources

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

### Namespaces with a LimitRange

The chart defaults (requests `10m`/`32Mi`) match what agents actually use. In a namespace with a
`LimitRange` minimum or a `ResourceQuota`, admission may reject an agent pod whose request is below
the floor; the CR then reports `Registered=False/WorkloadBlocked` with the admission message (e.g.
`minimum cpu usage per Container is 100m`). Raise the agent block to clear it — cluster-wide on the
Tailnet, or per CR:

```yaml
kind: Tailnet
spec:
  proxy:
    resources:
      requests: {cpu: 100m, memory: 128Mi}
      limits: {memory: 512Mi}
```

Each block is selected whole (`CR.spec.resources` > `Tailnet.spec.proxy.resources` > chart default);
there is no per-key merge, so set every value you need in the block you choose.

## Network isolation

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

## Kustomize

```sh
kubectl apply -k deploy
```

`deploy/operator.yaml` is generated from the default chart values (`task deploy-gen`) and contains
Namespace, RBAC, ServiceAccount, Deployment and metrics Service; the CRDs are in `deploy/crds/`.
Use an overlay for namespace, images and site policies.

## What the chart ships and what the site provides

| Component | Chart default | Turn off | Site provides |
| --- | --- | --- | --- |
| CRDs (`crds/`) | installed with `helm install`, never upgraded by Helm | `--skip-crds` | upgrades per [Upgrade](upgrade-rollback.md#upgrade) (`task crd-upgrade` or Flux `crds: CreateReplace`) |
| Deployment, RBAC, ServiceAccount, metrics Service, PDB | on; PDB only with `replicas > 1` | — (that is the operator) | one release per cluster, the namespace |
| ServiceMonitor, PrometheusRule, dashboard | off | `monitoring.serviceMonitor/rules/dashboard.enabled` | Prometheus and Grafana Operator CRDs, a Prometheus that selects them |
| PodMonitor for agents and gateways | off | `monitoring.podMonitor.enabled` | PodMonitor CRD; `scrapeFrom` peers, otherwise the agent policy blocks the scrape |
| Operator NetworkPolicy | off | `networkPolicy.enabled` | `provider: kubernetes` needs `kubeAPICIDRs`, `headscaleCIDRs`, `metricsPeers`; `provider: cilium` needs the Cilium CRDs and label peers. For a Headscale outside the cluster (shared/spoke clusters) set `cilium.headscalePeers: []` and populate `headscaleCIDRs` — the chart adds a `toCIDR` egress on `headscalePorts`. |
| Agent NetworkPolicies | always generated by the operator (not the chart) | — | `consumerNamespaces` on the CR; a CNI that enforces NetworkPolicy |
| Headscale | not shipped | — | 0.29.x reachable from the cluster, bootstrap API key Secret, policy base per [Prepare Headscale](install-headscale.md) |
| Headscale API trust | public roots only | `headscale.caConfigMapRef.name` | a ConfigMap with the issuer CA behind an `https://` `apiUrl` ([API over TLS](install-headscale.md#api-over-tls)) |
| PKI for `mode: http` ingress | not shipped | — | cert-manager and an issuer, or a TLS Secret; the ingress name must resolve to the agent |
| Image-pull Secrets | none referenced | — | Secrets by name in operator and tenant namespaces (`imagePullSecrets`, `agent.imagePullSecrets`) |
| LoadBalancer IPs for gateways | not shipped | — | an LB implementation and pool matching `tailnetLBCIDR` / `service.poolLabels` ([Run the gateway](gateway.md)) |
| Cluster CoreDNS forward | not touched | — | the `forward` stanza for the alias zones ([Wire the cluster CoreDNS](dns-coredns.md#wire-the-cluster-coredns)) |
| Flux/cosign verification | public key in `deploy/cosign.pub` | — | the `verify` block on `OCIRepository`/`HelmRelease` ([SECURITY.md](../explanation/security-model.md)) |
| `Tailnet`, `TailnetEgress`, `TailnetIngress`, `TailnetSite`, `TailnetGateway` | none created | — | every CR; the chart installs only the schemas |
