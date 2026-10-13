# tailnet-operator

Tsunaro — TailnetEgress, TailnetIngress and experimental kernel TailnetGateway for Headscale.

![Version: 0.14.2](https://img.shields.io/badge/Version-0.14.2-informational?style=flat-square)  ![AppVersion: v0.14.2](https://img.shields.io/badge/AppVersion-v0.14.2-informational?style=flat-square)

## Installation

```sh
helm install tailnet-operator oci://oci.this-is-fine.io/charts/tailnet-operator \
  --version 0.14.2 --namespace tailnet-system --create-namespace
# or from a source checkout:
helm install tailnet-operator ./charts/tailnet-operator --namespace tailnet-system --create-namespace
```

Install one release per cluster. `namespace` defaults to the release namespace; a different value
must already exist (`--create-namespace` only creates the release namespace). Uninstall keeps the
namespace and the CRDs. The Tailnet CR, bootstrap key, Headscale policy and DNS wiring are described
in [INSTALL](../../docs/INSTALL.md).

## CRDs

`task crds` generates `deploy/crds/` and copies the files into this chart's `crds/`. Helm installs
missing CRDs but never upgrades or removes them: use `task crd-upgrade KUBE_CONTEXT=<context>` for a
manual installation, or `install.crds: CreateReplace` / `upgrade.crds: CreateReplace` on a Flux
`HelmRelease`. Validate existing CRs against a new schema first ([USAGE §13](../../docs/USAGE.md#13-validation)).

## Permissions

The chart grants main-resource PATCH for ingress CRs cluster-wide and egress CRs in the operator
namespace, intended for future drain finalizers. PATCH also permits spec edits; RBAC cannot restrict
it to metadata. Main Tailnet resources remain read-only. ReplicaSets and Pods have only
`get/list/watch`; Services remain operator-namespace scoped. Review the
[exact RBAC reference](../../docs/reference/rbac.md) and
[DNS history schema limitations](../../docs/SECURITY.md#dns-claim-history-schema-not-lifecycle-enforcement).
The schema/RBAC addition installs no finalizers and implements no DNS lifecycle or publisher behavior.

## Leader election and availability

`leaderElection.enabled: true` (default) runs all controllers on the elected replica; the Lease is
`tailnet-operator.tsunaro.io` in the operator namespace (15 s lease, 10 s renew, 2 s retry).
Updates use `RollingUpdate` with `maxSurge: 1`, `maxUnavailable: 0`; `replicas > 1` adds a
PodDisruptionBudget with `minAvailable: 1`, and `topologySpreadConstraints` can spread replicas.
With election disabled, only one replica is allowed and updates use `Recreate`. Do not run electing
and non-electing operators at the same time. Generated agents stay singletons; operator replicas do
not make agents highly available.

## Images and credentials

An empty `agentImage` inherits the operator image including its digest; an explicit agent repository
uses `Chart.appVersion` unless it sets its own tag or digest. Per-CR `spec.image`, then
`Tailnet.spec.proxy.image`, then the chart's agent image. `imagePullSecrets` configures the operator
pod; `agent.imagePullSecrets` is the default list of Secret **names** for generated agent pods, which
`Tailnet.spec.proxy.imagePullSecrets` replaces (`[]` clears). Each Secret must exist in the agent's
namespace — the operator never copies registry credentials.

## Agent resources

`agent.resources` defaults to requests of CPU `10m` and memory `32Mi`, with a memory limit of `128Mi`
and no CPU limit. Both ingress and egress select one whole block, without merging lower-tier keys:

1. `TailnetIngress.spec.resources` or `TailnetEgress.spec.resources`.
2. `Tailnet.spec.proxy.resources`.
3. The operator's chart-supplied `agent.resources`.

A CR/Tailnet block with both requests and limits unset falls through. Either non-nil map, even empty,
selects that block in the controller; Kubernetes serialization may omit empty maps.
Helm merges values separately: `agent.resources: {}` retains chart defaults. Use `agent.resources: null`
to disable the chart fallback (the operator receives `{}`), or null individual default keys to remove them.
The operator validates quantities at startup, rejecting negative values and requests above matching limits.
Direct binary runs with `AGENT_RESOURCES` absent, empty, or `{}` retain the zero default.

Changing effective resources updates agent pod templates. Each affected CR gets a `Recreate` restart
and its ephemeral node re-registers; expect a brief interruption. Higher-tier overrides remain unchanged.

## Network isolation

`networkPolicy.enabled` isolates the operator pod (agents have their own generated policies). Set the
Kubernetes API and Headscale CIDRs and ports explicitly — NetworkPolicy cannot select a hostname.
DNS defaults to kube-dns in `kube-system`; agent status traffic on TCP 9080 stays allowed; metrics
ingress on TCP 8080 is denied unless `networkPolicy.metricsPeers` lists the scraper.

## Monitoring

All monitoring objects are disabled by default and each needs its CRD installed:

- `monitoring.serviceMonitor.enabled` — operator metrics on TCP 8080 (`honorLabels: true` keeps the CR's `namespace` label).
- `monitoring.podMonitor.enabled` — agent `/metrics` on the `health` port (TCP 9080) in all namespaces unless `namespaceSelector` restricts it.
- `monitoring.rules.enabled` — the bundled PrometheusRule (13 alerts). Non-empty `rules.groups` replaces all of them.
- `monitoring.dashboard.enabled` — the bundled dashboard as `GrafanaDashboard` (Grafana Operator v5, selector `grafana.internal/instance: grafana`, datasource `datasourceName`) or `kind: ConfigMap` for sidecars. Non-empty `dashboard.json` replaces it.

A PodMonitor grants no network access; agent NetworkPolicies allow TCP 9080 from the operator
namespace only, so a scraper elsewhere needs its own additive policy. Key-expiry alert thresholds are
`monitoring.rules.apiKeyExpiryWarningSeconds` (7 d) and `authKeyExpiryWarningSeconds` (1 d); keep
them below half the configured key lifetime. Alert semantics and runbooks:
[USAGE §14](../../docs/USAGE.md#14-monitoring-and-alert-runbooks).

## HTTP TLS termination

A `TailnetIngress` with a `mode: http` expose terminates TLS on the agent using a namespace-local
`kubernetes.io/tls` Secret or a cert-manager issuer ([USAGE §6.1](../../docs/USAGE.md#61-ingress-terminate-tls-on-the-agent)).
The chart grants `Certificate` get/create/patch/delete for the issuer path; missing cert-manager CRDs
do not affect startup or L4 operation. Do not downgrade below v0.4.0 while HTTP CRs exist.
Backend TLS and expose timeouts require v0.5.0 agents, including explicit image overrides.
CA ConfigMaps are namespace-local; existing ConfigMap permissions cover inspection and watch.
See [compatibility](../../docs/COMPATIBILITY.md#http-extension-compatibility-v050) before enabling extensions or downgrading.

## Development

- `task chart` — helm-docs, lint, kubeconform, CRD/render drift and Go contract tests.
- `task deploy-gen` — regenerate `deploy/operator.yaml` from the default values.
- `task rbac-check` / `task rbac-gen` — compare or update [the RBAC reference](../../docs/reference/rbac.md).
- Chart destination: `OCI_CHART_PATH` in `Taskfile.yaml` plus `Chart.name`. Release tags publish the
  plain `Chart.version` (`0.14.2`, without `v`); branch builds publish `-dev.g<sha>` pre-releases.

## Values

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| agent.imagePullSecrets | list | `[]` | Default agent pull-secret names, e.g. [dockerconfig]. Tailnet.spec.proxy.imagePullSecrets overrides these. Secrets must exist in each agent namespace. |
| agent.resources | object | `{"limits":{"memory":"128Mi"},"requests":{"cpu":"10m","memory":"32Mi"}}` | Default agent resource block, below CR spec.resources and Tailnet.spec.proxy.resources (no per-key merging). Set null to disable chart defaults; {} does not clear Helm defaults. Changes restart agents that inherit them. |
| agentImage.digest | string | `""` | Agent digest. An entirely empty agentImage inherits the complete operator image, including its digest. |
| agentImage.repository | string | `""` | Agent repository; empty inherits image.repository. |
| agentImage.tag | string | `""` | Agent tag. With an explicit repository, empty uses Chart.appVersion; otherwise inherits image.tag. |
| env.extra | list | `[]` | Additional EnvVar entries. POD_NAMESPACE, OPERATOR_IMAGE, AGENT_IMAGE_PULL_SECRETS, AGENT_RESOURCES and SSL_CERT_FILE are reserved. |
| fullnameOverride | string | `""` | Override the resource name with a letter-first DNS label (at most 53 characters). Install only one operator per cluster. |
| image.digest | string | `""` | Optional sha256 digest; takes precedence over the tag. |
| image.pullPolicy | string | `"IfNotPresent"` | Operator pull policy. |
| image.repository | string | `"docker.io/ff0x/tailnet-operator"` | Operator image repository. Verify mirror availability before installation. |
| image.tag | string | `""` | Image tag; empty uses Chart.appVersion. |
| imagePullSecrets | list | `[]` | Pull-secret references for the operator pod, e.g. [{name: dockerconfig}]. |
| leaderElection.enabled | bool | `true` | Elect one active operator using a Lease in the operator namespace. Disable only for a single replica with Recreate updates. |
| monitoring.dashboard.allowCrossNamespaceImport | bool | `true` | Allow Grafana Operator to import into matching instances in other namespaces. |
| monitoring.dashboard.datasourceName | string | `"Prometheus"` | Grafana Operator datasource name mapped to the bundled DS_PROMETHEUS input. Sidecar users must configure input substitution separately. |
| monitoring.dashboard.enabled | bool | `false` | Render the bundled dashboard, or the json override below. Disabled by default. |
| monitoring.dashboard.folder | string | `"Tailnet"` | Grafana Operator dashboard folder. |
| monitoring.dashboard.instanceSelector | object | `{"matchLabels":{"grafana.internal/instance":"grafana"}}` | Grafana Operator instance selector. |
| monitoring.dashboard.json | string | `""` | Nonempty JSON replaces the bundled dashboard; custom JSON is not template evaluated. |
| monitoring.dashboard.kind | string | `"GrafanaDashboard"` | GrafanaDashboard requires Grafana Operator v5 CRDs; ConfigMap supports dashboard sidecars. |
| monitoring.dashboard.labels | object | `{"grafana_dashboard":"1"}` | Labels for the dashboard resource, including the optional ConfigMap sidecar label. |
| monitoring.podMonitor.enabled | bool | `false` | Scrape generated agents on health TCP/9080 and gateways on kernel-health TCP/8080 + metrics-dns TCP/9153. Requires PodMonitor CRD; allow your Prometheus through scrapeFrom. |
| monitoring.podMonitor.interval | string | `"30s"` | Agent scrape interval. |
| monitoring.podMonitor.labels | object | `{}` | Additional PodMonitor labels for your Prometheus selector. |
| monitoring.podMonitor.namespaceSelector | object | `{"any":true}` | Agent namespace selection. Set any: false with matchNames to restrict namespaces; any: false without names selects only the PodMonitor namespace. |
| monitoring.podMonitor.scrapeFrom | list | `[]` | NetworkPolicy peers (namespaceSelector / podSelector / ipBlock) that may scrape the generated agents on TCP/9080, rendered into every agent NetworkPolicy next to the operator. Empty adds none. Gateways carry no policy. |
| monitoring.rules.apiKeyExpiryWarningSeconds | int | `604800` | API-key expiry warning threshold in seconds (7 days). For shorter key lifetimes, set below half-life to avoid warning before normal rotation. |
| monitoring.rules.authKeyExpiryWarningSeconds | int | `86400` | Egress/ingress auth-key expiry warning threshold in seconds (1 day). For shorter key lifetimes, set below half-life to avoid warning before normal rotation. |
| monitoring.rules.enabled | bool | `false` | Render a PrometheusRule. Requires Prometheus Operator CRDs. |
| monitoring.rules.groups | list | `[]` | Nonempty groups replace all bundled rules, without merging or template evaluation. |
| monitoring.serviceMonitor.enabled | bool | `false` | Requires Prometheus Operator CRDs. Disabled for a fresh Kubernetes installation. |
| monitoring.serviceMonitor.interval | string | `"30s"` | Scrape interval. |
| monitoring.serviceMonitor.labels | object | `{}` | Additional ServiceMonitor labels for your Prometheus selector. |
| namespace | string | `""` | Operator namespace; empty uses the Helm release namespace. Bootstrap and working keys live here. |
| networkPolicy.cilium.headscalePeers | list | `[{"podSelector":{"matchLabels":{"app.kubernetes.io/name":"headscale"}}}]` | Headscale peers for provider cilium (namespaceSelector / podSelector; no ipBlock). Without a namespaceSelector the peer is scoped to the operator namespace. |
| networkPolicy.dnsPeers | list | `[{"namespaceSelector":{"matchLabels":{"kubernetes.io/metadata.name":"kube-system"}},"podSelector":{"matchLabels":{"k8s-app":"kube-dns"}}}]` | DNS NetworkPolicy peers; customize for NodeLocal DNS or a different resolver. |
| networkPolicy.enabled | bool | `false` | Enable operator isolation. With provider kubernetes this requires explicit kubeAPI and Headscale CIDRs; CNI Service-DNAT behavior must be checked locally. |
| networkPolicy.headscaleCIDRs | list | `[]` | Headscale API endpoint CIDRs (not hostnames). Required for provider kubernetes; update when DNS addresses change. |
| networkPolicy.headscalePorts | list | `[443,8080]` | Headscale REST API TCP ports. |
| networkPolicy.kubeAPICIDRs | list | `[]` | API endpoint and/or Service CIDRs appropriate for your CNI, e.g. [10.96.0.1/32]. Required for provider kubernetes. |
| networkPolicy.kubeAPIPorts | list | `[443,6443]` | Kubernetes API TCP ports. |
| networkPolicy.metricsPeers | list | `[]` | Peers permitted to scrape metrics (provider kubernetes). Empty denies metrics ingress when isolation is enabled. |
| networkPolicy.provider | string | `"kubernetes"` | `kubernetes` renders a NetworkPolicy (ingress and egress, ipBlock-based). `cilium` renders an egress-only CiliumNetworkPolicy using `toEntities: kube-apiserver` and label selectors — ipBlock peers are rejected, ingress stays open, requires the cilium.io/v2 CRDs. |
| podSecurityContext | object | `{"runAsGroup":65532,"runAsNonRoot":true,"runAsUser":65532,"seccompProfile":{"type":"RuntimeDefault"}}` | Pod security context; the scratch image requires a numeric non-root UID. |
| replicas | int | `1` | Operator replicas; more than one requires leaderElection.enabled. A PDB with minAvailable=1 is rendered for multiple replicas. |
| resources | object | `{"limits":{"memory":"128Mi"},"requests":{"cpu":"25m","memory":"64Mi"}}` | Operator resource requests and limits. |
| securityContext | object | `{"allowPrivilegeEscalation":false,"capabilities":{"drop":["ALL"]},"readOnlyRootFilesystem":true}` | Operator container hardening. Agents are configured separately by the controller. |
| topologySpreadConstraints | list | `[]` | Optional operator pod topology spread constraints. Supply a labelSelector matching app.kubernetes.io/name: tailnet-operator. |
