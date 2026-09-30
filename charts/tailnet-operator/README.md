# tailnet-operator

Userspace TailnetEgress and TailnetIngress with an external Headscale server.

![Version: 0.3.1](https://img.shields.io/badge/Version-0.3.1-informational?style=flat-square)  ![AppVersion: v0.3.1](https://img.shields.io/badge/AppVersion-v0.3.1-informational?style=flat-square)

## Status and installation

Chart 0.3.1 and image v0.3.1 are release preparation, not a publication claim.
Verify both artifacts in your chosen registry before installation.
Install only one operator release per cluster. Replicas within that release share one leader-election Lease;
releases in different namespaces do not share a lock and can race key rotation and policy writes.

```sh
# From a source checkout, after building/publishing the matching image:
helm install tailnet-operator ./charts/tailnet-operator \
  --namespace tailnet-system --create-namespace
# Once the upgraded broker and the chart release are published:
helm install tailnet-operator oci://oci.this-is-fine.io/charts/tailnet-operator \
  --version 0.3.1 --namespace tailnet-system --create-namespace
```

`namespace` defaults to the release namespace. A different override namespace must already exist;
`--create-namespace` only creates the release namespace. Keep them equal unless you need separate release storage.
The namespace is not a chart-owned resource. Uninstall does not delete the namespace or CRDs.

See [INSTALL](../../docs/INSTALL.md) for the Tailnet CR, bootstrap key, Headscale policy and DNS setup.
The default chart needs no Prometheus or Grafana CRDs. All monitoring features are disabled by default.

## Monitoring

Enable each feature independently after installing its CRD:

- `monitoring.serviceMonitor.enabled`: scrape the operator metrics Service on TCP 8080.
  `honorLabels: true` preserves the observed CR's `namespace` label instead of replacing it with the operator namespace.
- `monitoring.podMonitor.enabled`: scrape generated egress and ingress pods at `/metrics` on the named `health` port (TCP 9080).
  `namespaceSelector` defaults to all namespaces; restrict it with `any: false` and `matchNames` when appropriate.
  Configure monitor labels to match your Prometheus selectors and grant Prometheus discovery RBAC in the selected namespaces.
- `monitoring.rules.enabled`: install the bundled PrometheusRule. Nonempty `rules.groups` replaces **all** bundled groups unchanged.
  Custom Prometheus annotations are not Helm templates. This requires the PrometheusRule CRD.
- `monitoring.dashboard.enabled`: install the seven-row bundled dashboard. Nonempty `dashboard.json` replaces it unchanged.
  The default `kind: GrafanaDashboard` requires Grafana Operator v5 (`grafana.integreatly.org/v1beta1`).
  Its instance selector defaults to `grafana.internal/instance: grafana`, folder to `Tailnet`, and cross-namespace import to `true`.
  `datasourceName` maps the `DS_PROMETHEUS` input to a Grafana datasource (default `Prometheus`).
  For dashboard sidecars, set `kind: ConfigMap`; the `grafana_dashboard: "1"` label remains available.
  Sidecar users must configure datasource input substitution themselves; Grafana Operator mappings do not apply to ConfigMaps.

**Network access is not granted by a PodMonitor.** Existing generated agent NetworkPolicies allow health/metrics access
only from the operator namespace. A scraper in another namespace needs a site-owned, additive NetworkPolicy selecting
the agent pods and allowing only that scraper on TCP 9080. This chart does not silently broaden agent policies.
The operator's separate `networkPolicy.metricsPeers` controls TCP 8080 when operator isolation is enabled.

Bundled alerts cover operator availability, reconciliation errors, Headscale 5xx, current Ready reasons,
policy convergence/rejection/write failures, generated-entry drops, route approval replays, offline nodes and key expiry.
`TailnetReconcileErrors` requires more than 0.1 errors/second for 10 minutes.
`TailnetHeadscaleAPIErrors` requires more than 5% HTTP 5xx over 10 minutes, sustained for 10 minutes.
`TailnetApprovalReplays` detects more than three successfully replayed route approvals in one hour.
`TailnetAPIKeyExpiringSoon` defaults to 7 days (604800 seconds); `TailnetEgressAuthKeyExpiringSoon` and
`TailnetIngressAuthKeyExpiringSoon` default to 1 day (86400 seconds), each sustained for 5 minutes.
Configure `monitoring.rules.apiKeyExpiryWarningSeconds` and `monitoring.rules.authKeyExpiryWarningSeconds` as positive integer seconds.
For shorter-than-default key lifetimes, set thresholds **below half the configured lifetime** to avoid warnings before normal rotation.
These thresholds affect only bundled rules, not custom `rules.groups`.
`PolicyStale` uses `tailnet_policy_pending == 1` for 15 minutes, **not** age of the applied timestamp.
Stable `InSync` policies retain their original timestamp and must not trigger a stale-policy alert.
Generated-entry drops can be intentional, and replays count routes rather than requests; review before remediation.
Runbook annotations use relative `docs/USAGE.md#monitoring-*` links until documentation hosting is available.

Readiness exists only for resources with a current Ready condition; Tailnet has no Ready gauge.
Condition reasons are 1 for the active reason and 0 for previously observed reasons, not a boolean success indicator.
The not-ready alert joins readiness and its active reason within each exporter before aggregation.
Overlapping replica observations can show multiple failing reasons; a stale Ready=1 observation cannot hide a failure.
The dashboard documents which namespace/tailnet/kind filters apply to each family. Agent namespace/pod identity comes
from scrape metadata; egress pod namespace can differ from the CR namespace. TCP byte counts cover accepted connections,
including encrypted bytes in TLS pass-through traffic. HTTP ingress is not yet supported. Dial latency includes health probes. No IPs, user identities, credentials or hashes
are metric labels. `tailnet_node_online` is 1 for a matching online node and 0 when a successful Headscale node listing
finds none online. An absent series means no current observation, not an offline node.
`TailnetNodeOffline` requires an observed zero for 5 minutes. `tailnet_node_last_seen_seconds` is the selected Headscale
node's Unix timestamp; it is absent when unknown. The dashboard displays its age in seconds, not the raw timestamp.
Both families use resource kind/namespace/name, without a tailnet label. Gateway and TLS telemetry remain explicit placeholders.

This is source-prepared monitoring, not a live-tested or Grafana-exported dashboard. `hack/dashboard-lint.sh` uses only jq
to validate JSON and every nested panel description, including rows. Local chart tests use real promtool when installed
to parse alert/dashboard queries and evaluate rule fixtures. Kubeconform skips missing monitoring/Grafana schemas;
render tests do not prove CRD admission, scrape discovery, NetworkPolicy reachability or successful Grafana import.

## Leader election and availability

Defaults are `replicas: 1` and `leaderElection.enabled: true` (`--leader-elect=true`).
All five controllers run only on the elected replica. The Lease is named `tailnet-operator.this-is-fine.io`
in the operator namespace, independent of the release name. Election uses 15s lease duration,
10s renew deadline and 2s retry period. Namespaced Lease RBAC is enabled with election.

Election-enabled updates use `RollingUpdate` with `maxSurge: 1` and `maxUnavailable: 0`.
Multiple replicas require election. The chart adds a `policy/v1` PodDisruptionBudget with `minAvailable: 1`
only when `replicas > 1`. Optional `topologySpreadConstraints` can spread replicas across nodes or zones;
supply a selector matching `app.kubernetes.io/name: tailnet-operator`.
The PDB limits voluntary disruptions, not node failures. Readiness includes standby replicas and does not prove leadership.
Generated agents remain singletons with their existing update strategies; operator replicas do not make agents highly available.

The manager allows 20s for graceful shutdown; the pod termination grace is 30s.
It does not release the Lease early (`ReleaseOnCancel=false`): a drain timeout cannot prove that all workers stopped.
Controller-runtime continues renewal during normal draining; a successor then waits for Lease expiry.
On leadership loss, the process exits without graceful draining. Lease election is not external-write fencing;
process pauses, partitions and in-flight Headscale requests still require failover testing.
These source and rendering contracts do not establish live failover or week-long soak acceptance.

With `leaderElection.enabled: false`, only one replica is allowed and updates use `Recreate`.
**Migration requires a non-overlapping handover:** before enabling election from a disabled or older non-electing binary,
stop the old operator and wait for its pod to terminate. Before disabling election, stop all electing replicas.
Do not roll between electing and non-electing processes: a Lease cannot protect against a process that ignores it.
Keep the existing app-name-only Deployment selector for manifest adoption; it is immutable.

## Images and credentials

An empty `agentImage` inherits the complete operator image, including its digest.
An explicit agent repository uses `Chart.appVersion` unless its own tag or digest is set.
An agent tag or digest without a repository uses `image.repository`.
CR image precedence remains: per-CR `spec.image`, then `Tailnet.spec.proxy.image`, then the chart's agent image.

`imagePullSecrets` configures the operator pod. `agent.imagePullSecrets` supplies a separate default
list of Secret **names** for generated pods. `Tailnet.spec.proxy.imagePullSecrets` replaces this default;
omit it to inherit, or use `[]` to clear it. It applies independently of image overrides.
The operator never copies registry credentials. Each referenced Secret must exist in the agent's namespace
(operator namespace for egress, tenant namespace for ingress). Prefer the public Docker Hub mirror for
agents in tenant namespaces, after checking that the required release has actually been mirrored.
ServiceAccount pull-secret inheritance is independent of service-account token automounting;
`automountServiceAccountToken: false` does not disable image-pull-secret inheritance.

## Network isolation

The optional NetworkPolicy isolates the operator, not its generated agents (which have their own policies).
Set Kubernetes API and Headscale endpoint CIDRs and ports explicitly. Standard NetworkPolicy cannot select
an external hostname; refresh CIDRs when DNS addresses change. Service DNAT and node-local DNS behavior are
CNI-specific: test these paths before enabling isolation. DNS defaults select kube-dns in kube-system.
Agent status traffic is allowed on TCP 9080 across namespaces, with agent pod label selectors.
Metrics ingress is denied unless `networkPolicy.metricsPeers` permits the scraper.

## CRD lifecycle and migration

`task crds` generates `deploy/crds/` and copies those exact files into this chart's `crds/`.
Helm CLI installs missing CRDs but does **not** upgrade, roll back or uninstall them. They are retained;
there is no `crds.keep` toggle that could safely remove them and all their custom resources.
Before changing CRDs, validate existing CRs against the new schema as described in INSTALL.
For a manually managed installation, use `task crd-upgrade KUBE_CONTEXT=<reviewed-context>`, then `helm upgrade`.
For Flux, use `HelmRelease.spec.install.crds: CreateReplace` and `upgrade.crds: CreateReplace`.
Do not combine independent CRD writers without an explicit ownership handover.

Switching from copied manifests is **not** a blind delete-and-install operation: protect CRDs from Flux
pruning first, retain CRs and bootstrap Secrets, plan Helm ownership adoption, and prevent overlapping
operator instances. Keep existing resource names, namespace and Deployment selectors. Test the handover
in lab before production. A Git revert alone does not undo Helm ownership or schema changes.
Never delete CRDs as a migration or rollback shortcut.

## Development and publishing

- `task chart`: helm-docs, lint, kubeconform, CRD/render drift checks and local Helm contract tests.
- `task deploy-gen`: replace the generated standalone `deploy/operator.yaml` with default chart resources.
- Planned native CI runs the portable lint/render/drift gate and a fresh native TEST container before publication.
  The broker itself does not provide Go, Task or helm-docs; local checks do not establish broker execution.
- The prepared `ci-build` extension (`mixed-helm-v1`) publishes charts alongside the image.
  Release and deploy it before publishing this repo. A planned consumer gate rejects older brokers before any build.
  The chart alone does not install that CI gate or prove that the running broker supports it.
- Chart destination: `Taskfile.yaml` variable `OCI_CHART_PATH` plus Chart.name.
  Mixed branch builds publish `0.3.1-dev.g<sha>` with appVersion set to the commit SHA, plus SHA/latest aliases.
  The annotated release publishes plain Chart.version (`0.3.1`), **not** `v0.3.1`; it must match the Git tag without `v`.
  Stable versions reject existing tags or uncertain registry lookups; sign/verify the digest before moving aliases.
  Client-side checks are not atomic: serialize publishers and enforce registry-side version protection.
- Image/chart publication is not a transaction. Inspect partial failures before recovery; never overwrite an existing release.
  The broker's explicit `CI_BUILD_ARTIFACTS=charts` recovery skips image building but still rejects existing protected chart versions.
  Verify actual artifacts and Cosign signatures before any rollout. Sources stay in this repo; no separate chart Git repo is required.

## Values

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| agent.imagePullSecrets | list | `[]` | Default agent pull-secret names, e.g. [dockerconfig]. Tailnet.spec.proxy.imagePullSecrets overrides these. Secrets must exist in each agent namespace. |
| agentImage.digest | string | `""` | Agent digest. An entirely empty agentImage inherits the complete operator image, including its digest. |
| agentImage.repository | string | `""` | Agent repository; empty inherits image.repository. |
| agentImage.tag | string | `""` | Agent tag. With an explicit repository, empty uses Chart.appVersion; otherwise inherits image.tag. |
| env.extra | list | `[]` | Additional EnvVar entries. POD_NAMESPACE, OPERATOR_IMAGE, AGENT_IMAGE_PULL_SECRETS and SSL_CERT_FILE are reserved. |
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
| monitoring.podMonitor.enabled | bool | `false` | Scrape generated agents on health TCP/9080. Requires PodMonitor CRD and site-owned NetworkPolicy access for external scrapers. |
| monitoring.podMonitor.interval | string | `"30s"` | Agent scrape interval. |
| monitoring.podMonitor.labels | object | `{}` | Additional PodMonitor labels for your Prometheus selector. |
| monitoring.podMonitor.namespaceSelector | object | `{"any":true}` | Agent namespace selection. Set any: false with matchNames to restrict namespaces; any: false without names selects only the PodMonitor namespace. |
| monitoring.rules.apiKeyExpiryWarningSeconds | int | `604800` | API-key expiry warning threshold in seconds (7 days). For shorter key lifetimes, set below half-life to avoid warning before normal rotation. |
| monitoring.rules.authKeyExpiryWarningSeconds | int | `86400` | Egress/ingress auth-key expiry warning threshold in seconds (1 day). For shorter key lifetimes, set below half-life to avoid warning before normal rotation. |
| monitoring.rules.enabled | bool | `false` | Render a PrometheusRule. Requires Prometheus Operator CRDs. |
| monitoring.rules.groups | list | `[]` | Nonempty groups replace all bundled rules, without merging or template evaluation. |
| monitoring.serviceMonitor.enabled | bool | `false` | Requires Prometheus Operator CRDs. Disabled for a fresh Kubernetes installation. |
| monitoring.serviceMonitor.interval | string | `"30s"` | Scrape interval. |
| monitoring.serviceMonitor.labels | object | `{}` | Additional ServiceMonitor labels for your Prometheus selector. |
| namespace | string | `""` | Operator namespace; empty uses the Helm release namespace. Bootstrap and working keys live here. |
| networkPolicy.dnsPeers | list | `[{"namespaceSelector":{"matchLabels":{"kubernetes.io/metadata.name":"kube-system"}},"podSelector":{"matchLabels":{"k8s-app":"kube-dns"}}}]` | DNS NetworkPolicy peers; customize for NodeLocal DNS or a different resolver. |
| networkPolicy.enabled | bool | `false` | Enable operator isolation. Requires explicit kubeAPI and Headscale CIDRs; CNI Service-DNAT behavior must be checked locally. |
| networkPolicy.headscaleCIDRs | list | `[]` | Headscale API endpoint CIDRs (not hostnames). Required when enabled; update when DNS addresses change. |
| networkPolicy.headscalePorts | list | `[443,8080]` | Headscale REST API TCP ports. |
| networkPolicy.kubeAPICIDRs | list | `[]` | API endpoint and/or Service CIDRs appropriate for your CNI, e.g. [10.96.0.1/32]. Required when enabled. |
| networkPolicy.kubeAPIPorts | list | `[443,6443]` | Kubernetes API TCP ports. |
| networkPolicy.metricsPeers | list | `[]` | Peers permitted to scrape metrics. Empty denies metrics ingress when isolation is enabled. |
| podSecurityContext | object | `{"runAsGroup":65532,"runAsNonRoot":true,"runAsUser":65532,"seccompProfile":{"type":"RuntimeDefault"}}` | Pod security context; the scratch image requires a numeric non-root UID. |
| replicas | int | `1` | Operator replicas; more than one requires leaderElection.enabled. A PDB with minAvailable=1 is rendered for multiple replicas. |
| resources | object | `{"limits":{"memory":"128Mi"},"requests":{"cpu":"25m","memory":"64Mi"}}` | Operator resource requests and limits. |
| securityContext | object | `{"allowPrivilegeEscalation":false,"capabilities":{"drop":["ALL"]},"readOnlyRootFilesystem":true}` | Operator container hardening. Agents are configured separately by the controller. |
| topologySpreadConstraints | list | `[]` | Optional operator pod topology spread constraints. Supply a labelSelector matching app.kubernetes.io/name: tailnet-operator. |
