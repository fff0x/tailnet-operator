# Changelog

Notable changes are recorded here using [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).
Versions before v0.4.0 are summarized in [INSTALL](docs/INSTALL.md#8-upgrade).

## [Unreleased]

### v0.4.0 release preparation

This version is not yet published. Local tests do not establish registry availability,
signed artifacts, broker-CI acceptance or production migration safety.

### Added

- Helm chart with generated standalone manifests, CRDs, configurable agent images and namespace-local image-pull Secret references.
- Operator leader election, optional multi-replica disruption budget and topology spread settings.
- Optional ServiceMonitor, PodMonitor, Prometheus alerts and Grafana Operator or ConfigMap dashboard provisioning.
- Agent-side HTTPS termination for `TailnetIngress`: one `mode: http` expose on port 443,
  namespace-local TLS Secret or cert-manager issuer, and a Tailnet-wide default issuer.
  The listener binds SNI and HTTP Host to the ingress DNS name; upstream traffic is plain HTTP.
  Certificates reload without an agent restart. `TLSReady` reports local certificate and listener readiness,
  not client trust or remote reachability.
- Isolated API-server/Headscale tests, local kind installation/failover tests and an isolated HTTP ingress/renewal fixture.
- Internal per-child API-group metadata-transfer primitive with ownership, expiry and role translation,
  optimistic concurrency checks and isolated API-server regression tests. This is not a live migration command
  or automatic runtime adoption; full-fleet migration acceptance remains required.
- Native CI test gates and post-publication image verification, vulnerability scanning,
  SPDX SBOM and provenance attestations. These require the upgraded broker and audit tools;
  their presence in source is not evidence of a successful published release.
- Security policy, reviewed RBAC reference and dependency-update configuration.

### Changed

- Product name: **Tsunaro**. Go module: `tsunaro.io/tailnet-operator`.
  Chart name, image repository and binary names remain unchanged.
- **Breaking:** Kubernetes API group changes from `tailnet.this-is-fine.io` to `tsunaro.io`.
  Metadata keys and the leader-election Lease also change. There is no CR conversion or coordinated child-adoption migration.
  CRs must be recreated under the new group through a reviewed, stop-first migration.
  Do not delete old CRDs or permit Flux pruning before accounting for every dependent resource.
  See the [migration warning](docs/INSTALL.md#80-v040-api-group-migration).
- Agent containers use a read-only root filesystem and do not automatically mount ServiceAccount tokens.
- Headscale error handling and tests redact credentials from logs, Events and status.

### Release acceptance still required

- Rehearse the API-group/ownership migration before any production upgrade.
- Verify image/chart publication, signatures, attestations and the public image mirror.
- Complete the remaining data-plane, nightly, production monitoring and soak gates listed in
  [COMPATIBILITY](docs/COMPATIBILITY.md#remaining-acceptance-gates).
- Migrate applications and verify their HTTP access before removing a shared tailnet gateway.
