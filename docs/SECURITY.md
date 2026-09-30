# Security policy

This document describes the current source and its limits. Unreleased hardening and test work is
not evidence that a published image or an installed cluster has those changes.
See [installation and artifact verification](INSTALL.md) and the
[compatibility evidence](COMPATIBILITY.md) before deployment.

## Private reporting

Report suspected vulnerabilities to **ff0x@this-is-fine.io**.
Do not put credentials, exploit details or private cluster configuration in public issues.
Send a minimal reproduction, affected versions, impact and sanitized logs.
Do not email live API keys, preauth keys, kubeconfigs, private keys or complete Secret objects.
Ask for an agreed encrypted transfer method if sensitive evidence is necessary.

Reports for the latest minor release line and the preceding minor line are in scope.
Use the latest patch in the relevant line. Older lines do not receive routine security maintenance.
Headscale, Kubernetes, cert-manager, CNI and host vulnerabilities also require their respective upstream fixes.

The maintainer coordinates disclosure with the reporter, normally within 90 days of the initial report.
A shorter or longer period can be agreed for active exploitation, incomplete fixes or upstream dependencies.
The remediation targets are **7 days for critical findings** and **30 days for high-severity findings**.
These are best-effort targets, not an SLA or a guaranteed delivery date.
Available mitigation, upstream fixes and verification work affect the release schedule.
Public advisories belong in release notes and Radicle issues labelled `security` after coordinated disclosure.
A GitHub advisory mirror is not currently promised.

## Trust model

| Actor or boundary | Assets and controls | Explicit limit |
| --- | --- | --- |
| Kubernetes administrator | Controls operator installation, RBAC, CRDs, bootstrap Secrets and base policy | A cluster administrator can read credentials and replace workloads. The operator cannot defend against that administrator. |
| Headscale administrator | Controls node identity, grants, route approvals, API credentials and the control server | API credentials are powerful bearer credentials, not a least-privilege per-controller capability. A compromised server can change the tailnet. |
| Tailnet CR writer | Selects control endpoints, bootstrap Secret references and policy inputs | Treat write access as administrative. Do not delegate cluster-scoped Tailnet writes to untrusted tenants. |
| Egress/Ingress CR writer | Requests agent identities, tags, backends and access rules | These CRs are not a complete hostile-tenant boundary. Custom tags and cross-namespace ingress backends require trusted writers. An `allowFrom` allowlist alone is not sufficient tenant isolation. |
| Agent pod | Uses an ephemeral tsnet identity and a reusable preauth key; no Kubernetes client is required | Container compromise exposes the key and that identity's allowed network access. Ephemeral identity does not revoke a reusable key. |
| Operator pod | Reads credentials, writes workloads and status, and manages Headscale policy | Broad namespace access is required by the current controller design. A compromised operator is a cluster and tailnet security incident. |
| Tailnet peer | Access is controlled by Headscale policy and the generated per-CR identity | The operator does not authenticate application users. Applications still need their own authorization where appropriate. |
| HTTP backend | Agent HTTP mode is being prepared to terminate TLS on the tsnet listener | Backend transport is plain HTTP in the first design. It is not end-to-end TLS, and full HTTP-ingress acceptance is still pending. |
| Publisher and registry | Versioned artifacts are signed with the CI broker's fixed Cosign key | A trusted signing key does not establish runtime safety. Mirror availability, digest identity and signatures require independent verification. |

## Credentials and diagnostic output

- Bootstrap API keys stay in operator-namespace Secrets. The operator mints its own working key.
- Key rotation verifies the replacement before expiring the prior key. Bootstrap Secret data is not rewritten.
- Agent preauth keys are reusable until expiry. Protect Secret read access and restrict CR writers.
- Registry pull-secret names reference Secrets already present in the target namespace. Credentials are not replicated.
- Secret data is intentionally confidential; metadata, status, Events and logs must not copy whole credentials.
- Client failures expose bounded operation/status diagnostics, not upstream bodies, URLs or codec input literals.
  Unwrapped Go error causes are inspection-only and must not be logged.
- Redaction tests cover known fixture credentials and adversarial paths. They are not proof against every possible disclosure.

If a credential is exposed, revoke or rotate it at its issuer and inspect access to the affected identity.
Removing a log line or repairing an annotation does not revoke an already disclosed bearer token.
Preserve sanitized audit evidence; do not spread the credential through incident reports.

## Workloads, RBAC and network policy

Operator and agent specifications use non-root numeric identities, `RuntimeDefault` seccomp,
no privilege escalation, dropped capabilities and read-only root filesystems.
Agents retain writable `/state` and disable service-account token automounting.
The operator needs a Kubernetes API token. Image-pull-secret inheritance is independent of token automounting.
Live pod and admission-policy verification is a separate gate from object-rendering tests.

The operator's current cluster-wide permissions include workload and Secret access for tenant agents.
Kubernetes RBAC cannot restrict `create` with `resourceNames`; the authorization request does not include the new object's name.
The chart separates CR and workload ClusterRoles while keeping egress CR and Service permissions in the operator namespace.
Working Secret permissions also appear in the namespaced Role, but the workload ClusterRole already grants broader Secret access.
Do not interpret this split as reduced effective privilege or tenant isolation.
Run `task rbac-check` to compare the default rendering with the [permission reference](reference/rbac.md).
Review an intended permission change before `task rbac-gen` updates that reference.
Audit installed bindings and CR write grants separately before enabling tenant access.

Operator NetworkPolicy is opt-in because Kubernetes API and Headscale endpoint CIDRs are site-specific.
It is not safe to invent permissive CIDRs merely to enable a default-deny label.
Generated agent policies restrict inbound access; they do not establish a complete outbound allowlist.
Userspace tsnet needs control/DERP connectivity and outbound UDP. CNI Service-DNAT and DNS behavior require local verification.
Agent status and metrics share TCP 9080. A scraper outside the operator namespace needs an explicit site-owned allowance.
Do not expose `/status`, `/targets` or `/metrics` publicly.

Leader election limits normal concurrent reconciliation. It is **not external-write fencing** against pauses,
network partitions or in-flight requests. Do not overlap electing and non-electing operators during migration.

## Build and verification gates

The prepared CI test container runs `govulncheck` using a pinned scanner and the current public vulnerability database.
Its default failure criterion is reachable vulnerable symbols. Package-only and module-only findings still need review.
A successful scan is not proof that an image has no vulnerabilities or that all dynamic paths were analyzed.
Tests run in a fresh working container before publication, without signing credentials or host mounts.

Image signing is distinct from SBOM generation, image scanning and provenance attestations.
The prepared post-publication gate requires broker capabilities `mixed-helm-v1` and `image-result-v1`.
Tool requirements are Syft 1.52.0, Trivy 0.74.0 and Cosign 2.5.0.
Set `CI_BUILDER_IMAGE=<repository>@sha256:<digest>`.
Configure that identity to match the deployed broker; the gate validates its syntax, not the running container's identity.
Preflight checks tools and local signing-key configuration before the test build or publication.
No signing credentials enter the TEST container.
Automatic proxy forwarding is disabled during both image build and working-container creation.
The scratch production image does not include the Debian test toolchain or vulnerability scanner.

`hack/audit-image.sh --result <private-publisher-report>` verifies the signed index and requires exactly
linux/amd64 and linux/arm64 children with matching image configurations. It scans each immutable child through the registry.
It checks SPDX structure and Trivy coverage of both root Go executables.
Versioned stdlib/dependency coverage remains required even when the source-built main module has no version.
Scanner configuration, ignore files and caches are private; database updates remain enabled.
Telemetry and version-update checks are disabled. Scans target HIGH and CRITICAL findings, not every severity.
Findings warn for main builds and reject versioned releases. Tool, parsing and verification failures always fail.
Only after both platforms satisfy those checks does the gate attest and verify each SPDX predicate and the index provenance.

The hand-built SLSA-v1 predicate records the publisher's source RID/commit, configured builder digest
as an `oci://` URI, tool versions and bounded scan counts.
Source attribution trusts the publisher report plus a HEAD comparison; it is not an independent reconstruction of the build. No timestamps, invocation ID, SLSA level or reproducibility
claim are invented. Fixed-key attestation verification does not claim public Rekor transparency-log evidence.
Review the exact subject and predicate, not merely a successful verification exit code.

The audit runs **after** image/chart publication. Failure rejects acceptance but cannot undo published artifacts;
a late failure can leave some attestations. Private temporary reports are deleted on exit. Partial-publication
recovery needs independent artifact inspection and a reviewed procedure, not an automatic rerun of an immutable tag.
These gates remain source-prepared. Local mocks, filesystem scans and predicate-serialization checks do not establish
registry/attestation acceptance, a successful broker release build or evidence for existing releases.

Verify the exact immutable image/chart digest with the independently trusted CI broker public key before deployment.
Do not treat a mutable tag, CI badge, main-branch build or Docker Hub mirror name as signature evidence.
