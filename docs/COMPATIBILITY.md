# Compatibility

## Supported platforms

| Component | Supported | Notes |
| --- | --- | --- |
| Kubernetes | ≥ 1.31 | CRD admission uses the CEL IP library; tested against 1.31 and 1.36 |
| Headscale | 0.29.x | REST API for nodes, keys and policy; `POST /api/v1/policy/check` is required for operator-owned policy |
| Headscale 0.28.x | detected, not supported | Preflight reports `HeadscaleCompatible=False/Incompatible`; L4 egress/ingress with a hand-maintained policy still works |
| Headscale policy mode | `database` for operator-owned policy; `file` for read-only operation | In `file` mode the operator renders but never writes (`PolicyApplied=False/PolicyModeFile`) |
| cert-manager | any release serving `cert-manager.io/v1` | Only needed for `TailnetIngress.spec.tls.issuerRef`; `Issuer` and `ClusterIssuer` |
| CNI | NetworkPolicy support | `consumerNamespaces` isolation is a NetworkPolicy; ICMP handling is CNI-specific |
| Helm | 3 or 4 | Chart has no CRD dependencies by default; monitoring objects are opt-in |
| Architectures | `linux/amd64`, `linux/arm64` | One multi-arch image carries operator and agent |

## Preflight matrix

The Tailnet controller derives these conditions from the API response shape, not from a version string:

| Headscale | Policy mode | `HeadscaleCompatible` | `PolicyMode` |
| --- | --- | --- | --- |
| 0.29.x | database | `True/Compatible` | `True/Database` |
| 0.29.x | file | `False/Incompatible` | `False/File` |
| 0.28.x | database | `False/Incompatible` (no `policy/check`) | `True/Database` |
| 0.28.x | file | `False/Incompatible` | `False/File` |

`SplitDNS` is always `Unknown/CannotVerify`: Headscale has no DNS API, so the operator can only print
the split zone you have to configure. See [preflight](INSTALL.md#25-preflight) for the condition semantics.

## Test coverage

| Suite | Command | What it exercises |
| --- | --- | --- |
| Unit and chart contracts | `task test`, `task chart` | Policy rendering, key rotation, port assignment, route diagnosis, Helm rendering, alert rules |
| Admission | `task test-validation` | Every CRD validation rule against a disposable API server (envtest), including the negative fixtures in `deploy/examples/invalid/` |
| Headscale integration | `task e2e` | The production manager against envtest plus real Headscale 0.28.0 and 0.29.3 binaries: preflight, policy lifecycle, retry/backoff, key rotation, approval replay, DNS hosts rendering, credential redaction |
| Cluster | `task e2e-kind` | Rootless kind: Helm installation, two-replica leader failover, agent-to-peer HTTPS, Headscale over HTTPS, HTTP ingress with cert-manager issuance and renewal |

All suites run without a kube-context and never touch an existing cluster; `task e2e` downloads
checksum-pinned Headscale and envtest assets into `~/.cache/tailnet-operator-e2e`.
See [CONTRIBUTING](../CONTRIBUTING.md) for prerequisites.
