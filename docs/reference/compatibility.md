---
title: "Compatibility"
weight: 40
description: "Supported Kubernetes, Headscale, cert-manager, CNI and Helm versions; per-version compatibility notes; preflight matrix; test coverage."
---

Versions and verified platforms live here; the functional boundaries (TCP-only agents, SNI/Host
routing, one policy writer, IPv4 gateway) are collected in [Limitations](limitations.md).

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
| Architectures | `linux/amd64`, `linux/arm64` | One multi-arch image carries operator, agent and gateway; the pinned `tailscale`/`coredns` gateway digests are multi-arch indexes |

## HTTP extension compatibility (v0.5.0)

Existing L4 and HTTP CRs retain their behavior when the new fields are absent.
Backend TLS and HTTP timeouts require v0.5.0 CRDs, controller and agent images.
Check `Tailnet.spec.proxy.image` and `TailnetIngress.spec.image` overrides during upgrade.

| Configuration | Agent envelope | Pod protocol annotation |
| --- | --- | --- |
| Existing L4 | Legacy array | None |
| Existing HTTP without extensions | Version 1 | `http-v1` |
| Any backend TLS or timeout settings | Version 2 | `http-v2` |
| Multiple HTTP exposes, a `dnsLabel`, or an `alias` | Version 3 | `http-v3` |

## Virtual hosts and aliases (v0.6.0)

Several `mode: http` exposes per ingress, per-expose `dnsLabel`, and the optional short `alias`
require v0.6.0 CRDs, controller and agent images. The version-3 agent envelope adds a
`certificateDNSNames` policy and per-target `dnsAliases`; an old agent rejects it outright rather
than serving a subset. DNS names (including egress aliases) are arbitrated oldest-owner-wins across
one Tailnet; the losing CR reports `DNSNameConflict` and is withdrawn — replacing the previous purely
lexical hosts-file de-duplication. `ingressAliasTemplate` must share the zone of `ingressNameTemplate`.

Old agents reject the new envelope rather than silently ignoring security settings.
The `Recreate` strategy and changed `tsunaro.io/agent-config-protocol` annotation retire the old process on a protocol transition.
HTTP ingresses also carry a static `tsunaro.io/agent-http-config` digest of expose configuration and TLS/Tailnet references.
A separate marker tracks the resolved TLS source, including a Tailnet-default issuer.
On upgrade to v0.6.0, **every existing HTTP ingress retires its agent once**, including single-expose v1 and v2 ingresses, because this source marker is absent.
A missing or changed marker first scales the owned Deployment to zero and waits for its Pods to disappear, before checking Headscale dependencies.
This also protects a timeout-only v2 ingress when backend TLS is added. Missing dependencies cannot restore the plaintext predecessor.
Recovery installs the new configuration before restoring replicas. All exposes on that ingress are interrupted during retirement.
Failed Kubernetes writes or stuck terminating Pods delay the transition; the operator does not force-delete Pods.

CA content changes do not restart the Pod. New requests use the projected bundle; old idle connections close and established streams finish.
Kubernetes projection delay and existing streams mean CA removal is not immediate connection revocation.

Before downgrading below v0.5.0, move extended ingresses to a verified legacy gateway path.
Do not remove backend TLS to make old agents accept the configuration.
The two timeout fields do not reproduce Envoy connection-idle or stream-idle policies; review those separately before migrating applications.

## Gateway API scope

The `TailnetGateway` CRD is fresh-only and defaults to `suspend: true`. Explicit `false`
activates fresh-only IPv4 creation; existing gateways are never adopted or replaced.
The operator/chart require this fourth CRD, gateway read/status authorization and
operator-namespace get/create/delete for StatefulSets, PDBs, ServiceAccounts, Roles and
RoleBindings plus `patch` on `tailnetgateways` for the teardown finalizer. StatefulSets
additionally get `update`, used only to follow `image`/`dns.image` and the planned routes in
the Pod template (`OnDelete`: no Pod restart; `WorkloadCurrent` reports staleness); the
LoadBalancer Service gets `update` for `service.poolLabels`. Suspension freezes
reconciliation, not the running Pod. The completion receipt is format 3 and pins identity
fields only: `deletionPolicy`, `suspend`, static records, routes, pool labels and unrelated
Tailnet fields no longer block a running gateway, and a changed identity field reports
`IdentityChanged`. Gateways created by 0.9.0 or earlier carry a format-1 or format-2 receipt; delete them with
`deletionPolicy: Delete` and recreate.
CR deletion retains resources unless `deletionPolicy: Delete` explicitly consents to
the UID-preconditioned teardown. Partial creation remains blocked without automatic
remint or rollback. The derived `-coredns` ConfigMap is reconciled live from the
Tailnet hosts source via a CAS writer; the `DNSReady` condition reports the writer
verdict. Gateways rendered by versions before this slice carry no DNS CAS
annotations and permanently report `DNSReady=False/DNSUpdateBlocked`; delete and
recreate with `deletionPolicy: Delete` to migrate. Do not treat CR acceptance or observed generation as runtime,
DNS or identity evidence.
See the [gateway reference](gateway.md).

The legacy `tailnet.this-is-fine.io` → `tsunaro.io` ownership-inventory helper supports
exactly the original three kinds. Discovery of `TailnetGateway` deliberately blocks
that helper, even with no gateway instances. Complete the legacy handover using the
reviewed three-kind API set **before** installing the gateway CRD. Do not
invent a legacy gateway kind, omit discovered resources, or delete a CRD to bypass
this guard. A broader migration contract requires separate review.

## Preflight matrix

The Tailnet controller derives these conditions from the API response shape, not from a version string:

| Headscale | Policy mode | `HeadscaleCompatible` | `PolicyMode` |
| --- | --- | --- | --- |
| 0.29.x | database | `True/Compatible` | `True/Database` |
| 0.29.x | file | `False/Incompatible` | `False/File` |
| 0.28.x | database | `False/Incompatible` (no `policy/check`) | `True/Database` |
| 0.28.x | file | `False/Incompatible` | `False/File` |

`SplitDNS` is always `Unknown/CannotVerify`: Headscale has no DNS API, so the operator can only print
the split zone you have to configure. See [preflight](../how-to/install-headscale.md#preflight) for the condition semantics.

## Test coverage

| Suite | Command | What it exercises |
| --- | --- | --- |
| Unit and chart contracts | `task test`, `task chart` | Policy rendering, key rotation, port assignment, route diagnosis, Helm rendering, alert rules |
| Admission | `task test-validation` | Every CRD validation rule against a disposable API server (envtest), including the negative fixtures in `deploy/examples/invalid/` |
| Headscale integration | `task e2e` | The production manager against envtest plus real Headscale 0.28.0 and 0.29.3 binaries: preflight, policy lifecycle, retry/backoff, key rotation, approval replay, DNS hosts rendering, credential redaction |
| Cluster | `task e2e-kind` | Rootless kind: Helm installation, two-replica leader failover, agent-to-peer HTTPS, Headscale over HTTPS, HTTP ingress with cert-manager issuance and renewal |

`task e2e-full` chains all of the above, in the order CI runs the first three, and then every kind
selection. All suites run without a kube-context and never touch an existing cluster; `task e2e` downloads
checksum-pinned Headscale and envtest assets into `~/.cache/tailnet-operator-e2e`.
See [CONTRIBUTING](https://app.radicle.xyz/nodes/seed.this-is-fine.io/rad:z46fGxuhyvDV57psA8s6Q6PdHJrsX/tree/CONTRIBUTING.md) for prerequisites.
