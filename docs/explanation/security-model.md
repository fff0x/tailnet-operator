---
title: "Security model"
weight: 20
description: "Private reporting, trust model, credentials, workloads/RBAC/network, and supply-chain verification (cosign, Radicle release record)."
---

## Private reporting

Report suspected vulnerabilities to **ff0x@this-is-fine.io**. Send a minimal reproduction, the
affected version, the impact and sanitized logs. Do not put credentials, exploit details or private
cluster configuration in public issues, and do not email live API keys, preauth keys, kubeconfigs,
private keys or complete Secret objects — ask for an encrypted channel if sensitive evidence is needed.

The latest minor release line and the preceding one receive security fixes; use the latest patch of
your line. Disclosure is coordinated with the reporter, normally within 90 days. Remediation targets
are 7 days for critical and 30 days for high-severity findings (best effort, not an SLA). Advisories
are published in the release notes and as Radicle issues labelled `security`.

## Trust model

| Actor or boundary | Controls | Limit |
| --- | --- | --- |
| Kubernetes administrator | Operator installation, RBAC, CRDs, bootstrap Secret, base policy | Can read every credential and replace workloads; the operator cannot defend against its own administrator. |
| Headscale administrator | Node identities, grants, route approvals, API keys | API keys are bearer credentials with full control-server access, not per-controller capabilities. |
| `Tailnet` writer | Control endpoints, bootstrap Secret reference, policy inputs | Administrative. Do not delegate cluster-scoped `Tailnet` writes to tenants. |
| `TailnetEgress` / `TailnetIngress` writer | Agent identity, tag, backends, `allowFrom` | Not a hostile-tenant boundary: custom tags and cross-namespace backends require trusted writers; `allowFrom` is an allowlist, not isolation. |
| `TailnetGateway` writer | Persistent kernel identity, image pins, routes and retained resources | Administrative. Explicit activation creates a NET_ADMIN workload; never delegate this cluster-scoped CR to tenants. |
| Agent pod | Ephemeral tsnet identity, reusable preauth key, no Kubernetes client | Container compromise exposes the key and that identity's network access until the key expires. |
| Operator pod | Credentials, workloads, status, Headscale policy | Needs broad namespace access by design; a compromised operator is a cluster and tailnet incident. |
| Tailnet peer | Access per Headscale policy and per-CR identity | The operator authenticates nodes, not application users. |
| HTTP backend | In `mode: http` the agent terminates frontend TLS; `backend.tls` enables verified HTTPS upstream | Without `backend.tls`, the cluster hop is plain HTTP. With it, frontend and backend TLS remain separate sessions. |
| Operator → Headscale API | Bearer working key on every call; an `https://` `apiUrl` with the issuer CA in `headscale.caConfigMapRef` verifies the server | Over `http://` the key, minted pre-auth keys and the policy cross the cluster network in clear; only CNI pod-to-pod encryption covers that hop |
| Registry | Release images and charts are signed with the CI's fixed Cosign key | A valid signature says who built it, not that it is safe to run; verify the immutable digest you deploy. |

Backend HTTPS uses only the selected namespace-local CA bundle, with chain, hostname and validity verification.
There is no system-root fallback or insecure mode. Protect writes to referenced CA ConfigMaps as trust-policy changes.
After a projected CA change, new requests use the new transport and old idle connections close.
Established streams continue; deleting a CA is not immediate revocation of existing connections.
Service references can still resolve to administrator-controlled endpoints or ExternalName destinations; they are not an SSRF isolation boundary.

## Credentials

- The bootstrap API key stays in the operator-namespace Secret you create; the operator only reads
  it and mints its own working key, rotated at half-life after the replacement has been verified.
- Agent preauth keys are reusable until expiry. Protect Secret read access and restrict CR writers.
- Image-pull Secrets are referenced by name in the agent's namespace; credentials are never copied.
- Status, Events, metrics and logs never contain whole credentials; Headscale error bodies are
  withheld because they can echo them. Tests cover known fixture credentials and malformed inputs.
- If a credential leaks, revoke or rotate it at the issuer. Deleting a log line does not revoke a token.

## Workloads, RBAC and network

Operator and agent pods run as non-root numeric users with `RuntimeDefault` seccomp, no privilege
escalation, all capabilities dropped and a read-only root filesystem. Agents keep a writable `/state`
and do not mount a ServiceAccount token.

The kernel-mode `TailnetGateway` is different: Tailscale uses UID 0, only NET_ADMIN,
and `/dev/net/tun`; CoreDNS uses UID 65532 and only NET_BIND_SERVICE. Its projected
API token can get/update/patch only its pre-created State Secret. It cannot create
state or list Secrets. The operator reads private state keys in memory to verify
public identity. Auth/completion receipt ConfigMaps are privileged trust anchors:
protect their create/update/delete rights as strictly as Secrets. Replacing all
retained evidence can forge provenance; immutability alone does not prevent this.
The operator may `delete` the Gateway's StatefulSet, PDB, ServiceAccount, Role and
RoleBinding and `patch` `tailnetgateways` for its finalizer. Deletion happens only
with `deletionPolicy: Delete`, only for objects whose UID the receipt recorded or
that carry the operator's gateway label, and every call is UID-preconditioned; the
CR patch writes metadata only. The Secret/ConfigMap delete rights already existed.

The operator holds cluster-wide permissions on the workloads and Secrets it manages for tenant
agents, plus cert-manager `Certificate` get/create/patch/delete for `issuerRef` ingresses. Kubernetes
RBAC cannot limit `create` by `resourceNames`, so the ClusterRole/Role split in the chart is an
audit aid, not reduced privilege. The exact default grants are listed in the
[RBAC reference](../reference/rbac.md); `task rbac-check` fails when the chart drifts from it.

The operator NetworkPolicy is opt-in because API-server and Headscale CIDRs are site-specific.
Generated agent NetworkPolicies restrict inbound traffic to `consumerNamespaces` and the operator
namespace (TCP 9080 for `/status`, `/targets`, `/metrics`); they do not constrain outbound traffic,
which userspace tsnet needs for control, DERP and UDP. Do not expose port 9080 or the operator's
8080 outside the cluster. Leader election serialises reconciliation; it is not a fence against
in-flight writes from a paused replica.

## Supply chain

Every release publishes one multi-arch image (`linux/amd64`, `linux/arm64`) and the Helm chart,
each signed with the CI broker's fixed Cosign key, together with an SPDX SBOM and a SLSA v1
provenance attestation per platform. Images are scanned for HIGH/CRITICAL findings before a
versioned release is accepted; `govulncheck` runs on every build.

The public key is [`deploy/cosign.pub`](https://app.radicle.xyz/nodes/seed.this-is-fine.io/rad:z46fGxuhyvDV57psA8s6Q6PdHJrsX/tree/deploy/cosign.pub). Signatures are not uploaded to a
transparency log, so verification passes `--insecure-ignore-tlog`. Verify the digest you are about
to deploy, not a tag:

```sh
cosign verify --key deploy/cosign.pub --insecure-ignore-tlog docker.io/ff0x/tailnet-operator@sha256:<digest>
cosign verify-attestation --key deploy/cosign.pub --insecure-ignore-tlog --type spdxjson \
  docker.io/ff0x/tailnet-operator@sha256:<digest>
cosign verify --key deploy/cosign.pub --insecure-ignore-tlog \
  oci.this-is-fine.io/charts/tailnet-operator:<version>
```

The production image is built from `scratch` and contains only the two static binaries.

### Radicle release record

Each `vX.Y.Z` tag also has a Radicle release (collaborative object `dev.radicle.artifact`), created
and signed by a repository delegate and listed under *Releases* in Radicle Explorer. It registers
`deploy/cosign.pub` as an artifact (BLAKE3 CID) and carries the signed image and chart digests as
metadata (`image`, `chart`, `verify`), so the key, the release commit and the published digests are
bound together independently of the registry:

```sh
rad clone rad:z46fGxuhyvDV57psA8s6Q6PdHJrsX && cd tailnet-operator
rad-artifact show v0.19.0 --pretty          # creator must be a delegate; shows image/chart digests
test "$(rad-artifact cid deploy/cosign.pub)" = "<cid from show>"
```

Then run the `verify` command from the metadata against the digest you deploy.
