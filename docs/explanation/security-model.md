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
| `Tailnet` writer | Control endpoints, bootstrap Secret reference, policy inputs | Administrative. Do not delegate cluster-scoped `Tailnet` writes to tenants. A `policy.fragmentConfigMaps` entry or a `policy.spokes[]` entry is another cluster's grants — the GitOps review that lands the fragment or the spoke in the hub `Tailnet` is its gate, and the hub additionally refuses a fragment that steps outside its limits (owners, approvers, allowlist, tcp ports, reserved networks), so treat those ConfigMaps as trust-policy changes. |
| Hub → spoke API server | One kubeconfig Secret per `policy.spokes[]` entry, read by the hub every reconcile | The spoke mints it for a ServiceAccount that may read only the fragment ConfigMap (`policy.fragmentReader`); the hub holds a bearer token for another cluster, so protect that Secret like an API key. The token is sent only to an `https://` server; a kubeconfig that names a plain `http://` endpoint is reported `SpokeReachable=False/KubeconfigInvalid`. Status, events and metrics carry the HTTP status and our own words, never the kubeconfig or a server body. |
| Spoke fragment | What a spoke may claim in the tailnet-wide policy | A pulled fragment passes the same validation as a committed one, narrowed further by that spoke's `tagPatterns` and `routeAllowlist`; `approval: Manual` holds a changed fetch until an admin annotates the hub `Tailnet` with its hash, and until then only removals take effect. A compromised spoke can at most withdraw its own entries or add tags, grants and routes within its own pattern and allowlist — never touch the base, groups or other spokes. |
| `TailnetEgress` / `TailnetIngress` writer | Agent identity, tag, backends, `allowFrom` | Not a hostile-tenant boundary: custom tags and cross-namespace backends require trusted writers; `allowFrom` is an allowlist, not isolation. |
| `TailnetGrant` writer | Sources, target and ports of a policy grant; expiry | Administrative. A grant bypasses the `allowFrom` of an ingress, `ingressSourceAllowlist` and a spoke's allowlist, and it can target every ingress of the hub, every ingress that a merged spoke exports and every host inside a `TailnetSite`. Never delegate this cluster-scoped CR to tenants. The expiry follows the operator's clock. After it, new connections are refused and the agent closes the established connections to an ingress (measured: 0.7 to 2.5 s after the revocation). An established connection to a host inside a `TailnetSite` is not closed, because no agent is in that path ([Grants § Expiry](../how-to/grants.md#expiry)). |
| `TailnetGateway` writer | Persistent kernel identity, image pins, routes and retained resources | Administrative. Explicit activation creates a NET_ADMIN workload; never delegate this cluster-scoped CR to tenants. |
| Agent pod | Ephemeral tsnet identity, reusable preauth key, no Kubernetes client | Container compromise exposes the key and that identity's network access until the key expires. |
| Operator pod | Credentials, workloads, status, Headscale policy | Needs broad namespace access by design; a compromised operator is a cluster and tailnet incident. |
| Console pod | `get`, `list` and `watch` on Tailnets, TailnetIngresses, TailnetSites and TailnetGrants; the OIDC client secret; an in-memory session key; a projected token for the console API. With `console.accessManagement`: `create`, `update` and `patch` on TailnetGrants (no `delete`), `get`, `list`, `watch` and `create` on TailnetAccessRequests and `update` and `patch` on their status, `get`, `update` and `patch` on the one ConfigMap `<name>-console-audit`, and the audit volume | A compromised console discloses the cluster's tailnet topology, the client secret, every Headscale user (name, display name, e-mail, provider identifier) and the live policy. Read-only, it cannot change Kubernetes or Headscale. With access management it can grant any person or policy group access to any target of a policy-owning Tailnet, write any approval into a request, and rewrite the audit log and its head; the operator's grant checks still apply. The four-eyes rule is enforced by the console, not by the API server: whoever writes TailnetGrants or request status directly bypasses it. It never reads Secrets or other ConfigMaps. |
| Console user | Sign-in at the console's identity provider; role from the `groups` claim (`adminGroup`, `userGroup`) | Both roles see the same overview and "My access". With access management, only admins reach the grant and audit pages (users get 403); they see recipients by name. A user requests access only for themselves and sees only their own requests (another's answers 404); nobody decides their own request, and with `fourEyes` an admin's own grant needs another admin and a user's request two. Every change and every decision is recorded with issuer, subject and name before it is made, in a hash-chained log whose head the ConfigMap and the pod log keep; the pod log never names a person. A request's status names nobody: the approvals are counted from that log, and only admins see who decided. Forms are POST only and checked by `http.CrossOriginProtection`; the server checks every field again. User references in `allowFrom` appear only as a count; "My access" shows only the person's own rules and masks another person's reference as "a user's devices". The map shows tags, ingress and site names, ports and node state, never user references, node names, rule sources or owners. The only script is the console's own `/static/console.js`; the Content Security Policy allows scripts and fetches from the console's origin only and no inline code. The session cookie is sealed with AES-256-GCM, holds no tokens and expires after one hour; `allowFrom` of the console's ingress limits who reaches the sign-in at all. |
| Operator console API | Port 8082 on every operator replica, only with `console.enabled`; `create` on `tokenreviews` | Reads users, tagged nodes and the live policy with the working key, nothing else, and never writes. A caller needs a token with the audience `tailnet-operator` for exactly the console's ServiceAccount; an API-server token or another ServiceAccount is refused. The API speaks plain HTTP: token (10 minutes, useless against the API server) and user list cross the pod network in clear. With `networkPolicy.enabled` the chart admits only the console on that port, for both providers; metrics and health stay open under `cilium`. |
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
- Agent preauth keys are reusable until expiry. A key is expired on the server once it is replaced
  (half-life rotation, changed tag or server) or its CR is deleted; the Secret records the key's
  Headscale ID for that, and a Headscale that is unreachable never blocks the delete — the key then
  ages out at its own expiry. Protect Secret read access and restrict CR writers.
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
which userspace tsnet needs for control, DERP and UDP. An egress with `spec.expose` additionally
admits the declared LAN prefixes (`ipBlock`) to its proxy ports only; the prefixes are bounded at
admission (no default route, at most `/16` IPv4 or `/48` IPv6), must lie inside the Tailnet's
`exposeSourceAllowlist` (the admin's veto; empty denies) and the LoadBalancer is rendered with
`externalTrafficPolicy: Local` so the filter sees the client address. The filter is only as good
as address preservation by the LB implementation — the operator cannot verify it
([Bridge § security](../how-to/legacy-bridge.md#security-what-the-bridge-is-and-is-not)). On the
tailnet the bridge acts as its own tag; LAN hosts are never individually identifiable there. The
mirror on the ingress side, `bridgeNames`, lets a tenant obtain a certificate for and route a name
outside the tailnet zone; `Tailnet.spec.bridgeNameAllowlist` (empty denies) bounds this to zones the
admin has chosen, a bridge name must be a proper subdomain of one of them, and the tailnet name and
alias zones are excluded so that no tenant can impersonate another CR's name through it. Do not expose port 9080 or the operator's
8080 outside the cluster. Leader election serialises reconciliation; it is not a fence against
in-flight writes from a paused replica.

## Supply chain

Every release publishes one multi-arch image (`linux/amd64`, `linux/arm64`) and the Helm chart,
each signed with the CI broker's fixed Cosign key, together with an SPDX SBOM and a SLSA v1
provenance attestation per platform. Images are scanned for HIGH/CRITICAL findings before a
versioned release is accepted; `govulncheck` runs on every build.

The public key is [`deploy/cosign.pub`](https://app.radicle.xyz/nodes/seed.this-is-fine.io/rad:z46fGxuhyvDV57psA8s6Q6PdHJrsX/tree/deploy/cosign.pub). Signatures and, from v0.21.1 on,
the SBOM and provenance attestations are recorded in the public Rekor transparency log, so plain
`cosign verify` checks the log entry too. Verify the digest you are about to deploy, not a tag:

```sh
cosign verify --key deploy/cosign.pub docker.io/ff0x/tailnet-operator@sha256:<digest>
cosign verify-attestation --key deploy/cosign.pub --type spdxjson \
  docker.io/ff0x/tailnet-operator@sha256:<digest>
cosign verify --key deploy/cosign.pub oci.tsunaro.io/charts/tailnet-operator:<version>
```

The image (with its SBOM and provenance) and the Helm chart live on **two different hosts** — the
image on the container registry, the chart under `oci.tsunaro.io/charts` — so a verify command
names the right host for each. The Radicle release record binds both digests together regardless of
where each is served (see below).

Attestations of releases before v0.21.1 were not uploaded; verify those with `--insecure-ignore-tlog`.

The production image is built from `scratch` and contains only the two static binaries.

### Radicle release record

Each `vX.Y.Z` tag also has a Radicle release (collaborative object `dev.radicle.artifact`), created
and signed by a repository delegate and listed under *Releases* in Radicle Explorer. It registers
`deploy/cosign.pub` as an artifact (BLAKE3 CID) and carries the signed image and chart digests as
metadata (`image`, `chart`, `verify`), so the key, the release commit and the published digests are
bound together independently of the registry:

```sh
rad clone rad:z46fGxuhyvDV57psA8s6Q6PdHJrsX && cd tailnet-operator
rad-artifact show v0.25.0 --pretty          # creator must be a delegate; shows image/chart digests
test "$(rad-artifact cid deploy/cosign.pub)" = "<cid from show>"
```

Then run the `verify` command from the metadata against the digest you deploy.
