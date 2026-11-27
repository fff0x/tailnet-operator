---
title: "Ingress: publish a web app over HTTPS"
weight: 55
description: "Terminate TLS on the agent with a Secret or cert-manager certificate (virtual hosts, aliases, verified backend HTTPS, timeouts), or keep TLS at a shared gateway."
---

*The shop frontend should be `https://shop-shop-dev.prod-1.tailnet.example.internal` for tailnet users.*

Two shapes: let the **agent terminate TLS** (one CR, a certificate, no gateway) or keep TLS at a
**shared gateway** and use the ingress only for the per-app tailnet identity.

## Overview

A `TailnetIngress` is a plain-TCP node on the tailnet. For TCP services nothing else is needed:

```yaml
apiVersion: tsunaro.io/v1alpha1
kind: TailnetIngress
metadata:
  name: shop
  namespace: shop-dev
spec:
  tailnetRef: { name: corp }
  allowFrom: [group:shop]           # used when the operator owns the policy (see Operator-owned policy)
  exposes:
    - { name: postgres, port: 5432, backend: { service: shop-db-rw, port: 5432 } }
```

Peers dial `ingress-shop:5432` (MagicDNS) or `shop-shop-dev.prod-1.tailnet.example.internal:5432`
([DNS with CoreDNS](dns-coredns.md)).

**HTTPS** has two shapes. With `mode: http` the agent terminates TLS itself using a `kubernetes.io/tls`
Secret or a cert-manager issuer. It forwards HTTP, or verified HTTPS with `backend.tls`, to one backend without a shared gateway
([Terminate TLS on the agent](#terminate-tls-on-the-agent)). Or TLS keeps terminating at a shared
gateway and the ingress adds a per-app tailnet identity: point an expose at the gateway's Service
(in its namespace) and give the tenant's HTTPRoute the rendered name:

```yaml
kind: TailnetIngress                      # tenant namespace
spec:
  exposes:
    - name: https
      port: 443
      backend: { service: envoy-prod-1-tailnet, namespace: envoy-gateway-system, port: 443 }
---
kind: HTTPRoute
spec:
  parentRefs: [{ name: shared-gateway-tailnet, namespace: envoy-gateway-system, sectionName: prod-1-https }]
  hostnames: ["shop-shop-dev.prod-1.tailnet.example.internal"]   # = status.dnsName
```

Peer → name → node IP (grant `dst = tag:ingress-shop`) → Envoy (SNI matches the wildcard, route by
Host) → app. Authorization is the tailnet policy's job, not Envoy's. In-cluster pods usually cannot
route `100.x` — ingress names are for tailnet peers.

## Terminate TLS on the agent

```yaml
apiVersion: tsunaro.io/v1alpha1
kind: TailnetIngress
metadata: { name: shop, namespace: shop-dev }
spec:
  tailnetRef: { name: corp }
  allowFrom: [group:shop]
  tls:
    issuerRef: { name: apps-ca, kind: Issuer }        # cert-manager; or secretName: shop-cert
  exposes:
    - name: web
      mode: http
      port: 443
      backend: { service: shop-frontend, port: 8080 }
```

One ingress may publish several `mode: http` exposes (virtual hosts), always on port 443; other
exposes stay L4. Each HTTP expose gets its own DNS name: without `dnsLabel` it uses the ingress base
name (`status.dnsName`); with `dnsLabel: grafana` it renders `{name}` in
`Tailnet.spec.dns.ingressNameTemplate` from that label. At most one HTTP expose may omit `dnsLabel`.
The agent terminates TLS on one certificate covering every name, selects the backend by SNI, and
requires the HTTP `Host` to equal the SNI. The backend receives plain HTTP unless `backend.tls`
selects verified HTTPS. `Tailnet.spec.dns.ingressNameTemplate` must be set; each resolved name is
reported in `status.exposes[].dnsName`. The `HOSTS` column (`status.hosts`) lists every name that is
actually served, aliases included; `status.dnsName` is the ingress base name in the gateway zone and
the first certificate name, which is *not* a route once every HTTP expose carries a `dnsLabel`.
It is rendered from the CR name and does not change with `spec.hostname`; the MagicDNS identity
(`<hostname>.<base_domain>`) is `status.hostname`, which is why the gateway zone must differ from the
MagicDNS `base_domain` ([Preflight](install-headscale.md#preflight)). A request to that name
(or any other certificate name without a route) gets the certificate and an HTTP answer instead of a
TLS alert: `308` to the only served host, or `404` listing the served hosts.

An HTTP expose may also request a shorter alias with `alias: true`, rendered from
`Tailnet.spec.dns.ingressAliasTemplate` (same effective label). The alias must resolve in the SAME
DNS zone as `ingressNameTemplate` — the operator rejects a different zone with `InvalidDNSName`,
because only that zone is guaranteed over the tailnet. Aliases become extra certificate SANs and SNI
routes, listed in `status.exposes[].dnsAliases`. A name claimed by two CRs of one Tailnet is
resolved oldest-owner-first; the younger CR reports `Ready=False/DNSNameConflict` and is not
published. For multi-tenant clusters use `{name}.{namespace}.<zone>` (dot-separated, never a hyphen)
so conflicts can only arise within one namespace.

```yaml
# Multiple virtual hosts behind one node, with a short alias for the primary.
spec:
  exposes:
    - name: web
      mode: http
      port: 443
      alias: true                                     # also serve {name}.<alias-zone>
      backend: { service: shop-frontend, port: 8080 }
    - name: admin
      mode: http
      port: 443
      dnsLabel: shop-admin                            # shop-admin.<zone>
      backend: { service: shop-admin, port: 8080 }
```

### Bridge names

Clients that reach the node through a [bridge](legacy-bridge.md) resolve a name the *site* owns,
not the tailnet zone. `bridgeNames` (up to 4 per HTTP expose) adds such names as certificate SANs
and SNI routes of that expose — and nothing more: no hosts-file record, no claim across CRs, no
MagicDNS. The admin allows the zones first in `Tailnet.spec.bridgeNameAllowlist`; each bridge
name must be a proper subdomain of an allowed zone (`shop.site.example.internal` for
`site.example.internal`, never the zone itself) and must not lie in the tailnet name or alias zone.
A name that fails this reports `TLSReady=False/BridgeNameDenied`; the accepted names are listed
in `status.exposes[].bridgeNames` and `status.hosts`.

```yaml
# Tailnet (admin): which foreign zones ingresses may serve.
spec:
  bridgeNameAllowlist: [site.example.internal]
---
# TailnetIngress: the site's name for this service, pointed at the bridge by the site DNS.
spec:
  exposes:
    - name: shop
      mode: http
      port: 443
      bridgeNames: [shop.site.example.internal]
      backend: { service: shop, port: 8080 }
```

The certificate source is, in order of precedence: `spec.tls.secretName` (a `kubernetes.io/tls`
Secret in the ingress namespace whose leaf covers `status.dnsName`, wildcard SAN allowed),
`spec.tls.issuerRef` (`Issuer` or `ClusterIssuer`, group `cert-manager.io`; the operator creates
the Certificate `<ingress>-tls` in the ingress namespace), or `Tailnet.spec.defaults.tls.issuerRef`.
`secretName` and `issuerRef` are mutually exclusive; an invalid explicit source does not fall back
to the default. The operator never adopts a foreign Certificate or overwrites an existing Secret.

```sh
kubectl -n shop-dev get tailnetingress shop -o jsonpath='{.status.tlsSecretName} {.status.tlsNotAfter}{"\n"}'
curl -sI https://shop-shop-dev.prod-1.tailnet.example.internal | head -1      # from a tailnet device
# HTTP/2 200
```

| Condition | Meaning | Fix |
| --- | --- | --- |
| `TLSReady=False/TLSSecretMissing`, `TLSSecretInvalid` | Secret absent, not `kubernetes.io/tls`, or key pair invalid | create or fix the Secret |
| `TLSReady=False/TLSCertificatePending` | cert-manager has not issued yet | `kubectl -n shop-dev describe certificate shop-tls` |
| `TLSReady=False/TLSCertificateMismatch`, `TLSInvalidDNSName` | leaf does not cover every expose name (the first uncovered name is in the message) | fix the SANs or the ingress name/alias template |
| `TLSReady=False/TLSChainInvalid` | the Secret carries a `ca.crt`, but the leaf does not verify against it — a foreign issuer or a name outside the issuing CA's name constraints. The agent keeps serving the leaf; only the status reports it. | reissue the leaf from the CA in `ca.crt`, or correct `ca.crt`; absent `ca.crt`, no chain check runs |
| `Ready=False/DNSNameConflict` | an older CR of this Tailnet already claims one of these DNS names/aliases | rename, drop the alias, or remove the other CR |
| `TLSReady=False/BridgeNameDenied` | a `bridgeNames` entry is outside every zone in `Tailnet.spec.bridgeNameAllowlist`, is the zone itself, or lies in the tailnet name/alias zone | ask the admin to allow the zone, or use a proper subdomain of an allowed one ([Bridge names](#bridge-names)) |
| `Ready=False/WorkloadMigrating` | the pre-0.12 Deployment named after the CR is being drained before `ingress-<name>` is created (one restart, normally under a minute) | wait |
| `Ready=False/WorkloadMigrationBlocked` | the legacy Deployment could not be scaled down or deleted | read the message; check RBAC and the Deployment's finalizers |
| `TLSReady=False/TLSCertificateExpired`, `TLSCertificateNotYetValid` | validity interval | renew |
| `TLSReady=False/TLSConfigMismatch`, `TLSProbeStale` | agent serves another configuration or has not reported within 30 s | wait one probe interval (≤ 20 s); check the agent pod |
| `TLSReady=False/TLSCertificateConflict`, `TLSSecretConflict` | a foreign Certificate/Secret owns the target name (a leftover Secret that cert-manager issued for this very Certificate name and nothing owns is taken over automatically) | rename or remove the foreign object |

`TLSReady` proves a local in-memory handshake with the frontend certificate.
`BackendsReachable` requires a TCP connection, or a verified TLS handshake when `backend.tls` is set.
`Ready` requires both proofs and registration; none establishes the remote tailnet path. Certificate rotation
is picked up within a minute without restarting the pod or dropping existing connections. A missing
or invalid source withdraws the HTTP listener instead of serving plaintext. Switching an expose
between `l4` and `http` changes the pod template and recreates the agent pod, which briefly
interrupts the CR's other exposes; do not downgrade the operator below v0.4.0 while HTTP CRs exist.

### Verified backend HTTPS (v0.5.0)

```yaml
# Within exposes[], with mode: http and port: 443:
backend:
  service: shop-frontend
  namespace: shop-backend
  port: 8443
  tls:
    serverName: shop-frontend.shop-backend.svc.cluster.local
    caConfigMapRef:
      name: backend-ca
      key: ca.crt
```

Create `backend-ca` in the **TailnetIngress namespace**, even when the Service uses another namespace.
The selected key must contain only PEM certificates, at most 1 MiB. The agent mounts that key read-only.
Frontend certificates and backend trust are independent. The operator does not copy CA material between namespaces.

`serverName` controls backend SNI and certificate verification, not the dial destination or HTTP Host.
The agent requires TLS 1.2 or later and verifies the chain, hostname and validity interval.
There is no insecure mode, system-root fallback or retry over plaintext HTTP.

After Kubernetes projects a changed CA bundle, the agent uses a new transport and closes old idle connections.
Existing verified streams finish normally. CA removal or malformed content blocks new requests and backend readiness.
Use an overlapping old/new CA bundle for planned rotation. Revocation is not instantaneous and does not terminate existing streams.

`BackendsReachable` reports bounded backend TLS failures. Readiness requires a fresh handshake whose CA digest matches the current ConfigMap.
A reachable TCP port alone does not establish backend TLS readiness. Preserve backend NetworkPolicies; admit only the intended ingress agent.

### HTTP timeouts (v0.5.0)

```yaml
# Within the HTTP expose, alongside backend:
timeouts:
  request: 600s
  backendRequest: 600s
```

| Field | Omitted | Meaning |
| --- | --- | --- |
| `timeouts.request` | No whole-response deadline | From request handler entry through response completion, including uploads and SSE |
| `timeouts.backendRequest` | `30s` | Wait for backend response headers after sending the request body |

`0s` disables the named timer. Values use Gateway API duration syntax, such as `500ms`, `30s` or `1h2m`.
There is no additional 24-hour limit: inputs are bounded by that syntax and Go duration parsing.
Choose a finite budget for each application when unlimited requests are not appropriate.
The first applicable deadline wins. A successful protocol upgrade completes the HTTP exchange; the request timer does not limit the upgraded tunnel's lifetime.
A timeout before response commitment returns 504. Its delivery has a bounded one-second write budget.
After commitment, the response is aborted without appending an error body. The write deadline also covers buffered output after handler return.

These are not connection-idle or stream-idle timers. Existing keepalive settings remain unchanged.
Do not copy an Envoy `connectionIdleTimeout` into either field.

Upgrade CRDs, operator and agents to v0.5.0 before using these fields, including explicit image overrides.
Enabling extensions changes the internal protocol to `http-v2` and recreates the agent Pod.
For changed extended HTTP configuration, the controller stops the owned predecessor before checking Headscale dependencies.
It waits for termination and valid replacement configuration before restoring replicas. CA content rotation does not trigger this retirement.
Before a downgrade, restore a verified legacy gateway path; do not remove backend TLS merely to satisfy an older agent.

`allowFrom` authorizes tailnet peers; it neither performs OIDC nor supplies application identity headers.
Removing gateway authentication is a separate access-control decision. Native application login and credentials remain independent.

When the policy stops permitting a peer, the agent closes its open connections, including keep-alive connections and WebSockets, with the request to the backend.
The agent checks once per second ([Grants § Expiry](grants.md#expiry)). Agent unit tests cover this for `mode: http`; the kind suite measures `mode: l4` only.

## Tailnet without a policy writer (spoke cluster)

Only one Tailnet per Headscale may run `policy.mode: Apply`. On every other cluster sharing that
control plane (a *spoke*) the operator still enrols the agent and renders DNS, but it cannot write
`tagOwners` or grants — `allowFrom` is informational there. The hub's admin declares them in the base
policy, so pin the tag instead of relying on the template:

```yaml
spec:
  tag: tag:ingress-prod-2-shop          # explicit: the hub policy references this literal
  hostname: prod-2-shop                 # explicit: unique across the whole tailnet
  allowFrom: [group:shop]               # documents the intent; the hub grant is authoritative
```

Hub base policy (`policy.jsonc`), reviewed like any other admin change
([Change the base policy](policy.md#change-the-base-policy-admin)):

```jsonc
"tagOwners": { "tag:ingress-prod-2-shop": ["group:operator"] },
"grants": [ { "src": ["group:shop"], "dst": ["tag:ingress-prod-2-shop"], "ip": ["tcp:443"] } ]
```

Until the hub applies it the CR reports `TagKnown=False/Unknown` (no key is minted); afterwards it is `Ready`
like on the hub. Peers that still cannot connect are missing the grant, not the agent.

Instead of hand-copying each tag and grant, run the spoke operator in `policy.mode: Export`: it
renders exactly these entries into a fragment ConfigMap the hub merges — see
[Second cluster](policy.md#second-cluster-export-on-the-spoke-merge-on-the-hub) and the full
walk-through [Connect a second cluster](second-cluster.md).

## HTTPS through a shared gateway

TLS terminates at the gateway (it holds `*.prod-1.tailnet.example.internal`); the ingress gives the
app its own tailnet identity and name:

```yaml
kind: TailnetIngress
metadata: { name: shop, namespace: shop-dev }
spec:
  tailnetRef: { name: corp }
  allowFrom: [autogroup:member]
  exposes:
    - name: https
      port: 443
      backend: { service: envoy-prod-1-tailnet, namespace: envoy-gateway-system, port: 443 }
---
apiVersion: gateway.networking.k8s.io/v1
kind: HTTPRoute
metadata: { name: shop, namespace: shop-dev }
spec:
  parentRefs: [{ name: shared-gateway-tailnet, namespace: envoy-gateway-system, sectionName: prod-1-https }]
  hostnames: ["shop-shop-dev.prod-1.tailnet.example.internal"]     # = status.dnsName
  rules:
    - backendRefs: [{ name: shop-frontend, port: 8080 }]
```

`allowFrom: [autogroup:member]` needs `autogroup:*` in the admin allowlist; otherwise the admin adds
the grant to the base policy.
