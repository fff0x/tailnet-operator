# Usage and administration

Task-oriented recipes. Each one: the situation, the manifest, how to check, and what the usual
failure looks like. Installation and one-time wiring (Headscale, CoreDNS, gateway) are in
[INSTALL.md](INSTALL.md); day-2 operations and alert runbooks in [OPERATIONS.md](OPERATIONS.md)
(formerly §10–14 of this page); field-by-field reference in the [README](../README.md#crd-reference).

Placeholders throughout: Tailnet `corp`, operator namespace `tailnet-system`, cluster `prod-1`,
domain `tailnet.example.internal`, tenant namespaces `billing-dev` / `billing`, site network `10.0.0.0/8`.

**Egress (tenant reaches the site)**
1. [Reach a database at the site](#1-egress-reach-a-database-at-the-site)
2. [Reach an HTTPS service by hostname (SNI / Host)](#2-egress-reach-an-https-service-by-hostname-sni--host)
3. [Share targets between prod and dev](#3-egress-share-targets-between-prod-and-dev)
4. [Add, remove, rename a target](#4-egress-add-remove-rename-a-target)

**Ingress (tailnet reaches the cluster)**
5. [Publish a TCP service on the tailnet](#5-ingress-publish-a-tcp-service-on-the-tailnet)
6. [Publish a web app over HTTPS](#6-ingress-publish-a-web-app-over-https)

**Policy**
7. [Read what the operator generated](#7-policy-read-what-the-operator-generated)
8. [Change the base policy](#8-policy-change-the-base-policy-admin)
9. [Review before Apply, drift, rollback](#9-policy-review-before-apply-drift-rollback)
9a. [Declare a site network (TailnetSite)](#9a-policy-declare-a-site-network-tailnetsite)

**Gateway**
9b. [Run the subnet router and split-DNS as a CR](#9b-gateway-run-the-subnet-router-and-split-dns-as-a-cr)

**Operations** — keys, diagnosis, upgrade, backup, validation, alert runbooks: [OPERATIONS.md](OPERATIONS.md)

---

## 1. Egress: reach a database at the site

*The `billing-dev` namespace needs the Oracle database `10.0.10.20:1521` that lives behind the site's
subnet router.*

```yaml
apiVersion: tsunaro.io/v1alpha1
kind: TailnetEgress
metadata:
  name: billing-dev            # = tenant name by convention; one CR per tenant namespace
  namespace: tailnet-system    # egress CRs are admin resources: always the operator namespace
spec:
  tailnetRef: { name: corp }
  consumerNamespaces: [billing-dev]
  targets:
    - { name: db-1, address: 10.0.10.20, port: 1521 }
```

The application connects to **`db-1.tailnet-system.svc:1521`** — plain TCP; the tunnel is invisible.

```sh
kubectl -n tailnet-system get tailnetegress billing-dev
# NAME          TAG                      HOSTNAME             READY   AGE
# billing-dev   tag:egress-billing-dev   egress-billing-dev   True    2m

kubectl -n tailnet-system get tailnetegress billing-dev -o jsonpath='{range .status.targets[*]}{.name} port={.listenPort} present={.present} reachable={.reachable} {.reason}{"\n"}{end}'
# db-1 port=10000 present=true reachable=true
```

Not `READY`? Read the reason of the target, then the condition:

| `status.targets[].reason` / condition | Meaning | Fix |
| --- | --- | --- |
| `TagKnown=False/Unknown` | tag not in `tagOwners` | add it to the policy (file mode) |
| `TagKnown=False/PolicyPending` | operator owns the policy, tag not applied yet | wait a reconcile; check `kubectl describe tailnet corp` → `PolicyApplied` |
| `NotAdvertised` | no node advertises a route covering `10.0.10.20` | add the host (`/32`) or its subnet to the router's `--advertise-routes` |
| `NotApproved` | advertised, not approved (a `TailnetGateway` reports the same state as `RoutesInSync=False/NotApproved`) | when the operator owns the policy: wait one policy reconcile (≤ 5 min) — it replays the missed approval; persists → the router's tag is not in the `autoApprovers` entry. File mode: `headscale nodes approve-routes …` |
| `NoGrant` | tag has no grant to `10.0.10.20/32:1521` | add the grant (file mode) — generated automatically when the operator owns the policy |
| `ProbeFailed` | the operator could not scrape the agent (`/status`, `/targets`) | agent pod down, or a NetworkPolicy between operator and agent — the other reasons are unknown until this is fixed |
| `TargetsReachable=False` | TCP to the host fails (`dial …: context deadline exceeded` in the agent log) | site firewall: router address → target port; host down |

Isolation check — a pod in a *foreign* namespace must time out:

```sh
kubectl -n some-other-ns run t --rm -it --image=busybox --restart=Never -- nc -zw3 db-1.tailnet-system.svc 1521
# nc: timed out            ← correct: the NetworkPolicy allows consumerNamespaces only
```

## 2. Egress: reach an HTTPS service by hostname (SNI / Host)

*`billing` needs `https://api.corp.example`. The far end is a reverse proxy that routes by name, so the
client must send the real hostname — `api.tailnet-system.svc` would get a 404 or a certificate error.*

Add an **alias**; the operator publishes `api.corp.example → <Service ClusterIP>` in the DNS hosts file
([INSTALL §5](INSTALL.md#5-dns-coredns)); the client dials the real name and TLS/SNI survive the tunnel:

```yaml
  targets:
    - name: api-corp
      address: 10.0.30.10
      port: 443
      aliases: [api.corp.example, ipam.corp.example]   # several names on the same host: one target
```

```sh
kubectl -n tailnet-system get cm tailnet-dns-hosts -o jsonpath='{.data.hosts}'
# # managed by tailnet-operator (Tailnet corp) — do not edit
# 10.96.28.170   api.corp.example
# 10.96.28.170   ipam.corp.example

kubectl -n billing exec deploy/billing -- getent hosts api.corp.example
# 10.96.28.170    api.corp.example
kubectl -n billing exec deploy/billing -- sh -c 'printf "HEAD / HTTP/1.1\r\nHost: api.corp.example\r\n\r\n" | openssl s_client -quiet -connect api.corp.example:443 -servername api.corp.example 2>/dev/null | head -1'
# HTTP/1.1 200 OK
```

Notes: the alias zone must be forwarded to the resolver that mounts the hosts file
([INSTALL §5.3](INSTALL.md#53-wire-the-cluster-coredns)). Certificates come from the site (often an
internal CA) — the *application* needs that CA in its trust store; the tunnel does not touch TLS.

## 3. Egress: share targets between prod and dev

*`billing` (prod) already reaches `api.corp.example`; `billing-dev` needs it too.*

A DNS alias can point to **one** Service cluster-wide, and the SNI must be the real name — so there
is no "dev alias". Let the dev namespace consume the prod egress instead:

```yaml
kind: TailnetEgress
metadata: { name: billing, namespace: tailnet-system }
spec:
  consumerNamespaces: [billing, billing-dev]     # dev traffic uses the prod proxy and its tag
```

Keep separate egress CRs for targets that genuinely differ between the environments (a dev
database), and give those targets distinct names (`db-1-dev`) — target names are Service names and
must be unique in the operator namespace.

## 4. Egress: add, remove, rename a target

- **Add**: append to `targets`; the operator adds a Service, a listener port (stable per name), a
  NetworkPolicy entry, the DNS aliases and — with operator-owned policy — the route approval and grant.
  No pod restart; `status.targets[]` shows the new entry within a minute.
- **Remove**: delete the entry; Service, alias and grant disappear on the next reconcile. Consumers
  still dialling the Service name get `NXDOMAIN`.
- **Rename**: is a remove + add — the Service name changes, consumers must follow. Prefer adding the
  new name first and removing the old one after the switch.

```sh
kubectl -n tailnet-system get svc -l app.kubernetes.io/instance=billing-dev
# NAME   TYPE        CLUSTER-IP     PORT(S)    AGE
# db-1   ClusterIP   10.96.78.33    1521/TCP   3d
```

## 5. Ingress: publish a TCP service on the tailnet

*Team `shop` wants developers on the tailnet to reach the dev database directly, without VPN or
port-forward.*

```yaml
apiVersion: tsunaro.io/v1alpha1
kind: TailnetIngress
metadata:
  name: shop
  namespace: shop-dev                 # tenant namespace: the tenant owns the CR
spec:
  tailnetRef: { name: corp }
  allowFrom: [group:shop]             # who may connect (operator-owned policy)
  exposes:
    - { name: postgres, port: 5432, backend: { service: shop-db-rw, port: 5432 } }
```

```sh
kubectl -n shop-dev get tailnetingress shop
# NAME   TAG                HOSTNAME       HOSTS                                             READY   AGE
# shop   tag:ingress-shop   ingress-shop   [shop-shop-dev.prod-1.tailnet.example.internal]   True    2m
```

From a laptop in `group:shop`: `psql -h shop-shop-dev.prod-1.tailnet.example.internal -p 5432`
(or `ingress-shop` via MagicDNS).

| Condition | Meaning | Fix |
| --- | --- | --- |
| `PolicyGranted=False/PolicyDenied` | an `allowFrom` entry is outside the admin allowlist (`Tailnet.spec.policy.ingressSourceAllowlist`) | use an allowed principal (e.g. a `group:`), or ask the admin to widen the allowlist |
| `BackendsReachable=False` | `shop-db-rw:5432` does not answer from the agent pod | Service/port wrong, backend down, NetworkPolicy in the tenant namespace blocks the agent |
| `TagKnown=False` | see egress table above | |

## 6. Ingress: publish a web app over HTTPS

*The shop frontend should be `https://shop-shop-dev.prod-1.tailnet.example.internal` for tailnet users.*

Two shapes: let the **agent terminate TLS** (one CR, a certificate, no gateway) or keep TLS at a
**shared gateway** and use the ingress only for the per-app tailnet identity.

### 6.1. Ingress: terminate TLS on the agent

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
MagicDNS `base_domain` ([INSTALL §2.5](INSTALL.md#25-preflight)). A request to that name
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
| `Ready=False/DNSNameConflict` | an older CR of this Tailnet already claims one of these DNS names/aliases | rename, drop the alias, or remove the other CR |
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

#### Verified backend HTTPS (v0.5.0)

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

#### HTTP timeouts (v0.5.0)

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

### 6.2. Ingress: HTTPS through a shared gateway

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

## 7. Policy: read what the operator generated

*Before trusting Apply mode, or when a grant seems missing.*

```sh
kubectl get tailnet corp
# NAME   SERVER                   APIKEY   EXPIRES                POLICY    AGE
# corp   https://ts.example.com   True     2026-10-28T12:00:00Z   Applied   3d

kubectl get tailnet corp -o jsonpath='{.status.policy}'
# {"appliedAt":"2026-09-28T12:02:11Z","appliedHash":"c88d…","renderedHash":"c88d…","generated":{"tags":2,"grants":2,"routes":1}}

kubectl -n tailnet-system get cm headscale-policy-rendered -o jsonpath='{.data.policy}' | jq '.grants[-2:], .autoApprovers.routes'
# [
#   { "src": ["tag:egress-billing-dev"], "dst": ["10.0.10.20/32"], "ip": ["tcp:1521"] },
#   { "src": ["group:shop"], "dst": ["tag:ingress-shop"], "ip": ["tcp:5432"] }
# ]
# { "10.0.0.0/24": ["tag:fabric"], "10.0.10.20/32": ["tag:fabric"] }
```

`PolicyRendered`'s message lists denied ingress tags and skipped inputs: name-addressed targets
(which get no grant), gateways whose routes do not plan (`gateway/<name>`) and blocked sites
(`site/<name>`, see section 9a).
`renderedHash == appliedHash` means Headscale runs exactly this document.

## 8. Policy: change the base policy (admin)

*A new group needs SSH to the gateways.*

Edit the base in Git (the ConfigMap `headscale-policy`), push, and watch the apply:

```sh
kubectl describe tailnet corp | grep -A2 -E 'PolicyRendered|PolicyApplied'
#   PolicyRendered  True   Rendered   2 tags, 2 grants, 1 routes generated
#   PolicyApplied   True   Applied    rendered policy written to the control server
```

If Headscale refuses:

```
#   PolicyApplied   False  PolicyRejected   headscale PUT /api/v1/policy: HTTP 500
```

the previous policy is still active. Upstream error bodies are withheld because they can contain credentials.
One cause is named anyway: while two Headscale users share a name, Headscale rejects every policy
write ("multiple users found"); the Tailnet then shows `UsersUnique=False/Duplicate` with the user IDs
and the `PolicyRejected` message points there — destroy the surplus user (`headscale users destroy -i <id>`).
Otherwise validate the rendered policy privately, then fix the base and push again. Use the base's `tests` block to
pin what must never break (your own device → Kubernetes API, the resolver) — a wrong edit is then
rejected instead of applied.

Never run `headscale policy set` by hand while the operator is in `Apply`: it is overwritten within
5 minutes and reported as event `PolicyDriftOverwritten`.

## 9. Policy: review before Apply, drift, rollback

| Want | Do |
| --- | --- |
| See what Apply would write | `mode: DryRun`, read `headscale-policy-rendered`, validate: `… \| kubectl -n tailnet-system exec -i deploy/headscale -- headscale policy check -f /dev/stdin` |
| Compare live and render | `kubectl get tailnet corp -o jsonpath='{.status.policy.appliedHash} {.status.policy.renderedHash}'` — equal = in sync |
| Find manual changes | `kubectl get events -A --field-selector reason=PolicyDriftOverwritten` |
| Stop the operator writing | `mode: DryRun` |
| Restore the Git policy on the server | `mode: DryRun`, then `headscale policy set -f /acl/policy` |

Full procedures in [INSTALL §9](INSTALL.md#9-rollback).

## 9a. Policy: declare a site network (TailnetSite)

*A branch office (or a management range, or a lone printer) sits behind a subnet router, and
people as well as workloads must reach it. Today its prefixes are hand-written `autoApprovers`
lines that must stay identical to the router's advertised routes.*

A `TailnetSite` declares the network once, in the cluster whose operator owns the policy
(`policy.mode: Apply`). The router can be an operator-managed `TailnetGateway` ([§9b](#9b-gateway-run-the-subnet-router-and-split-dns-as-a-cr))
**or a hand-built router in another cluster** — the operator identifies it by tag, not by CR
(fixture: [`deploy/examples/tailnetsite.yaml`](../deploy/examples/tailnetsite.yaml)):

```yaml
apiVersion: tsunaro.io/v1alpha1
kind: TailnetSite
metadata:
  name: branch-north
spec:
  tailnetRef: {name: corp}
  prefixes: [10.0.102.0/24, 10.0.60.215/32]   # a /32 is a single host
  advertisedBy: {tags: [tag:fabric]}           # omit → Tailnet.spec.policy.routeApprovers
  owner: netops
  description: Branch office north, reached through the on-prem subnet router
```

What the operator does — and does not do:

| Does | Does not |
| --- | --- |
| Appends `autoApprovers.routes[<prefix>] = advertisedBy.tags` to the rendered policy | Render a grant: **who may reach the site stays a grant in the base policy** (`dst: 10.0.102.0/24`) |
| Replays the approval on every node carrying an advertiser tag that advertises the prefix | Advertise anything: the router's own route list (`--advertise-routes`, `TS_ROUTES`) is still yours |
| Reports `Advertised` / `Approved` / `Ready` per site from the control server's node list | De-approve or withdraw routes, ever |
| Blocks a site whose prefix overlaps `Tailnet.spec.reservedNetworks` or an **older** site | Touch the older site: a conflict never flips an already-serving network |

Fill `Tailnet.spec.reservedNetworks` first — the node prefix and every cluster's LAN/pod/service/
tailnet-LB ranges on this control server — otherwise a typo like `100.64.8.0/22` in CGNAT space
would be approved onto the routers:

```yaml
spec:
  reservedNetworks:
    - {name: nodes,  prefixes: [100.64.0.0/16]}
    - {name: prod-1, prefixes: [10.210.1.0/24, 10.244.0.0/16, 10.96.0.0/12, 10.103.2.16/28]}
```

Check:

```sh
kubectl get tailnetsite
# NAME           TAILNET   OWNER    READY           AGE
# branch-north   corp      netops   Ready           2m
# branch-south   corp      netops   NotAdvertised   2m   ← router does not offer 10.0.103.0/24 yet
# mgmt-typo      corp      netops   RouteConflict   1m   ← overlaps reserved network nodes
kubectl describe tailnetsite branch-south | grep -A1 -E 'Advertised|Approved|RouteConflict|Unmanaged'
```

| Condition | Reason | Meaning |
| --- | --- | --- |
| `RouteConflict` | `OverlapsReserved` / `OverlapsSite` | Blocked; message names the reserved network or the older site and the prefix. Nothing rendered or approved. |
| `Advertised` | `NotAdvertised` | No node with an advertiser tag offers the listed prefixes (exact match — a `/24` does not count for a `/32`). Fix the router's route list. |
| `Approved` | `NotApproved` | Advertised but not approved yet; the replay runs with the next policy reconcile (≤ 5 min). Persisting → the node lacks the tag. |
| `UnmanagedOverlap` | `Unmanaged` | A node *without* an advertiser tag advertises an overlapping route (named in the message). Report only. |
| `Ready` | `NotObserved` | The control server was not queried in this reconcile (DryRun without a working key, API failure). |

Migrating hand-written lines: create the sites, keep the old `autoApprovers` entries until
`renderedHash` equals today's live policy (the render is a set union, so the document does not
change), then delete the base lines in Git. Rollback is deleting the `TailnetSite` CRs — approvals
already granted stay, because the operator never de-approves.

## 9b. Gateway: run the subnet router and split-DNS as a CR

*`prod-1` sits in a datacenter LAN `192.0.2.0/24` (router `192.0.2.1`). Tailnet peers must reach
that LAN, the cluster's tailnet-facing LoadBalancer IPs, and every egress target the operator
manages — and resolve `*.prod-1.tailnet.example.internal` without a hand-built resolver. The
cluster already runs Cilium with an IP pool and iBGP to the LAN router.*

A `TailnetGateway` is one kernel-mode Tailscale Pod (subnet router, `NET_ADMIN`, no host
network) plus a CoreDNS that serves the operator's hosts file as an authoritative zone. The CR is
**fresh-only**: it creates a new node with a persistent identity and never adopts, updates or
replaces an existing router ([reference](reference/gateway.md)). One-time wiring (kernel
prerequisites, LB pool, Headscale split-DNS, cluster CoreDNS forward) is in
[INSTALL §7a](INSTALL.md#7a-gateway-subnet-router--split-dns); this recipe is the manifest and
how to read it.

### The gateway

```yaml
apiVersion: tsunaro.io/v1alpha1
kind: TailnetGateway
metadata:
  name: prod-1-gw                        # cluster-scoped; also names the LoadBalancer Service
spec:
  suspend: false                         # default true: nothing is created until you opt in
  deletionPolicy: Retain                 # CR deletion keeps node, Secret and resources (Delete = teardown)
  tailnetRef: { name: corp }
  hostname: prod-1-gw                    # Headscale node name; immutable
  tags: [tag:fabric]                     # default; must be in policy.routeApprovers for auto-approval
  stateSecretRef: { name: prod-1-gw-state }   # created empty by the operator, holds the node identity
  image: ghcr.io/tailscale/tailscale:v1.102.4 # kernel tailscale; a version tag or digest, never :latest
  routes:
    lan: [192.0.2.0/24]                  # the site LAN; 1–128 IPv4 prefixes
    advertiseEgressTargets: true         # default: every literal TailnetEgress target becomes a /32 route
  service:
    loadBalancerIP: 198.51.100.17        # the split-DNS nameserver address peers will use; immutable
    tailnetLBCIDR: 198.51.100.0/24       # the whole LB pool is advertised, so peers reach every LB IP
    poolLabels:
      io.cilium/lb-pool: tailnet         # how your LB implementation picks the pool (labels on the Service)
  dns:
    zone: prod-1.tailnet.example.internal    # = the split zone of Tailnet.spec.dns.ingressNameTemplate
    serviceName: prod-1-gw-dns           # in-cluster DNS Service for the CoreDNS forward
    serviceClusterIP: 10.96.0.54         # stable, must be free in the Service CIDR; immutable
    image: docker.io/coredns/coredns:1.14.7
    staticRecords:
      - name: api                        # api.prod-1.tailnet.example.internal
        target: kube-api-platform.prod-1.tailnet.example.internal   # CNAME to a TailnetIngress name (agents change IP; never pin)
      - name: router                     # router.prod-1.tailnet.example.internal
        address: 192.0.2.1               # A record for a fixed LAN host
    wildcardAddress: 198.51.100.80       # *.prod-1.… → shared Envoy gateway (§6); dynamic names win
```

What the operator does with it, in order: render and validate; create the empty state Secret;
mint a tag-bound 24 h pre-auth key; create ServiceAccount, Role, RoleBinding, PDB, three
Services (`prod-1-gw` LoadBalancer :53, `prod-1-gw-dns` ClusterIP :53, `prod-1-gw-headless`), the
`-coredns` ConfigMap and the StatefulSet (nine objects, StatefulSet last); write the immutable `-fresh` receipt; then report `Ready` once the Pod runs,
the node is online and advertises the planned routes. The advertised set is
`routes.lan ∪ tailnetLBCIDR ∪ {egress targets}/32` — here `192.0.2.0/24`, `198.51.100.0/24` and,
from [§1](#1-egress-reach-a-database-at-the-site), `10.0.10.20/32`. When the Tailnet owns its
policy (`policy.mode: Apply`) the policy controller renders `tag:fabric` into `tagOwners` and every
route into `autoApprovers.routes` and approves them within one policy reconcile (≤ 5 min); otherwise
approve in Headscale.

Turn `advertiseEgressTargets` off when every egress host already lies inside `routes.lan`:
covered `/32`s are not deduplicated, and each new or deleted `TailnetEgress` would mark the Pod
template stale until you delete the Pod.

### Site-provided pieces

The operator configures none of these; it only depends on them.

**LB pool.** The gateway's Service carries the labels from `service.poolLabels`; your pool selects on
them, and the default pool excludes them so ordinary Services never land in the tailnet range:

```yaml
apiVersion: cilium.io/v2
kind: CiliumLoadBalancerIPPool
metadata: { name: tailnet }
spec:
  blocks: [{ cidr: 198.51.100.0/24 }]
  serviceSelector: { matchLabels: { io.cilium/lb-pool: tailnet } }
---
apiVersion: cilium.io/v2
kind: CiliumLoadBalancerIPPool
metadata: { name: default }
spec:
  blocks: [{ cidr: 198.51.101.0/24 }]
  serviceSelector:
    matchExpressions: [{ key: io.cilium/lb-pool, operator: NotIn, values: [tailnet] }]
```

**iBGP.** Tailnet peers reach `198.51.100.0/24` through the gateway (it is an advertised route); the
*LAN* reaches those addresses only if the nodes announce them. With Cilium's BGP control plane,
one instance in the site ASN peering with the LAN router (MetalLB or kube-vip speakers do the same
job):

```yaml
apiVersion: cilium.io/v2
kind: CiliumBGPClusterConfig
metadata: { name: site }
spec:
  bgpInstances:
    - name: lan
      localASN: 65010
      peers:
        - name: router
          peerASN: 65010                 # same ASN = iBGP
          peerAddress: 192.0.2.1
          peerConfigRef: { name: router }
---
apiVersion: cilium.io/v2
kind: CiliumBGPPeerConfig
metadata: { name: router }
spec:
  families:
    - afi: ipv4
      safi: unicast
      advertisements: { matchLabels: { advertise: lb } }
---
apiVersion: cilium.io/v2
kind: CiliumBGPAdvertisement
metadata: { name: lb, labels: { advertise: lb } }
spec:
  advertisements:
    - advertisementType: Service
      service: { addresses: [LoadBalancerIP] }
      selector: { matchExpressions: [{ key: io.cilium/lb-pool, operator: Exists }] }
```

**Headscale split-DNS.** Peers resolve the zone at the gateway's LoadBalancer IP (Headscale has no
API for this; `SplitDNS=Unknown/CannotVerify` on the Tailnet is the reminder):

```yaml
dns:
  nameservers:
    split:
      prod-1.tailnet.example.internal: [198.51.100.17]
```

**Cluster CoreDNS.** Pods ask `kube-system` CoreDNS; forward the zone to the gateway's ClusterIP
Service (replaces the hand-built resolver of [INSTALL §5.2](INSTALL.md#52-serve-the-file)):

```corefile
prod-1.tailnet.example.internal:53 {
    errors
    cache 30
    forward . 10.96.0.54 { prefer_udp }
}
```

### Declare the LAN as a site

The gateway advertises `192.0.2.0/24`; a `TailnetSite` makes that network a first-class object with
`Advertised`/`Approved`/`Ready`, metrics and the overlap guard of [§9a](#9a-policy-declare-a-site-network-tailnetsite).
`advertisedBy` is omitted, so the advertiser tags default to `policy.routeApprovers` — the gateway's tag:

```yaml
apiVersion: tsunaro.io/v1alpha1
kind: TailnetSite
metadata: { name: prod-1-lan }
spec:
  tailnetRef: { name: corp }
  prefixes: [192.0.2.0/24]
  owner: platform
  description: prod-1 datacenter LAN, advertised by prod-1-gw
```

Do **not** list the LAN or the LB CIDR in `Tailnet.spec.reservedNetworks` — those are routes the
gateway advertises, so they are site material, not protected space.

### Check

```sh
kubectl get tailnetgateway prod-1-gw
# NAME        HOSTNAME    SUSPENDED   READY
# prod-1-gw   prod-1-gw   false       True
kubectl get tailnetgateway prod-1-gw -o jsonpath='{.status.nodeId} {.status.ipv4} {.status.serviceIP}{"\n"}{range .status.conditions[*]}{.type}={.status}/{.reason}{"\n"}{end}'
# 42 100.64.0.17 198.51.100.17
# Ready=True/FreshRuntimeReady  RoutesInSync=True/Approved  WorkloadCurrent=True/PodCurrent  ServiceReady=True/LoadBalancerAssigned
kubectl -n tailnet-system exec deploy/headscale -- headscale nodes list-routes
# prod-1-gw: 192.0.2.0/24, 198.51.100.0/24, 10.0.10.20/32 — all approved
kubectl -n billing exec deploy/app -- getent hosts api.prod-1.tailnet.example.internal   # in-cluster path
# from a tailnet peer:
dig +short router.prod-1.tailnet.example.internal                                        # 192.0.2.1 via split-DNS
kubectl get tailnetsite prod-1-lan                                                       # READY=Ready
```

| Symptom | Meaning | Fix |
| --- | --- | --- |
| `Ready=False/Provisioning` for minutes | Pod not yet running | `kubectl -n tailnet-system describe pod prod-1-gw-0`: image pull, kernel preflight (`/dev/net/tun`, `ip_forward`), Pod Security admission |
| `Ready=False/FreshBlocked` | bootstrap blocked: key expired before registration, receipt or template drift, a pool key colliding with an operator label | alert `TailnetGatewayFreshBlocked`; runbook [OPERATIONS](OPERATIONS.md#monitoring-gateway-fresh-blocked) |
| `RoutesInSync=False/NotApproved` | advertised but not approved | `policy.mode: Apply` with the tag in `routeApprovers`, or approve in Headscale |
| `ServiceReady=False/LBPending` | no LoadBalancer address | pool CIDR contains `loadBalancerIP`, selector matches `poolLabels`, LB controller healthy; `Ready` does not wait for this |
| `WorkloadCurrent=False/PodTemplateStale` | image or route change written to the template | delete Pod `prod-1-gw-0` when convenient; the running Pod keeps serving |
| `WorkloadCurrent=False/WorkloadUpdateBlocked` | an IPv6 route, a `tailnetLBCIDR` that no longer contains the LB IP, or an unverified StatefulSet | revert the spec; IPv6 routes are not supported yet |
| `ClusterDNSForward`, `StaleNodes` `Unknown/ExternallyManaged` | by design | the CoreDNS forward and old Headscale nodes are yours |
| peers resolve nothing | split-DNS or route | `nameservers.split` points at `198.51.100.17`; `198.51.100.0/24` approved; `dig @198.51.100.17` from a peer |

### After creation

| Change | Effect |
| --- | --- |
| `image`, `dns.image`, `routes.*`, `service.tailnetLBCIDR`, egress targets | written into the StatefulSet template; apply by deleting the Pod (`PodTemplateStale`), no restart by the operator |
| `dns.staticRecords`, `dns.wildcardAddress`, the hosts file | re-rendered live into the zone (and the extra-zone `hosts` key); no Pod change |
| `service.poolLabels` | set/removed on the Service in place |
| `deletionPolicy`, `suspend` | lifecycle only; a suspend/resume cycle keeps the identity |
| `tailnetRef`, `hostname`, `stateSecretRef`, `tags`, `replicas`, `service.loadBalancerIP`, `service.loadBalancerClass`, `dns.zone`, `dns.serviceName`, `dns.serviceClusterIP`, `dns.extraZones` | identity — admission rejects most, the rest report `IdentityChanged`; recreate with `deletionPolicy: Delete` |

### Extra zones for legacy networks

When peers must also resolve corporate zones whose internal resolvers carry
authoritative overrides (an SNI-routing proxy under `lolek.konzern.intern`, say),
add them as `dns.extraZones`. Names inside such a zone that appear in the Tailnet
hosts source are answered by the gateway; everything else is forwarded to the
listed upstreams. Add the zone to the Headscale split-DNS (`nameservers.split`)
pointing at the gateway LB IP, like the primary zone.

```yaml
spec:
  dns:
    zone: hydra.tailnet.example.internal
    extraZones:
      - zone: konzern.intern
        upstreams: ["10.90.200.1", "10.90.200.2"]
      - zone: it.persona.de
        upstreams: ["10.90.200.1"]
```

Overrides come from the hosts source (`spec.dns.hostsConfigMap` of the Tailnet, i.e.
`TailnetEgress` DNS aliases and `TailnetIngress` names): an alias such as
`lolek.konzern.intern` on an egress makes the gateway answer it with the egress
address instead of forwarding. Only A/AAAA are served locally; other record types for
an overridden name reach the upstream. Zones must not overlap each other or the
primary zone; `dns.extraZones` is immutable after creation.

Declared in the schema but **rejected by the current writer** (`Ready=False/FreshBlocked` or
admission): `forwards[]`/`forwardImage` (TCP forwards), `authKeySecretRef`
(external bootstrap key), `adoption`, IPv6 prefixes, `replicas` other than `1`. Lifecycle, rollback
and deletion: [gateway reference](reference/gateway.md#key-and-expiry-lifecycle).
