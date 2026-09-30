# Usage and administration

Task-oriented recipes. Each one: the situation, the manifest, how to check, and what the usual
failure looks like. Installation and one-time wiring (Headscale, CoreDNS, gateway) are in
[INSTALL.md](INSTALL.md); field-by-field reference in the [README](../README.md#crd-reference).

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

**Operations**
10. [Keys and expiry](#10-operations-keys-and-expiry)
11. [Diagnosis cheat sheet](#11-operations-diagnosis-cheat-sheet)
12. [Upgrade the operator](#12-operations-upgrade-the-operator)
13. [Validation](#13-validation)

---

## 1. Egress: reach a database at the site

*The `billing-dev` namespace needs the Oracle database `10.0.10.20:1521` that lives behind the site's
subnet router.*

```yaml
apiVersion: tailnet.this-is-fine.io/v1alpha1
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
| `NotApproved` | advertised, not approved | when the operator owns the policy: wait one policy reconcile (≤ 5 min) — it replays the missed approval; persists → the router's tag is not in the `autoApprovers` entry. File mode: `headscale nodes approve-routes …` |
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
apiVersion: tailnet.this-is-fine.io/v1alpha1
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
# NAME   TAG                HOSTNAME       DNS                                             READY   AGE
# shop   tag:ingress-shop   ingress-shop   shop-shop-dev.prod-1.tailnet.example.internal   True    2m
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

TLS terminates at the shared gateway (it holds `*.prod-1.tailnet.example.internal`); the ingress gives
the app its own tailnet identity and name:

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

```sh
curl -sI https://shop-shop-dev.prod-1.tailnet.example.internal | head -1      # from a tailnet device
# HTTP/2 200
```

`allowFrom` needs `autogroup:*` in the admin allowlist for this to be generated; otherwise the admin
adds the grant to the base policy.

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

`PolicyRendered`'s message lists denied ingress tags and name-addressed targets (which get no
grant). `renderedHash == appliedHash` means Headscale runs exactly this document.

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
#   PolicyApplied   False  PolicyRejected   headscale PUT /api/v1/policy: 500 …: test failed: alice@ cannot reach site-dns:53
```

the previous policy is still active; fix the base and push again. Use the base's `tests` block to
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

## 10. Operations: keys and expiry

| Key | Where | Lifetime | Rotation |
| --- | --- | --- | --- |
| Bootstrap API key | Secret `headscale-bootstrap` (yours) | as created | manual — replace the Secret before it expires; the operator only reads it |
| Working API key | Secret `corp-apikey` (operator) | `apiKeyLifetime` (720h) | automatic at half-life, verified before the old one is expired |
| Pre-auth key per CR | Secret `<cr>-authkey` (operator) | `authKeyLifetime` (168h) | automatic at half-life; a restarted agent re-registers with it |

```sh
kubectl get tailnet corp -o jsonpath='{.status.apiKeyExpiresAt}'      # working key
# 2026-10-28T12:00:00Z
```

Metrics: `tailnet_apikey_expires_seconds`, `tailnetegress_authkey_expires_seconds`,
`tailnetingress_authkey_expires_seconds` — alert when they stop rising after a rotation was due. An
expired **bootstrap** key only matters at the next working-key rotation (`ApiKeyValid=False/Error`).

## 11. Operations: diagnosis cheat sheet

| Question | Command | Healthy output |
| --- | --- | --- |
| Is the control server reachable? | `kubectl describe tailnet corp` | `ApiReachable=True`, `ApiKeyValid=True` |
| Does preflight pass? | `kubectl get tailnet corp`, `kubectl describe tailnet corp` | `COMPAT=Compatible`, `PolicyMode=True/Database`; `DNS=CannotVerify` is a manual split-DNS configuration hint |
| Why is an egress not ready? | `kubectl -n tailnet-system get tailnetegress X -o jsonpath='{range .status.targets[*]}{.name} {.present} {.reachable} {.reason}{"\n"}{end}'` | `true true` per target, empty reason |
| Is the route on the router? | `kubectl -n tailnet-system exec deploy/headscale -- headscale nodes list-routes` | the target's `/32` or a covering subnet under the router's approved routes |
| Does the agent reach the host? | `kubectl -n tailnet-system logs deploy/X \| grep target` | no `dial …: context deadline exceeded` |
| What does the agent probe say? | `wget -qO- http://<agent-pod-ip>:9080/targets` from any pod | `"reachable":true` per target |
| Does an alias resolve? | `kubectl -n <tenant> exec deploy/app -- getent hosts api.corp.example` | the Service ClusterIP |
| Is the hosts file current? | `kubectl -n tailnet-system get cm tailnet-dns-hosts -o jsonpath='{.data.hosts}'` | one line per alias / ingress name |
| Resolver errors? | `kubectl -n <resolver-ns> logs <coredns-pod> \| grep -i error` | none; `i/o timeout` = upstream unreachable |
| What did the policy render? | `kubectl get tailnet corp -o jsonpath='{.status.policy}'`, ConfigMap `headscale-policy-rendered` | hashes equal, `PolicyApplied=True` |
| Who is on the tailnet? | `kubectl -n tailnet-system exec deploy/headscale -- headscale nodes list` | egress/ingress nodes online with their tags |

## 12. Operations: upgrade the operator

1. Apply the new CRDs, then the Deployment (image + `OPERATOR_IMAGE`).
2. The operator re-rolls agent Deployments whose image changed.
3. Verify:

```sh
kubectl -n tailnet-system rollout status deploy/tailnet-operator
kubectl get tailnetegress,tailnetingress -A
# every row READY=True
kubectl get tailnet corp          # COMPAT=Compatible; POLICY=Applied/InSync; DNS=CannotVerify (manual)
```

Version-specific notes: [INSTALL §8](INSTALL.md#8-upgrade).

## 13. Validation

Kubernetes **1.31 or later** is required. The API server validates these rules before storing a CR:

| Object / field | Rule |
| --- | --- |
| All three kinds | `spec` is required |
| Egress / ingress CR name | Lowercase DNS label, at most 40 characters; no dots |
| Egress `targets` | 1–50 entries; unique names, each a DNS-1035 label of at most 63 characters, starting with a letter (Service compatibility with Kubernetes 1.31) |
| Target `address` | Single IPv4/IPv6 address or lowercase DNS name (≤253 characters, labels ≤63); no CIDR, URL, host:port, IPv6 zone ID or malformed numeric IP |
| Target `aliases` | Each a lowercase DNS name of at most **63 characters** (a product limit, not the DNS FQDN maximum) |
| Egress `consumerNamespaces` | At least one namespace; each a DNS label of at most 63 characters |
| Ingress `allowFrom` | Required, at least one non-empty entry; the Tailnet's source allowlist still controls authorization |
| Ingress `exposes` | 1–50 entries; unique names and listener ports; names are DNS labels of at most 63 characters |
| Backend `service` / optional `namespace` | DNS labels of at most 63 characters |
| Target, listener and backend ports | 1–65535 |
| Tailnet `server` | HTTPS scheme and a non-empty remainder; `apiUrl` may still use an internal HTTP endpoint |
| Tailnet `apiKeyLifetime` | Valid duration ≥1h, at most 32 characters; omitted defaults to 720h |
| Tailnet `policy.mode` | `DryRun` or `Apply` |
| Tailnet `dns.ingressNameTemplate` | Empty disables ingress DNS names; otherwise contains `{name}`, uses only `{name}`/`{namespace}`, and ends in a literal lowercase zone with at least two labels; at most 253 characters |
| Tailnet `policy.ingressSourceAllowlist` | Each entry begins with `group:`, `tag:` or `autogroup:` plus a non-empty suffix, or is an email-shaped pattern; at most 253 characters; bare `*` is rejected |
| Tailnet `headscale.ref` | Reserved; only empty is accepted |

The list limits bound CEL's duplicate checks. Validation does not prove that a backend Service,
Headscale group or DNS delegation exists. Rendered ingress DNS names are also validated at reconcile
time because their length depends on the ingress name and namespace. Each rendered label must fit
63 characters, even when it combines `{name}` and `{namespace}`. When policy generation is off,
`allowFrom` does not itself create a Headscale grant.

### Test without changing a cluster

Use upstream [controller-tools envtest binaries](https://github.com/kubernetes-sigs/controller-tools/releases)
for Kubernetes 1.31 or later. Set `KUBEBUILDER_ASSETS` to the directory containing `kube-apiserver`,
`etcd` and `kubectl`, then run:

```sh
export KUBEBUILDER_ASSETS=/path/to/envtest/binaries
task test-validation
```

This starts a disposable local API server with the generated CRDs. It checks valid examples,
boundaries and every file in `deploy/examples/invalid/`, including the shell checker below.
It ignores the current kube-context and asserts that no test CR was persisted. The ordinary
`task test` does not start envtest; admission tests require this explicit task.

Before a CRD upgrade, also test a fresh export of the existing CRs:

```sh
live=$(mktemp)
kubectl get tailnet,tailnetegress,tailnetingress -A -o json > "$live"
LIVE_CR_FILE="$live" task test-validation
rm -f -- "$live"
```

The export is read-only. The test submits each spec as a fresh dry-run object to the **local** API
server, so unchanged legacy fields cannot bypass validation through ratcheting.

### Check an installed schema

After installing the new CRDs in a test cluster, run:

```sh
task validate-examples -- --context <test-context> --namespace <existing-namespace>
```

`hack/validate-examples.sh` uses server-side dry-run **create**, not apply/merge with an existing CR.
Every negative fixture must fail with its `ExpectedError` header. Missing CRDs, authentication,
RBAC and connection errors do not count as successful validation tests. Do not apply the invalid
examples without dry-run.
