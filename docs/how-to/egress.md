---
title: "Egress: reach services at the site"
weight: 40
description: "Reach a database or an HTTPS service behind the subnet router, share targets between namespaces, and add, remove or rename targets."
---

## Reach a database at the site

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
| `Registered=False/WorkloadBlocked` | the agent pod is refused by a LimitRange/ResourceQuota/PodSecurity (message carries the admission text) | raise `spec.resources` or `Tailnet.spec.proxy.resources` — see [Agent resources](install-operator.md#namespaces-with-a-limitrange) |
| `NotAdvertised` | no node advertises a route covering `10.0.10.20`; an exit node's default route (`0.0.0.0/0`, `::/0`) never counts | add the host (`/32`) or its subnet to the router's `--advertise-routes` |
| `NotApproved` | advertised, not approved (a `TailnetGateway` reports the same state as `RoutesInSync=False/NotApproved`) | when the operator owns the policy: wait one policy reconcile (≤ 5 min) — it replays the missed approval; persists → the router's tag is not in the `autoApprovers` entry. File mode: `headscale nodes approve-routes …` |
| `NoGrant` | tag has no grant to `10.0.10.20/32:1521` | add the grant (file mode) — generated automatically when the operator owns the policy |
| `ProbeFailed` | the operator could not scrape the agent (`/status`, `/targets`) | agent pod down, or a NetworkPolicy between operator and agent — the other reasons are unknown until this is fixed |
| `TargetsReachable=False` | TCP to the host fails (`dial …: context deadline exceeded` in the agent log) | site firewall: router address → target port; host down |

Isolation check — a pod in a *foreign* namespace must time out:

```sh
kubectl -n some-other-ns run t --rm -it --image=busybox --restart=Never -- nc -zw3 db-1.tailnet-system.svc 1521
# nc: timed out            ← correct: the NetworkPolicy allows consumerNamespaces only
```

## Reach an HTTPS service by hostname (SNI / Host)

*`billing` needs `https://api.corp.example`. The far end is a reverse proxy that routes by name, so the
client must send the real hostname — `api.tailnet-system.svc` would get a 404 or a certificate error.*

Add an **alias**; the operator publishes `api.corp.example → <Service ClusterIP>` in the DNS hosts file
([DNS with CoreDNS](dns-coredns.md)); the client dials the real name and TLS/SNI survive the tunnel:

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
([Wire the cluster CoreDNS](dns-coredns.md#wire-the-cluster-coredns)). Certificates come from the site (often an
internal CA) — the *application* needs that CA in its trust store; the tunnel does not touch TLS.

## Reach a service published by a TailnetIngress

A target may be a **MagicDNS name** instead of an IP — typically the name of a `TailnetIngress` in
another cluster. No subnet route is involved then: `status.targets[].route` stays empty and
`present` is true; the only authorization is the ingress's `allowFrom`, which must list this egress's
tag, and a missing grant shows as `TargetsReachable=False/Unreachable`. To hand such a target on to
hosts *outside* the cluster, see [Bridge](legacy-bridge.md) (`spec.expose`).

Use the MagicDNS name (`<hostname>.<base_domain>`), which the agent resolves from its own netmap.
A name in a **tailnet split-DNS zone** only resolves if the egress tag holds a `:53` grant to the
zone's resolver; without it the agent cannot look the name up and the target reports
`TargetsReachable=False/NameUnresolved` (distinct from a plain `Unreachable`, which means the name
resolved but the dial failed — usually a missing `allowFrom` grant). The per-target cause is in
`status.targets[].reason`.

## Share targets between prod and dev

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

## Add, remove, rename a target

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
