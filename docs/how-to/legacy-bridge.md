---
title: "Bridge: let a legacy network reach the tailnet"
weight: 97
description: "Hosts without a tailnet client reach services published on the tailnet through the site cluster: a TailnetEgress with spec.expose, two-sided consent, a bounded source filter — and why a NAT subnet router is not the answer."
---

*A shop backend was moved into the `prod-1` cluster and is published on the tailnet as
`shop.prod-1.tailnet.example.internal` (a `TailnetIngress`). The ERP on the legacy host
`192.0.2.77` still has to call it. The ERP has no tailnet client and will not get one; the site
runs its own cluster (`site-1`) in the same LAN.*

This is the migration gap: once a service moves into the tailnet, everything that stayed behind
loses it. The fix is **a bridge in the site cluster** — a `TailnetEgress` that dials the ingress by
name and, with `spec.expose`, is itself reachable from the LAN on a LoadBalancer address. The
legacy host dials an IP in its own network; the egress agent carries the connection into the
tailnet under its own tag. Nothing is routed, nothing is NATed through, and both ends say who may
use the bridge.

## The shape

```text
192.0.2.77 (ERP) ──► 192.0.2.200:443 (LoadBalancer, site-1) ──► egress agent (tag:egress-shop-bridge)
                                                                       │ tailnet
                                                                       ▼
                                                     ingress-shop (prod-1, allowFrom: tag:egress-shop-bridge)
```

Three parties consent, none alone is enough:

| Who | Where | What it decides |
| --- | --- | --- |
| Service owner (`prod-1`) | `TailnetIngress.spec.allowFrom` | which tags may dial the service — the bridge's tag must be listed |
| Bridge owner (`site-1` tenant) | `TailnetEgress.spec.expose.allowFrom` | which LAN hosts may use the bridge, as bounded prefixes |
| Tailnet admin | `Tailnet.spec.exposeSourceAllowlist` | which LAN prefixes any tenant may ever expose to — the veto |

## 1. Admin: allow the site prefixes

On the `Tailnet` of the site cluster, list the client prefixes bridges may admit. Empty means no
egress can be exposed.

```yaml
apiVersion: tsunaro.io/v1alpha1
kind: Tailnet
metadata:
  name: corp
spec:
  # …
  exposeSourceAllowlist: [192.0.2.0/24]
```

Keep it as narrow as the organisation allows: the server VLAN, not the whole site. A tenant may
only request prefixes *inside* these.

## 2. Service owner: grant the bridge tag

In `prod-1`, the ingress lists the bridge's tag. That grant is the only thing that lets the agent
reach the service; the LAN side has no say in it.

```yaml
apiVersion: tsunaro.io/v1alpha1
kind: TailnetIngress
metadata:
  name: shop
  namespace: shop
spec:
  tailnetRef: { name: corp }
  allowFrom: [group:shop, tag:egress-shop-bridge]
  exposes:
    - { name: shop, port: 443, backend: { service: shop, port: 8443 } }
```

The tag defaults to `tag:egress-<name>` of the egress CR (`Tailnet.spec.tagTemplate`). With
operator-owned policy the grant is rendered; without it, write `{src: [tag:egress-shop-bridge],
dst: [tag:ingress-shop], ip: [tcp:443]}` yourself.

**HTTP ingress and the site's name.** The ingress above is L4: the agent passes TLS through and
the ERP must dial the service's real name. If the ingress instead terminates TLS (`mode: http`),
the agent only answers SNI it holds a certificate for, and the ERP dials whatever the site DNS
calls the bridge (`shop.site.example.internal`). Give the expose that name as a **bridge name**;
the admin first allows the zone on the Tailnet:

```yaml
# Tailnet (admin)
spec:
  bridgeNameAllowlist: [site.example.internal]
---
# TailnetIngress (service owner)
spec:
  exposes:
    - name: shop
      mode: http
      port: 443
      bridgeNames: [shop.site.example.internal]
      backend: { service: shop, port: 8443 }
```

A bridge name becomes an extra certificate SAN and SNI route of that expose — nothing else: the
operator neither renders it into the hosts file nor claims it across CRs, the site DNS owns it.
It must be a proper subdomain of an allowed zone and must not lie in the tailnet name or alias
zone; otherwise `TLSReady=False/BridgeNameDenied`. The certificate is still issued by the
ingress's issuer, so the ERP must trust that CA ([Ingress: HTTPS](ingress-https.md#bridge-names)).

## 3. Bridge owner: the exposed egress

In the site cluster's operator namespace:

```yaml
apiVersion: tsunaro.io/v1alpha1
kind: TailnetEgress
metadata:
  name: shop-bridge
  namespace: tailnet-system
spec:
  tailnetRef: { name: corp }
  consumerNamespaces: [shop-legacy]     # in-cluster consumers, if any; required by the schema
  targets:
    - { name: shop, address: shop.prod-1.tailnet.example.internal, port: 443 }
  expose:
    allowFrom: [192.0.2.77/32]           # the ERP host, nothing else
    loadBalancer:
      annotations: { example.com/address-pool: legacy }   # whatever your LB implementation reads
```

Full examples with comments: [`deploy/examples/tailnetegress-bridge.yaml`](https://app.radicle.xyz/nodes/seed.this-is-fine.io/rad:z46fGxuhyvDV57psA8s6Q6PdHJrsX/tree/deploy/examples/tailnetegress-bridge.yaml) — the same file the site's guided tour shows — and, for the HTTP ingress with a bridge name, [`deploy/examples/tailnetingress-bridge.yaml`](https://app.radicle.xyz/nodes/seed.this-is-fine.io/rad:z46fGxuhyvDV57psA8s6Q6PdHJrsX/tree/deploy/examples/tailnetingress-bridge.yaml).

What the operator renders:

- The target **Service** `shop` becomes `type: LoadBalancer` with `externalTrafficPolicy: Local`
  (fixed, see [Security](#security-what-the-bridge-is-and-is-not)), no NodePorts, and your
  `loadBalancer.class`/`annotations`/`labels` passed through. Address assignment is the cluster's
  job — MetalLB, Cilium LB-IPAM/BGP, kube-vip, a cloud controller; the operator does not pick IPs.
- The agent **NetworkPolicy** gains an `ipBlock` rule: exactly `allowFrom`, exactly the proxy listen
  ports. Not the health port, not everything.
- The target is a **MagicDNS name**, so no subnet route is involved: `status.targets[].route` is
  empty and `present` is true; `TargetsReachable` tells you whether the far ingress accepts the
  tag (its probe dials the name through the tailnet).

```sh
kubectl -n tailnet-system get tailnetegress shop-bridge -o jsonpath='{range .status.conditions[*]}{.type}={.status}/{.reason}{"\n"}{end}{.status.expose}'
# TagKnown=True/Known  Registered=True/Registered  RoutesGranted=True/AllGranted
# TargetsReachable=True/AllReachable  Exposed=True/AddressAssigned  Ready=True/Ready
# {"addresses":["192.0.2.200"]}
```

## 4. Site: DNS and firewall

The operator stops at the LoadBalancer address. Two things stay with the site:

- **DNS.** Give the ERP a name it can use: an A record `shop.site.example.internal → 192.0.2.200`
  in the site DNS (take the address from `status.expose.addresses`). If the far service checks the
  TLS server name, the ERP must dial the *real* name — add `shop.prod-1.tailnet.example.internal`
  itself as that record, or use a target alias so the agent's hosts file carries it. The L4 tunnel
  passes SNI through untouched. If the far ingress terminates TLS itself (`mode: http`), give it the
  site name as a bridge name instead ([§ 2](#2-service-owner-grant-the-bridge-tag)) — then the
  site record is the only record needed and the tailnet zone stays out of the site DNS.
- **Firewall.** If the ERP sits in another VLAN than the cluster nodes, open `192.0.2.77 →
  192.0.2.200:443` there as well. The NetworkPolicy is the second filter, not the only one.

## Status and reasons

| Condition | Reason | Meaning |
| --- | --- | --- |
| `Exposed=False` | `Denied` | an `allowFrom` entry is outside `Tailnet.spec.exposeSourceAllowlist` (or the list is empty). The egress is rendered **without** the expose: Services stay ClusterIP, no `ipBlock`. `Ready` is `False/Denied`. |
| `Exposed=False` | `PendingAddress` | a target Service has no LoadBalancer address yet. Usually no LB implementation, an exhausted pool, or a `class`/pool selector nothing claims. `kubectl -n tailnet-system describe svc shop` shows the implementation's events. |
| `Exposed=True` | `AddressAssigned` | every target Service has an address; listed in `status.expose.addresses`. |
| `TargetsReachable=False` | `Unreachable` | for a DNS-named target: the name resolved but the dial failed — usually the far ingress does not grant the bridge tag. Check the ingress `allowFrom` and `ingressSourceAllowlist` on its Tailnet. |
| `TargetsReachable=False` | `NameUnresolved` | the target name did not resolve: use its MagicDNS name `<hostname>.<base_domain>`, or grant the egress tag `:53` to the split-DNS zone's resolver. |
| `TLSReady=False` (far ingress) | `BridgeNameDenied` | a `bridgeNames` entry is not a proper subdomain of a zone in `Tailnet.spec.bridgeNameAllowlist` (or the list is empty), or lies in the tailnet name/alias zone. Nothing is rendered for the ingress until fixed. |

`kubectl get tneg` shows `Ready`; `Exposed` and `status.expose.addresses` are in the full status.

## Security: what the bridge is and is not

The bridge must not become a free pass from the LAN into the tailnet. These properties make it
narrow, and they are the reason it is a feature rather than a `Service` someone edits by hand:

- **Per-service, not per-network.** The egress reaches *one* set of targets, each a `host:port`;
  there is no route into the tailnet and the agent accepts none. A compromised ERP can reach the
  shop API — not the cluster API, not the other spokes, not the next tenant.
- **Two-sided consent.** The LAN side cannot grant itself anything: the service owner's
  `allowFrom` is a tailnet grant on *their* side and the admin's `ingressSourceAllowlist` bounds it.
  Removing the tag from `allowFrom` cuts the bridge at once.
- **Bounded sources, admin veto.** `expose.allowFrom` is required, rejects a default route and
  anything wider than `/16` (IPv4) or `/48` (IPv6) at admission, and every entry must lie inside
  the admin's `exposeSourceAllowlist`. Shrinking the allowlist closes already running bridges on the
  next reconcile.
- **The filter needs the real client address.** `externalTrafficPolicy: Local` is fixed so the LB
  does not SNAT and the `ipBlock` sees `192.0.2.77`, not a node address. This holds for L2/BGP
  implementations that forward to the node running the Pod (MetalLB, Cilium LB-IPAM, kube-vip)
  and for cloud NLBs with client IP preservation. **It does not hold** behind a proxying LB or an
  upstream NAT: then the `ipBlock` sees the proxy and either admits everyone behind it or nobody.
  The operator cannot detect this — it reports `AddressAssigned`, not "filter effective". Verify
  once from an *unlisted* host that the connection is refused.
- **Identity on the tailnet is the tag.** Traffic leaves the bridge as `tag:egress-shop-bridge`;
  the far side sees that tag, never the ERP's address. Audit on the tailnet therefore attributes
  calls to the bridge, not to individual LAN hosts — name the bridge after its consumer and keep
  one bridge per legacy system if you need that attribution.
- **No UDP, no ICMP, TCP only** — as for every agent ([Limitations](../reference/limitations.md)).

## Without a cluster at the site (fallback)

If the legacy network has no Kubernetes cluster, the same shape is built by hand: one small host
("proxy box") with a Tailscale client under its own tag and a TCP listener per published service.
It is the bridge without the operator — plan for the pieces the operator would otherwise render:

- a tag per box (`tag:proxy-erp`), granted on the service owner's ingress exactly as above;
- a listener per target (`socat` or HAProxy in TCP mode; `tailscale serve` works the other way
  round — the box has to *dial* the tailnet), bound to the LAN address, forwarding to
  `shop.prod-1.tailnet.example.internal:443`;
- a host firewall that admits only the legacy clients to those ports — the `ipBlock` by hand;
- `--accept-routes=false` and no `--advertise-routes`: a proxy box is not a router;
- monitoring of the listener and of the dial: there is no `TargetsReachable` for you.

The box has the same security properties as the cluster bridge *if* every item is kept. The
operator version exists so that they are kept by construction.

## Not this: a NAT subnet router

The tempting shortcut is a Tailscale subnet router on the LAN that advertises the legacy prefix and
masquerades (SNAT) LAN clients into the tailnet. It "just works" and is wrong for this problem:

- It exposes the **whole tailnet** (everything the router's tag may reach) to the **whole prefix**
  — the opposite of per-service consent. Grants are then written against the router tag, so every
  LAN host inherits every grant.
- With SNAT the far side sees the router, so neither Headscale grants nor the far ingress can tell
  the ERP from the next host; without SNAT you need return routes on every target and the tailnet
  ACL model stops meaning what it says.
- A legacy VPN that already gives developers wide subnet access is the same shortcut at a bigger
  scale; migrating a service into the tailnet is the moment to stop extending it.

Use the subnet router for what it is for — reaching the *site* from the tailnet
([Gateway](gateway.md), [TailnetSite](site-network.md)) — and bridge the other direction per
service.

## See also

- [Egress: reach services at the site](egress.md) — targets, aliases, SNI
- [Connect a second cluster](second-cluster.md) — names and grants between clusters
- [Security model](../explanation/security-model.md) · [Reasons](../reference/reasons.md)
