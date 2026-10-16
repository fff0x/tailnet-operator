---
title: "Run the gateway (subnet router + split-DNS)"
weight: 90
description: "One-time wiring (kernel prerequisites, LB pool, split-DNS, CoreDNS forward) and the complete worked example of a TailnetGateway with LB pool, iBGP, split-DNS and site."
---

Optional. A `TailnetGateway` is the operator-managed subnet router and resolver in one Pod: kernel Tailscale advertising
`routes.lan ∪ service.tailnetLBCIDR ∪ {egress targets}/32`, and a CoreDNS serving the hosts file of
[DNS with CoreDNS](dns-coredns.md) as the authoritative zone. It is fresh-only — a new node with a persistent identity; an existing
router is never adopted. The complete worked example (manifest, LB pool, iBGP, split-DNS, site) is
[the worked example](#worked-example); the contract
(receipts, immutability, deletion) is the [gateway reference](../reference/gateway.md).

## Prerequisites

| Requirement | Why | Check |
| --- | --- | --- |
| `/dev/net/tun` on the nodes and `net.ipv4.ip_forward=1` visible in the Pod network namespace (Talos inherits it from the host; elsewhere allow the namespaced `net.ipv4.ip_forward` unsafe sysctl) | kernel Tailscale; an unprivileged init container only *checks* and fails startup otherwise | `kubectl -n tailnet-system logs prod-1-gw-0 -c kernel-preflight` after the first start |
| Pod Security admission in the operator namespace permits `NET_ADMIN` (level `privileged`, or an exemption) | the Tailscale container needs exactly that capability, no host network, no privilege escalation | `kubectl get ns tailnet-system -o jsonpath='{.metadata.labels}'` |
| A LoadBalancer implementation with a pool whose selector matches `service.poolLabels` and whose CIDR contains `service.loadBalancerIP` | the LB IP is the split-DNS nameserver peers dial; `tailnetLBCIDR` is advertised so peers reach every IP of the pool | `kubectl -n tailnet-system get svc prod-1-gw` shows an `EXTERNAL-IP` |
| A free, stable ClusterIP for `dns.serviceClusterIP` | the cluster CoreDNS forwards the zone to it; immutable | `kubectl get svc -A -o jsonpath='{.items[*].spec.clusterIP}' \| tr ' ' '\n' \| grep 10.96.0.54` prints nothing before creation |
| `Tailnet.spec.policy.mode: Apply` with the gateway tag in `routeApprovers` and `tagOwners` set — or a hand-maintained policy with matching `tagOwners` and `autoApprovers.routes` | routes are approved automatically only when the operator owns the policy | `kubectl get tailnet corp` shows `POLICY=Applied` |
| Headscale `dns.nameservers.split` for the zone → the LB IP (manual; Headscale has no DNS API) | peers must ask the gateway for `*.<zone>` | `Tailnet` reports `SplitDNS=Unknown/CannotVerify`, by design |
| Backup of the state Secret and the receipt ConfigMaps | the node identity lives there; without them the gateway is a new node | [State, backup and loss](../operations/state-backup.md) |

## Order

1. Pool and (if used) BGP for the tailnet LB range exist and announce.
2. `Tailnet.spec.policy` is `Apply` ([Apply](policy.md#apply)) or the policy carries the tag and routes by hand.
3. Apply the `TailnetGateway` with `suspend: false` ([worked example](#worked-example)). Within about a minute:
   `kubectl get tailnetgateway` → `READY=True`; `RoutesInSync=True/Approved` after the next policy
   reconcile (≤ 5 min).
4. Set the Headscale split-DNS entry; add the cluster CoreDNS `forward` for the zone to
   `dns.serviceClusterIP` ([Wire the cluster CoreDNS](dns-coredns.md#wire-the-cluster-coredns) form, upstream = the gateway's DNS Service). Repeat both for
   every `dns.extraZones[]` zone the gateway serves for a legacy network ([Extra zones for legacy networks](#extra-zones-for-legacy-networks)).
5. Declare the LAN as a `TailnetSite` ([Declare a site network](site-network.md)) so overlaps are blocked and the site has a status.
6. Verify from both sides: a Pod resolves `api.<zone>` through the cluster CoreDNS; a tailnet peer
   resolves `router.<zone>` through split-DNS and reaches `192.0.2.1` through the gateway.

Done when `Ready=True`, `RoutesInSync=True/Approved`, `ServiceReady=True/LoadBalancerAssigned`,
`WorkloadCurrent=True/PodCurrent`, and the alert `TailnetGatewayFreshBlocked` is silent.
`ClusterDNSForward` and `StaleNodes` stay `Unknown/ExternallyManaged`: they are yours.

## Afterwards

The operator never restarts the gateway Pod. Image and route changes are written into the
StatefulSet template and applied when *you* delete `prod-1-gw-0` (`WorkloadCurrent=False/PodTemplateStale`
until then). Rollback of the operator keeps the gateway running — see the
[rollback table](../reference/gateway.md#rollback); a downgrade below 0.11.0 is not supported for an
existing gateway. Deleting the CR with the default `deletionPolicy: Retain` keeps node, Secret and
resources; `Delete` is the explicit teardown ([deletion](../reference/gateway.md#deletion)).

## Worked example

*`prod-1` sits in a datacenter LAN `192.0.2.0/24` (router `192.0.2.1`). Tailnet peers must reach
that LAN, the cluster's tailnet-facing LoadBalancer IPs, and every egress target the operator
manages — and resolve `*.prod-1.tailnet.example.internal` from the gateway. The
cluster already runs Cilium with an IP pool and iBGP to the LAN router.*

A `TailnetGateway` is one kernel-mode Tailscale Pod (subnet router, `NET_ADMIN`, no host
network) plus a CoreDNS that serves the operator's hosts file as an authoritative zone. The CR is
**fresh-only**: it creates a new node with a persistent identity and never adopts, updates or
replaces an existing router ([reference](../reference/gateway.md)). One-time wiring (kernel
prerequisites, LB pool, Headscale split-DNS, cluster CoreDNS forward) is in
[the one-time wiring above](#prerequisites); this recipe is the manifest and
how to read it.

## The gateway

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
    wildcardAddress: 198.51.100.80       # *.prod-1.… → shared Envoy gateway (ingress over HTTPS); dynamic names win
```

What the operator does with it, in order: render and validate; create the empty state Secret;
mint a tag-bound 24 h pre-auth key; create ServiceAccount, Role, RoleBinding, PDB, three
Services (`prod-1-gw` LoadBalancer :53, `prod-1-gw-dns` ClusterIP :53, `prod-1-gw-headless`), the
`-coredns` ConfigMap and the StatefulSet (nine objects, StatefulSet last); write the immutable `-fresh` receipt; then report `Ready` once the Pod runs,
the node is online and advertises the planned routes. The advertised set is
`routes.lan ∪ tailnetLBCIDR ∪ {egress targets}/32` — here `192.0.2.0/24`, `198.51.100.0/24` and,
from [Reach a database at the site](egress.md#reach-a-database-at-the-site), `10.0.10.20/32`. When the Tailnet owns its
policy (`policy.mode: Apply`) the policy controller renders `tag:fabric` into `tagOwners` and every
route into `autoApprovers.routes` and approves them within one policy reconcile (≤ 5 min); otherwise
approve in Headscale.

Turn `advertiseEgressTargets` off when every egress host already lies inside `routes.lan`:
covered `/32`s are not deduplicated, and each new or deleted `TailnetEgress` would mark the Pod
template stale until you delete the Pod.

## Site-provided pieces

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
Service (or to the resolver from [Bring your own resolver](dns-coredns.md#serve-the-file)):

```corefile
prod-1.tailnet.example.internal:53 {
    errors
    cache 30
    forward . 10.96.0.54 { prefer_udp }
}
```

## Declare the LAN as a site

The gateway advertises `192.0.2.0/24`; a `TailnetSite` makes that network a first-class object with
`Advertised`/`Approved`/`Ready`, metrics and the overlap guard of [Declare a site network](site-network.md).
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

## Check

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
| `Ready=False/FreshBlocked` | bootstrap blocked: key expired before registration, receipt or template drift, a pool key colliding with an operator label | alert `TailnetGatewayFreshBlocked`; runbook [OPERATIONS](../OPERATIONS.md#monitoring-gateway-fresh-blocked) |
| `RoutesInSync=False/NotApproved` | advertised but not approved | `policy.mode: Apply` with the tag in `routeApprovers`, or approve in Headscale |
| `ServiceReady=False/LBPending` | no LoadBalancer address | pool CIDR contains `loadBalancerIP`, selector matches `poolLabels`, LB controller healthy; `Ready` does not wait for this |
| `WorkloadCurrent=False/PodTemplateStale` | image or route change written to the template | delete Pod `prod-1-gw-0` when convenient; the running Pod keeps serving |
| `WorkloadCurrent=False/WorkloadUpdateBlocked` | an IPv6 route, a `tailnetLBCIDR` that no longer contains the LB IP, or an unverified StatefulSet | revert the spec; IPv6 routes are not supported yet |
| `ClusterDNSForward`, `StaleNodes` `Unknown/ExternallyManaged` | by design | the CoreDNS forward and old Headscale nodes are yours |
| peers resolve nothing | split-DNS or route | `nameservers.split` points at `198.51.100.17`; `198.51.100.0/24` approved; `dig @198.51.100.17` from a peer |

## After creation

| Change | Effect |
| --- | --- |
| `image`, `dns.image`, `routes.*`, `service.tailnetLBCIDR`, egress targets | written into the StatefulSet template; apply by deleting the Pod (`PodTemplateStale`), no restart by the operator |
| `dns.staticRecords`, `dns.wildcardAddress`, the hosts file | re-rendered live into the zone (and the extra-zone `hosts` key); no Pod change |
| `service.poolLabels` | set/removed on the Service in place |
| `deletionPolicy`, `suspend` | lifecycle only; a suspend/resume cycle keeps the identity |
| `tailnetRef`, `hostname`, `stateSecretRef`, `tags`, `replicas`, `service.loadBalancerIP`, `service.loadBalancerClass`, `dns.zone`, `dns.serviceName`, `dns.serviceClusterIP`, `dns.extraZones` | identity — admission rejects most, the rest report `IdentityChanged`; recreate with `deletionPolicy: Delete` |

## Extra zones for corporate resolvers

When peers must also resolve corporate zones whose resolvers carry
authoritative overrides (an SNI-routing proxy under `proxy.corp.example`, say),
add them as `dns.extraZones`. Names inside such a zone that appear in the Tailnet
hosts source are answered by the gateway; everything else is forwarded to the
listed upstreams. Add the zone to the Headscale split-DNS (`nameservers.split`)
pointing at the gateway LB IP, like the primary zone.

```yaml
spec:
  dns:
    zone: prod-1.tailnet.example.internal
    extraZones:
      - zone: corp.example
        upstreams: ["198.51.100.53", "198.51.100.54"]
      - zone: partner.example
        upstreams: ["198.51.100.53"]
```

Overrides come from the hosts source (`spec.dns.hostsConfigMap` of the Tailnet, i.e.
`TailnetEgress` DNS aliases and `TailnetIngress` names): an alias such as
`proxy.corp.example` on an egress makes the gateway answer it with the egress
address instead of forwarding. Only A/AAAA are served locally; other record types for
an overridden name reach the upstream. Zones must not overlap each other or the
primary zone; `dns.extraZones` is immutable after creation.

Declared in the schema but **rejected by the current writer** (`Ready=False/FreshBlocked` or
admission): `forwards[]`/`forwardImage` (TCP forwards), `authKeySecretRef`
(external bootstrap key), `adoption`, IPv6 prefixes, `replicas` other than `1`. Lifecycle, rollback
and deletion: [gateway reference](../reference/gateway.md#key-and-expiry-lifecycle).
