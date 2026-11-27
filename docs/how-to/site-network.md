---
title: "Declare a site network (TailnetSite)"
weight: 80
description: "Declare a remote network behind a subnet router once, let the operator render and replay the approvals, and block overlaps with reserved networks."
---

*A branch office (or a management range, or a lone printer) sits behind a subnet router, and
people as well as workloads must reach it. Today its prefixes are `autoApprovers` lines in the
base policy that must stay identical to the router's advertised routes.*

A `TailnetSite` declares the network once, in the cluster whose operator owns the policy
(`policy.mode: Apply`). The router can be an operator-managed `TailnetGateway` ([the worked example](gateway.md#worked-example))
**or any router carrying the tag, in this or another cluster** — the operator identifies it by tag, not by CR
(fixture: [`deploy/examples/tailnetsite.yaml`](https://app.radicle.xyz/nodes/seed.this-is-fine.io/rad:z46fGxuhyvDV57psA8s6Q6PdHJrsX/tree/deploy/examples/tailnetsite.yaml)):

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
| Appends `autoApprovers.routes[<prefix>] = advertisedBy.tags` to the rendered policy | Render a grant: **who may reach the site is a grant in the base policy** (`dst: 10.0.102.0/24`) **or a [`TailnetGrant`](grants.md)** with `target.prefixes` inside the site |
| Replays the approval on every node carrying an advertiser tag that advertises the prefix | Advertise anything: the router's own route list (`--advertise-routes`, `TS_ROUTES`) is still yours |
| Reports `Advertised` / `Approved` / `Ready` per site from the control server's node list | De-approve or withdraw routes, ever |
| Blocks a site whose prefix overlaps `Tailnet.spec.reservedNetworks` or an **older** site | Touch the older site: a conflict never flips an already-serving network |

Fill `Tailnet.spec.reservedNetworks` first — address space that must never become a tailnet route:
the node prefix and every cluster's pod and service ranges on this control server. Otherwise a typo
like `100.64.8.0/22` in CGNAT space would be approved onto the routers:

```yaml
spec:
  reservedNetworks:
    - {name: nodes,  prefixes: [100.64.0.0/16]}
    - {name: prod-1, prefixes: [10.244.0.0/16, 10.96.0.0/12]}
```

Never list a network a router advertises — a LAN, a gateway's tailnet-LB range. That network is
declared as a site or through the gateway, and a reserved entry blocks both the site
(`OverlapsReserved`) and every spoke fragment that carries a route inside it.

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
| `Ready` | `NotObserved` | The control server was not queried in this reconcile (DryRun or Export without a working key, API failure). |

**On a spoke** (`policy.mode: Export`) a site adds its prefixes to the exported fragment and reports
the same conditions from the node list. The spoke never approves a route: `Approved` stays
`NotApproved` until the hub has merged the fragment and replayed the approval. The hub accepts the
route only inside one of its own `TailnetSite` or `routeAllowlist` prefixes, so a network the hub
already declares needs no site on the spoke. Declare the network in front of the spoke's API on the
hub — the hub must reach it before it can read the fragment
([Connect a second cluster](second-cluster.md#2a-reach-the-spoke-api-through-the-tailnet)).

Migrating existing `autoApprovers` lines: create the sites, keep the old entries until
`renderedHash` equals today's live policy (the render is a set union, so the document does not
change), then delete the base lines in Git. Rollback is deleting the `TailnetSite` CRs — approvals
already granted stay, because the operator never de-approves.
