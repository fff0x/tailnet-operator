---
title: "Declare a site network (TailnetSite)"
weight: 80
description: "Declare a remote network behind a subnet router once, let the operator render and replay the approvals, and block overlaps with reserved networks."
---

*A branch office (or a management range, or a lone printer) sits behind a subnet router, and
people as well as workloads must reach it. Today its prefixes are hand-written `autoApprovers`
lines that must stay identical to the router's advertised routes.*

A `TailnetSite` declares the network once, in the cluster whose operator owns the policy
(`policy.mode: Apply`). The router can be an operator-managed `TailnetGateway` ([the worked example](gateway.md#worked-example))
**or a hand-built router in another cluster** — the operator identifies it by tag, not by CR
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
