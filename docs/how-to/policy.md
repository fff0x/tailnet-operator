---
title: "Let the operator own the policy"
weight: 70
description: "What is generated, DryRun review, migrating Headscale from file mode, Apply, base tests, reading the render, changing the base, drift and rollback."
---

Without this section every new target means four policy edits plus a route. With it, the CR is the
only input: the operator renders your **base** document plus what the CRs imply and writes the result
to Headscale.

## What is generated

| From | Into | Entry |
| --- | --- | --- |
| every egress/ingress tag | `tagOwners` | `tag: policy.tagOwners` (base entry wins if present) |
| every egress target with an IP address | `autoApprovers.routes` | `/32: policy.routeApprovers` (merged into an existing list) |
| every `TailnetGateway` tag of this Tailnet | `tagOwners` | `tag: policy.tagOwners` (base entry wins if present) |
| every route of a `TailnetGateway` of this Tailnet (LAN, `tailnetLBCIDR`, egress host routes) | `autoApprovers.routes` | `prefix: the gateway's own spec.tags` (merged into an existing list) |
| every egress, per port | `grants` | `{src: [tag], dst: [/32…], ip: ["tcp:port"]}` |
| every ingress with `allowFrom` | `grants` | `{src: allowFrom, dst: [tag], ip: ["tcp:port"…]}` — only if every source matches `ingressSourceAllowlist` |

Nothing is ever removed from the base; identical grants are not duplicated; unknown blocks (`ssh`,
`tests`, `nodeAttrs`, …) pass through. Targets addressed by **name** get no grant (a policy cannot
route a name) and are listed in the `PolicyRendered` message.

**Route approval replay.** Headscale's `autoApprovers` act only on a route *change* event, so a route
advertised before its approver existed stays "available, not approved". After every successful write
(and every `InSync` check) the operator lists the nodes and approves each advertised route that lies
inside an `autoApprovers.routes` prefix of the rendered policy naming one of the node's tags —
exactly what the event would have done, nothing more. Approvals are never removed. Events
`RoutesApproved` / `RouteApprovalFailed` on the `Tailnet` show what happened.

A fresh `TailnetGateway` is covered by the same replay: its tags and the routes it advertises are
rendered into the policy, so its node gets them approved without a manual `approve-routes`. The
gateway's `RoutesInSync` condition reports the result and never writes an approval. Caveat: a
prefix approved for the gateway's tag is also approvable for any other node carrying that tag.
Gateways whose routes do not plan are left out and named in the `PolicyRendered` message
(`gateway/<name>`).

## Enable in DryRun

Put the base policy into a ConfigMap in the operator namespace (Git-managed; the example works):

```sh
kubectl -n tailnet-system create configmap headscale-policy --from-file=policy=deploy/examples/policy-base.jsonc
```

```yaml
kind: Tailnet
spec:
  policy:
    baseConfigMap: headscale-policy         # key "policy"
    mode: DryRun                            # render only
    tagOwners: [group:operator]
    routeApprovers: [tag:fabric]
    ingressSourceAllowlist: ["group:*"]     # what tenants may put into allowFrom
```

```sh
kubectl describe tailnet corp | grep -A1 Policy
#   PolicyRendered  True   Rendered   2 tags, 2 grants, 1 routes generated
#   PolicyApplied   False  DryRun     mode DryRun: review ConfigMap tailnet-system/headscale-policy-rendered
kubectl -n tailnet-system get cm headscale-policy-rendered -o jsonpath='{.data.policy}' \
  | kubectl -n tailnet-system exec -i deploy/headscale -- headscale policy check -f /dev/stdin
# Policy is valid
```

## Migrating from file mode

Headscale accepts `PUT /api/v1/policy` only in `database` mode. Switch and import in **one** step —
with an empty policy table Headscale answers `GET /api/v1/policy` with 500 and applies no policy:

1. Add a `tests` block to the base (see the example) — Headscale rejects any write whose tests fail.
2. Set `policy.mode: database` in the Headscale config (`HEADSCALE_POLICY_MODE=database`); keep the
   file mounted for the import and for rollback. If Stakater Reloader (or similar) restarts Headscale
   on ConfigMap changes, exclude the policy ConfigMap (`configmap.reloader.stakater.com/reload` with
   an explicit list instead of `reloader.stakater.com/auto`) — in database mode a base edit needs no
   restart, and every restart is a policy-less window plus `ApplyFailed` noise.
3. Restart Headscale and import immediately:

   ```sh
   kubectl -n tailnet-system exec deploy/headscale -- sh -c 'headscale policy set -f /acl/policy && headscale policy get | head -3'
   ```

4. Check that members still reach what they should (your own device → Kubernetes API is a good probe).

## Apply

```yaml
spec:
  policy:
    mode: Apply
```

```sh
kubectl get tailnet corp
# NAME   SERVER                   APIKEY   EXPIRES                COMPAT       POLICY    DNS            AGE
# corp   https://ts.example.com   True     2026-10-28T12:00:00Z   Compatible   Applied   Configured     3d
```

From now on: **never run `headscale policy set` by hand.** The operator compares the live document
with its render every 5 minutes (and on every CR change) and rewrites it when they differ — a manual
change is overwritten and reported as event `PolicyDriftOverwritten`. Change the base ConfigMap
in Git instead. Once the operator generates the tenant blocks, delete them from the base; the render
does not change (the union is the same), but the base gets shorter and cannot drift.

`status.policy` carries `renderedHash`, `appliedHash`, `appliedAt` and `generated{tags,grants,routes}`;
metrics `tailnet_policy_applied_timestamp_seconds` and `tailnet_policy_apply_errors_total` back an
alert (`time() - applied > 900` while `renderedHash != appliedHash`).

## Base `tests` — what they can and cannot assert

Headscale evaluates the base's `tests` on every write, including the operator's `PUT`. A failing
test rejects the whole document (`PolicyApplied=False/PolicyRejected`) and the previous policy
stays live. Rules found on Headscale v0.29:

- `dst` must be a single host or IP (`"site-dns:53"`), no CIDR.
- `src` must resolve to **existing nodes** — a generated tag has no node until the operator applied
  the tag, so it deadlocks as `src`. Use long-lived tagged nodes (a router, a bot).
- A member `src` (`alice@`) evaluates as ALLOWED for every `dst` and discriminates nothing.
- The base must pass `headscale policy check -f` **on its own** (that is also the rollback import), so
  tests cannot assert generated grants — only that the base never widens what a tenant proxy may do.

```sh
kubectl -n tailnet-system exec -i deploy/headscale -c headscale -- headscale policy check -f /dev/stdin < policy.jsonc
```

## Read what the operator generated

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
(`site/<name>`, see [Declare a site network](site-network.md)).
`renderedHash == appliedHash` means Headscale runs exactly this document.

## Change the base policy (admin)

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

Agents of *other* clusters on the same Headscale (spoke Tailnets without a policy block) are not
generated here. Either declare their tags and grants in this base policy by hand — see
[Tailnet without a policy writer](ingress-tcp.md#tailnet-without-a-policy-writer-spoke-cluster) — or
let the spoke export them and merge the fragment, below.

## Review before Apply, drift, rollback

| Want | Do |
| --- | --- |
| See what Apply would write | `mode: DryRun`, read `headscale-policy-rendered`, validate: `… \| kubectl -n tailnet-system exec -i deploy/headscale -- headscale policy check -f /dev/stdin` |
| Compare live and render | `kubectl get tailnet corp -o jsonpath='{.status.policy.appliedHash} {.status.policy.renderedHash}'` — equal = in sync |
| Find manual changes | `kubectl get events -A --field-selector reason=PolicyDriftOverwritten` |
| Stop the operator writing | `mode: DryRun` |
| Restore the Git policy on the server | `mode: DryRun`, then `headscale policy set -f /acl/policy` |

Full procedures in [Rollback](upgrade-rollback.md#rollback).

## Second cluster: export on the spoke, merge on the hub

Only one operator per Headscale writes the policy (the *hub*, `mode: Apply`). A second cluster (a
*spoke*) cannot write — but instead of the hub admin hand-copying each spoke tag and grant, the spoke
renders exactly what its own CRs imply into a **fragment** and the hub merges it.

On the spoke, run the policy generator in Export mode (no base, nothing is written to Headscale):

```yaml
kind: Tailnet
spec:
  policy:
    mode: Export                 # render only this cluster's generated entries
    tagOwners: [group:operator]  # the owner stamped on the exported tags
    routeApprovers: [tag:fabric]
    ingressSourceAllowlist: ["group:*"]
```

```sh
kubectl describe tailnet corp | grep -A1 Policy
#   PolicyRendered  True   Rendered   3 tags, 3 grants, 1 routes exported
#   PolicyApplied   False  Export     mode Export: commit ConfigMap tailnet-system/corp-policy-fragment to the hub and list it in policy.fragmentConfigMaps
```

Copy the fragment into the hub cluster as a ConfigMap (key `policy`) and commit it to the hub's
GitOps repo — that Git review **is** the gate for the spoke's grants, the same review the hand-written
entries went through:

```sh
kubectl -n tailnet-system get cm corp-policy-fragment -o jsonpath='{.data.policy}' > spoke-corp.json
# review spoke-corp.json, then (in the hub repo) ship it as ConfigMap tailnet-system/spoke-corp-fragment
```

On the hub, list the fragment ConfigMaps next to the base:

```yaml
spec:
  policy:
    baseConfigMap: headscale-policy
    mode: Apply
    fragmentConfigMaps: [spoke-corp-fragment]   # key "policy", operator namespace
    tagOwners: [group:operator]
    routeApprovers: [tag:fabric]
```

The hub renders base → its own CRs → fragments; base and hub entries win, fragments only add. A
spoke may only add `tagOwners`, `autoApprovers.routes` and `grants` — a fragment carrying any other
block (`acls`, `groups`, `ssh`, …) is rejected with `PolicyRendered=False/FragmentInvalid` and
nothing is written. A **listed fragment that is missing** fails the render closed
(`PolicyRendered=False/FragmentMissing`): the live policy keeps the spoke's grants rather than
silently dropping them, so delete the fragment from `fragmentConfigMaps` before you delete its
ConfigMap.

Until the hub applies the merged policy, the spoke's own CRs report `TagKnown=False/Unknown` — that
gap is the review window for the foreign grants. Names, DNS zones, cross-cluster grants and the
repository layout for a spoke are in [Connect a second cluster](second-cluster.md).
