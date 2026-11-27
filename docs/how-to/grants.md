---
title: "Grant time-bound access (TailnetGrant)"
weight: 75
description: "Give people or policy groups TCP access to an ingress or a host inside a site, with an optional expiry that the operator enforces."
---

*A maintainer needs the production database until Friday evening. Today that is a hand-written
grant in the base policy, and somebody must remember to remove it.*

A `TailnetGrant` declares the access once, in the cluster whose operator owns the policy
(`policy.mode: Apply`). The operator renders one grant into the policy and removes it at
`expiresAt` (fixture: [`deploy/examples/tailnetgrant.yaml`](https://app.radicle.xyz/nodes/seed.this-is-fine.io/rad:z46fGxuhyvDV57psA8s6Q6PdHJrsX/tree/deploy/examples/tailnetgrant.yaml)):

```yaml
apiVersion: tsunaro.io/v1alpha1
kind: TailnetGrant
metadata:
  name: alice-shop-db
spec:
  tailnetRef: {name: corp}
  description: Maintenance of the production database
  sources:
    - https://id.example.com/59ac9125-c31b-46c5-814e-06242908cf57@   # one person
    - group:db-maintainers                                            # a group of the base policy
  target:
    tag: tag:ingress-shop        # TailnetIngress.status.tag
  ports: [5432]
  expiresAt: "2026-12-01T18:00:00Z"   # omit for a permanent grant
```

The rendered entry is `{src: sources, dst: [tag], ip: ["tcp:5432"]}`. A grant gives network access
to the port. It does not give a login: the database credentials stay with the application.

**A grant is administrative.** It bypasses the `allowFrom` of the ingress, the hub's
`ingressSourceAllowlist` and the allowlist of a spoke. Do not delegate write access to this
cluster-scoped kind to tenants ([Security model](../explanation/security-model.md#trust-model)).

## Targets

A grant has exactly one target: a tag or a list of prefixes.

| Target | Value | Valid when |
| --- | --- | --- |
| Ingress in this cluster | `target.tag`: the `status.tag` of the `TailnetIngress` | the ingress is bound to the same `Tailnet` |
| Ingress in a spoke cluster | `target.tag`: the ingress tag of the spoke | a merged fragment (`policy.spokes[]` or `fragmentConfigMaps`) carries the tag as a grant destination |
| Hosts behind a subnet router | `target.prefixes`: for example `["10.0.102.5/32"]` | each prefix lies inside a prefix of an unblocked [`TailnetSite`](site-network.md) |

A host inside a site:

```yaml
spec:
  tailnetRef: {name: corp}
  sources: [group:netops]
  target:
    prefixes: ["10.0.102.5/32", "10.0.102.6/32"]   # a /32 or /128 is a single host
  ports: [22, 443]
```

An ingress in a spoke cluster uses the tag that the spoke exports:

```yaml
  target:
    tag: tag:prod-2-ingress-shop   # kubectl --context prod-2 get tailnetingress shop -o jsonpath='{.status.tag}'
```

An ingress with an empty `allowFrom` is reachable only through grants.

The operator does not render a grant with an invalid target. Headscale rejects a whole policy that
names an undeclared tag as a destination, so one stale grant would otherwise freeze every policy
change. The grant reports `TargetUnknown` or `TargetOutsideSites`, and the other grants stay live.

## Sources

| Source | Form | Note |
| --- | --- | --- |
| Group | `group:<name>` | The base policy must declare the group in `groups`. An undeclared group is dropped and reported as `SourceGroupUnknown`; the other sources stay granted. |
| Person | a Headscale user reference with exactly one `@` | Provider identifier, e-mail address or user name. |

Use the **provider identifier** for a person. It has the form `<issuer>/<subject>@` and comes from
the field `providerId` of `GET /api/v1/user`. An e-mail address or a user name can change or be
reassigned; the provider identifier cannot.

Tags and `autogroup:` values are not accepted as a source. Workloads get access through
`TailnetIngress.spec.allowFrom`.

Headscale accepts a reference to a user it does not know. A typing error in a user reference
grants nothing and is not reported.

## Expiry

- The operator's clock decides. From `expiresAt` on, the grant is expired.
- The operator schedules its own reconcile for the next `expiresAt`. No object change is necessary.
  The integration test accepts at most 15 seconds between `expiresAt` and the removal from the
  live policy.
- An expired object stays, with `Ready=False/Expired`. The operator does not delete it. The console
  deletes its own expired grants after `console.accessManagement.retentionDays`.
- To extend a grant, set a new `expiresAt`. To make it permanent, remove the field.
- To revoke a grant early, delete the object or set `expiresAt` to a time in the past.
- With `console.accessManagement`, console admins create, extend and revoke grants in the web
  console, and every change is in its audit log ([Console](console.md#access-management)). The
  console changes only grants with `app.kubernetes.io/managed-by: tailnet-console`.
- An `expiresAt` in the past is accepted. The grant is then expired from the start.
- If the policy write fails at `expiresAt`, the access stays until a write succeeds. The grant
  reports `ExpiryPending`, and `TailnetResourceNotReady` fires after 10 minutes.

After the expiry Headscale distributes the new policy to the nodes. **New** connections are
refused. The agent of a `TailnetIngress` also closes each connection that is **already open** and
that the new policy does not permit.

Once per second the agent asks its packet filter whether each open connection could be opened
again, from the same source to the same port. If not, the agent closes the connection and its
connection to the backend. The cause of the policy change does not matter: an expired or deleted
grant, a changed `allowFrom` or a changed base policy. The check covers
`mode: l4` and `mode: http`, including WebSockets. The agent logs the number of closed
connections, without addresses.

The kind test measured an L4 ingress with a userspace (tsnet) client in three runs. It exchanges
data on the open connection once per second. The table shows when the first failed exchange
started, counted from the revocation (`expiresAt`, or the change of the object):

| Revocation | First failed exchange | The client sees |
| --- | --- | --- |
| `expiresAt`; no other rule connects the two nodes | 0.7 to 1.8 s | A timeout. |
| `expiresAt`; another rule keeps the two nodes peers | 1.5 and 2.5 s; one run between 1.4 and 6.5 s | A closed connection. |
| The grant is deleted | 1.2 to 2.2 s | A closed connection. |
| The user leaves the `allowFrom` group of the ingress | 1.2 to 2.3 s | A closed connection. |

These times include the policy write of the operator. In the run with "between 1.4 and 6.5 s" the
test did not sample in that interval. In the first row the nodes stop being peers, so the close
does not reach the client and its data stops instead. A connection of a user who stayed permitted
never failed in these runs.

The agent does not close these connections:

- **A target inside a `TailnetSite`.** The path goes through the `TailnetGateway`, and no agent is
  in it. The Tailscale packet filter checks the packet that opens a TCP connection and accepts the
  later packets of that connection (source of `tailscale.com` v1.94.1). Not measured; assume that
  the connection continues while another rule keeps the client and the gateway peers. If such a
  session must end at `expiresAt`, end it at the service.
- **An agent without contact to Headscale.** The agent checks against the last policy it received.
  A revocation that did not reach the agent has no effect there, neither on new nor on open
  connections.

Not measured in kind: `mode: http` (agent unit tests cover a keep-alive connection and a
WebSocket), a client with kernel `tailscaled` and a deleted client node.

## Check

```sh
kubectl get tailnetgrant        # short name: tngr
# NAME            TAILNET   EXPIRES                READY                AGE
# alice-shop-db   corp      2026-12-01T18:00:00Z   Granted              2m
# bob-old-db      corp      2026-11-20T18:00:00Z   Expired              9d
# carol-printer   corp                             TargetOutsideSites   1m
kubectl get tailnet corp -o jsonpath='{.status.policy.generated}'   # grants are counted here
```

The only condition is `Ready`. It is `True/Granted` when the grant is rendered and the live policy
equals the render. Otherwise it is `False` with the first reason that applies, in this order:

| Reason | Meaning | Remedy |
| --- | --- | --- |
| `NotPolicyWriter` | The `Tailnet` does not write the policy: mode `Export`, or `policy.baseConfigMap` is not set. | Create the grant in the cluster whose `Tailnet` runs `Apply`. |
| `Expired` | `expiresAt` has passed and the live policy does not carry the grant. | None. Extend or delete the object. |
| `ExpiryPending` | `expiresAt` has passed, but the operator has not confirmed that the live policy dropped the grant: mode `DryRun`, a failed write or a render that stopped. | Read `PolicyRendered` and `PolicyApplied` on the `Tailnet`. |
| `TargetUnknown` | The target tag is neither the tag of a bound `TailnetIngress` nor an ingress tag of a merged fragment. | Correct the tag, or wait for the hub to merge the spoke fragment. |
| `TargetOutsideSites` | A target prefix lies in no unblocked `TailnetSite`; the message names the prefixes. | Declare the network as a site, or resolve the `RouteConflict` of the site. |
| `SourceGroupUnknown` | A source group is not declared in the base `groups`; the other sources are granted. | Declare the group in the base policy. |
| `PolicyPending` | Rendered, but the live policy does not equal the render: mode `DryRun`, a rejected or failed write. | Read `PolicyApplied` on the `Tailnet`. |

Status messages, logs and metric labels never contain a user reference. Group names can appear.

## Limits

- **TCP only.** A grant lists 1 to 16 TCP ports. UDP, ICMP and "all ports" are not available.
- **One writer.** Only the `Tailnet` that owns the policy renders grants. On a spoke the grant
  reports `NotPolicyWriter`.
- **No status without a `Tailnet`.** A grant whose `tailnetRef` names a missing `Tailnet` gets no
  status, like a `TailnetSite`. When the `Tailnet` is deleted, the grant keeps its last status,
  also `Ready=True/Granted`; nothing updates it.
- **No status before the render.** If the policy reconcile stops before the render (the base
  ConfigMap does not exist, a fragment is invalid), a grant that is not expired keeps its previous
  status.
- **Spoke ingress outside the spoke allowlist.** A spoke exports an ingress tag as a grant
  destination only when the `allowFrom` of the ingress passes the spoke's `ingressSourceAllowlist`.
  A hub grant to an ingress that the spoke does not export reports `TargetUnknown`.
- **Open connections to a site target are not cut.** The agent of a `TailnetIngress` closes an
  open connection that the policy no longer permits. No agent is in the path to a host inside a
  `TailnetSite`; such a connection can continue after the expiry or the deletion of the grant
  ([Expiry](#expiry)).
- **`Expired` is kept.** A grant that reported `Expired` keeps this reason while its `spec` is
  unchanged, also when a later reconcile cannot compare the live policy. The operator never
  renders an expired grant again.
- **Identical grants merge.** Two grants with the same sources, target and ports produce one policy
  entry. The entry stays until the last of them expires or is deleted. A grant that equals a base
  grant adds nothing, and the base grant stays when the `TailnetGrant` expires.
- **Alert side effect.** Grants count in `tailnet_policy_generated{kind="grants"}`. When more than
  half of the generated grants expire within 10 minutes, `TailnetPolicyGeneratedDrop` fires
  ([Alerts](../reference/alerts.md)).
- **Upgrade.** Apply the `TailnetGrant` CRD before the operator that reads it
  ([Upgrade and roll back](upgrade-rollback.md)).
