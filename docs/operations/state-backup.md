---
title: "State, backup and loss"
weight: 20
description: "What the operator owns, what must be backed up, behaviour while the operator is down, and restore after a lost namespace."
---

Everything the operator owns is either declarative (re-derived from the CRs on the next reconcile) or
one of the objects below. Back up the **must back up** rows with the rest of the cluster; nothing else
in the operator namespace needs a backup.

| Object | Owner | Loss means | Backup |
| --- | --- | --- | --- |
| CRs (`Tailnet`, `TailnetEgress`, `TailnetIngress`, `TailnetSite`, `TailnetGateway`) | you (Git) | nothing — redeploy from Git | Git is the backup |
| Secret `headscale-bootstrap` (bootstrap API key) | you | no new working key can be minted; running agents keep working until their pre-auth key expires | **must back up** (or be able to mint a new key on Headscale) |
| Secret `<tailnet>-apikey` (working key) | operator | re-minted from the bootstrap key at the next reconcile | no |
| Secret `<cr>-authkey` (agent pre-auth key) | operator | re-minted; the agent pod restarts and re-registers as the same node name | no |
| ConfigMaps `tailnet-dns-hosts`, `<base>-rendered` | operator | rewritten at the next reconcile | no |
| Headscale policy (live document) | operator in `Apply`, you in `DryRun` | base policy lives in Git/ConfigMap; the render is deterministic | base ConfigMap source in Git |
| Secret `<gateway>-state` (tsnet node state) and ConfigMaps `<gateway>-auth-receipt`, `<gateway>-fresh` | operator, written once | gateway node identity is gone: delete the CR (`deletionPolicy: Delete` removes the Headscale node) and create it again | **must back up** together, see [gateway reference](../reference/gateway.md#key-and-expiry-lifecycle) |
| Headscale database | Headscale | out of scope here; every operator-managed node, key and the applied policy live in it | per your Headscale runbook |

Behaviour when the operator itself is down: agent pods keep forwarding, Services and NetworkPolicies
stay in place, the CoreDNS hosts file keeps resolving, and the live policy stays applied. What stops
is change: no key rotation (alert on `tailnet_*_expires_seconds` flat-lining), no new CRs, no status
updates. Restore the Deployment before the shortest key lifetime elapses (`authKeyLifetime`, default
168h) and nothing else needs attention.

Restore after a lost namespace: install the chart, recreate `headscale-bootstrap`, apply the CRs. Egress
and ingress agents register as new Headscale nodes with the same names; delete the stale nodes with
`headscale nodes delete` once the new ones are online (the old ones also age out as ephemeral nodes).
A gateway without its `-state` Secret is a new node and needs the full fresh bootstrap; see the
[rollback table](../reference/gateway.md#rollback).
