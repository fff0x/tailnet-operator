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
| CRs (`Tailnet`, `TailnetEgress`, `TailnetIngress`, `TailnetSite`, `TailnetGrant`, `TailnetGateway`) | you (Git) | nothing — redeploy from Git | Git is the backup |
| Secret `headscale-bootstrap` (bootstrap API key) | you | no new working key can be minted; running agents keep working until their pre-auth key expires | **must back up** (or be able to mint a new key on Headscale) |
| Secret `<tailnet>-apikey` (working key) | operator | re-minted from the bootstrap key at the next reconcile | no |
| Secret `<cr>-authkey` (agent pre-auth key) | operator | re-minted; the agent pod restarts and re-registers as the same node name | no |
| ConfigMaps `tailnet-dns-hosts`, `<base>-rendered`, `<tailnet>-policy-fragment` | operator (label `tsunaro.io/role`) | rewritten at the next reconcile; an ownerRef-less one carrying that label is re-adopted, a foreign one is refused with event `ConfigMapNotOwned` | no |
| Headscale policy (live document) | operator in `Apply`, you in `DryRun` | base policy lives in Git/ConfigMap; the render is deterministic | base ConfigMap source in Git |
| Secret `<gateway>-state` (tsnet node state) and ConfigMaps `<gateway>-auth-receipt`, `<gateway>-fresh` | operator, written once | gateway node identity is gone: delete the CR (`deletionPolicy: Delete` removes the Headscale node) and create it again | **must back up** together, see [gateway reference](../reference/gateway.md#key-and-expiry-lifecycle) |
| TailnetGrants with label `app.kubernetes.io/managed-by: tailnet-console` | console admins | the access they grant is gone; Git does not have them | with the other CRs (for example a Velero backup of `tailnetgrants.tsunaro.io`) |
| TailnetAccessRequests (`tnar`) | console | pending requests are gone and must be made again; decided ones are only a record, the audit log has them too. Their approvals are in the audit log, not in the request | with the other CRs (`tailnetaccessrequests.tsunaro.io`), status included |
| PersistentVolumeClaim `<name>-console-audit` (`audit.jsonl`) | console, append-only | who changed which access is lost, and pending requests lose their approvals; the console starts a new log and reports the missing anchor as a break | **must back up**, together with the ConfigMap below |
| ConfigMap `<name>-console-audit` (head of the audit chain) | console | the console reports a break and continues; restored without the volume (or the reverse), the head no longer matches and the page lists that as a break | **must back up** with the volume, from the same moment |
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
