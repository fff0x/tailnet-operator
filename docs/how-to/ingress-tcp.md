---
title: "Ingress: publish a TCP service"
weight: 50
description: "Expose an in-cluster TCP service to tailnet peers as its own node with a tag and a DNS name."
---

*Team `shop` wants developers on the tailnet to reach the dev database directly, without VPN or
port-forward.*

```yaml
apiVersion: tsunaro.io/v1alpha1
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
# NAME   TAG                HOSTNAME       HOSTS                                             READY   AGE
# shop   tag:ingress-shop   ingress-shop   [shop-shop-dev.prod-1.tailnet.example.internal]   True    2m
```

From a laptop in `group:shop`: `psql -h shop-shop-dev.prod-1.tailnet.example.internal -p 5432`
(or `ingress-shop` via MagicDNS).

| Condition | Meaning | Fix |
| --- | --- | --- |
| `PolicyGranted=False/PolicyDenied` | an `allowFrom` entry is outside the admin allowlist (`Tailnet.spec.policy.ingressSourceAllowlist`) | use an allowed principal (e.g. a `group:`), or ask the admin to widen the allowlist |
| `BackendsReachable=False` | `shop-db-rw:5432` does not answer from the agent pod | Service/port wrong, backend down, NetworkPolicy in the tenant namespace blocks the agent |
| `TagKnown=False` | see egress table above | |

## Tailnet without a policy writer (spoke cluster)

Only one Tailnet per Headscale may run `policy.mode: Apply`. On every other cluster sharing that
control plane (a *spoke*) the operator still enrols the agent and renders DNS, but it cannot write
`tagOwners` or grants — `allowFrom` is informational there. The hub's admin declares them in the base
policy, so pin the tag instead of relying on the template:

```yaml
spec:
  tag: tag:ingress-prod-2-shop          # explicit: the hub policy references this literal
  hostname: prod-2-shop                 # explicit: unique across the whole tailnet
  allowFrom: [group:shop]               # documents the intent; the hub grant is authoritative
```

Hub base policy (`policy.jsonc`), reviewed like any other admin change
([Change the base policy](policy.md#change-the-base-policy-admin)):

```jsonc
"tagOwners": { "tag:ingress-prod-2-shop": ["group:operator"] },
"grants": [ { "src": ["group:shop"], "dst": ["tag:ingress-prod-2-shop"], "ip": ["tcp:5432"] } ]
```

Until the hub applies it the CR reports `TagKnown=False/Unknown` (no key is minted); afterwards it is `Ready`
like on the hub. Peers that still cannot connect are missing the grant, not the agent.
