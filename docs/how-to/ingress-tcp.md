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
