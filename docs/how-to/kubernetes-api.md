---
title: "Ingress: reach the Kubernetes API over the tailnet"
weight: 57
description: "Publish the API server (and, if you run one, the node management API) as a TailnetIngress so administrators and automation reach the cluster without a public endpoint."
---

*The platform team manages `prod-1` from laptops and CI runners on the tailnet. The API server
should not be reachable from the internet, and nobody wants a bastion or a VPN concentrator.*

The API server is a Service like any other: `kubernetes.default.svc:443`. A `TailnetIngress` in
the operator namespace exposes it as one tailnet node; who may dial it is a policy grant, derived
from `allowFrom`.

```yaml
apiVersion: tsunaro.io/v1alpha1
kind: TailnetIngress
metadata:
  name: k8s
  namespace: tailnet-system
spec:
  tailnetRef: { name: corp }
  allowFrom: [group:operator]                  # admins and CI runners: members of this group, nobody else
  exposes:
    - name: api
      port: 6443                               # what peers dial on the node
      backend: { service: kubernetes, namespace: default, port: 443 }
```

```sh
kubectl -n tailnet-system get tailnetingress k8s
# NAME   TAG               HOSTNAME      HOSTS                                                  READY   AGE
# k8s    tag:ingress-k8s   ingress-k8s   [k8s-tailnet-system.prod-1.tailnet.example.internal]   True    1m
```

## kubeconfig

The API server certificate carries the names it was issued for (`kubernetes`,
`kubernetes.default.svc`, its ClusterIP, your configured SANs) — not the tailnet name. Either add
the tailnet name to the API server's SANs, or tell the client which name to verify:

```yaml
clusters:
  - name: prod-1-tailnet
    cluster:
      server: https://k8s-tailnet-system.prod-1.tailnet.example.internal:6443
      certificate-authority-data: <cluster CA, as in your existing kubeconfig>
      tls-server-name: kubernetes.default.svc
```

```sh
kubectl --kubeconfig prod-1-tailnet.yaml get --raw /readyz
# ok
```

Authentication is unchanged: the agent forwards TCP, so client certificates, OIDC tokens and
ServiceAccount tokens work exactly as on the LAN. The operator adds a network boundary (the grant),
not an identity layer — a peer that may dial the node still needs valid Kubernetes credentials.

## Node management API

A node API that does not live behind a Service (Talos `apid`, for example, on port 50000) gets a
Service plus a hand-written EndpointSlice, then the same ingress pattern:

```yaml
apiVersion: v1
kind: Service
metadata: { name: node-api, namespace: tailnet-system }
spec:
  ports: [{ name: api, port: 50000, protocol: TCP, targetPort: 50000 }]
---
apiVersion: discovery.k8s.io/v1
kind: EndpointSlice
metadata:
  name: node-api
  namespace: tailnet-system
  labels:
    kubernetes.io/service-name: node-api
    endpointslice.kubernetes.io/managed-by: gitops
addressType: IPv4
ports: [{ name: api, port: 50000, protocol: TCP }]
endpoints:
  - addresses: ["10.20.0.10"]                  # control-plane node or VIP
    conditions: { ready: true }
---
apiVersion: tsunaro.io/v1alpha1
kind: TailnetIngress
metadata: { name: nodes, namespace: tailnet-system }
spec:
  tailnetRef: { name: corp }
  allowFrom: [group:operator]
  exposes:
    - { name: api, port: 50000, backend: { service: node-api, port: 50000 } }
```

Point the node client's endpoint at `nodes-tailnet-system.prod-1.tailnet.example.internal`.

## When it is not Ready

| Condition | Meaning | Fix |
| --- | --- | --- |
| `BackendsReachable=False` | the agent cannot open `kubernetes.default.svc:443` | a NetworkPolicy in `tailnet-system` or `default` blocks the agent pod; allow egress to the API server |
| `PolicyGranted=False/PolicyDenied` | an `allowFrom` entry is outside `Tailnet.spec.policy.ingressSourceAllowlist` | use an allowed principal or widen the allowlist ([policy](policy.md)) |
| connection refused from the laptop | the grant exists but the peer is not in `group:operator` | `headscale policy get` and check the group membership |
| `x509: certificate is valid for …` | the tailnet name is not in the API server SANs | set `tls-server-name` as above, or add the SAN |

The agent is a userspace node without `NET_ADMIN`; it forwards TCP only. Session recording,
impersonation or request rewriting are out of scope — the API server's own audit log sees the
agent pod's IP as the client address, so keep the grant narrow and let Kubernetes authentication
carry the identity.
