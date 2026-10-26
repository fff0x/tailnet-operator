---
title: "Getting started"
weight: 10
description: "From a running Headscale to a first egress and a first ingress in about thirty minutes: install the operator, pass preflight, reach a site database from a namespace, publish a cluster service to tailnet peers."
---

By the end of this tutorial a namespace in your cluster reaches a database at a remote site
through a stable Service name, and a laptop on the tailnet reaches a database inside the cluster
by DNS name. Every step shows the command and the output you should see. Budget: about thirty
minutes, most of it waiting for pods.

Placeholders throughout: Tailnet `corp`, operator namespace `tailnet-system`, cluster `prod-1`,
tenant namespace `billing-dev`, team namespace `shop-dev`, site database `10.0.10.20:1521`.
Replace them with your values as you go.

## Before you start

You need:

- A Kubernetes cluster ≥ 1.31 with a CNI that enforces NetworkPolicy, `kubectl` and `helm`.
- A Headscale 0.29.x server reachable from the cluster, and shell access to its CLI
  (`headscale …`; in-cluster: `kubectl -n <ns> exec deploy/headscale -- headscale …`).
- A subnet router on the tailnet tagged `tag:fabric` that advertises the site network
  containing `10.0.10.20` (for example `--advertise-routes=10.0.10.0/24`), approved in Headscale.
- Your own device enrolled in the tailnet, member of `group:shop` in the policy.

The tutorial keeps the policy in **file mode** and edits it by hand, so you see exactly what the
operator needs. Switching to an operator-owned policy comes afterwards
([Let the operator own the policy](../how-to/policy.md)).

## 1. Create the bootstrap API key (2 min)

The operator authenticates with a long-lived **bootstrap** key it only reads; it mints and
rotates its own working key from it.

```sh
headscale apikeys create --expiration 8760h
# <prints one key; copy it, you will not see it again>
```

## 2. Add the policy entries (5 min)

Every egress and ingress node carries a tag, and the tag is the authorization. Add to your
Headscale policy file:

```jsonc
{
  "tagOwners": {
    "tag:fabric":              ["group:operator"],
    "tag:egress-billing-dev":  ["group:operator"],
    "tag:ingress-shop":        ["group:operator"]
  },
  "autoApprovers": { "routes": { "10.0.10.0/24": ["tag:fabric"] } },
  "grants": [
    { "src": ["tag:egress-billing-dev"], "dst": ["10.0.10.20/32"],  "ip": ["tcp:1521"] },
    { "src": ["group:shop"],             "dst": ["tag:ingress-shop"], "ip": ["tcp:5432"] }
  ]
}
```

Reload Headscale (SIGHUP or restart) and confirm it accepted the file:

```sh
headscale policy check -f /acl/policy
# Policy is valid
```

## 3. Install the operator (5 min)

```sh
helm install tailnet-operator oci://oci.this-is-fine.io/charts/tailnet-operator \
  --version 0.22.0 --namespace tailnet-system --create-namespace

kubectl -n tailnet-system create secret generic headscale-bootstrap --from-literal=apiKey='<key from step 1>'

kubectl -n tailnet-system rollout status deploy/tailnet-operator
# deployment "tailnet-operator" successfully rolled out
```

Use your secret manager instead of `--from-literal` outside a tutorial.

## 4. Bind the Tailnet and pass preflight (3 min)

```sh
kubectl apply -f - <<'EOF'
apiVersion: tsunaro.io/v1alpha1
kind: Tailnet
metadata:
  name: corp
spec:
  server: https://ts.example.com
  apiUrl: http://headscale.tailnet-system.svc:8080
  apiSecretRef: { name: headscale-bootstrap, key: apiKey }
  dns:
    hostsConfigMap: tailnet-dns-hosts
    ingressNameTemplate: "{name}-{namespace}.prod-1.tailnet.example.internal"
EOF

kubectl get tailnet corp
# NAME   SERVER                   APIKEY   EXPIRES                COMPAT         POLICY   DNS            AGE
# corp   https://ts.example.com   True     2026-11-14T12:00:00Z   Incompatible            CannotVerify   30s
```

Read the three reason columns:

- `APIKEY=True` — the operator reached the API and minted its working key (`EXPIRES` is that key).
- `COMPAT=Incompatible` is **expected in file mode**: it means the operator cannot write the
  policy, which is what you want for now. In database mode it reads `Compatible`.
- `DNS=CannotVerify` until a gateway and one agent exist: Headscale has no DNS API, so the split-DNS
  zone (`prod-1.tailnet.example.internal`) is yours to configure; the operator then reads it back
  from an agent's netmap and reports `Configured`, `Missing` or `Mismatch`.

If `APIKEY` is not `True`, `kubectl describe tailnet corp` names the cause (`ApiReachable`,
`ApiKeyValid`); fix `apiUrl` or the Secret and the Tailnet retries on its own. The `http://`
`apiUrl` is fine for this tutorial; for production serve the API over TLS
([API over TLS](../how-to/install-headscale.md#api-over-tls)).

## 5. First egress (5 min)

1. Advertise the target on the subnet router and approve it (or rely on `autoApprovers`).
2. Declare tag, route approval and grant in the policy ([step 2](#2-add-the-policy-entries-5-min)) — skip
   when the operator owns the policy.
3. Apply the CR **in the operator namespace** (egress CRs are admin resources):

```yaml
apiVersion: tsunaro.io/v1alpha1
kind: TailnetEgress
metadata:
  name: billing-dev
  namespace: tailnet-system
spec:
  tailnetRef: { name: corp }
  consumerNamespaces: [billing-dev]
  targets:
    - { name: db-1, address: 10.0.10.20, port: 1521 }
```

```sh
kubectl -n tailnet-system get tailnetegress billing-dev
# NAME          TAG                      HOSTNAME             READY   AGE
# billing-dev   tag:egress-billing-dev   egress-billing-dev   True    2m
```

A pod in `billing-dev` now dials `db-1.tailnet-system.svc:1521`. If `READY` is `False`, the
per-target `reason` in `status.targets[]` names the missing step — see
[Reach a database at the site](../how-to/egress.md#reach-a-database-at-the-site).

Prove it from the consumer namespace, and prove the isolation from any other namespace:

```sh
kubectl create namespace billing-dev 2>/dev/null
kubectl -n billing-dev run t --rm -it --image=busybox --restart=Never -- nc -zw3 db-1.tailnet-system.svc 1521
# db-1.tailnet-system.svc (10.96.78.33:1521) open

kubectl -n default run t --rm -it --image=busybox --restart=Never -- nc -zw3 db-1.tailnet-system.svc 1521
# nc: timed out            ← correct: the NetworkPolicy allows consumerNamespaces only
```

## 6. First ingress (5 min)

Publish a database inside the cluster to the members of `group:shop`. The CR lives in the
**tenant** namespace — the team owns it:

```sh
kubectl apply -f - <<'EOF'
apiVersion: tsunaro.io/v1alpha1
kind: TailnetIngress
metadata:
  name: shop
  namespace: shop-dev
spec:
  tailnetRef: { name: corp }
  allowFrom: [group:shop]
  exposes:
    - { name: postgres, port: 5432, backend: { service: shop-db-rw, port: 5432 } }
EOF

kubectl -n shop-dev get tailnetingress shop
# NAME   TAG                HOSTNAME       HOSTS                                             READY   AGE
# shop   tag:ingress-shop   ingress-shop   [shop-shop-dev.prod-1.tailnet.example.internal]   True    2m
```

From your laptop (a member of `group:shop`):

```sh
psql -h ingress-shop -p 5432 -U app shop      # MagicDNS name, works right away
```

The longer name in `HOSTS` resolves once your resolver serves the operator's hosts file —
that wiring is [DNS with CoreDNS](../how-to/dns-coredns.md), not part of this tutorial.

`READY=False` with `BackendsReachable=False` means `shop-db-rw:5432` does not answer from the
agent pod (Service name, port, or a NetworkPolicy in `shop-dev`); the table in
[Ingress: publish a TCP service](../how-to/ingress-tcp.md) covers the other reasons.

## What you have

- A per-namespace egress identity with its own tag, a stable in-cluster Service and a
  NetworkPolicy that keeps other namespaces out.
- A per-app ingress identity that tailnet peers reach by name, authorized by the policy, not by
  anything inside the cluster.
- `kubectl get` output that names the missing step when something is not ready.

## Where to go next

- Stop editing the policy by hand: [Let the operator own the policy](../how-to/policy.md)
  renders tags, approvals and grants from the CRs and writes them to Headscale.
- Serve the DNS names: [DNS with CoreDNS](../how-to/dns-coredns.md), or run the subnet router
  and resolver as a CR with [Run the gateway](../how-to/gateway.md).
- Publish a web app with TLS on the agent: [Ingress: publish a web app over HTTPS](../how-to/ingress-https.md).
- Before production: [Install the operator](../how-to/install-operator.md) (resources, network
  isolation, what the site must provide) and the [security model](../explanation/security-model.md).
