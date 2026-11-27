---
title: "Architecture by scenario"
weight: 15
description: "One diagram per scenario — what runs inside the cluster, what the operator creates, where the tailnet begins — and a table of every object a CR produces."
---

Each scenario below shows the cluster boundary, the operator, the agent it runs and the objects it
creates, and the peer on the far side of the tailnet. The diagrams render on the website; in a
plain Markdown viewer they appear as Mermaid source. [Model and how it works](model.md) explains
the kinds and the reconcilers in prose; this page shows the resulting shape.

Conventions: `corp` is the Tailnet, `tailnet-system` the operator namespace, `billing-dev` and
`shop-dev` tenant namespaces.

## Egress: a namespace reaches a host at the site

```mermaid
flowchart LR
  subgraph cluster["Kubernetes cluster"]
    subgraph ns["namespace billing-dev"]
      app["app pod"]
    end
    subgraph ops["namespace tailnet-system"]
      op["tailnet-operator"]
      svc["Service db-1\n(ClusterIP :1521)"]
      agent["agent pod billing-dev\n(userspace tsnet, AGENT_MODE=egress)"]
      np["NetworkPolicy\nconsumerNamespaces only"]
    end
  end
  hs["Headscale"]
  router["subnet router\n(tag:fabric)"]
  db["db-1 10.0.5.20:1521"]
  op -- "pre-auth key, policy" --> hs
  op -. "creates" .-> svc & agent & np
  app -- "db-1.tailnet-system.svc:1521" --> svc --> agent
  agent == "WireGuard" ==> router --> db
```

`TailnetEgress billing-dev` yields one agent Deployment, one Service per target and a
NetworkPolicy that admits only the listed consumer namespaces. The agent registers as
`egress-billing-dev` with `tag:egress-billing-dev`, accepts the site routes and `Dial`s the target
over the tailnet; the operator derives the tag owner and the grant from the CR.

## Ingress: tailnet peers reach a cluster Service

```mermaid
flowchart RL
  subgraph cluster["Kubernetes cluster"]
    subgraph ns["namespace shop-dev"]
      agent["agent pod ingress-shop\n(AGENT_MODE=ingress)"]
      np["NetworkPolicy\nhealth port from operator"]
      backend["Service shop-db-rw :5432"]
    end
    subgraph ops["namespace tailnet-system"]
      op["tailnet-operator"]
      hosts["ConfigMap tailnet-dns-hosts"]
    end
  end
  hs["Headscale"]
  peer["peer in group:shop"]
  op -- "pre-auth key, policy" --> hs
  op -. "creates" .-> agent & np & hosts
  peer -- "shop-shop-dev.prod-1.tailnet.example.internal:5432" --> agent --> backend
```

`TailnetIngress shop` lives in the tenant namespace. Its agent listens on the tailnet as one node
(`ingress-shop`, `tag:ingress-shop`) and forwards to the backend Service; `allowFrom` becomes the
grant, and the DNS name is written into the hosts ConfigMap for the cluster's CoreDNS.

## Ingress `mode: http`: TLS terminated on the agent

```mermaid
flowchart RL
  subgraph cluster["Kubernetes cluster"]
    subgraph ns["namespace shop-dev"]
      agent["agent pod ingress-shop\nTLS listener, SNI routing"]
      cert["cert-manager Certificate\n→ Secret (projected)"]
      web["Service shop-web :8080"]
    end
    op["tailnet-operator"]
  end
  issuer["cert-manager issuer"]
  peer["browser on the tailnet"]
  op -. "creates" .-> agent & cert
  cert -- "issues" --> issuer
  peer -- "https://shop-shop-dev.prod-1.tailnet.example.internal" --> agent -- "HTTP, or verified HTTPS\nwith backend.tls" --> web
```

Each `mode: http` expose is a virtual host: the agent terminates TLS with the certificate the
operator requested from cert-manager (or a Secret you supply), routes by SNI and Host, and
forwards HTTP/1.1 or HTTP/2 to the backend — plain, or HTTPS verified against `backend.tls`.

## Gateway: subnet router and split-DNS as a CR

```mermaid
flowchart LR
  subgraph cluster["Kubernetes cluster"]
    subgraph ops["namespace tailnet-system"]
      op["tailnet-operator"]
      sts["StatefulSet corp-gateway\n(containers tailscale + coredns)"]
      lb["Service corp-gateway\n(LoadBalancer, pool IP)"]
      dns["Service dns.serviceName\n(ClusterIP :53)"]
      state["Secret state\n(persistent identity)"]
      receipts["ConfigMaps -fresh, -auth-receipt\n(immutable receipts)"]
    end
    coredns["cluster CoreDNS"]
  end
  hs["Headscale"]
  peer["tailnet peer"]
  op -- "mints bootstrap key,\napproves routes" --> hs
  op -. "creates once" .-> sts & lb & dns & state & receipts
  peer -- "10.0.0.0/8 via advertised route" --> lb --> sts
  coredns -- "forward zone" --> dns
```

`TailnetGateway` is the one persistent identity: created exactly once, pinned by receipts, never
restarted or adopted by the operator. Route changes flow into the StatefulSet template, the hosts
file into the CoreDNS zone. Deleting the CR removes nothing unless `deletionPolicy: Delete`.

## Policy and keys: what the operator says to Headscale

```mermaid
sequenceDiagram
  participant CR as Tailnet / Egress / Ingress / Site CRs
  participant Op as tailnet-operator
  participant HS as Headscale API
  Op->>HS: create working API key from the bootstrap key
  Note over Op,HS: rotated at half-life, new key verified before the old one expires
  CR->>Op: tags, consumers, allowFrom, site networks
  Op->>Op: render base policy + tagOwners, /32 approvals, grants + merge reviewed spoke fragments
  Op->>HS: validate and set policy (mode Apply)
  Op->>HS: create reusable pre-auth key per agent (ephemeral for egress, persistent for ingress)
  Op->>HS: list nodes, classify routes (NotAdvertised / NotApproved / NoGrant)
  Op->>HS: approve routes missed by autoApprovers
```

Everything the operator writes to Headscale is derived from CRs and visible beforehand: the
rendered policy lands in a ConfigMap, `DryRun` shows it without writing. A second cluster that shares
the Headscale cannot write; in `mode: Export` it renders only its own entries into a fragment
ConfigMap, which the single Apply writer merges after review — see
[Second cluster](../how-to/policy.md#second-cluster-export-on-the-spoke-merge-on-the-hub).

## What the operator creates

| CR | Kubernetes objects (owned, garbage-collected with the CR) | Headscale side | On delete |
| --- | --- | --- | --- |
| `Tailnet corp` | Secret `corp-apikey` (working key, expiry in annotations); with `dns`: ConfigMap `spec.dns.hostsConfigMap`; with `policy`: ConfigMap `<base>-rendered` | API keys created and expired on rotation; policy written in `Apply` | Secret and ConfigMaps go; the live policy and keys stay as they are |
| `TailnetEgress billing-dev` | Deployment `billing-dev`, ConfigMap `billing-dev-targets`, Secret `billing-dev-authkey`, one Service per target (named after the target), NetworkPolicy `billing-dev` | Pre-auth key (reusable, ephemeral, rotated); node `egress-billing-dev`; stale offline duplicates removed | Objects are garbage-collected; the ephemeral node ages out |
| `TailnetIngress shop` | Deployment `ingress-shop`, ConfigMap `shop-targets`, Secret `shop-authkey`, NetworkPolicy `ingress-shop`, ServiceAccount/Role/RoleBinding `ingress-shop`, state Secret `ingress-shop-state-<hash>`; `mode: http` with an issuer: cert-manager Certificate and its TLS Secret | Pre-auth key (reusable, non-ephemeral, rotated); persistent node `ingress-shop`; DNS name in the hosts file | Objects are garbage-collected; the operator deletes the node (best effort, before the finalizer is dropped) |
| `TailnetGateway corp-gateway` | StatefulSet, headless Service, LoadBalancer Service, DNS ClusterIP Service, CoreDNS ConfigMap, ServiceAccount, Role, RoleBinding, PDB; state Secret and auth Secret; receipt ConfigMaps — none with an owner reference | Non-ephemeral bootstrap key; persistent node; approved routes | `Retain` (default): nothing; `Delete`: fail-closed teardown of what this Gateway provably created |
| `TailnetSite` | none | `autoApprovers` and approvals for the declared network | Rendered policy loses the entries |
| `TailnetGrant` | none | One grant in the rendered policy while the target is valid and `expiresAt` has not passed | Rendered policy loses the grant at the next policy reconcile |

Names and labels follow the CR name; selectors are per CR, so two CRs never share a pod. For the
field-level view see the [CRD reference](../reference/crds.md), for the gateway's exact contract
the [TailnetGateway reference](../reference/gateway.md).
