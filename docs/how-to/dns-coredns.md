---
title: "Serve DNS names with CoreDNS"
weight: 60
description: "Render the hosts file, serve it from the resolver for your tailnet zone, and forward the alias zones from the cluster CoreDNS."
---

Needed for two things: egress **aliases** (a client must dial `api.corp.example`, not
`api.tailnet-system.svc`, when the far end routes by TLS SNI / HTTP Host) and **ingress names**
(`shop-shop-dev.prod-1.tailnet.example.internal` for a `TailnetIngress`). The operator itself serves
no DNS. It renders a CoreDNS [`hosts`](https://coredns.io/plugins/hosts/) file into a ConfigMap; either
a `TailnetGateway` serves it as the zone ([Run the gateway](gateway.md); skip [Serve the file](#serve-the-file)) or
you mount it into the resolver that is authoritative for those zones.

## Enable rendering

```yaml
kind: Tailnet
spec:
  dns:
    hostsConfigMap: tailnet-dns-hosts   # operator namespace, key "hosts"
    ingressNameTemplate: "{name}-{namespace}.prod-1.tailnet.example.internal"
```

```sh
kubectl -n tailnet-system get cm tailnet-dns-hosts -o jsonpath='{.data.hosts}'
# # managed by tailnet-operator (Tailnet corp) — do not edit
# 10.43.12.7    api.corp.example
# 100.64.0.42   shop-shop-dev.prod-1.tailnet.example.internal
```

Keep the ingress template **one label** below your gateway's wildcard certificate: `*.prod-1.<domain>`
covers `shop-shop-dev.prod-1.<domain>`, not `shop.shop-dev.prod-1.<domain>`.

## Serve the file

Mount the ConfigMap into the resolver for your tailnet zone (in a Headscale setup: the resolver your
split-DNS entry delegates `prod-1.tailnet.example.internal` to), `optional: true` so it starts before
the first render:

```yaml
volumes:
  - name: dns-hosts
    configMap: { name: tailnet-dns-hosts, optional: true }
containers:
  - name: coredns
    volumeMounts: [{ name: dns-hosts, mountPath: /etc/tailnet-dns, readOnly: true }]
```

```corefile
prod-1.tailnet.example.internal:53 {
    hosts /etc/tailnet-dns/hosts { fallthrough }                 # operator records win …
    template IN A { answer "{{ .Name }} 30 IN A 10.0.0.80" }     # … the gateway wildcard catches the rest
    cache 30
    reload
}
corp.example:53 {                                                # zones with egress aliases
    hosts /etc/tailnet-dns/hosts { fallthrough }
    cache 30
    forward . 10.0.0.53 { max_concurrent 1000 }                  # everything else: the site's DNS
    reload
}
```

## Wire the cluster CoreDNS

Pods ask the cluster CoreDNS (`kube-system`). Forward the alias zones to your resolver first, with
the site DNS as sequential fallback so real corporate names keep resolving when the resolver is down:

```corefile
corp.example:53 {
    errors
    cache 30
    forward . 10.96.0.54 10.0.0.53 {       # 10.96.0.54 = ClusterIP of your resolver Service
        policy sequential
        max_concurrent 1000
    }
}
```

Two details worth knowing: `forward` treats SERVFAIL as an answer (no failover, only unreachable
upstreams fail over), and a resolver without a route into the site network cannot use the site DNS
as upstream — forward that zone to a peer resolver *inside* the site over the tailnet instead
(`forward . 100.64.0.3`, a subnet router's tailnet IP running the same block).

Freshness is ConfigMap propagation (≤ ~1 min) plus the `hosts` reload (5 s). If the operator dies,
the last file stays valid — the data path never depends on it.

### Who owns `kube-system/coredns`

On many platforms the cluster CoreDNS ConfigMap is not yours: Talos rewrites it to its default on
every `talosctl upgrade-k8s`, and managed distributions (EKS, AKS, GKE) do the same through their
add-on managers. A GitOps copy that replaces the whole ConfigMap is reverted at each upgrade and comes
back only at the next sync plus CoreDNS's own reload (30–70 s) — measured windows of 4–8 min with a
15 min sync interval. In that window pods lose the forwarded zones (aliases, tailnet names, and in a
hub/spoke setup the hub's path to a spoke API by tailnet name); egress agents are not affected (they
dial through the tailnet's own DNS), nor are ingress backends (`cluster.local`).

Prefer not to fight the platform: leave its CoreDNS untouched and run your own resolver for the
forwarded zones (on Talos, `cluster.coreDNS.disabled: true` and bring your own `kube-dns`; platform
hooks such as AKS `coredns-custom` or a Corefile `import` work too). If you must replace the ConfigMap,
reconcile it at a short interval (`1m`) so the window is bounded, and check the zones after every
Kubernetes upgrade:

```sh
kubectl -n kube-system get cm coredns -o jsonpath='{.data.Corefile}' | grep -c 'corp.example'   # 1
```
