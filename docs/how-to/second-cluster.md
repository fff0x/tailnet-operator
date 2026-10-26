---
title: "Connect a second cluster"
weight: 95
description: "Join another Kubernetes cluster to the same Headscale: one policy writer (hub), spokes that export their entries, per-cluster names and DNS zones, and which repository holds what."
---

*`prod-1` already runs the operator with Headscale in-cluster and owns the policy. A second cluster,
`prod-2` at another site, should publish its own services on the same tailnet and reach the same
site networks — without a second Headscale and without anyone copying tags and grants by hand.*

Both clusters run the same chart and the same five CRDs. What differs is one block in each
`Tailnet` and which repository the policy entries are reviewed in.

## Roles: one hub, any number of spokes

| | Hub (`prod-1`) | Spoke (`prod-2`, …) |
| --- | --- | --- |
| Headscale | in-cluster (or wherever it runs); `spec.server` is the public login URL, `spec.apiUrl` the in-cluster REST endpoint | the same login URL; `apiUrl` empty, so the REST API is reached at the same public endpoint (expose `/api/v1` through your gateway, over TLS) |
| API key | its own `apiSecretRef` | its own `apiSecretRef` — one Headscale API key per cluster, rotated independently |
| Policy | `policy.mode: Apply` with `baseConfigMap` — the only writer | `policy.mode: Export` — renders its own entries into a fragment, writes nothing |
| Agents, DNS hosts, gateway | as on any cluster | as on any cluster |

Only one `Tailnet` per Headscale may run `Apply`: two writers would overwrite each other's render.
A spoke still enrols agents, mints keys and renders DNS; it only lacks the right to change the policy.

## 1. Give each cluster its own names

Tags, hostnames and DNS names are tailnet-wide. The defaults (`tag:egress-{name}`,
`ingress-{name}`) collide as soon as two clusters publish a `shop`. Put the cluster into the
templates of **every** `Tailnet`, hub included:

```yaml
apiVersion: tsunaro.io/v1alpha1
kind: Tailnet
metadata:
  name: corp
spec:
  server: https://headscale.example.com
  apiSecretRef: {name: headscale-api, key: apiKey}
  tagTemplate: "tag:egress-prod-2-{name}"
  hostnameTemplate: "prod-2-egress-{name}"
  ingressTagTemplate: "tag:ingress-prod-2-{name}"
  ingressHostnameTemplate: "prod-2-{name}"
  dns:
    hostsConfigMap: tailnet-dns-hosts
    ingressNameTemplate: "{name}-{namespace}.prod-2.tailnet.example.internal"
    ingressAliasTemplate: "{name}.prod-2.tailnet.example.internal"
```

The zone after the placeholders (`prod-2.tailnet.example.internal`) is this cluster's DNS zone; the
hub uses `prod-1.…`. A CR may still pin `spec.tag` / `spec.hostname` explicitly, as the spoke
sections of [Ingress: TCP](ingress-tcp.md#tailnet-without-a-policy-writer-spoke-cluster) show.

## 2. Export on the spoke, merge on the hub

Spoke `Tailnet`:

```yaml
spec:
  policy:
    mode: Export
    tagOwners: ["group:operator"]          # owner stamped on the exported tags
    routeApprovers: ["tag:fabric"]         # who may approve the /32s of this cluster's egress targets
    ingressSourceAllowlist: ["group:*"]    # same list as the hub, or allowFrom is rendered as Denied
```

```sh
kubectl describe tailnet corp | grep -A1 Policy
#   PolicyRendered  True   Rendered   3 tags, 3 grants, 12 routes exported
#   PolicyApplied   False  Export     mode Export: commit ConfigMap tailnet-system/corp-policy-fragment to the hub …
kubectl -n tailnet-system get cm corp-policy-fragment -o jsonpath='{.data.policy}' | jq -S . > prod-2-policy-fragment.json
```

Commit the file into the **hub's** repository next to the base policy and ship it as a ConfigMap in
the operator namespace (key `policy`); then list it on the hub `Tailnet`:

```yaml
# hub repository, kustomization next to policy.jsonc
configMapGenerator:
  - name: headscale-policy
    files: [policy=policy.jsonc]
  - name: prod-2-policy-fragment
    files: [policy=prod-2-policy-fragment.json]
generatorOptions:
  disableNameSuffixHash: true
```

```yaml
# hub Tailnet
spec:
  policy:
    baseConfigMap: headscale-policy
    mode: Apply
    fragmentConfigMaps: [prod-2-policy-fragment]
```

The hub renders base → its own CRs → fragments. Base and hub entries win; a fragment only adds
`tagOwners`, `autoApprovers.routes` and `grants`. The Git review of the fragment file is the gate for
the spoke's grants — the same review a hand-written entry gets. Details, failure reasons
(`FragmentMissing`, `FragmentInvalid`) and the removal order are in
[Policy § Second cluster](policy.md#second-cluster-export-on-the-spoke-merge-on-the-hub).

Refresh the fragment whenever the spoke adds or removes a CR: until the hub applies the new render,
a new spoke CR reports `TagKnown=False/Unknown` (no key is minted) — that window is the review.

**Changing the base while a fragment is in play.** The hub applies whatever its render says the moment
the base ConfigMap changes. If you remove hand-written spoke entries from the base in the same
commit that adds the fragment, make sure the `Tailnet` already lists the fragment *before* the base
changes — or switch the hub to `DryRun` in a commit of its own first. Otherwise the hub may write one
intermediate policy without the spoke's tags.

## 3. Grants between clusters

Grants are tailnet-wide; a cluster boundary is nothing special in the policy. Three shapes occur:

- **Peer → spoke ingress**: generated from the spoke's `allowFrom` and exported in the fragment. Nothing to write.
- **Spoke egress → site host**: the spoke's egress tag → `<host>/32:<port>` grant and the `/32`
  route approval are exported too. The route itself must be advertised by a router carrying one of
  the `routeApprovers` tags — the hub's gateway, the spoke's gateway, or any tagged router; the operator
  identifies routers by tag, not by cluster ([Site network](site-network.md)).
- **Cluster → cluster service** (e.g. replication between gateways): a plain grant in the hub base,
  `tag:fabric → tag:fabric` or egress-tag → ingress-tag. Keep it narrow; a proxy with `--accept-routes`
  installs every route its grants let it reach.

## 4. DNS: one zone per cluster

Each cluster renders its own hosts file (`dns.hostsConfigMap`) and serves its own zone — through its
`TailnetGateway` ([Run the gateway](gateway.md)) or a resolver you run
([DNS with CoreDNS](dns-coredns.md)). Headscale has no DNS API, so add one `dns.nameservers.split`
entry per zone by hand:

```yaml
dns:
  nameservers:
    split:
      prod-1.tailnet.example.internal: [198.51.100.17]   # prod-1 gateway LB IP
      prod-2.tailnet.example.internal: [198.51.100.33]   # prod-2 gateway LB IP
```

Egress **aliases** (`api.corp.example → Service ClusterIP`) are cluster-local by nature: the hosts
entry points at a ClusterIP, so forward the alias zone from each cluster's own CoreDNS to its own
resolver; never to the other cluster's.

## 5. What lives where

| Item | Repository | Why |
| --- | --- | --- |
| Base policy (`groups`, `hosts`, site grants, `tests`) | hub | one writer, one review queue |
| Spoke fragments (`*-policy-fragment.json`) | hub, generated on the spoke | the hub needs them at render time; the diff is the review |
| `Tailnet`, CRs, `TailnetGateway`, LB pool, CoreDNS forward | each cluster | cluster-local objects |
| Headscale `dns.nameservers.split` | Headscale configuration | one entry per zone |
| Headscale API keys | each cluster's Secret | independent rotation — [Keys and expiry](../operations/keys.md) |

## Verify

```sh
# spoke
kubectl get tailnet corp -o jsonpath='{range .status.conditions[*]}{.type}={.status}/{.reason}{"\n"}{end}'
#   PolicyRendered=True/Rendered, PolicyApplied=False/Export, TagKnown on each CR True/Known once the hub applied
# hub
kubectl get tailnet corp -o jsonpath='{.status.policy}{"\n"}'          # renderedHash == appliedHash
kubectl -n tailnet-system get cm headscale-policy-rendered -o jsonpath='{.data.policy}' | jq '.tagOwners | keys'
# any peer
dig +short shop-shop-dev.prod-2.tailnet.example.internal
```

| Symptom | Cause | Fix |
| --- | --- | --- |
| spoke CR `TagKnown=False/Unknown` | hub has not applied the fragment yet, or it is not listed | commit/refresh the fragment, check `fragmentConfigMaps` |
| hub `PolicyRendered=False/FragmentMissing` | listed ConfigMap absent in the operator namespace | ship the ConfigMap, or remove it from the list first |
| hub `PolicyRendered=False/FragmentInvalid` | fragment carries `groups`/`acls`/`ssh`/…, or a grant/owner/route outside the hub's limits (the message names the path) | export again; never hand-edit the fragment beyond review; widen the hub's `tagOwners`/`routeApprovers`/`ingressSourceAllowlist` only deliberately |
| spoke `PolicyRendered` message lists `denied …` | `allowFrom` outside the spoke's `ingressSourceAllowlist` | align the allowlist with the hub |
| spoke egress `RoutesGranted=False`, target reason `NotAdvertised` | no router advertises a route covering the host | add the `/32` or its subnet to a gateway's routes or a `TailnetSite` |
