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

## 2. Export on the spoke, pull on the hub

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
#   PolicyApplied   False  Export     mode Export: waiting for the hub to merge ConfigMap tailnet-system/corp-policy-fragment …
```

The hub reads that ConfigMap itself, through a kubeconfig that may read nothing else. On the
**spoke**, let the chart mint the identity:

```yaml
# spoke Helm values
policy:
  fragmentReader:
    enabled: true
    configMaps: [corp-policy-fragment]
```

The hub reaches the spoke's API server only through the tailnet — it is never exposed to the
internet. On the **hub**, a `TailnetEgress` whose target is the spoke API address (inside a site
network the spoke's gateway advertises, [Site network](site-network.md)) gives the operator an
in-cluster Service for it; the grant and the `/32` approval are generated like for any egress:

```yaml
# hub
apiVersion: tsunaro.io/v1alpha1
kind: TailnetEgress
metadata:
  name: spoke-prod-2
spec:
  tailnetRef: {name: corp}
  consumerNamespaces: [tailnet-system]      # the operator itself is the consumer
  targets:
    - name: prod-2-api
      address: 203.0.113.10                  # the spoke's API server address
      port: 6443
```

```sh
# spoke → kubeconfig for the hub (ServiceAccount token, scoped to one ConfigMap, this cluster's CA);
# the server is the hub's egress Service, tls-server-name a SAN of the spoke API certificate
kubectl -n tailnet-system get secret tailnet-operator-fragment-reader-token \
  -o go-template='apiVersion: v1
kind: Config
clusters: [{name: prod-2, cluster: {server: https://prod-2-api.tailnet-system.svc:6443, tls-server-name: api.prod-2.example.internal, certificate-authority-data: {{index .data "ca.crt"}}}}]
users: [{name: reader, user: {token: {{index .data "token" | base64decode}}}}]
contexts: [{name: prod-2, context: {cluster: prod-2, user: reader}}]
current-context: prod-2
' > prod-2-kubeconfig
# hub
kubectl -n tailnet-system create secret generic prod-2-kubeconfig --from-file=kubeconfig=prod-2-kubeconfig
```

The server must be `https`: the operator sends the token only over TLS, and the spoke's certificate
is still verified against its CA. Then list the spoke on the **hub** `Tailnet`:

```yaml
# hub Tailnet
spec:
  policy:
    baseConfigMap: headscale-policy
    mode: Apply
    spokes:
      - name: prod-2
        kubeconfigSecretRef: {name: prod-2-kubeconfig}   # key "kubeconfig"
        # namespace / configMap default to the operator namespace and "prod-2-policy-fragment";
        # the spoke Tailnet above is called corp, so name its ConfigMap:
        configMap: corp-policy-fragment
        tagPatterns: ["tag:*-prod-2-*"]                   # default: tag:*-<name>-*
        routeAllowlist: ["10.20.0.0/16"]                  # site networks of prod-2 the hub has no TailnetSite for
        approval: Manual                                  # default Auto
```

A hub with `networkPolicy.enabled` must allow this dial, which none of the default rules cover.
The dial goes to the `spoke-prod-2` egress agent pod on its listen port (an address outside the
cluster would be a CIDR instead):

```yaml
# hub chart values
networkPolicy:
  spokePeers:
    - podSelector: {matchLabels: {app.kubernetes.io/name: tailnet-egress, app.kubernetes.io/instance: spoke-prod-2}}
  spokePorts: [10000]            # the egress target's listen port (first target: 10000)
  # spokeCIDRs: [203.0.113.10/32]  # or: the spoke API server address, with spokePorts: [6443]
```

Every reconcile the hub fetches the fragment (10 s timeout), validates it like a committed fragment
plus the spoke's `tagPatterns` and `routeAllowlist`, and keeps a copy as
`prod-2-policy-fragment-approved` in its own namespace. `approval: Auto` merges each valid fetch at
once; `Manual` holds a changed fetch as `prod-2-policy-fragment-pending` and reports it:

```sh
kubectl get tailnet corp -o jsonpath='{.status.spokes[0]}' | jq .
# { "name": "prod-2", "fetchedHash": "9f2c…", "approvedHash": "41ab…", "pendingHash": "9f2c…",
#   "pendingDelta": { "grantsAdded": 1, "routesAdded": 1 }, … }
kubectl -n tailnet-system get cm prod-2-policy-fragment-pending -o jsonpath='{.data.policy}' | jq .
kubectl annotate tailnet corp tsunaro.io/approve-spoke.prod-2=9f2c…      # pendingHash verbatim
```

While a fetch is pending the hub merges the approved fragment **minus** anything the spoke removed:
a spoke can withdraw its own grants without approval, additions wait. An unreachable spoke, a
`403`, or an invalid fetch keeps the last approved fragment merged; `SpokesReady` and
`status.spokes[].conditions` (`SpokeReachable`, `SpokeFragmentValid`, `SpokeFragmentApproved`) say
which. Removing a spoke from `spokes[]` drops its copies and its entries from the next render.

**Alternative: commit the fragment into the hub repository.** Without a kubeconfig, copy the
fragment by hand, ship it as a ConfigMap (key `policy`) in the hub's operator namespace and list it
in `policy.fragmentConfigMaps`; the Git diff is the review. Refresh it whenever the spoke adds or
removes a CR: until the hub applies the new render, a new spoke CR reports `TagKnown=False/Unknown`
(no key is minted). Both paths validate the same way; details and failure reasons are in
[Policy § Second cluster](policy.md#second-cluster-export-on-the-spoke-merge-on-the-hub).

**Changing the base while a fragment is in play.** The hub applies whatever its render says the moment
the base ConfigMap changes. If you remove hand-written spoke entries from the base in the same
commit that adds the spoke, make sure the `Tailnet` already lists the spoke (and, with `Manual`, the
first fetch is approved) *before* the base changes — or switch the hub to `DryRun` in a commit of
its own first. Otherwise the hub may write one intermediate policy without the spoke's tags.

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
| Spoke kubeconfig Secret, `spokes[]` entry | hub | the hub pulls the fragment; `approval: Manual` makes the annotation the review |
| `TailnetEgress` to the spoke API server | hub | the only path to the spoke API; grant and `/32` approval are generated |
| Spoke fragments (`*-policy-fragment.json`, Git path) | hub, generated on the spoke | the hub needs them at render time; the diff is the review |
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
| spoke CR `TagKnown=False/Unknown` | hub has not merged the fragment yet: fetch pending approval, spoke unreachable, or (Git path) not listed | `kubectl get tailnet -o jsonpath='{.status.spokes}'`, approve or fix the spoke; Git path: commit/refresh the fragment, check `fragmentConfigMaps` |
| hub `SpokesReady=False/SpokeUnreachable` | kubeconfig Secret missing or invalid, token revoked (`HTTP 403`), API server unreachable — with `networkPolicy.enabled` also a missing `spokePeers`/`spokeCIDRs` entry | the `SpokeReachable` message names which; last approved fragment stays merged |
| hub `SpokesReady=False/ApprovalPending` | `approval: Manual` and the fetched fragment differs from the approved one | review `<spoke>-policy-fragment-pending` and `pendingDelta`, annotate with the pending hash |
| hub `SpokesReady=False/NothingApproved` | `Manual` spoke whose first fetch was never approved | annotate once; until then the spoke contributes nothing |
| hub `PolicyRendered=False/FragmentMissing` | listed `fragmentConfigMaps` entry absent in the operator namespace | ship the ConfigMap, or remove it from the list first |
| hub `SpokesReady=False/SpokeFragmentInvalid` or `PolicyRendered=False/FragmentInvalid` | fragment carries `groups`/`acls`/`ssh`/…, or a grant/owner/route outside the hub's limits (the message names the path); for a pulled fragment also a tag outside `tagPatterns` or a route outside `routeAllowlist` | export again; never hand-edit the fragment beyond review; widen the hub's `tagOwners`/`routeApprovers`/`ingressSourceAllowlist` only deliberately |
| spoke `PolicyRendered` message lists `denied …` | `allowFrom` outside the spoke's `ingressSourceAllowlist` | align the allowlist with the hub |
| spoke egress `RoutesGranted=False`, target reason `NotAdvertised` | no router advertises a route covering the host | add the `/32` or its subnet to a gateway's routes or a `TailnetSite` |
