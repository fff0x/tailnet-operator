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
#   PolicyApplied   False  HubPending hub policy lacks 18 of 18 exported entries (tag:egress-…, …); fragment ConfigMap tailnet-system/corp-policy-fragment awaits merge
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

## 2a. Reach the spoke API through the tailnet

The hub's operator reads the spoke's ConfigMap from the spoke's API server, and that server is never
exposed to the internet. It is reached the way any site host is reached: the spoke API address lies
in a network that a router carrying one of the `routeApprovers` tags advertises — normally the spoke's
own `TailnetGateway` ([Run the gateway](gateway.md), [Site network](site-network.md)) — and the hub
runs a `TailnetEgress` for it. The egress gives the operator an in-cluster Service; its grant and the
`/32` approval are generated like for any other egress:

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
      address: 10.20.0.10                    # the spoke's API server address inside the spoke's network
      port: 6443
```

**First contact.** The spoke gateway advertises its network (`10.20.0.0/16`), not the `/32`, and the
approval for that network sits in the fragment the hub cannot read yet. Declare the network on the
hub, like the hub's own LAN ([Declare the LAN as a site](gateway.md#declare-the-lan-as-a-site)):

```yaml
# hub
apiVersion: tsunaro.io/v1alpha1
kind: TailnetSite
metadata:
  name: prod-2-lan
spec:
  tailnetRef: {name: corp}
  prefixes: [10.20.0.0/16]                  # the route the spoke gateway advertises
  owner: platform
```

The hub renders the approval and replays it on the spoke gateway; then the egress turns `Ready`.
The target must be the private address: no site router advertises a public one, and an exit node's
default route never counts.

```sh
kubectl -n tailnet-system get tailnetegress spoke-prod-2 \
  -o jsonpath='{range .status.conditions[*]}{.type}={.status}/{.reason}{"\n"}{end}'
#   TagKnown=True/Known  Registered=True/Registered  RoutesGranted=True/AllGranted
#   TargetsReachable=True/AllReachable  Ready=True/Ready
```

Wait for `Ready` before listing the spoke below: until the route to the spoke API is advertised and
approved, the hub reports `SpokeUnreachable`. A GitOps tool that waits for health reports the
whole set as failed while one egress is not ready, so ship the site first. From now on the spoke API server is
`prod-2-api.tailnet-system.svc:6443` inside the hub cluster. The TLS session still terminates at the
spoke API server; because the kubeconfig now dials a Service name, `tls-server-name` must carry a
name the spoke API certificate actually holds (one of its SANs), and the CA stays the spoke's:

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
        routeAllowlist: ["198.51.100.32/28"]              # prod-2 routes inside no hub TailnetSite
        approval: Manual                                  # default Auto
```

`routeAllowlist` holds every network route of the fragment that lies inside no hub `TailnetSite` —
at least the `tailnetLBCIDR` of the spoke's gateway (here `198.51.100.32/28`; `10.20.0.0/16` is
covered by the `prod-2-lan` site). A missing entry is `SpokeFragmentInvalid` on the first fetch.

A hub with `networkPolicy.enabled` must allow this dial, which none of the default rules cover.
The dial goes to the agent pod of the `spoke-prod-2` egress from [2a](#2a-reach-the-spoke-api-through-the-tailnet)
on its listen port (an address outside the cluster would be a CIDR instead):

```yaml
# hub chart values
networkPolicy:
  spokePeers:
    - podSelector: {matchLabels: {app.kubernetes.io/name: tailnet-egress, app.kubernetes.io/instance: spoke-prod-2}}
  spokePorts: [10000]            # the egress target's listen port (first target: 10000)
  # spokeCIDRs: [10.20.0.10/32]  # or: the spoke API server address, with spokePorts: [6443]
```

Every reconcile the hub fetches the fragment (10 s timeout), validates it like a committed fragment
plus the spoke's `tagPatterns` and `routeAllowlist`, and keeps a copy as
`prod-2-policy-fragment-approved` in its own namespace. `status.spokes[].fetchedAt` is when the
fetched hash last *changed*, not a heartbeat: with a quiet spoke it stays put for weeks while
`SpokeReachable` (set on every reconcile) and the metric `tailnet_spoke_reachable` tell you the
pull still works. `approval: Auto` merges each valid fetch at
once; `Manual` holds a changed fetch as `prod-2-policy-fragment-pending` and reports it:

```sh
kubectl get tailnet corp -o jsonpath='{.status.spokes[0]}' | jq .
# { "name": "prod-2", "fetchedHash": "9f2c…", "approvedHash": "41ab…", "pendingHash": "9f2c…",
#   "pendingDelta": { "grantsAdded": 1, "routesAdded": 1 }, … }
kubectl -n tailnet-system get cm prod-2-policy-fragment-pending -o jsonpath='{.data.policy}' | jq .
kubectl annotate tailnet corp tsunaro.io/approve-spoke.prod-2=9f2c…      # pendingHash verbatim
```

The annotation is read once, to adopt the pending fragment. The approval lives in the
`-approved` copy, so a GitOps tool that removes the annotation at its next apply changes nothing.

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

## 3a. Reach a spoke service from a pod on the hub

*A monitoring job in the hub namespace `ops` should read the Talos API and Grafana of `prod-2`,
which `prod-2` publishes as `TailnetIngress` objects. Ordinary pods have no tailnet client, and
`prod-2`'s names live in its own zone, which the hub cluster does not resolve.*

The pod dials the spoke service's real name, so TLS SNI and the certificate check hold. On the hub
a `TailnetEgress` carries that name as an alias and forwards to the ingress node; the hub gateway
answers the name from its hosts source. Four pieces, all declarative:

**1. Admit the hub egress tag on the spoke.** The egress below gets the tag `tag:egress-prod-1-ops`
from the hub's `tagTemplate`. List it in the `allowFrom` of each spoke ingress, and allow it in the
`ingressSourceAllowlist` of **both** `Tailnet`s: the spoke renders the grant only with it, and the hub
rejects a fragment whose grant source it does not allow.

```yaml
# spoke: each ingress the hub may reach
spec:
  allowFrom: [group:operator, tag:egress-prod-1-ops]
---
# spoke and hub Tailnet
spec:
  policy:
    ingressSourceAllowlist: ["group:*", "tag:egress-prod-1-*"]
```

With `approval: Manual` the hub holds the changed fragment until you approve it ([2](#2-export-on-the-spoke-pull-on-the-hub)).

**2. Egress on the hub.** Each target is the ingress node's MagicDNS name (`status.hostname` plus
the tailnet's MagicDNS `base_domain`, here `magic.tailnet.example.internal`) with the ingress name
as alias. No route is involved; the grant from step 1 is the only authorization.

```yaml
# hub
apiVersion: tsunaro.io/v1alpha1
kind: TailnetEgress
metadata:
  name: ops
  namespace: tailnet-system
spec:
  tailnetRef: {name: corp}
  consumerNamespaces: [ops]
  targets:
    - name: prod-2-talos                              # L4 ingress: Talos API
      address: prod-2-talos.magic.tailnet.example.internal
      port: 50000
      aliases: [talos.prod-2.tailnet.example.internal]
    - name: prod-2-grafana                            # mode: http ingress: TLS ends on the agent
      address: prod-2-monitoring.magic.tailnet.example.internal
      port: 443
      aliases: [grafana.prod-2.tailnet.example.internal]
```

An HTTP ingress requires its own name as SNI and `Host`, so the alias must be one of the names in
the ingress's `status.hosts`. An L4 ingress passes TCP through; the alias must be a name the
backend's certificate carries.

**3. Serve the spoke zone on the hub gateway.** The aliases land in the hub's hosts file; the hub
`TailnetGateway` answers them once their zone is listed in `dns.aliasZones`
([Gateway](gateway.md#alias-zones-for-names-of-another-cluster)). Add one entry per spoke:

```yaml
# hub TailnetGateway
spec:
  dns:
    zone: prod-1.tailnet.example.internal
    aliasZones: [prod-2.tailnet.example.internal]
```

**4. Forward the zone from the hub's cluster CoreDNS** to the gateway's `dns.serviceClusterIP`,
like the hub's own zone ([Wire the cluster CoreDNS](dns-coredns.md#wire-the-cluster-coredns)). A
block for the common parent `tailnet.example.internal` covers every spoke at once.

```sh
# hub
kubectl -n tailnet-system get tailnetegress ops \
  -o jsonpath='{range .status.targets[*]}{.name} reachable={.reachable} {.reason}{"\n"}{end}'
# prod-2-talos reachable=true
# prod-2-grafana reachable=true
kubectl -n ops run t --rm -it --image=busybox --restart=Never -- nslookup talos.prod-2.tailnet.example.internal
# Address: 10.96.41.7                       ← the egress Service ClusterIP
```

`TargetsReachable=False/Unreachable` with the names resolving means the grant is missing: the
fragment is not approved yet, or the ingress's `allowFrom` lacks the tag. Names that do not resolve
in the pod point at step 3 or 4; a name in an alias zone without an alias answers SERVFAIL.
Authentication stays the service's own: a Talos client certificate, a Kubernetes credential or the
application login. The egress adds the network path, not an identity, and every pod in
`consumerNamespaces` may use it.

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
resolver; never to the other cluster's. A hub pod that reaches a spoke name through an egress
alias resolves it on the hub as well: the hub gateway serves the spoke zone from its own hosts file
([3a](#3a-reach-a-spoke-service-from-a-pod-on-the-hub)).

## 5. What lives where

| Item | Repository | Why |
| --- | --- | --- |
| Base policy (`groups`, `hosts`, site grants, `tests`) | hub | one writer, one review queue |
| Spoke kubeconfig Secret, `spokes[]` entry | hub | the hub pulls the fragment; `approval: Manual` makes the annotation the review |
| `TailnetEgress` to the spoke API server | hub | the only path to the spoke API; grant and `/32` approval are generated |
| `TailnetEgress` to spoke services, gateway `dns.aliasZones` | hub | hub pods dial spoke names ([3a](#3a-reach-a-spoke-service-from-a-pod-on-the-hub)) |
| Hub egress tag in the spoke ingresses' `allowFrom` | spoke | exported as a grant in the fragment |
| Spoke fragments (`*-policy-fragment.json`, Git path) | hub, generated on the spoke | the hub needs them at render time; the diff is the review |
| `Tailnet`, CRs, `TailnetGateway`, LB pool, CoreDNS forward | each cluster | cluster-local objects |
| Headscale `dns.nameservers.split` | Headscale configuration | one entry per zone |
| Headscale API keys | each cluster's Secret | independent rotation — [Keys and expiry](../operations/keys.md) |

## Verify

```sh
# spoke
kubectl get tailnet corp -o jsonpath='{range .status.conditions[*]}{.type}={.status}/{.reason}{"\n"}{end}'
#   PolicyRendered=True/Rendered, PolicyApplied=True/HubMerged once the hub applied (False/HubPending before; False/Export while the control server is unreadable), TagKnown on each CR True/Known
# hub
kubectl get tailnet corp -o jsonpath='{.status.policy}{"\n"}'          # renderedHash == appliedHash
kubectl -n tailnet-system get cm headscale-policy-rendered -o jsonpath='{.data.policy}' | jq '.tagOwners | keys'
# any peer
dig +short shop-shop-dev.prod-2.tailnet.example.internal
```

| Symptom | Cause | Fix |
| --- | --- | --- |
| spoke CR `TagKnown=False/Unknown` | hub has not merged the fragment yet: fetch pending approval, spoke unreachable, or (Git path) not listed | `kubectl get tailnet -o jsonpath='{.status.spokes}'`, approve or fix the spoke; Git path: commit/refresh the fragment, check `fragmentConfigMaps` |
| hub `SpokesReady=False/SpokeUnreachable` | kubeconfig Secret missing or invalid, token revoked (`HTTP 403`), API server unreachable — the `TailnetEgress` to the spoke API not `Ready` (route not advertised or approved, [2a](#2a-reach-the-spoke-api-through-the-tailnet)), or with `networkPolicy.enabled` a missing `spokePeers`/`spokeCIDRs` entry | the `SpokeReachable` message names which; check the egress conditions; last approved fragment stays merged |
| hub `status.spokes[].fetchedAt` unchanged for days | nothing to report: the spoke's fragment has not changed since | normal while `SpokeReachable=True`; the timestamp moves only with a new fetched hash |
| hub `SpokesReady=False/ApprovalPending` | `approval: Manual` and the fetched fragment differs from the approved one | review `<spoke>-policy-fragment-pending` and `pendingDelta`, annotate with the pending hash |
| hub `SpokesReady=False/NothingApproved` | `Manual` spoke whose first fetch was never approved | annotate once; until then the spoke contributes nothing |
| hub `PolicyRendered=False/FragmentMissing` | listed `fragmentConfigMaps` entry absent in the operator namespace | ship the ConfigMap, or remove it from the list first |
| hub `SpokesReady=False/SpokeFragmentInvalid` or `PolicyRendered=False/FragmentInvalid` | fragment carries `groups`/`acls`/`ssh`/…, or a grant/owner/route outside the hub's limits (the message names the path); for a pulled fragment also a tag outside `tagPatterns` or a route outside `routeAllowlist` | export again; never hand-edit the fragment beyond review; widen the hub's `tagOwners`/`routeApprovers`/`ingressSourceAllowlist` only deliberately |
| spoke `PolicyRendered` message lists `denied …` | `allowFrom` outside the spoke's `ingressSourceAllowlist` | align the allowlist with the hub |
| spoke egress `RoutesGranted=False`, target reason `NotAdvertised` | no router advertises a route covering the host | add the `/32` or its subnet to a gateway's routes or a `TailnetSite` |
| hub egress to the spoke API `RoutesGranted=False`, target reason `NotApproved` | the spoke gateway advertises its network, but nothing on the hub approves it before the first merge | declare the spoke network as a `TailnetSite` on the hub ([2a](#2a-reach-the-spoke-api-through-the-tailnet)) |
| hub egress to the spoke API `RoutesGranted=False`, target reason `NotAdvertised` | the target is a public address, or the spoke gateway is not up yet | target the API server's private address inside the network the spoke gateway advertises |
| spoke `TailnetSite` `Ready=False/NotApproved` | the hub has not merged the fragment yet, or rejects the route | approve the fragment on the hub; a network the hub already declares needs no site on the spoke ([Site network](site-network.md)) |
