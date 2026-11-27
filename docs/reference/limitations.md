---
title: "Limitations"
weight: 45
description: "What the operator deliberately does not do, why, and what to use instead — data path, policy, HTTP mode, gateway, IPv6, control plane."
---

One page for the boundaries that are otherwise scattered across the how-to guides. Every row is
checked against the code of the pinned release; if a row stops being true the page is wrong, not the
code. Versions and the preflight matrix are in [Compatibility](compatibility.md).

## Data path (agents)

| Limit | Why | Workaround or status |
| --- | --- | --- |
| Agents forward **TCP only**. No UDP, no ICMP, no ping through an egress or ingress. | The agent is a userspace `tsnet` node: it `Listen`s and `Dial`s TCP streams and copies bytes. It has no `NET_ADMIN`, no `/dev/net/tun`, no kernel routes. | UDP/ICMP to a site goes through the [gateway](../how-to/gateway.md) (a real subnet router). Diagnose reachability with the agent's `/targets` probe and the `TargetsReachable` condition, not with ping. |
| Agents do not advertise routes and do not accept routes. | An egress agent dials one `host:port` per target; it is not a router and must never pull the site's prefixes into a tenant namespace. | Site prefixes are advertised by the `TailnetGateway` (or any tagged router) and approved per `/32` from the egress targets. |
| One agent Pod per CR, `Recreate` on change. A resource or image change restarts it. | Two Pods would briefly share one hostname and tag. | Expect a short interruption per change ([Agent resources](../how-to/install-operator.md#agent-resources)). No HA pair per CR. Pin `agentImage` separately so an operator bump alone does not roll agents ([Upgrade](../how-to/upgrade-rollback.md)). |
| **Egress identity is ephemeral**: every egress Pod start is a new Headscale node with a new tailnet IP. **Ingress identity persists** across Pod restarts. | An egress agent keeps its `tsnet` state in memory and registers with an ephemeral pre-auth key; no state Secret, no Kubernetes client. An ingress agent writes its state to a Secret in its namespace through its own ServiceAccount (`ingress-<name>`), so a restarted Pod is the same node; a changed tag, server or hostname is a new identity (new Secret, fresh registration, old node deleted by the operator). | Address egress agents by name (`dnsName`, aliases), never by tailnet IP; the split-DNS zone is re-rendered at once and records carry a 30 s TTL ([Troubleshooting](../how-to/troubleshooting.md#clients-time-out-right-after-an-agent-restart)). Ingress peers may keep the address they resolved. |
| An egress target is `address:port` (IP or MagicDNS name), one Service per CR, TCP ports only. | The Service's `ClusterIP:listenPort` maps 1:1 onto a tunnel. | Several hosts behind one name: several targets or several CRs. HTTPS with a hostname check: an alias, so SNI/Host stay intact ([Egress § aliases](../how-to/egress.md)). |
| Egress aliases resolve to a **ClusterIP** and are therefore cluster-local. | The hosts file maps the alias to the Service of that cluster. | Each cluster forwards its alias zone to its own resolver ([Second cluster § DNS](../how-to/second-cluster.md#4-dns-one-zone-per-cluster)); another cluster's zone is served locally through the gateway's `dns.aliasZones` ([§ 3a](../how-to/second-cluster.md#3a-reach-a-spoke-service-from-a-pod-on-the-hub)). |
| An exposed egress (`spec.expose`) filters LAN clients by **source address**; the operator cannot verify that the LoadBalancer preserves it. | The filter is a NetworkPolicy `ipBlock` on the agent Pod; `externalTrafficPolicy: Local` is fixed, but a proxying LB or upstream NAT still replaces the client address, and `Exposed=True/AddressAssigned` only means an address was assigned. | Use an LB that forwards to the Pod's node (MetalLB, Cilium LB-IPAM, kube-vip, cloud NLB with client-IP preservation); verify once from an unlisted host ([Bridge § security](../how-to/legacy-bridge.md#security-what-the-bridge-is-and-is-not)). |
| Exposed Services need a LoadBalancer implementation; the operator assigns no addresses. | Address pools are cluster infrastructure (`class`, annotations, labels pass through). | Without one the egress stays `Exposed=False/PendingAddress`. |

## HTTP ingress (`mode: http`)

| Limit | Why | Workaround or status |
| --- | --- | --- |
| Routing by **TLS SNI and `Host` only**. No path, header or method rules; no rewrites. | The agent terminates TLS for the names it holds a certificate for and hands each request to one `httputil.ReverseProxy` per virtual host. Authorization is the tailnet policy's job. | L7 rules belong to the backend or to an in-cluster gateway behind the ingress ([Ingress: HTTPS § passthrough](../how-to/ingress-https.md)). |
| A request for a name without a virtual host gets `308` (one served host) or `404` (several). | Unknown SNI is rejected at the handshake; an unknown `Host` on a known certificate cannot be routed. | Add the name as an alias (same zone) or, for a name the site resolves itself, as a bridge name (`bridgeNames`, admin-allowed zone) — both are extra SANs and virtual hosts. |
| Clients may speak HTTP/1.1 or HTTP/2 (and upgrade to WebSocket); the **backend is always spoken to over HTTP/1.1**. No end-to-end gRPC, no HTTP/3. | `x/net/http2` is configured on the listener only; the backend transport uses its own dialer without HTTP/2 negotiation. QUIC is UDP. | gRPC: publish the port as a TCP ingress (`mode` L4) and let the client terminate TLS; HTTP/3: terminate elsewhere. |
| Backend TLS verification needs `backendServerName` **and** a CA bundle. | Without a name to verify there is nothing to pin; `InsecureSkipVerify` is not offered. | Mount the CA ConfigMap ([Ingress: HTTPS § backend TLS](../how-to/ingress-https.md)). |

## Policy

| Limit | Why | Workaround or status |
| --- | --- | --- |
| **Exactly one** `Tailnet` per Headscale may run `policy.mode: Apply`. | The render is base + generated; two writers would overwrite each other. | Spokes use `Export` and the hub merges their fragments ([Second cluster](../how-to/second-cluster.md)). |
| The operator never edits `groups`, `hosts`, `acls`, `ssh` or `tests`; a fragment may only add `tagOwners`, `autoApprovers.routes` and `grants`. | Those blocks are the admin's authorization model; the operator only derives what its CRs imply. | Edit the base ConfigMap in Git; the operator re-renders. |
| Requires Headscale **policy mode `database`** for `Apply`; in `file` mode it renders but never writes. | `PUT /api/v1/policy` is only accepted in database mode. | Migrate once ([Policy § migrate from file mode](../how-to/policy.md)); read-only `DryRun` works in either mode. |
| `allowFrom` is checked against `ingressSourceAllowlist` with path-style globs; an empty allowlist denies every source. | Tenants must not grant themselves `autogroup:member` or `*`. | Set the allowlist on the `Tailnet` (`["group:*"]`, specific tags). |
| A `TailnetGrant` grants **TCP ports only**, to one ingress tag or to prefixes inside a `TailnetSite`; sources are groups and user references. | The kind covers people reaching a service; UDP, ICMP, "all ports", tags and `autogroup:` sources are not modelled. | Write such a grant in the base policy. |
| A `TailnetGrant` expires by the **operator's clock**, and the access ends with the next successful policy write. | Headscale has no expiry for a policy entry; the operator rewrites the policy at `expiresAt`. | A failed write shows as `Ready=False/ExpiryPending` and fires `TailnetResourceNotReady` after 10 min. |
| After a policy change the agent closes an **established connection** only on a `TailnetIngress`. A connection to a host inside a `TailnetSite` is not closed, also after its `TailnetGrant` expired. An agent without contact to Headscale keeps the last policy it received. | The Tailscale packet filter checks only the packet that opens a TCP connection. The agent compares its open connections with its packet filter once per second (measured: closed 0.7 to 2.5 s after the revocation); the path to a site goes through the `TailnetGateway`, without an agent. | End a session to a site target at the service ([Grants § Expiry](../how-to/grants.md#expiry)). |
| An **unknown user** in `TailnetGrant.spec.sources` is not reported. | Headscale accepts a reference to a user it does not know. | Use the provider identifier from `/api/v1/user` ([Grants § Sources](../how-to/grants.md#sources)). |
| Headscale `tests` cannot assert operator-generated grants. | Tests run on the base alone (`headscale policy check`, rollback import) and `src` must resolve to existing nodes. | Test invariants of the base only, with a long-lived tagged node as `src`. |

## Gateway (`TailnetGateway`)

| Limit | Why | Workaround or status |
| --- | --- | --- |
| **Fresh IPv4 gateways only.** An IPv6 LAN route or IPv6 LB/DNS address blocks the workload update (`WorkloadCurrent=False/WorkloadUpdateBlocked`). | The fresh writer verifies an IPv4-only plan before it touches the StatefulSet. | Keep IPv6 prefixes out of `routes.lan` for now. |
| No adoption of an existing subnet router; `spec.suspend` defaults to `true`. | The operator creates the node, state Secret and key itself; a foreign node's state cannot be verified. | Run the operator gateway next to the old router, then retire the old one ([Replace a hand-built gateway](../how-to/gateway.md#replace-a-hand-built-gateway)); a lost state Secret or receipt means a new node ([no adoption](gateway.md#no-adoption)). |
| One StatefulSet, **one replica** — no HA pair, no failover between gateways. | A subnet router is a single node identity in Headscale; two advertisers of the same prefix are a Headscale/HA question, not an operator one. | Two gateways with disjoint prefixes, or accept the single router. |
| LoadBalancer pool, iBGP peering, kernel forwarding and `/dev/net/tun` are **site prerequisites**. | The operator renders the Service and the BGP intent; the platform must honour them. | [Gateway prerequisites](../how-to/gateway.md#prerequisites). |
| Headscale split-DNS cannot be set by the operator. | Headscale has no DNS API. | Add `dns.nameservers.split` by hand; the `Tailnet` verifies it from an agent's netmap (`SplitDNS=Configured` / `Missing` / `Mismatch`) and prints the expected address. |

## IPv6

| Limit | Why | Workaround or status |
| --- | --- | --- |
| Egress targets may be IPv6 addresses; the operator generates a `/128` approval and dials them. | tsnet carries both families. | — |
| The rendered **hosts file is IPv4-only**: an ingress node's tailnet IPv6 address is skipped. | Clients prefer AAAA, and tsnet/netstack agents did not accept tailnet IPv6 in the clusters verified so far; a dead AAAA would cost a connect timeout on every lookup. | Planned as a `Tailnet.spec.dns` switch once IPv6 is verified. |
| The gateway is IPv4-only (above). | Fresh writer scope. | — |

## Console

| Limit | Why | Workaround or status |
| --- | --- | --- |
| The console shows Tailnets, spokes, TailnetIngresses, TailnetSites, the person's own access and, for admins with access management, TailnetGrants; not egresses or gateways. It writes only TailnetGrants and TailnetAccessRequests. | Not built yet. | `kubectl get` for the other kinds. |
| Without `fourEyes`, admins create and extend grants alone. With it, a single admin can approve nothing that needs another admin. | Four-eyes is a choice of the installation; the console cannot count admins. | Set `console.accessManagement.fourEyes` with at least two admins in `adminGroup`. |
| Four-eyes approval binds the console only. Whoever writes TailnetGrants or a request's status with `kubectl`, or `request.approve` entries into the audit volume, bypasses it. | The API server has no notion of an approval; approvals live in the audit log so that no person is named in the cluster. | Limit write access to `tailnetgrants`, `tailnetaccessrequests/status` and the audit volume to the console; a rewritten log shows as a chain break unless the ConfigMap is rewritten too. |
| The requester does not see who approved or rejected their request, only how many approved and when it was decided. | Only admins may read the audit log, which names the deciding admins. | Ask an admin. |
| A user cannot revoke their own grant, and nobody can change a request. The console never deletes a request, and pending requests never expire. | Planned next. | An admin revokes; reject stale requests; `kubectl delete tnar` removes old ones. |
| Approval groups, notifications and e-mail do not exist. Admins see new requests by the count at **Requests** or by the alert `TailnetConsoleAccessRequestPending`. | Not built. | Route the alert to the admins. |
| The console changes only the grants it created, and only their expiry. It never deletes a grant. | Grants from Git stay in Git; one changed field keeps the audit entries simple. | Revoke and create anew to change ports or recipients; `kubectl delete` to remove one. |
| The audit log records only changes made in the console. `kubectl`, Git and the operator's expiries are not in it. Old expired console grants stay. | Observed changes and cleanup come in a later release. | `kubectl get tailnetgrant`; the API server's audit log. |
| The audit log is never rotated, and every check reads it whole. | Rotation would delete records. | Size the volume (about 1 KiB per change); move to a larger volume with `existingClaim`. |
| Whoever can write both the audit volume and the ConfigMap `<name>-console-audit` can rewrite the audit log unnoticed by the console. | The head has only two copies in the cluster. | Keep the pod log's `audit head` lines in a log store outside the cluster. |
| "My access" names the origin of a grant by comparison. A base-policy rule equal to a grant's rule shows the grant and its expiry, although the rule stays after the grant expires. | The rendered policy records no origin per grant. | Keep base rules and grants distinct. |
| "My access" shows no SSH rules, no `via` and no app capabilities. | Only network access by `grants` and accepting `acls` is evaluated. | Read the policy. |
| "My access" needs the Headscale user's provider identifier to be the one Headscale 0.29.6 builds from issuer and `sub`. | The console repeats that construction (one `/`, empty path segments dropped, URL-encoded); another form shows "no user for your sign-in". | Use the same issuer for Headscale and the console. |
| The console API speaks plain HTTP inside the cluster. | No TLS on the operator's listener yet. | Enable `networkPolicy` (both providers admit only the console on port 8082); use a CNI with pod-to-pod encryption. |
| "My access" and the map's node state can be up to 15 seconds old. | The console keeps each answer of the console API, and each error, for 15 seconds. | Wait for the next update or reload. |
| The map shows at most 12 entries per list, and only the first spoke whose patterns match a tag. | One fixed layout per Tailnet; overlapping `tagPatterns` have no single owner. | The tables list every ingress and site; keep spoke patterns disjoint. |
| In `DryRun` a spoke tag whose rules are not live appears on the map only through its nodes, without ports. | The map reads the live policy, which gets the spoke fragments only when the operator writes it (`Apply`). | Read the rendered policy ConfigMap for the ports. |
| Live updates poll the whole page every 10 seconds. | No server push; the console renders the page again for every update. | Close idle tabs; polling pauses while a tab is hidden. |
| **One replica**; a restart signs everybody out. | The session key lives in memory only, so no Secret holds it and no second replica could open its cookies. | Sign in again after a rollout. |
| A session stays valid for its hour after the person leaves the group or the IdP. | The console checks the groups at sign-in only and keeps no refresh token. | Remove the person from the console ingress's `allowFrom` source group to cut access at the network level. |
| Sign-out ends the console session only. | No RP-initiated logout at the IdP. | Sign out at the IdP as well. |
| The page shows the state at load time. | No JavaScript, no polling. | Reload the page. |
| No metrics for the console pod or the console API. | Not built yet. | Watch the console log lines `access read failed` and `sign-in rejected`. |
| The console NetworkPolicy needs the identity provider as CIDRs. | NetworkPolicy and `toCIDR` cannot select a hostname. | Update `console.networkPolicy.idpCIDRs` when the IdP's addresses change. |
| The IdP needs a certificate from a public CA. | The scratch image carries the public roots only; no CA ConfigMap is mounted for the console. | Use a publicly trusted issuer certificate. |

## Not provided

| Feature | Status |
| --- | --- |
| Exit nodes, app connectors, Tailscale Serve/Funnel, session recording | Not modelled. An exit-node tag can live in the base policy and on a node you run yourself. |
| HA proxy groups / coalescing several CRs into one node | Not modelled; one CR = one node. |
| Managing Headscale itself (users, pre-auth for humans, DNS config, OIDC) | Out of scope; the operator consumes the REST API for nodes, keys and policy only. |
| Kubernetes `Ingress`/Gateway API objects as input | Not read; the input is the six `tsunaro.io` kinds. |

## Control plane

| Limit | Why | Workaround or status |
| --- | --- | --- |
| Headscale **0.29.x** only; 0.28.x is detected and reported `HeadscaleCompatible=False`. | Operator-owned policy needs `POST /api/v1/policy/check`, which 0.28 lacks. | [Compatibility](compatibility.md); L4 egress/ingress with a hand-maintained policy still works on 0.28. |
| More than one operator replica needs `leaderElection.enabled`. | Two active managers would reconcile the same objects. | Chart value; a PDB with `minAvailable=1` is rendered for several replicas. |
| The `Tailnet` is cluster-scoped and administrative. | Its writer controls policy inputs and credentials. | Do not delegate `Tailnet` writes to tenants ([Security model](../explanation/security-model.md)). |
