---
title: "Troubleshoot"
weight: 110
description: "Symptom table with the condition reasons, and the diagnosis cheat sheet."
---

## Symptoms

| Symptom | Look at | Typical cause |
| --- | --- | --- |
| `Tailnet` `ApiReachable=False/Unreachable` | condition message | `apiUrl` wrong, NetworkPolicy blocks the operator |
| `Tailnet` `ApiReachable=False/Unhealthy` | Headscale `/health`, its database | Headscale answers but cannot reach its database (it then returns 401 on every API call) |
| `Tailnet` `ApiKeyValid=False/Rejected` | Headscale `apikeys list` | working key expired or deleted on the server; `Error` = rotation failed (bootstrap key expired) |
| `HeadscaleCompatible=False/Incompatible` | condition message | missing policy/check endpoint (requires ≥ 0.29), or file policy mode |
| `PolicyMode=False/File`, `PolicyApplied=False/PolicyModeFile` | Headscale `policy.mode` | switch to database mode using [Migrating from file mode](policy.md#migrating-from-file-mode); writes are skipped until mode detection changes |
| Preflight `Unknown/ProbeFailed` | API/key conditions and Headscale logs | failed requests or invalid response shape; not proof of file mode |
| `SplitDNS=False/Missing` or `Mismatch` | condition message (observed vs expected resolver) and Headscale `dns.nameservers.split` | point the named zone at the gateway LoadBalancer IP; Headscale has no DNS API, so this is a manual edit |
| `SplitDNS=Unknown/CannotVerify` | condition message | no `TailnetGateway` binds the Tailnet, or no agent (ingress/egress) is online to read the netmap |
| `UsersUnique=False/Duplicate`, `PolicyApplied=False/PolicyRejected` | `headscale users list` | duplicate user names (typically OIDC plus a CLI-created user); destroy the surplus user, the next reconcile clears both |
| Egress `TagKnown=False/Unknown` | `kubectl describe tailnetegress` | tag missing in `tagOwners` (file mode) |
| Egress `TagKnown=False/PolicyPending` | `kubectl describe tailnet` → `PolicyApplied` | policy not applied yet / rejected |
| `Registered=False/WorkloadBlocked` | condition message, `kubectl -n <ns> describe deploy <agent>` | agent pod refused by a LimitRange/ResourceQuota/PodSecurity — raise `spec.resources` or `Tailnet.spec.proxy.resources` ([Agent resources](install-operator.md#namespaces-with-a-limitrange)) |
| `status.targets[].reason=NotAdvertised` | router `--advertise-routes` | route not advertised |
| `… NotApproved` | `headscale nodes list-routes`, `kubectl describe tailnet` events | route not approved; with operator-owned policy it is re-approved on the next policy reconcile — persists → `autoApprovers` entry missing or router tag differs |
| `… NoGrant` | policy `grants` | no grant tag → /32:port (file mode) |
| `TargetsReachable=False` | agent log `dial …: context deadline exceeded` | site firewall, target down |
| Alias does not resolve in a pod | `kubectl -n tailnet-system get cm tailnet-dns-hosts`, resolver log | zone not forwarded, ConfigMap not mounted, Service not created yet |
| Ingress `PolicyGranted=False/PolicyDenied` | condition message | `allowFrom` entry not covered by `ingressSourceAllowlist` |
| `PolicyRendered=False/PolicyEmpty` | base ConfigMap | base has no `tagOwners` or no `acls`/`grants` — refused to avoid a lock-out |
| `PolicyApplied=False/ApplyFailed` | condition message (`read: …; write: …`) | Headscale still in file mode, empty policy table, API unreachable |
| Event `PolicyDriftOverwritten` | `kubectl get events -A --field-selector reason=PolicyDriftOverwritten` | someone ran `headscale policy set` |
| hosts/rendered ConfigMap not updating; Event `ConfigMapNotOwned` | `kubectl get events -A --field-selector reason=ConfigMapNotOwned`, `kubectl -n tailnet-system get cm <name> -o yaml` | a ConfigMap of that name is controlled by another resource — rename it or remove the foreign one (an ownerRef-less one with label `tsunaro.io/role` is adopted automatically) |

## Diagnosis cheat sheet

| Question | Command | Healthy output |
| --- | --- | --- |
| Is the control server reachable? | `kubectl describe tailnet corp` | `ApiReachable=True`, `ApiKeyValid=True` |
| Does preflight pass? | `kubectl get tailnet corp`, `kubectl describe tailnet corp` | `COMPAT=Compatible`, `PolicyMode=True/Database`; `DNS=Configured` once a gateway and one agent are up; `Missing`/`Mismatch` name the Headscale `dns.nameservers.split` fix |
| Why is an egress not ready? | `kubectl -n tailnet-system get tailnetegress X -o jsonpath='{range .status.targets[*]}{.name} {.present} {.reachable} {.reason}{"\n"}{end}'` | `true true` per target, empty reason |
| Is the route on the router? | `kubectl -n tailnet-system exec deploy/headscale -- headscale nodes list-routes` | the target's `/32` or a covering subnet under the router's approved routes |
| Does the agent reach the host? | `kubectl -n tailnet-system logs deploy/X \| grep target` | no `dial …: context deadline exceeded` |
| What does the agent probe say? | `wget -qO- http://<agent-pod-ip>:9080/targets` from any pod | `"reachable":true` per target |
| Does an alias resolve? | `kubectl -n <tenant> exec deploy/app -- getent hosts api.corp.example` | the Service ClusterIP |
| Is the hosts file current? | `kubectl -n tailnet-system get cm tailnet-dns-hosts -o jsonpath='{.data.hosts}'` | one line per alias / ingress name |
| Resolver errors? | `kubectl -n <resolver-ns> logs <coredns-pod> \| grep -i error` | none; `i/o timeout` = upstream unreachable |
| What did the policy render? | `kubectl get tailnet corp -o jsonpath='{.status.policy}'`, ConfigMap `headscale-policy-rendered` | hashes equal, `PolicyApplied=True` |
| Who is on the tailnet? | `kubectl -n tailnet-system exec deploy/headscale -- headscale nodes list` | egress/ingress nodes online with their tags |

### Clients time out right after an agent restart

An egress agent Pod carries no state: each start registers a new Headscale node with a new tailnet
IP ([Limitations](../reference/limitations.md#data-path-agents)); an ingress keeps its node across
restarts and is not affected. The operator rewrites the split-DNS zone
within seconds and deletes the old node on its next reconcile, but a client that resolved the name
just before the restart keeps the old address until the 30 s record TTL expires — connections time
out for up to that long, on top of the restart itself. It is a symptom of the restart, not a second
fault: check why the agent restarted (`kubectl -n <ns> describe deploy <agent>`, OOM, LimitRange)
and confirm the new identity is live:

```sh
kubectl -n <ns> get tailnetingress <name> -o jsonpath='{.status.nodeId} {.status.tailnetIps}{"\n"}'
dig +short <dnsName> @<gateway DNS Service IP>   # must show the new IP
```

Address agents by name, never by tailnet IP; the name is the contract that survives a restart.

### Known CNI behavior: ICMP errors

Kubernetes NetworkPolicy specifies TCP, UDP and SCTP; ICMP handling is up to the CNI, and some
implementations drop node-generated ICMP errors (unreachable, fragmentation-needed) to
policy-selected pods. A timeout on an agent is therefore not proof of reachability, and path-MTU
discovery may not work; `Tailnet.spec.proxy.mtu` (default 1200) sidesteps the latter.
