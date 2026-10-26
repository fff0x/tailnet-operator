---
title: "Conditions and reasons"
weight: 80
description: "Every condition type per kind, its reasons, how Ready derives its reason, and the policy status fields."
---

<!-- Curated: moved from the root README "Status and conditions"; the reason tables in the how-to guides give the remedy per reason. -->


| Kind | Conditions | Notable reasons |
| --- | --- | --- |
| `Tailnet` | `ApiReachable`, `ApiKeyValid`, `HeadscaleCompatible`, `PolicyMode`, `SplitDNS`, `UsersUnique`, `PolicyRendered`, `PolicyApplied` | `Reachable` / `Unreachable` / `Unhealthy` (database down); `Valid` / `Rejected` / `Error`; `Compatible` / `Incompatible` / `CannotVerify` / `ProbeFailed`; `Database` / `File`; `Configured` / `Missing` / `Mismatch` (split zone read back from an agent's netmap and compared with the gateway LoadBalancer IP) / `CannotVerify` (no bound gateway or no online agent); `Unique` / `Duplicate` (two Headscale users share a name — every policy write is rejected until one is destroyed; `status.userConflicts` counts them) / `CannotVerify`; `Rendered`, `BaseMissing`, `BaseInvalid`, `PolicyEmpty` (refused: would lock everyone out), `FragmentMissing` / `FragmentInvalid` (a listed spoke fragment is absent, carries a non-additive block or steps outside the hub's limits — owners, approvers, allowlist, tcp ports, reserved networks; render fails closed, nothing written); `DryRun`, `InSync`, `Applied`, `Export` (spoke: fragment rendered for the hub, nothing written), `PolicyModeFile` (write skipped), `PolicyRejected` (Headscale refused; old policy stays), `ApplyFailed`, `NoAPIKey` |
| `TailnetEgress` | `TagKnown`, `Registered`, `RoutesGranted`, `TargetsReachable`, `ServiceConflict`, `Ready` | `Known` / `Unknown` / `PolicyPending` (tag not in live policy yet); `Registered` / `NotRegistered` / `WorkloadBlocked` (agent pod refused by admission — LimitRange/quota/PodSecurity; message carries the admission text); `RoutesMissing`, `Unreachable`, `ProbeFailed` (agent not scraped — NetworkPolicy or pod down; nothing is known about routes/dials); `Conflict` (target name taken by a foreign Service); `Ready` false with `NoTailnet`, `NoAPIKey`, `TagUnknown`, otherwise with the reason of the first blocking condition (`NotRegistered`, `RoutesMissing`, `ProbeFailed`, `Unreachable`); per target `status.targets[].reason` ∈ `NotAdvertised`, `NotApproved` (re-approved by the operator on the next policy reconcile), `NoGrant`, `ProbeFailed` |
| `TailnetSite` | `RouteConflict`, `UnmanagedOverlap`, `Advertised`, `Approved`, `Ready` | `OverlapsReserved` / `OverlapsSite` (blocked, nothing rendered; the older site is untouched); `Unmanaged` (a node without an advertiser tag advertises an overlapping route — report only); `NotAdvertised` / `NotApproved` (exact-prefix match on advertiser nodes); `NotObserved` (control server not queried); `Ready` false carries the first blocking reason in the order `RouteConflict`, `Advertised`, `Approved` |
| `TailnetGateway` | `Registered`, `RoutesInSync`, `DNSReady`, `StaleNodes`, `ClusterDNSForward`, `WorkloadCurrent`, `ServiceReady`, `Ready` | `Suspended`; `Provisioning` / `FreshBlocked` / `IdentityChanged` / `FreshRuntimeReady` (Ready); `Approved` / `NotApproved` (routes); `PodCurrent` / `PodTemplateStale` / `WorkloadUpdateBlocked`; `LoadBalancerAssigned` / `LBPending`; `ExternallyManaged` (DNS forward, stale nodes) |
| `TailnetIngress` | `TagKnown`, `PolicyGranted`, `Registered`, `BackendsReachable`, `TLSReady`, `Ready` | as egress, plus `Granted` / `PolicyDenied` (`allowFrom` outside the allowlist), `InvalidDNSName`, `DNSNameConflict` (an older CR already claims a name/alias), and for `mode: http` the `TLS*` reasons ([Terminate TLS on the agent](../how-to/ingress-https.md#terminate-tls-on-the-agent)); `Ready` false carries the first blocking reason in the order `Registered`, `PolicyGranted`, `TLSReady`, `BackendsReachable` |

`Tailnet.status.policy` = `{renderedHash, appliedHash, appliedAt, generated{tags,grants,routes}}`;
`TailnetIngress.status.dnsName` is the ingress-level DNS name; HTTP names and aliases appear in
`status.exposes[].dnsName` and `.dnsAliases`. All are published as A records with the node's IPv4
address; `status.tag` is the effective tag. `kubectl get tailnet` includes `COMPAT` and `DNS` reason columns.
Preflight uses the API response shape, not a reported server version: database policy mode and a
successful non-mutating `policy/check` probe are required for `Compatible`. Missing or failed
observations stay `Unknown`. See [preflight details](../how-to/install-headscale.md#preflight).
Event `PolicyDriftOverwritten` fires when
the live policy was changed behind the operator's back and rewritten. Event `ConfigMapNotOwned`
fires when a hosts or rendered/fragment ConfigMap of the configured name is controlled by another
resource (an ownerRef-less one carrying the operator's `tsunaro.io/role` label is re-adopted instead).
