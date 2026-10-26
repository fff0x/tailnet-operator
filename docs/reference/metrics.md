---
title: "Metrics"
weight: 60
description: "Every Prometheus metric the operator (TCP 8080) and the agents (TCP 9080) expose, with labels and meaning."
---

<!-- Curated from internal/metrics/metrics.go and cmd/agent/metrics.go. Keep in step when a collector changes. -->

The operator serves `/metrics` on TCP 8080 (chart `ServiceMonitor`), each agent and gateway pod on
TCP 9080 (chart `PodMonitor`). Collectors observe persisted status only — never messages,
credentials, peer addresses or dynamic Headscale paths. How to read them in practice:
[Metric interpretation](../OPERATIONS.md#metric-interpretation).

## Operator

| Metric | Type | Labels | Meaning |
| --- | --- | --- | --- |
| `tailnet_resource_ready` | gauge | `kind`, `namespace`, `name`, `tailnet` | Current-generation `Ready` condition is True; absent without a current `Ready` condition (`Tailnet` has none; suspended gateways are withdrawn). |
| `tailnet_resource_condition` | gauge | `kind`, `namespace`, `name`, `type`, `reason` | 1 for the current-generation reason of each condition (including False and Unknown); previously observed reasons are 0. Read type and reason, not the value as a boolean. |
| `tailnet_egress_target_state` | gauge | `namespace`, `name`, `target`, `reason` | Current-generation target route reason; `Present` represents an empty successful route reason. |
| `tailnet_ingress_expose_reachable` | gauge | `namespace`, `name`, `expose` | Current-generation expose backend reachability. |
| `tailnet_node_online` | gauge | `kind`, `namespace`, `name` | 1 when a successful Headscale node list contains an online node matching this resource's tag and hostname; absent without a current observation. |
| `tailnet_node_last_seen_seconds` | gauge | `kind`, `namespace`, `name` | Unix timestamp of Headscale `lastSeen` for the matching node; absent when unknown. Use `time() - …` for the age. |
| `tailnet_headscale_user_conflicts` | gauge | `tailnet` | Headscale user names carried by more than one user (`status.userConflicts`); anything above 0 makes Headscale reject every policy write. Absent without a current `UsersUnique` verdict. |
| `tailnet_policy_pending` | gauge | `tailnet` | 1 only in `Apply` mode while a non-empty `renderedHash` differs from `appliedHash`; 0 otherwise. Absent without policy status. |
| `tailnet_spoke_reachable` | gauge | `tailnet`, `spoke` | 1 when the hub read the spoke's fragment ConfigMap on the last reconcile (`SpokeReachable=True`), 0 otherwise. One series per `policy.spokes[]` entry; withdrawn when the spoke is removed. |
| `tailnet_spoke_fragment_valid` | gauge | `tailnet`, `spoke` | 1 when the last fetched fragment passed the hub's validation (`SpokeFragmentValid=True`), 0 when it failed or nothing was fetched. |
| `tailnet_spoke_fragment_pending` | gauge | `tailnet`, `spoke` | 1 while a valid fetched fragment waits for `tsunaro.io/approve-spoke.<spoke>` (`approval: Manual`); 0 otherwise. |
| `tailnet_policy_generated` | gauge | `tailnet`, `kind` | Generated entries in the persisted policy status (`kind` ∈ `tags`, `grants`, `routes`). |
| `tailnet_policy_applied_timestamp_seconds` | gauge | `tailnet` | Unix time the rendered policy was last applied to the control server. An old value alone is healthy. |
| `tailnet_policy_apply_errors_total` | counter | `tailnet` | Policy writes the control server rejected or that failed. |
| `tailnet_policy_write_duration_seconds` | histogram | `tailnet` | `SetPolicy` latency including failures. |
| `tailnet_route_approvals_replayed_total` | counter | `tailnet` | Routes successfully approved by replay — counted per route, not per request, so one batch adds several. |
| `tailnet_headscale_api_requests_total` | counter | `tailnet`, `method`, `path_template`, `code` | Headscale operations; paths are bounded templates, `code` 0 means no HTTP response (transport failure). |
| `tailnet_headscale_api_duration_seconds` | histogram | `tailnet`, `method`, `path_template`, `code` | Headscale operation latency including failures. |
| `tailnet_apikey_expires_seconds` | gauge | `tailnet` | Seconds until the operator's working API key expires; negative once expired. |
| `tailnetegress_authkey_expires_seconds` | gauge | `namespace`, `name` | Seconds until a `TailnetEgress` pre-auth key expires. |
| `tailnetingress_authkey_expires_seconds` | gauge | `namespace`, `name` | Seconds until a `TailnetIngress` pre-auth key expires. |
| `tailnetegress_routes_missing` | gauge | `namespace`, `name` | **Deprecated** (kept through v0.4.x): use `tailnet_egress_target_state`. Target routes missing from the egress netmap. |
| `tailnetingress_backends_unreachable` | gauge | `namespace`, `name` | **Deprecated** (kept through v0.4.x): use `tailnet_ingress_expose_reachable`. Backends an ingress agent could not reach. |

The controller-runtime families (`controller_runtime_reconcile_errors_total`, …) and the Go runtime
families are exported as well; the bundled alerts use `controller_runtime_reconcile_errors_total` and `up`.

## Agents (egress, ingress) and gateways

| Metric | Type | Labels | Meaning |
| --- | --- | --- | --- |
| `tailnet_agent_connections_active` | gauge | `target`, `expose` | Open client TCP connections assigned to a target; HTTP assignment begins at a recognized SNI. |
| `tailnet_agent_bytes_total` | counter | `target`, `expose`, `direction` | Bytes on target-assigned client connections (`to_target` / `from_target`); HTTP counts after the recognized SNI, including TLS wire overhead. |
| `tailnet_agent_dial_duration_seconds` | histogram | `target`, `expose` | Upstream TCP dial duration, including failed dials and health probes. |
| `tailnet_agent_http_unattributed_connections_active` | gauge | — | Open HTTP connections without a recognized SNI (HTTP listeners only). |
| `tailnet_agent_http_unattributed_bytes_total` | counter | `direction` | TLS wire bytes before a recognized SNI, including rejected handshakes. |

Labels carry target and expose **names**, never peers or IP addresses. A `TailnetGateway` pod
additionally exposes the Tailscale sidecar's own metrics on TCP 8080 and the CoreDNS metrics on
TCP 9153; the chart `PodMonitor` scrapes all three.
