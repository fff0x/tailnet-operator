---
title: "Alerts"
weight: 70
description: "The bundled PrometheusRule: every alert with severity, condition and a link to its runbook."
---

<!-- Curated from charts/tailnet-operator/files/rules.yaml. Keep in step when a rule changes. -->

Enabled with `monitoring.rules.enabled: true` (needs the Prometheus Operator CRDs; see
[Monitoring and alert runbooks](../OPERATIONS.md)). Thresholds for the key-expiry alerts come from
`monitoring.rules.apiKeyExpiryWarningSeconds` (default 7 days) and
`monitoring.rules.authKeyExpiryWarningSeconds` (default 1 day). Non-empty `monitoring.rules.groups`
replaces the whole bundled group.

| Alert | Severity | Fires when | Runbook |
| --- | --- | --- | --- |
| `TailnetOperatorDown` | critical | no healthy operator metrics endpoint for 5 min (`up` absent or 0) | [operator down](../OPERATIONS.md#monitoring-operator-down) |
| `TailnetReconcileErrors` | warning | more than 0.1 controller-runtime reconcile errors/s for 10 min | [reconcile errors](../OPERATIONS.md#monitoring-reconcile-errors) |
| `TailnetHeadscaleAPIErrors` | warning | more than 5 % HTTP 5xx on Headscale operations over 10 min (code 0 = transport, not 5xx) | [Headscale API](../OPERATIONS.md#monitoring-headscale-api) |
| `TailnetResourceNotReady` | warning | a CR has been `Ready=False` for 10 min; the `reason` label is the current `Ready` reason | [resource not ready](../OPERATIONS.md#monitoring-resource-not-ready) |
| `TailnetPolicyStale` | warning | `tailnet_policy_pending == 1` for 15 min (`Apply` mode, render ≠ applied) | [policy stale](../OPERATIONS.md#monitoring-policy-stale) |
| `TailnetPolicyRejected` | warning | `PolicyApplied=False/PolicyRejected` for 5 min; the previous policy stays live | [policy rejected](../OPERATIONS.md#monitoring-policy-rejected) |
| `TailnetPolicyApplyErrors` | warning | at least 6 failed policy writes in 30 min | [policy apply errors](../OPERATIONS.md#monitoring-policy-apply-errors) |
| `TailnetPolicyGeneratedDrop` | warning | generated tags, grants or routes fell by more than half within 10 min | [policy generated drop](../OPERATIONS.md#monitoring-policy-generated-drop) |
| `TailnetApprovalReplays` | warning | more than 3 routes re-approved by replay within 1 h | [route replays](../OPERATIONS.md#monitoring-route-replays) |
| `TailnetRouteConflict` | warning | a `TailnetSite` has carried `RouteConflict` (`OverlapsReserved` / `OverlapsSite`) for 15 min | [route conflict](../OPERATIONS.md#monitoring-route-conflict) |
| `TailnetUnmanagedRouteOverlap` | info | for 30 min a node without an advertiser tag advertises a route overlapping a `TailnetSite` | [unmanaged route overlap](../OPERATIONS.md#monitoring-unmanaged-route-overlap) |
| `TailnetGatewayFreshBlocked` | warning | a `TailnetGateway` has reported `Ready=False/FreshBlocked` for 5 min | [gateway fresh blocked](../OPERATIONS.md#monitoring-gateway-fresh-blocked) |
| `TailnetNodeOffline` | warning | Headscale has listed the resource's node as offline for 5 min | [node offline](../OPERATIONS.md#monitoring-node-offline) |
| `TailnetAPIKeyExpiringSoon` | warning | `tailnet_apikey_expires_seconds` below the API-key threshold for 5 min | [key expiry](../OPERATIONS.md#monitoring-key-expiry) |
| `TailnetEgressAuthKeyExpiringSoon` | warning | `tailnetegress_authkey_expires_seconds` below the auth-key threshold for 5 min | [key expiry](../OPERATIONS.md#monitoring-key-expiry) |
| `TailnetIngressAuthKeyExpiringSoon` | warning | `tailnetingress_authkey_expires_seconds` below the auth-key threshold for 5 min | [key expiry](../OPERATIONS.md#monitoring-key-expiry) |

The `runbook_url` annotation of every rule is the repository-relative path of its runbook
(`docs/OPERATIONS.md#monitoring-…`); prefix it with your docs base URL in Alertmanager templates.
