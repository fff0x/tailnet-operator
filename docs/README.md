# Documentation

Reading paths by role. Every page is self-contained; the paths only say where to start.

| You are… | Start | Then |
| --- | --- | --- |
| evaluating the operator | [README](../README.md) (model, quickstart, CRD field tables) | [COMPATIBILITY](COMPATIBILITY.md) — supported Kubernetes/Headscale versions, verified platforms, test coverage |
| installing it | [INSTALL](INSTALL.md) — prerequisites, chart values, what the site must provide, network isolation, upgrade and rollback | [SECURITY](SECURITY.md) — trust model, credentials, supply chain verification |
| running it (SRE) | [USAGE §10–14](USAGE.md#10-operations-keys-and-expiry) — keys, diagnosis cheat sheet, upgrade, state and backup, alert runbooks | [reference/gateway.md](reference/gateway.md) if a `TailnetGateway` is in use |
| a tenant publishing or reaching a service | [USAGE §1–6](USAGE.md#1-egress-reach-a-database-at-the-site) — one worked example per scenario | [USAGE §13](USAGE.md#13-validation) before editing CRs by hand |
| a Headscale/policy admin | [USAGE §7–9a](USAGE.md#7-policy-read-what-the-operator-generated) — what the operator renders, how to review before `Apply`, `TailnetSite` | [reference/rbac.md](reference/rbac.md) — every RBAC rule the chart grants |
| auditing it | [SECURITY](SECURITY.md) | [reference/rbac.md](reference/rbac.md), [COMPATIBILITY § Test coverage](COMPATIBILITY.md#test-coverage), [CHANGELOG](../CHANGELOG.md) |
| contributing | [CONTRIBUTING](../CONTRIBUTING.md) — toolchain, gates, how CI builds and signs | [README § Develop](../README.md#develop) — task list and package map |

## Pages

| Page | Scope |
| --- | --- |
| [INSTALL.md](INSTALL.md) | Prerequisites, Helm/kustomize install, chart vs. site responsibilities, preflight, network isolation (Kubernetes and Cilium policies), upgrade, rollback |
| [USAGE.md](USAGE.md) | Scenario walk-throughs for egress, ingress and policy; operations (keys, diagnosis, upgrade, state and backup); validation rules; monitoring and alert runbooks |
| [COMPATIBILITY.md](COMPATIBILITY.md) | Supported platforms, per-version compatibility notes, preflight matrix, test coverage |
| [SECURITY.md](SECURITY.md) | Private reporting, trust model, credentials, workloads/RBAC/network, supply chain (cosign, Radicle release record) |
| [reference/gateway.md](reference/gateway.md) | `TailnetGateway` contract: fresh bootstrap chain, receipts, deletion, spec updates, key lifecycle, rollback, verified platforms |
| [reference/rbac.md](reference/rbac.md) | Generated RBAC reference; `task rbac-check` keeps it in sync with the chart |
| [../CHANGELOG.md](../CHANGELOG.md) | Per-release Added/Changed/Fixed and upgrade notes |
| [../charts/tailnet-operator/README.md](../charts/tailnet-operator/README.md) | Generated chart README: every value with default and description |

Conventions: `corp` is the example `Tailnet`, `tailnet-system` the operator namespace, `example`
domains stand in for yours. Commands assume `kubectl` against the target cluster and, where Headscale
is in-cluster, `kubectl -n tailnet-system exec deploy/headscale -- headscale …`.
