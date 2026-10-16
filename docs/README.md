---
title: "Documentation"
description: "Tsunaro (tailnet-operator) documentation: tutorial, how-to guides, reference and explanation."
---

The documentation follows [Diátaxis](https://diataxis.fr/): a **tutorial** to learn by doing,
**how-to guides** for tasks, **reference** for facts, **explanation** for understanding, plus the
**operations** pages for whoever runs it day to day. Every page is self-contained; the table only
says where to start.

| Section | Start here |
| --- | --- |
| [Tutorials](tutorials/README.md) | [Getting started](tutorials/getting-started.md) — Headscale to first egress and ingress in about thirty minutes |
| [How-to guides](how-to/README.md) | [Prepare Headscale](how-to/install-headscale.md) · [Install the operator](how-to/install-operator.md) · [Egress](how-to/egress.md) · [Ingress: TCP](how-to/ingress-tcp.md) · [Ingress: HTTPS](how-to/ingress-https.md) · [DNS with CoreDNS](how-to/dns-coredns.md) · [Operator-owned policy](how-to/policy.md) · [Site network](how-to/site-network.md) · [Gateway](how-to/gateway.md) · [Upgrade and roll back](how-to/upgrade-rollback.md) · [Troubleshoot](how-to/troubleshooting.md) |
| [Reference](reference/README.md) | [CRDs](reference/crds.md) · [Chart values](reference/values.md) · [RBAC](reference/rbac.md) · [Compatibility](reference/compatibility.md) · [TailnetGateway contract](reference/gateway.md) · [Metrics](reference/metrics.md) · [Alerts](reference/alerts.md) · [Conditions and reasons](reference/reasons.md) · [Changelog](../CHANGELOG.md) |
| [Explanation](explanation/README.md) | [Model and how it works](explanation/model.md) · [Security model](explanation/security-model.md) |
| [Operations](operations/README.md) | [Keys and expiry](operations/keys.md) · [State, backup and loss](operations/state-backup.md) · [Validation](operations/validation.md) · [Monitoring and alert runbooks](OPERATIONS.md) |

## Reading paths by role

| You are… | Start | Then |
| --- | --- | --- |
| evaluating the operator | [Model and how it works](explanation/model.md) | [Compatibility](reference/compatibility.md) — supported Kubernetes/Headscale versions, verified platforms, test coverage |
| installing it | [Getting started](tutorials/getting-started.md), then [Prepare Headscale](how-to/install-headscale.md) and [Install the operator](how-to/install-operator.md) — chart values, what the site must provide, network isolation | [Security model](explanation/security-model.md) — trust model, credentials, supply chain verification |
| running it (SRE) | [Operations](operations/README.md) — keys, state and backup, validation; [Monitoring and alert runbooks](OPERATIONS.md) | [Troubleshoot](how-to/troubleshooting.md); [TailnetGateway contract](reference/gateway.md) if a gateway is in use |
| running a gateway (subnet router + split-DNS as a CR) | [Run the gateway](how-to/gateway.md) — prerequisites, order, complete example with LB pool, iBGP, split-DNS, site | [TailnetGateway contract](reference/gateway.md) |
| a tenant publishing or reaching a service | [Egress](how-to/egress.md), [Ingress: TCP](how-to/ingress-tcp.md), [Ingress: HTTPS](how-to/ingress-https.md) — one worked example per scenario | [Validation](operations/validation.md) before editing CRs by hand |
| a Headscale/policy admin | [Let the operator own the policy](how-to/policy.md), [Declare a site network](how-to/site-network.md) | [RBAC reference](reference/rbac.md) — every rule the chart grants |
| auditing it | [Security model](explanation/security-model.md) | [RBAC](reference/rbac.md), [Compatibility § Test coverage](reference/compatibility.md#test-coverage), [Changelog](../CHANGELOG.md) |
| contributing | [CONTRIBUTING](../CONTRIBUTING.md) — toolchain, gates, how CI builds and signs | [README § Develop](../README.md#develop) — task list and package map |

Conventions: `corp` is the example `Tailnet`, `tailnet-system` the operator namespace, `prod-1`
the cluster, `tailnet.example.internal` the domain, `billing-dev` / `billing` / `shop-dev` tenant
namespaces, `10.0.0.0/8` the site network. Commands assume `kubectl` against the target cluster
and, where Headscale is in-cluster, `kubectl -n tailnet-system exec deploy/headscale -- headscale …`.

The documentation is licensed under [CC BY 4.0](LICENSE); the operator under
[Apache-2.0](../LICENSE). Former page names (`INSTALL.md`, `USAGE.md`, `SECURITY.md`,
`COMPATIBILITY.md`) remain as redirect stubs for one release.
