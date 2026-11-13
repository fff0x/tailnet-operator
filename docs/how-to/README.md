---
title: "How-to guides"
weight: 20
description: "Task-oriented recipes: one scenario per page, with the commands, the expected status and the reasons when it is not Ready."
---

Each guide solves one task for someone who already knows what they want. Guides assume the
operator is installed; if it is not, start with [Getting started](../tutorials/getting-started.md).

| Page | Task |
| --- | --- |
| [Prepare Headscale](install-headscale.md) | Version, policy entries the operator needs, bootstrap API key, preflight checks |
| [Install the operator](install-operator.md) | Helm or kustomize install, chart vs. site responsibilities, network isolation (Kubernetes and Cilium policies) |
| [Egress: reach services at the site](egress.md) | A namespace dials a site database/broker/HTTPS API through a stable Service name; aliases, SNI, status reasons |
| [Ingress: publish a TCP service](ingress-tcp.md) | Tailnet peers reach a cluster Service by name; who may dial it |
| [Ingress: publish a web app over HTTPS](ingress-https.md) | TLS terminated on the agent with cert-manager, or passthrough to a shared gateway |
| [Ingress: reach the Kubernetes API over the tailnet](kubernetes-api.md) | API server (and node management API) without a public endpoint; kubeconfig and grant |
| [Serve DNS names with CoreDNS](dns-coredns.md) | Turn the operator's hosts file into a resolvable zone and wire the cluster CoreDNS |
| [Let the operator own the policy](policy.md) | Read what the operator renders, review in DryRun, switch to Apply, migrate from file mode |
| [Declare a site network (TailnetSite)](site-network.md) | Give a LAN a name and a status; block overlapping routes |
| [Run the gateway (subnet router + split-DNS)](gateway.md) | Prerequisites and order, complete example with LB pool, iBGP, split-DNS and site |
| [Connect a second cluster](second-cluster.md) | Hub and spokes on one Headscale: per-cluster names, exported policy fragments, grants between clusters, one DNS zone per cluster, what lives in which repository |
| [Bridge: let a legacy network reach the tailnet](legacy-bridge.md) | Hosts without a tailnet client reach a tailnet service through the site cluster: `TailnetEgress.spec.expose`, two-sided consent, bounded source filter; the proxy-box fallback and why a NAT subnet router is wrong |
| [Upgrade and roll back](upgrade-rollback.md) | Chart and CRD upgrade order, what to verify afterwards, how to roll back |
| [Troubleshoot](troubleshooting.md) | Symptom → cause → fix table and the diagnosis cheat sheet |
