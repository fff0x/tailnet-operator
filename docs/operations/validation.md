---
title: "Validation"
weight: 30
description: "Admission rules the API server enforces, and how to test CRs without a cluster before a CRD upgrade."
---

Kubernetes **1.31 or later** is required. The API server validates these rules before storing a CR:

| Object / field | Rule |
| --- | --- |
| All three kinds | `spec` is required |
| Egress / ingress CR name | Lowercase DNS label, at most 40 characters; no dots |
| Egress `targets` | 1–50 entries; unique names, each a DNS-1035 label of at most 63 characters, starting with a letter (Service compatibility with Kubernetes 1.31) |
| Target `address` | Single IPv4/IPv6 address or lowercase DNS name (≤253 characters, labels ≤63); no CIDR, URL, host:port, IPv6 zone ID or malformed numeric IP |
| Target `aliases` | Each a lowercase DNS name of at most **63 characters** (a product limit, not the DNS FQDN maximum) |
| Egress `consumerNamespaces` | At least one namespace; each a DNS label of at most 63 characters |
| Ingress `allowFrom` | Required, at least one non-empty entry; the Tailnet's source allowlist still controls authorization |
| Ingress `exposes` | 1–50 entries; unique names and listener ports; names are DNS labels of at most 63 characters |
| Backend `service` / optional `namespace` | DNS labels of at most 63 characters |
| Ingress expose `mode` | Omitted or `l4` preserves TCP forwarding; `http` requires port 443 and at most one HTTP expose |
| Ingress `tls` | HTTP only; optional Secret name or Issuer reference, never both; an omitted source may inherit the Tailnet issuer default |
| Expose `backend.tls` | HTTP only; explicit DNS verification name and namespace-local ConfigMap name/key; no insecure or system-root fallback |
| Expose `timeouts` | HTTP only; optional `request` and `backendRequest` durations; `0s` disables the named timer |
| TLS issuer reference | Name is a DNS subdomain of at most 253 characters; kind defaults to `Issuer`, also permits `ClusterIssuer`; group defaults to and must equal `cert-manager.io` |
| Target, listener and backend ports | 1–65535 |
| Tailnet `server` | HTTPS scheme and a non-empty remainder; `apiUrl` accepts `http://` for an in-cluster endpoint — prefer `https://` with the chart's `headscale.caConfigMapRef` ([API over TLS](../how-to/install-headscale.md#api-over-tls)) |
| Tailnet `apiKeyLifetime` | Valid duration ≥1h, at most 32 characters; omitted defaults to 720h |
| Tailnet `policy.mode` | `DryRun`, `Apply` or `Export`; `Export` (a spoke) forbids `baseConfigMap`/`fragmentConfigMaps`; `tagOwners` and `routeApprovers` are required with a base or in `Export` |
| Tailnet `policy.fragmentConfigMaps` | At most 32 DNS-subdomain names; only valid alongside `baseConfigMap` |
| Tailnet `dns.ingressNameTemplate` | Empty disables ingress DNS names; otherwise contains `{name}`, uses only `{name}`/`{namespace}`, and ends in a literal lowercase zone with at least two labels; at most 253 characters |
| Tailnet `policy.ingressSourceAllowlist` | Each entry begins with `group:`, `tag:` or `autogroup:` plus a non-empty suffix, or is an email-shaped pattern; at most 253 characters; bare `*` is rejected |
| Tailnet `headscale.ref` | Reserved; only empty is accepted |

Admission checks shape, not existence: a backend Service, Headscale group or DNS delegation may
still be missing. Rendered ingress DNS names are validated at reconcile time (`InvalidDNSName`)
because each label — including `{name}-{namespace}` — must fit 63 characters.

## Test without a cluster

```sh
export KUBEBUILDER_ASSETS=/path/to/envtest/binaries      # kube-apiserver, etcd, kubectl for Kubernetes >= 1.31
task test-validation
```

This starts a disposable API server with the generated CRDs and checks the valid examples, the
boundaries and every file in `deploy/examples/invalid/`. Before a CRD upgrade, add a fresh export of
the live CRs — each spec is submitted as a new object, so legacy fields cannot slip through ratcheting:

```sh
live=$(mktemp); kubectl get tailnet,tailnetegress,tailnetingress -A -o json > "$live"
LIVE_CR_FILE="$live" task test-validation; rm -f -- "$live"
```

Against an installed schema in a test cluster, `task validate-examples -- --context <ctx> --namespace <ns>`
runs the same negative fixtures as server-side dry-run creates.
