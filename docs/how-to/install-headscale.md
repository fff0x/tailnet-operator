---
title: "Prepare Headscale"
weight: 20
description: "Bootstrap API key, the policy entries every CR needs, policy mode, PostgreSQL TLS and what the preflight conditions mean."
---

## Bootstrap API key

The operator authenticates with a **bootstrap** key it only reads; from it it mints its own working
key (rotated at half-life) into the Secret `<tailnet>-apikey`. Create the bootstrap key with a long
life and store it once:

```sh
headscale apikeys create --expiration 8760h
```

Create the Kubernetes Secret after [installing the operator](install-operator.md). Do not commit the plaintext key.

## Policy: what must exist

Every egress/ingress node carries a **tag**, and the tag is the authorization. For each CR the policy
must contain:

| Block | Entry | Example |
| --- | --- | --- |
| `tagOwners` | the CR's tag | `"tag:egress-billing-dev": ["group:operator"]` |
| `autoApprovers.routes` | each egress target as `/32`, approved for the router's tag | `"10.0.10.20/32": ["tag:fabric"]` |
| `grants` | tag → target `/32` on the target port | `{ "src": ["tag:egress-billing-dev"], "dst": ["10.0.10.20/32"], "ip": ["tcp:1521"] }` |
| `grants` | who may reach an ingress | `{ "src": ["group:shop"], "dst": ["tag:ingress-shop"], "ip": ["tcp:5432"] }` |

You can maintain these by hand (policy mode `file`, the operator only *reads* the policy and reports
`NoGrant`/`NotApproved`) or let the operator generate them ([Operator-owned policy](policy.md)).
[`deploy/examples/policy-base.jsonc`](https://app.radicle.xyz/nodes/seed.this-is-fine.io/rad:z46fGxuhyvDV57psA8s6Q6PdHJrsX/tree/deploy/examples/policy-base.jsonc) is a minimal base that
works for both.

Two things always stay outside the policy: the router must **advertise** a route covering the
target (`--advertise-routes=10.0.10.20/32,…` per host, or an aggregate such as `10.0.10.0/24`; the
generated `/32` approval is then redundant but harmless), and the site firewall must allow the
router's address to the target port.

## Policy mode

| Mode | Where the policy lives | Who writes it |
| --- | --- | --- |
| `file` (default) | `policy.path`, e.g. a ConfigMap mounted at `/acl/policy` | you, via Git; Headscale reloads on SIGHUP/restart |
| `database` | the Headscale database | `headscale policy set -f …` or `PUT /api/v1/policy` — the operator in [Operator-owned policy](policy.md) |

Switching to `database` is described in [Migrating from file mode](policy.md#migrating-from-file-mode).

## PostgreSQL TLS

If Headscale uses PostgreSQL, set `HEADSCALE_DATABASE_POSTGRES_SSL=verify-full`, mount the server
CA and point `PGSSLROOTCERT` at it (with CloudNativePG: the generated server CA and the `-rw`
Service FQDN). Select the intended kube-context and the current database primary. Adjust the database
role filter if the deployment does not use `headscale`:

```sh
kubectl --context <context> -n <headscale-ns> exec <db-primary> -c postgres -- \
  psql -X --no-password -v ON_ERROR_STOP=1 -qtAc \
  "select host(a.client_addr), s.ssl, s.version, s.cipher from pg_stat_activity a left join pg_stat_ssl s using (pid) where a.usename='headscale'"
```

Require at least one row and `ssl=t` in every row. An empty result is inconclusive, not a pass;
`false` or `NULL` fails the transport check. Correlate client addresses with the running Headscale pods.

This proves encryption for the observed connections, not certificate-name or CA validation by itself.
Check the live pod's selected SSL mode, database hostname and CA mount without dumping credentials.
Absence of TLS errors in logs is not a negative validation test; retained logs might omit startup.
Test rejection of a wrong CA or hostname only in an isolated fixture, not by breaking a production database connection.

## API over TLS

Every operator call to `apiUrl` carries the working API key, and the responses carry freshly minted
pre-auth keys and the policy. Over `http://` that crosses the cluster network in clear; a CNI with
pod-to-pod encryption (Cilium WireGuard, for example) protects the wire, nothing else does. Prefer
HTTPS from Headscale itself — a public URL that terminates TLS at an ingress proxy only moves the
clear-text hop to proxy → Headscale.

1. Issue Headscale a certificate whose SANs include the in-cluster Service name, e.g. with
   cert-manager and an internal issuer: `dnsNames: [headscale.tailnet-system.svc,
   headscale.tailnet-system.svc.cluster.local]`.
2. Point Headscale at it: `tls_cert_path` / `tls_key_path` (or `HEADSCALE_TLS_CERT_PATH` /
   `HEADSCALE_TLS_KEY_PATH`). Headscale then serves HTTPS on `listen_addr` for *all* traffic, so a
   proxy in front of the public `server` URL must speak TLS to the backend (Gateway API
   `BackendTLSPolicy`) or pass TLS through.
3. Publish the issuer CA as a ConfigMap in the operator namespace (`ca.crt`, PEM) and name it in the
   chart: `headscale.caConfigMapRef: {name: local-ca-bundle, key: ca.crt}`. The operator mounts it
   read-only and sets `SSL_CERT_DIR`; Go merges it with the public roots, so a public `server` URL
   keeps working.
4. Set `apiUrl: https://headscale.tailnet-system.svc:8443` (the port is your `listen_addr`) on the
   Tailnet and watch `ApiReachable` and `ApiKeyValid` return to `True`.

A wrong SAN or CA shows as `ApiReachable=False` with a `tls:` error in the condition message.

## Preflight

The Tailnet controller probes the server's capabilities on every reconcile (at least every five
minutes; a failed probe retries after one minute). `kubectl get tailnet` shows the `COMPAT`, `POLICY`
and `DNS` reasons, `kubectl describe tailnet` the messages. Detection uses the API response shape,
not a version string; `spec.headscale.version` is an optional hint for diagnostics only.

| Condition | Meaning |
| --- | --- |
| `HeadscaleCompatible=True/Compatible` | Database policy mode and `POST /api/v1/policy/check` are available |
| `HeadscaleCompatible=False/Incompatible` | File policy mode, or no `policy/check` endpoint (Headscale < 0.29) |
| `PolicyMode=True/Database` | `GET /api/v1/policy` carries an `updatedAt` timestamp |
| `PolicyMode=False/File` | `updatedAt` is `null`; `Apply` skips policy writes and route approvals (`PolicyApplied=False/PolicyModeFile`) |
| `PolicyMode=Unknown/CannotVerify` | The response omits `updatedAt` |
| `…=Unknown/ProbeFailed` | A request failed or returned an invalid body; check reachability, credentials and Headscale logs |
| `SplitDNS=True/Configured` | An agent's netmap shows `dns.nameservers.split.<zone>` → the gateway LoadBalancer IP |
| `SplitDNS=False/Missing` / `Mismatch` | The zone is absent from the netmap, or resolves elsewhere; Headscale has no DNS API, so edit `dns.nameservers.split` by hand |
| `SplitDNS=Unknown/CannotVerify` | No `TailnetGateway` binds this Tailnet, or no agent is online to observe the netmap |
| `UsersUnique=False/Duplicate` | Two Headscale users share a name (`status.userConflicts`, IDs in the message); Headscale rejects every policy write until one is removed (`headscale users destroy -i <id>`) |

The split-DNS hint is the literal zone after the last placeholder label of `dns.ingressNameTemplate`:
`{name}-{namespace}.prod-1.tailnet.example.com` → `prod-1.tailnet.example.com`. That zone must not
be the MagicDNS `base_domain`: the gateway serves it from the CR names (`status.dnsName`,
`status.hosts`), while MagicDNS serves `<hostname>.<base_domain>` from the node name
(`status.hostname`) — the two stay in sync only by accident and diverge on the first
`spec.hostname` change. An empty policy
database does not block bootstrap (key validation uses the API-key listing); `DryRun` publishes
the rendered policy even in file mode.
