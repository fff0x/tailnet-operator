---
title: "Model and how it works"
weight: 10
description: "The five kinds, why the tag is the authorization, and what each reconciler turns a CR into."
---

Diagrams of the resulting shape, one per scenario, and the full list of objects each CR creates:
[Architecture by scenario](architecture.md).

## Model

- **`Tailnet`** (cluster-scoped) — one per Headscale control server: login URL, in-cluster API
  endpoint, a read-only bootstrap API key from which the operator mints and **rotates its own working
  key**. Optionally owns the **DNS hosts file** and the **policy** for everything below.
- **`TailnetEgress`** (operator namespace) — one egress identity: a tag, a reusable ephemeral
  pre-auth key (the ingress key is reusable and non-ephemeral), a userspace agent pod and one Service per target. Consumers in `consumerNamespaces`
  dial `<target>.<operator-ns>.svc:<port>`; **aliases** let them dial the real hostname when the far
  end routes by SNI/Host. A target may also be a tailnet peer by MagicDNS name (an ingress of
  another cluster); with **`spec.expose`** the target Services become LoadBalancers on the site
  LAN, filtered to declared client prefixes within the admin's `exposeSourceAllowlist` — the
  **bridge** that lets hosts without a tailnet client reach a tailnet service per service, not per
  network ([Bridge](../how-to/legacy-bridge.md)).
- **`TailnetIngress`** (tenant namespace) — the mirror: expose in-cluster Services *on* the tailnet
  as one node with a MagicDNS name and, with a template, a DNS name under your zone. L4 exposes
  forward TCP; one or more `mode: http` exposes (virtual hosts, each with its own name and optional
  short alias) terminate TLS on the agent with a Secret or cert-manager certificate and forward HTTP
  or explicitly verified HTTPS to the app, routed by SNI — no shared gateway needed.
- **`TailnetSite`** (cluster-scoped) — a remote network behind a subnet router: a branch `/24`, a
  management range, a single host as `/32`. Declared once in the policy-owning cluster; the router
  is identified **by tag**, so any tagged router, in this or another cluster, qualifies. The operator renders
  the `autoApprovers`, replays approvals, blocks overlaps with `reservedNetworks` or older sites and
  reports `Advertised`/`Approved`/`Ready`. Who may *reach* the site stays a grant in the base policy.
- **`TailnetGateway`** (cluster-scoped) — the subnet router and split-DNS resolver as a CR: one
  kernel-mode Tailscale Pod advertising the site LAN, the tailnet LoadBalancer range and every
  egress target, plus a CoreDNS that serves the hosts file as the authoritative zone. Identity is
  pinned in a state Secret and immutable receipts; **fresh-only** — it creates a new node and never
  adopts, restarts or replaces one. Suspended by default.
- **The tag is the authorization.** Each CR is its own node with its own tag; the policy's grants for
  that tag decide what it may reach (egress) or who may reach it (ingress). Without
  `Tailnet.spec.policy` the operator only *reads* the policy and reports what is missing; with it, the
  operator renders your base policy plus the CR-derived entries and writes the result to Headscale.

## How it works

Six reconcilers, each turning CRs into desired state applied with server-side apply — no per-CR
restart to add or remove a target:

- **Tailnet** — mints the working API key from the bootstrap key, rotates it at half-life (new key
  verified before the old one is expired), reports reachability.
- **Egress / Ingress** — per CR: tag pre-check against the live policy, a reusable pre-auth key
  (rotated at half-life and on server/tag change; a restarted egress pod re-registers on its own as
  a new node with a new tailnet IP — the DNS name is the stable handle, the operator prunes the old
  node — and a deleted CR's node ages out),
  one agent Deployment, one Service per target, a NetworkPolicy scoped to `consumerNamespaces`, and a
  status that classifies every target route (`NotAdvertised` / `NotApproved` / `NoGrant`) from the
  node's netmap and the router's advertised/approved sets — the two silent failures of a plain
  proxy, named.
- **Gateway** — creates the subnet-router StatefulSet, its Services and CoreDNS zone exactly once
  (immutable receipts pin the identity), then only follows image/route changes into the template and
  the hosts file into the zone; it never restarts, adopts or deletes the Pod without `deletionPolicy: Delete`.
- **DNS** — folds egress aliases and ingress names into one CoreDNS `hosts` ConfigMap per Tailnet.
  The resolver is the cluster's, not the operator's; if the operator dies the last file stays valid.
- **Policy** — parses the base HuJSON generically, appends tagOwners / `/32` approvals / grants
  derived from the CRs (base wins, nothing removed, unknown blocks pass through), publishes the render
  in a ConfigMap and, in `Apply`, writes it when the live document differs. A spoke cluster that
  shares the Headscale uses `Export` to render only its own entries into a fragment the hub merges
  after review. Headscale validates
  (including the base's `tests`) before storing, so a rejected render never becomes active. After a
  successful write it replays missed `autoApprovers` approvals (a route advertised before its
  approver existed) on the routers, so `NotApproved` heals without `headscale nodes approve-routes`.
- **Data plane** — one agent pod per CR is a userspace tsnet node. `AGENT_MODE` sets the direction
  and has no default (the operator sets it on every agent Deployment; an unset value is a startup error):
  egress takes `--accept-routes` and `Dial`s the off-cluster address over the tailnet; ingress listens
  on the tailnet and `Dial`s an in-cluster backend; an `http` expose terminates TLS on that listener
  (SNI and Host bound to the ingress DNS name, certificate reloaded from the projected Secret) and
  proxies HTTP/1.1 and HTTP/2 to the backend. Same binary, `io.Copy` with half-close, no SOCKS5, no
  second container. Egress state is in-memory and ephemeral by design; an ingress keeps its node key
  in a state Secret of its namespace (written through its own ServiceAccount), so its node ID and
  tailnet IP survive Pod restarts.

A single image carries both binaries; the operator runs `/tailnet-operator`, each agent pod runs
`/tailnet-agent`.
