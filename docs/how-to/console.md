---
title: "Run the console"
weight: 105
description: "Enable the web console with OIDC sign-in, publish it with a TailnetIngress, let admins manage TailnetGrants and decide access requests behind an audit log, and know what it shows and stores."
---

*The team wants to see which ingresses exist, who may reach them and whether the policy applied,
without `kubectl` access to the hub.*

The console is a third program in the operator image (`/tailnet-console`). It signs people in with
OIDC, takes their role from the `groups` claim and has two pages. **Overview** shows one map per
Tailnet and four tables: Tailnets, spokes, TailnetIngresses and TailnetSites; it updates itself
every 10 seconds. **My access** shows what the live policy lets the signed-in person reach. The
console reads the kinds through a watch cache and gets Headscale users, tagged nodes and the live
policy from the operator. It writes nothing unless `console.accessManagement.enabled` is set; then
admins also create, extend and revoke TailnetGrants, people request access that admins approve,
and every change goes to an audit log first (see [Access management](#access-management)). The chart renders the console only with
`console.enabled: true`.

## 1. Register a client at the identity provider

Create a confidential OIDC client with the authorization code flow and PKCE (S256). The redirect
URI is `<console.url>/auth/callback`. The console requests the scopes in `console.oidc.scopes`
(default `openid profile email groups`) and reads the `groups` claim from the ID token; when the ID
token has no `groups` claim, it asks the UserInfo endpoint once. The issuer must have a certificate
from a public CA: the image carries the public roots only.

Store the client secret in the operator namespace:

```sh
kubectl -n tailnet-system create secret generic console-oidc --from-literal=clientSecret='<secret>'
```

## 2. Enable the console

```yaml
console:
  enabled: true
  url: https://console.tail.example.internal   # = the ingress name below
  oidc:
    issuer: https://id.example.com
    clientID: tsunaro-console
    clientSecretRef: {name: console-oidc}
    adminGroup: tailnet-operator
    userGroup: tailnet-intern                  # empty: every signed-in person is a user
```

Rendering fails while `url`, `issuer`, `clientID`, `clientSecretRef.name` or `adminGroup` is empty,
when `url` or `issuer` is not `https://`, or when `url` has a path. The chart adds a Deployment, a Service on port 8080, a
ServiceAccount and a ClusterRole with `get`, `list` and `watch` on `tailnets`, `tailnetingresses`,
`tailnetsites` and `tailnetgrants`, all named `<name>-console`. The console has no access to
Secrets or ConfigMaps; the client secret reaches it as an environment variable from the Secret.

The chart also turns on the operator's console API: port 8082 on every operator replica, the
Service `<name>-console-api` and a ClusterRole of the same name that lets the operator create
`TokenReviews`. See [Console API](#console-api).

With `networkPolicy.enabled`, set `console.networkPolicy.idpCIDRs` to the addresses of the identity
provider; rendering fails without them. See [Network policy](#network-policy).

## 3. Publish it on the tailnet

The console serves plain HTTP and expects TLS in front of it. Use a `TailnetIngress` in `mode: http`
([`deploy/examples/console-ingress.yaml`](https://app.radicle.xyz/nodes/seed.this-is-fine.io/rad:z46fGxuhyvDV57psA8s6Q6PdHJrsX/tree/deploy/examples/console-ingress.yaml)):

```yaml
apiVersion: tsunaro.io/v1alpha1
kind: TailnetIngress
metadata: {name: console, namespace: tailnet-system}
spec:
  tailnetRef: {name: corp}
  allowFrom: [group:tailnet-operator, group:tailnet-intern]
  tls:
    issuerRef: {name: tailnet-ca, kind: ClusterIssuer}
  exposes:
    - name: console
      mode: http
      port: 443
      backend: {service: tailnet-operator-console, port: 8080}
```

Set `console.url` to `https://` plus the `status.dnsName` of that ingress. `allowFrom` decides who
reaches the sign-in page; the groups decide what a signed-in person may see.

## Roles

| Role | Who | Sees |
| --- | --- | --- |
| admin | Member of `adminGroup` | Overview, My access; with access management also Requests (all of them), Grants and Audit log |
| user | Member of `userGroup`, or every signed-in person when `userGroup` is empty | Overview, My access; with access management also Requests (their own) |
| none | Everybody else | "No access" (HTTP 403), no session |

On the overview, user references in `allowFrom` (entries with `@`) appear only as a count, such as
`2 user(s)`, for both roles. A user who opens a grant or audit page gets HTTP 403; without access
management these pages do not exist (404) and no role sees a link to them.

## Map

The overview draws one SVG map per Tailnet, rendered by the server. The hub is on the left, one
box per `spec.policy.spokes[]` entry on the right, sorted by name, with a line from the hub to each
spoke.

1. The hub box shows the Tailnet's server, Headscale version, policy mode and `PolicyApplied`, then
   its TailnetIngresses and TailnetSites.
2. A spoke box shows `SpokeReachable`, `SpokeFragmentValid`, `SpokeFragmentApproved`, whether a
   change is pending, and the spoke's tags. A spoke the hub cannot reach is drawn dashed.
3. A spoke tag is the tag of a tagged node or a `tag:` destination of a live rule. It belongs to
   the first spoke, by name, whose `tagPatterns` match it (default `tag:*-<spoke>-*`); a tag no
   spoke matches is not drawn. The tags of the hub's own ingresses never count. The details of a
   tag list the ports of all live rules with that tag as destination.
4. A square shows `Ready` (green true, red false, grey unknown). An ingress also has a circle for
   its node: filled when a node with its tag is online, a red ring when nodes exist but none is
   online, a grey ring when the console API knows no node with the tag. A spoke tag has only the
   square, which shows that node state (green online, red offline, grey unknown).
5. A list shows at most 12 entries, sorted by name. Above that, a last field says `+N more` and,
   when some hidden entries are not ready, `, k not ready`. The tables below list everything.

Hover, focus or tap an entry for its details (ports, hosts, condition, node state). The map shows
no user references, node names, rule sources or owners. When the console API does not answer for a
Tailnet within 3 seconds, the map says so: node state is unknown and the spoke boxes show no tags.
While a Tailnet is in `DryRun`, the operator does not write the spoke fragments to the live policy:
a spoke tag whose rules are not live appears only through its nodes, without ports.

## Live updates

The overview loads `/static/console.js`, the console's only script. Every 10 seconds it fetches the
page again and replaces the map and the tables when they changed; it waits, and says so, while an
entry inside them has the focus, and pauses while the browser tab is hidden. The line under the heading shows
the time of the last update, or that the console is unreachable and the page shows the last state.
When the session has expired, the script stops, and a notice with a sign-in link replaces the map
and the tables. Without JavaScript the page works as before and shows the state of its load.

The Content Security Policy allows scripts and fetches from the console's own origin only
(`script-src 'self'; connect-src 'self'`), and no inline script or style.

## My access

The page has one section per Tailnet, with two lists. It evaluates the live policy that Headscale
serves, not the rendered one, so a `DryRun` Tailnet shows what is in force.

1. You are the Headscale user whose provider identifier is the one Headscale builds from the
   console's issuer and your `sub` claim: both joined by one `/`, empty path segments dropped, the
   URL encoded (`auth0|abc` becomes `auth0%7Cabc`). Headscale stores that identifier when you sign
   in to the tailnet with the same identity provider. Without such a user, both lists stay empty and
   the page says so.
2. A reference names you when it equals your e-mail address, your user name or your provider
   identifier, each with `@` appended when it has none. Empty fields never match.
3. Your policy groups are the groups that list such a reference.
4. The page reads all `grants` and all `acls` with `action: accept`.
5. **Personal**: `src` names you or one of your groups. **For everyone**: `src` names
   `autogroup:member` or `*`, and the rule is not personal.
6. Tags, hosts, addresses, `autogroup:tagged` and `autogroup:danger-all` name devices, not people;
   such rules do not appear.

Each row shows the destinations and ports as the rule writes them, with the name of a known
ingress or site, the entry of `src` that matched (`you`, a group, `autogroup:member` or `*`), the
origin and, for a grant with `expiresAt`, the remaining time. An ACL gives one row per distinct set
of ports, with exactly the destinations that have these ports. Another person's reference never
appears: a destination that names a user shows as "a user's devices".

The origin is a comparison, not a record:

| Origin | When |
| --- | --- |
| `TailnetGrant <name>` | A grant with `Ready=True` has the same destinations and ports, and its `sources` contain the rule's sources |
| `TailnetIngress <namespace>/<name>` | Otherwise, an ingress whose tag is the only destination, with the same ports, and whose `allowFrom` contains the rule's sources |
| `Policy` | Everything else: the base policy or a spoke fragment |

A grant or ingress with exactly the rule's sources is preferred to one that only contains them.
A base-policy rule that equals a grant's rule therefore shows the grant and its expiry, although
the rule stays after the grant expires. SSH rules, `via` and app capabilities are not shown.

## Access management

```yaml
console:
  accessManagement:
    enabled: true
    fourEyes: false          # true: a second admin approves every new grant and extension
    audit:
      size: 1Gi              # never rotated; one change is about 1 KiB
      storageClassName: ""   # empty: the cluster's default
      existingClaim: ""      # for example a restored volume
```

The chart then adds, in the release namespace:

- `create`, `update` and `patch` on `tailnetgrants`, `get`, `list`, `watch` and `create` on
  `tailnetaccessrequests`, and `update` and `patch` on their status to the ClusterRole
  `<name>-console`, but no `delete`;
- the PersistentVolumeClaim `<name>-console-audit` (`ReadWriteOnce`), mounted at
  `/var/lib/tsunaro-console`, and `fsGroup: 65532` for the pod;
- the ConfigMap `<name>-console-audit`, rendered without data, and a Role with `get`, `update` and
  `patch` on exactly that ConfigMap;
- the console's metrics on port 8081 (`metrics`) of the Service `<name>-console`, and with
  `monitoring.serviceMonitor.enabled` a ServiceMonitor `<name>-console` (see [Metrics](#metrics)).

Access requests are objects of the cluster-scoped kind `TailnetAccessRequest` (`tnar`). Helm does
not upgrade CRDs: apply the new CRD before the upgrade that enables access management, see
[Upgrade](upgrade-rollback.md).

The volume and the ConfigMap carry `helm.sh/resource-policy: keep`: `helm uninstall` leaves them.
The ConfigMap also carries `helm.toolkit.fluxcd.io/driftDetection: disabled`, so a Flux
HelmRelease does not reset the data the console writes. The console still has one replica; the
volume needs no `ReadWriteMany`.

### Grants

**Grants** lists every TailnetGrant in the cluster with target, ports, recipients, expiry and
`Ready`. Recipients show with the Headscale user's name; only admins see this page. The console
changes only the grants it created, which carry the label
`app.kubernetes.io/managed-by: tailnet-console`; for all others the page says "Git or kubectl".

**New grant** has two steps and works without JavaScript:

1. Choose a target. The list holds, for every Tailnet that writes its policy (mode `DryRun` or
   `Apply` with a base ConfigMap), its TailnetIngresses with a `status.tag`, its spoke tags as the
   [map](#map) assigns them, and its TailnetSites.
2. Ports are prefilled with the target's current ports (an ingress's `exposes`, the TCP ports of
   the live rules for a spoke tag) and stored as a fixed list; a later change of the target does
   not change the grant. For a site, give addresses or masked prefixes inside the site's
   prefixes; an address becomes a `/32` or `/128`. Recipients are Headscale users with a provider
   identifier, stored as `<providerId>@`, and the groups of the live policy. A user who never
   signed in to the tailnet with the identity provider cannot be chosen. The duration is 1 hour,
   8 hours, 24 hours, 7 days, 30 days or permanent, counted from now.

The server checks every field again against the same lists. The grant is named `console-` plus ten
random characters. **Extend** sets a new `expiresAt` from now with the same durations; on an
expired grant the button says **Renew**. **Revoke** sets `expiresAt` to now: the operator removes
the rule at its next reconcile, and the object stays. To change ports or recipients, revoke the
grant and create a new one. The operator's checks still apply: a grant whose target goes away
reports `TargetUnknown`, see [Grant temporary access](grants.md).

With `fourEyes`, **Create grant** and **Extend** make a request instead (the button says
**Request grant**), which another admin approves on **Requests**; **Revoke** still acts at once. A
notice on the page says so.

### Requests

**Requests** shows a user their own requests and the console grants that name them alone, and an
admin every request. A request asks for a new grant or for a new expiry of a console grant.

1. **New request** has the steps of **New grant**, with one difference: the only recipient is the
   person who asks, as `<providerId>@`. The list holds only Tailnets whose Headscale knows that
   person by the provider identifier (see [My access](#my-access)); whoever never signed in to the
   tailnet with the identity provider is offered nothing.
2. **Ask to extend** is offered for console grants whose `sources` are exactly the person's own
   reference. Admins extend on **Grants**.
3. A request needs approvals by admins other than the requester:

   | Requested by | `fourEyes: false` | `fourEyes: true` |
   | --- | --- | --- |
   | user | 1 admin | 2 different admins |
   | admin (only with `fourEyes`, from **Grants**) | 1 other admin | 1 other admin |

   The setting counts when an admin decides, not when the request was made. Nobody decides their
   own request, and nobody approves twice. With only one admin, nothing that needs another admin
   can be approved.
4. **Reject**: any admin except the requester; one rejection ends the request. **Withdraw**: the
   requester, while the request is pending.
5. The last approval checks the request again: the target, ports and recipients must still be
   offered, and an extended grant must still exist, be a console grant and, for a user, name only
   that user. Otherwise the console answers "Request no longer valid" (409) and changes nothing;
   reject the request then.
6. The duration counts from the last approval. A new grant is named `console-` plus the ten
   characters of the request's name `request-<ten>`, and carries the annotation
   `tsunaro.io/access-request: <request>`. An extended grant gets
   `tsunaro.io/extended-by: <request>`.
7. When the last approval wrote the grant but not the request's status, the request stays pending
   with "grant written; approve to close". It counts as decided: **Reject** and **Withdraw** answer
   "Request not changed" (409), and **Approve** by any admin other than the requester only closes
   it (`request.close`), without a new check and without changing the grant. To take the access
   back, revoke the grant. When a later extension has replaced `tsunaro.io/extended-by`, the older
   request is an ordinary pending request again.

The request's status names nobody: `phase` (`Pending`, `Approved`, `Rejected`, `Withdrawn`; empty
means pending), `decidedAt` and `grantName`. Who approved, rejected or withdrew is only in the
[audit log](#audit-log): the console counts a request's approvals from its `request.approve`
entries, one per person. When the console cannot read the log, it shows and decides no request
("Requests unavailable", 503). Admins see the approvers and the deciding person by name; the
requester sees how many approved and when the request was decided. Its `spec` never changes.
The console never deletes a request; `kubectl get tnar` lists them.

### Audit log

Every change is first written to `/var/lib/tsunaro-console/audit.jsonl`, one JSON line per entry:

```json
{"v":1,"seq":12,"time":"2026-11-27T13:00:00Z","action":"grant.create","actor":{"iss":"https://id.example.com","sub":"3f2a","name":"Alice Example"},"grant":"console-k3x9q0b2mz","tailnet":"corp","details":{"expiresAt":"2026-11-27T21:00:00Z","ports":[443],"sources":["https://id.example.com/3f2a@"],"tag":"tag:wiki"},"prev":"9c1e…"}
```

1. `prev` is the SHA-256 of the previous line as written; the first entry has an empty `prev`.
2. After every entry the console writes the head (number and hash) to the ConfigMap
   `<name>-console-audit` and logs it as `audit head` with `seq` and `hash`. Neither names a
   person.
3. The change runs only after the entry is synced to disk and the ConfigMap is written. When
   either fails, the console answers "Change refused" (503) and changes nothing.
4. When the API server then rejects the write, an entry `grant.failed` with the HTTP status
   follows, and the page says "Change failed" (502).
5. The console checks the chain at start and every time the audit page opens. A break is a line
   that is not readable, a `prev` that does not match the line before, a wrong number, a missing
   or changed ConfigMap, or a log that ends before or after the ConfigMap's head.
6. Every newly found break gets its own entry `chain.broken`, and the log continues after it. The
   page lists every break ever found; the pod log says `audit chain broken` with the entry number.
7. Nothing is deleted or rotated.

Actions are `grant.create`, `grant.extend`, `grant.revoke`, `grant.failed`, `request.create`,
`request.approve`, `request.reject`, `request.withdraw`, `request.close` and `chain.broken`. The
last approval of a request is recorded as `grant.create` or `grant.extend`, with the request, the
requester and every approver in `details`; its actor is the last approver. Entries of a request
carry its name in `details.request`; a following `grant.failed` names only the grant and the
failed action. The console also checks the chain every
10 minutes in the background for the metric below.
**Audit log** shows the newest 200 entries, newest first, with a link to older ones.

The chain shows changes made on the volume alone. Whoever can write both the volume and the
ConfigMap, such as a cluster admin, can rewrite the log unnoticed by the console; the head in the
pod log, if your log store keeps it, is the third copy to compare. Changes made with `kubectl` or
Git and the operator's own expiries are not in this log.

### Metrics

With access management the console serves `GET /metrics` on port 8081:

| Metric | Labels | Meaning |
| --- | --- | --- |
| `tailnet_console_access_requests_pending` | `tailnet` | Requests waiting for a decision; no series for a tailnet without one |
| `tailnet_console_audit_chain_breaks` | — | Breaks the last check found; a recorded break stays |

No label names a person. The bundled alerts `TailnetConsoleAccessRequestPending` and
`TailnetConsoleAuditChainBroken` use them, see [Alerts](../reference/alerts.md).

## Console API

The console has no Headscale key. It asks the operator, which reads Headscale with the Tailnet's
working key:

| Path | Answer |
| --- | --- |
| `GET /v1/tailnets/<name>/users` | `id`, `name`, `displayName`, `email`, `providerId` of every Headscale user |
| `GET /v1/tailnets/<name>/nodes` | `name`, `online`, `lastSeen`, `tags` of tagged nodes only; personal devices are left out |
| `GET /v1/tailnets/<name>/policy` | The live policy as Headscale returns it |

Every request carries a ServiceAccount token with the audience `tailnet-operator`, which the kubelet
projects into the console pod and rotates (lifetime 10 minutes). The operator checks it with a
`TokenReview` and accepts only the console's ServiceAccount
(`CONSOLE_API_SUBJECT=system:serviceaccount:<namespace>:<name>-console`). A token for the API
server's own audience is rejected. Answers: 401 without a valid token, 403 for another
ServiceAccount, 404 for an unknown Tailnet or path, 405 for a write, 503 without a working key, 502
when Headscale fails. Error answers have no body, and logs name only the reason.

The console keeps each Tailnet's answers, and its errors, for 15 seconds in memory and asks the API
once per Tailnet at a time, so a change appears on the page up to 15 seconds late. The API speaks
plain HTTP inside the cluster; with `networkPolicy.enabled` only the console reaches it (see below).

## Network policy

With `networkPolicy.enabled`, the chart renders `<name>-console` for the selected provider:

- `kubernetes`: ingress on TCP/8080 from `console.networkPolicy.ingressPeers` (default: pods
  `app.kubernetes.io/name: tailnet-ingress` in the release namespace, the agent of the console's
  ingress); egress to `networkPolicy.dnsPeers`, `networkPolicy.kubeAPICIDRs` on `kubeAPIPorts`,
  the operator pods on TCP/8082, and `console.networkPolicy.idpCIDRs` on `idpPorts` (default 443).
  The operator's own NetworkPolicy admits the console on TCP/8082. With access management, the
  console also admits `networkPolicy.metricsPeers` on TCP/8081.
- `cilium`: ingress on TCP/8080 from `ingressPeers`, translated to `fromEndpoints` (an `ipBlock`
  peer fails the rendering), and from the node (`host`) for the kubelet's probes; egress to
  `kube-apiserver`, DNS, the operator pods on TCP/8082 and `toCIDR` for the identity provider. The
  operator's CiliumNetworkPolicy then gets an ingress section too: the console on TCP/8082, and
  everybody on metrics (8080) and health (8081). With access management the console admits
  everybody on its metrics (TCP/8081). `networkPolicy.metricsPeers` is not applied there.

When the console's `TailnetIngress` lives in another namespace, add a `namespaceSelector` to
`ingressPeers`.

## Sessions

The console keeps no tokens. After the sign-in it sets the cookie `__Host-tsunaro-session`
(`Secure`, `HttpOnly`, `SameSite=Lax`). The cookie holds issuer, subject, display name and role,
encrypted and authenticated with AES-256-GCM, and expires after one hour. The key is generated at
every start, so a restart or a rollout signs everybody out. **Sign out** deletes the cookie; the
session at the identity provider stays. Logs record the outcome of a sign-in and the role, never a
subject, a name or a mail address.

## Troubleshooting

| Symptom | Cause | Fix |
| --- | --- | --- |
| "Sign-in unavailable" (503) | The console cannot fetch the issuer's discovery document | Check `issuer`, DNS and egress from the console pod; the console stays ready and retries at the next sign-in |
| "Sign-in failed" (400) | The sign-in took longer than 10 minutes, or it started in another browser | Sign in again |
| "Sign-in failed" (401) | Token exchange or ID token check failed: wrong client secret, redirect URI, audience or clock | Compare the client at the IdP with `console.oidc`; check the console log line `sign-in rejected` |
| "No access" (403) | The account is in neither group, or the IdP sends no `groups` | Add the account to a group; make the IdP release `groups` in the ID token or UserInfo |
| The console pod restarts and never becomes ready | It cannot list or watch the four kinds: the ClusterRoleBinding `<name>-console` is missing, or the cluster lacks one of the CRDs. The console serves HTTP only after its cache has synced, so the liveness probe fails | Check the binding; apply the current CRDs ([Upgrade](upgrade-rollback.md)) |
| "My access" says the operator cannot provide a tailnet | The console API answered with an error or was not reachable. The console log line `access read failed` names the status: 401 (token audience or projection), 403 (`CONSOLE_API_SUBJECT` does not name the console), 503 (no working key, see `ApiKeyValid`), 502 (Headscale) | Compare the operator's `CONSOLE_API_SUBJECT` with the console's ServiceAccount; check the network policies for TCP/8082 |
| The map says the console API did not answer; nodes show a grey ring | Same causes as the row above; the overview does not log them | Open "My access" for the status in the log line `access read failed`; fix as above |
| The page stops updating and asks to sign in again | The session expired (one hour) or the console restarted | Sign in again |
| The line under the heading says the console is unreachable | The fetch failed: the console pod, its ingress or the network is down | The page keeps the last state and retries every 10 seconds |
| A spoke entry sits under the wrong spoke, or under none | It belongs to the first spoke, by name, whose `tagPatterns` match it | Make the patterns of the spokes disjoint |
| "Change refused" (503) | The console cannot write `audit.jsonl` or the ConfigMap `<name>-console-audit`; the console log line `audit write failed` has the error | Check that the volume is bound and writable (`fsGroup`), and that the ConfigMap and the Role `<name>-console-audit` exist |
| "Change failed" (502) | The API server rejected the grant or request; the page shows the status, the audit log has `grant.failed` | 403: the ClusterRole lacks the write verbs (`accessManagement.enabled`); 404 on a request: the TailnetAccessRequest CRD is missing, apply it ([Upgrade](upgrade-rollback.md)); 409: a grant of that name exists without the request's annotation; 422: the object does not pass admission, compare with [Grant temporary access](grants.md) |
| "Changed meanwhile" (409) | Somebody changed the request or grant at the same time | Reload the page and decide again |
| "Request no longer valid" (409) | Since the request, the target, its ports or the recipient left the lists, or the grant to extend is gone or names somebody else | Reject the request; the requester may ask again |
| "Request not changed" (409) | The request is decided already, it is your own, you approved it already, or its grant is written already and only **Approve** closes it | With `fourEyes`, another admin must approve; revoke a written grant to take the access back |
| "Requests unavailable" (503), or the console log says `request list failed` | The console cannot list TailnetAccessRequests: the CRD or the ClusterRole rule is missing | Apply the CRD; check `accessManagement.enabled` |
| "Requests unavailable" (503), and the console log says `audit check failed` | The console cannot read its audit log, which keeps the approvals | Check the audit volume and the ConfigMap `<name>-console-audit` |
| **New request** offers no tailnet | Headscale knows no user with your provider identifier in a tailnet that writes its policy | Sign in to the tailnet once with the same identity provider |
| "Not your grant" (403) | The grant names more than you, or not you | Ask an admin |
| "Not a console grant" (403) | The grant has no label `app.kubernetes.io/managed-by: tailnet-console` | Change it where it is defined, in Git or with `kubectl` |
| The audit page says the chain is broken | A line was changed, removed or cut, or the ConfigMap was reset or deleted, for example by a restore of only one of the two | Compare the listed entry numbers with a backup and the `audit head` lines of the pod log; the break stays listed |
| A recipient is missing from the list | The Headscale user has no provider identifier: it never signed in with the identity provider | Let the person sign in to the tailnet once; or choose a group of the live policy |
| A target is missing from the list | The Tailnet does not write its policy, the ingress has no `status.tag` yet, or the spoke tag has no node and no live rule | Set the policy mode to `DryRun` or `Apply`; wait for the ingress to be Ready |
| "My access" says the tailnet has no user for you | No Headscale user has the provider identifier that Headscale builds from the console's issuer and your `sub` | Sign in to the tailnet once with the same identity provider; check that Headscale's OIDC issuer equals `console.oidc.issuer` |
