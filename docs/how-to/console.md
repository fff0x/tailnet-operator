---
title: "Run the read-only console"
weight: 105
description: "Enable the web console with OIDC sign-in, publish it with a TailnetIngress, and know what it shows and stores."
---

*The team wants to see which ingresses exist, who may reach them and whether the policy applied,
without `kubectl` access to the hub.*

The console is a third program in the operator image (`/tailnet-console`). It signs people in with
OIDC, takes their role from the `groups` claim and has two pages. **Overview** shows four tables:
Tailnets, spokes, TailnetIngresses and TailnetSites. **My access** shows what the live policy lets
the signed-in person reach. The console reads the kinds through a watch cache, gets Headscale users
and the live policy from the operator, and writes nothing. The chart renders it only with
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
| admin | Member of `adminGroup` | Overview, My access |
| user | Member of `userGroup`, or every signed-in person when `userGroup` is empty | Overview, My access |
| none | Everybody else | "No access" (HTTP 403), no session |

In this release both roles see the same pages. User references in `allowFrom` (entries with `@`)
appear only as a count, such as `2 user(s)`.

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

The console keeps each Tailnet's answers for 15 seconds in memory, so a change appears on the page
up to 15 seconds late. The API speaks plain HTTP inside the cluster. Only the network policy of
provider `kubernetes` restricts who reaches it (see below).

## Network policy

With `networkPolicy.enabled`, the chart renders `<name>-console` for the selected provider:

- `kubernetes`: ingress on TCP/8080 from `console.networkPolicy.ingressPeers` (default: pods
  `app.kubernetes.io/name: tailnet-ingress` in the release namespace, the agent of the console's
  ingress); egress to `networkPolicy.dnsPeers`, `networkPolicy.kubeAPICIDRs` on `kubeAPIPorts`,
  the operator pods on TCP/8082, and `console.networkPolicy.idpCIDRs` on `idpPorts` (default 443).
  The operator's own NetworkPolicy admits the console on TCP/8082.
- `cilium`: egress only, to `kube-apiserver`, DNS, the operator pods on TCP/8082 and `toCIDR`
  for the identity provider. Ingress stays open: every pod in the cluster reaches the console on
  TCP/8080 and the operator's console API on TCP/8082. The sign-in and the `TokenReview` are then
  the only guards.

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
| "My access" says the tailnet has no user for you | No Headscale user has the provider identifier that Headscale builds from the console's issuer and your `sub` | Sign in to the tailnet once with the same identity provider; check that Headscale's OIDC issuer equals `console.oidc.issuer` |
