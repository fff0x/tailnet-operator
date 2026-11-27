---
title: "Run the read-only console"
weight: 105
description: "Enable the web console with OIDC sign-in, publish it with a TailnetIngress, and know what it shows and stores."
---

*The team wants to see which ingresses exist, who may reach them and whether the policy applied,
without `kubectl` access to the hub.*

The console is a third program in the operator image (`/tailnet-console`). It signs people in with
OIDC, takes their role from the `groups` claim and shows four tables: Tailnets, spokes,
TailnetIngresses and TailnetSites. It reads these kinds through a watch cache and writes nothing.
The chart renders it only with `console.enabled: true`.

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
ServiceAccount and a ClusterRole with `get`, `list` and `watch` on `tailnets`, `tailnetingresses`
and `tailnetsites`, all named `<name>-console`. The console has no access to Secrets or
ConfigMaps; the client secret reaches it as an environment variable from the Secret.

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
| admin | Member of `adminGroup` | Overview |
| user | Member of `userGroup`, or every signed-in person when `userGroup` is empty | Overview |
| none | Everybody else | "No access" (HTTP 403), no session |

In this release both roles see the same overview. User references in `allowFrom` (entries with
`@`) appear only as a count, such as `2 user(s)`.

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
| The console pod restarts and never becomes ready | It cannot list or watch the three kinds: the ClusterRoleBinding `<name>-console` is missing, or the cluster lacks one of the CRDs. The console serves HTTP only after its cache has synced, so the liveness probe fails | Check the binding; apply the current CRDs ([Upgrade](upgrade-rollback.md)) |
