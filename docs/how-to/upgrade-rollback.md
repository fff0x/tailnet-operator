---
title: "Upgrade and roll back"
weight: 100
description: "Validate CRs against the new schema, upgrade CRDs and operator, verify, and the rollback table for policy and operator."
---

## Upgrade

Validate existing CRs against the new schema **before** installing new CRDs — admission rules
tighten between releases and the check is offline ([Validation](../operations/validation.md)):

```sh
live=$(mktemp); kubectl get tailnet,tailnetegress,tailnetingress -A -o json > "$live"
LIVE_CR_FILE="$live" task test-validation; rm -f -- "$live"
```

1. Apply the new CRDs. Helm installs CRDs from `crds/` but never upgrades them: run
   `task crd-upgrade KUBE_CONTEXT=<context>` for a manual installation, or set
   `install.crds: CreateReplace` and `upgrade.crds: CreateReplace` on a Flux `HelmRelease`.
   A release that adds a kind needs its CRD first: without the `TailnetGrant` CRD (new in v0.28.0)
   the policy controller of the new operator cannot start its watch. The operator process then exits
   after the cache sync timeout (2 minutes) and restarts in a loop.
2. `helm upgrade` (or apply the new `deploy/`). The operator re-rolls every agent whose image changed;
   agent Deployments use `Recreate`, so each affected CR's data path is interrupted for the restart.
3. `kubectl get tailnet` — `COMPAT=Compatible`, `POLICY=InSync` or `Applied`, `DNS=Configured` (or `CannotVerify` without a gateway).
4. `kubectl get tailnetegress,tailnetingress -A` — every row `READY=True`; test one egress and one
   ingress connection.

A pure operator restart with unchanged desired state does not restart agents; a `Ready=False` during
an agent image change is a real interruption, not a status flap. Outside upgrades, an agent restarts
only when something it dials or presents changes: `Tailnet.spec.server`, the tag or hostname
templates, the TLS defaults, or the CR itself. `Tailnet.spec.apiUrl` is the operator's path to the
Headscale API and leaves agents alone.

### Operator bump ≠ agent bump

An empty `agentImage` inherits the operator image, so every operator release rolls every agent. Pin
the agent separately to decouple the two:

```yaml
image:
  tag: v0.25.0
  digest: sha256:<operator digest>
agentImage:
  digest: sha256:<agent digest>   # same repository; set once, move only when a release requires it
```

Then an operator bump changes `image.*` only and agents stay up. Move `agentImage.digest` when
[Compatibility](../reference/compatibility.md) names the release as requiring new agent images
(envelope or identity changes); the first pin is roll-free when it equals the current operator
digest. An ingress agent keeps its node identity across the roll, an egress agent re-registers.

Breaking changes per version are

### Verify after the upgrade

1. Apply the new CRDs, then the Deployment (image + `OPERATOR_IMAGE`).
2. The operator re-rolls agent Deployments whose image changed.
3. Verify:

```sh
kubectl -n tailnet-system rollout status deploy/tailnet-operator
kubectl get tailnetegress,tailnetingress -A
# every row READY=True
kubectl get tailnet corp          # COMPAT=Compatible; POLICY=Applied/InSync; DNS=Configured
```

## Rollback

| Situation | Action |
| --- | --- |
| A render is wrong but not yet applied (`DryRun`) | fix the base or the CR; nothing reached Headscale |
| Headscale rejected the render (`PolicyApplied=False/PolicyRejected`) | the previous policy is still active; read the message, fix — the write is retried with backoff (15 s doubling to 1 min; transport failures to 5 min), a base/CR change retries at once |
| The operator must stop writing | `policy.mode: DryRun` — the operator only renders from now on |
| Restore the Git policy on the server | `kubectl -n tailnet-system exec deploy/headscale -- headscale policy set -f /acl/policy` (mode DryRun first, or it is overwritten within 5 min) |
| Leave database mode | `HEADSCALE_POLICY_MODE=file`, restart; the mounted file is authoritative again |
| Downgrade the operator | restore both the previous container image and `OPERATOR_IMAGE` (agents also roll back); the newer CRDs and their admission rules remain installed |
| Relax the v0.3.0 admission rules | restore the previous `deploy/crds/` manifests through the same deployment mechanism; never delete the CRDs, which also deletes their CRs |

Neither rollback restores a previously applied Headscale policy — switch to `DryRun` first if writes
must stop. Keep the desired CR manifests in Git: an older schema prunes newer optional fields on write.
