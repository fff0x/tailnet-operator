# Tier 2: disposable kind install and leader failover

Run from the source checkout:

```sh
bash hack/e2e-kind.sh
# If kind is not installed (requires kind v0.32.0):
nix-shell -p kind --run 'bash hack/e2e-kind.sh'
# With explicit permission for a temporary delegated user scope (no persistent host change):
nix-shell -p kind --run 'systemd-run --user --scope -p Delegate=yes -- bash hack/e2e-kind.sh'
```

Requires local rootless Podman, kind, kubectl, Helm, Go and timeout.
The runner rejects remote runtime/socket/context overrides and root execution.
Every Podman invocation uses `--remote=false`; `podman info` must report rootless.
No Docker socket, existing kubeconfig, host configuration changes or privileged fallback is used.
If kind reports missing systemd `Delegate=yes`, the runner stops and cleans up.
It does not attempt to change delegation, sysctls or services.

The runner creates a random cluster name and private temporary kubeconfig.
All Kubernetes and Helm operations select that context explicitly.
Exit and signal traps delete only the owned cluster, remaining labelled containers and local test image tags.
The temporary build context, binaries, archives, kubeconfig and Helm state are outside the checkout and removed on exit.
No credentials or raw fixture logs are printed. Bootstrap keys travel through captured CLI stdout and the Kubernetes API only.

## Coverage

`TestInstall` installs the local chart, waits for its CRDs and manager readiness,
then starts real Headscale v0.29.3 with ephemeral SQLite storage.
The fixture disables update checks, logtail, DERP downloads and route probes.
Its embedded empty DERP region has no peers.
The Tailnet uses the HTTP cluster Service for REST; its HTTPS control URL is an unused placeholder.
No egress or ingress CRs are created, so no tsnet agent dials that placeholder.

The test checks `HeadscaleCompatible=True` and `PolicyApplied=True/InSync`.
It compares the live Headscale policy with the rendered/applied status hashes and the expected base ACL.
The CLI independently reads the live policy over Headscale's Unix socket.
API credentials are neither command arguments nor diagnostic output.

`TestLeaderFailover` independently uses the same installer, then scales the operator Deployment to two replicas.
It waits for two ready Pods and the `tailnet-operator.this-is-fine.io` Lease in `tailnet-system`.
The complete `pod-name_UUID` holder identity must map to an observed Pod; prefixes and guessed identities are rejected.
Both Pods are sampled through explicit, bounded Kubernetes Pod-proxy `/metrics` requests, not a load-balanced Service.
The test normally deletes the leader, then immediately changes the base ACL destination to `192.0.2.2:443`.
Within **30 seconds from deletion**, it requires a different leader identity, desired rendered/applied hashes, and independently matching Headscale CLI policy.
Production lease timings, graceful shutdown and `ReleaseOnCancel=false` remain unchanged.

Final samples require an unchanged surviving-process error counter and zero errors on the new Pod.
A standby's fixture counter can be absent until its first reconcile; the elected replica must expose it.
Process-start metrics detect a surviving Pod's process restart, which could otherwise hide a counter reset.
These samples do **not** prove exactly-once external writes or cover deleted-Pod counters across the sampling gap.
No agent CRs are created. These tests do **not** establish data-plane, TLS ingress, NetworkPolicy enforcement or soak acceptance.
Default kind CNI cannot validate NetworkPolicies.

Each top-level test installs its own fixture, including when selected individually with Go's `-run`.
They must not run in parallel. Cleanup deletes the fixture Tailnet, uninstalls Helm, then deletes and waits for the namespace.
This prevents the two tests from sharing a release, Lease or Headscale state; CRDs remain until cluster deletion.
Cleanup has its own bounded context and also runs on test failure.
Failure diagnostics emit only workload counts, booleans and fixed log categories, never raw logs or Event messages.

An earlier authorized local rootless-kind run passed both tests: `TestInstall` in **87.01s** and `TestLeaderFailover` in **47.12s**.
Leadership and real-policy convergence took **17.935s**, within the 30-second bound.
Per-fixture cleanup took **10.658s** and **10.767s**, included in the test durations.
The script completed in **203s**, deleted the cluster, and removed its owned image tags and private work directory.
Two earlier integrated runs also passed; an intervening run failed both Helm installs before Pods existed.
That early Helm failure remains unexplained; its sanitized failure evidence is retained, not counted as acceptance.
Cleanup was verified for all four runs. This is bounded failover evidence, not a reliability or soak claim.
Private evidence for that series is under `/home/ff0x/.local/state/pi/tailnet-operator/evidence/p1-integrated/` (`tier2-integrated-verify.*`).

The subsequent combined RBAC/metrics run also passed after the readiness-timing correction:
`TestInstall` **87.21s**, `TestLeaderFailover` **104.75s**, policy convergence **16.884s**,
and per-fixture cleanup **10.8s/10.74s**. The Go test stage took **192.059s**, excluding build/startup.
Owned cluster `tn-kind-yohwph8mkd`, both local image tags and the private directory were confirmed absent.
Evidence: `p1-observability-final/kind-rbac-metrics.log` under the same private evidence root.
This additional pass does not explain the earlier Helm failure or satisfy data-plane/soak gates.

The independently exported chart-plus-kind index also passed: `TestInstall` **26.54s**,
`TestLeaderFailover` **36.00s**, policy convergence **17.393s**, cleanup **10.685s/10.77s**.
The Go stage took **62.630s**, not including build/startup. Owned cluster `tn-kind-bh0ivi20lz`,
image tags and private directory were independently confirmed absent.
Evidence: `p1-integrated/staged-kind-runtime.log`; scope and remaining gates are unchanged.

## Image provenance

- `kind.yaml` pins the Kubernetes v1.36.1 node digest embedded in kind v0.32.0.
- The runner pins `ghcr.io/juanfont/headscale:0.29.3` to its registry manifest digest.
  It was verified with unauthenticated `skopeo inspect`; runtime also checks `headscale version`.
- The operator image is local and unique to each run, not published.
  Go statically builds both binaries from the current checkout into a temporary directory.
  `Dockerfile` copies them and the system CA file to `/`, matching the bundle repack layout.
  The root Dockerfile's final `/bundle` carrier is not runnable and is not used here.

For source-only checks, without any cluster:

```sh
bash -n hack/e2e-kind.sh
shellcheck hack/e2e-kind.sh
go test -mod=readonly -tags=e2e_kind -count=1 -v ./test/e2e-kind
```

Without runner-owned environment, both integration tests skip before making any API request.
`TestConfigGuard` tests rejection of foreign contexts, remote endpoints, proxies and credential helpers.
`TestPolicySampleParser` and `TestHolderPod` test counter parsing and exact Lease-to-Pod mapping without a cluster.
These source-only checks are not a successful Tier 2 execution.
