# Compatibility and local integration tests

## Verified scope

The Tier-1 tests run the production manager against a disposable Kubernetes API server
and real Headscale release binaries. They do not run pods or connect to an installed operator.
The local matrix has passed on Kubernetes 1.31.0 and 1.36.0 with Go's race detector.
Complete local runs took approximately 80 seconds each; this is not a broker-CI result.

| Headscale | Policy mode | Expected preflight | Coverage |
| --- | --- | --- | --- |
| v0.28.0 | database | `HeadscaleCompatible=False/Incompatible` | Missing `policy/check`; database-mode detection; key bootstrap and health |
| v0.28.0 | file | `PolicyMode=False/File`, incompatible | Rendering permitted; no policy PUT, even with operator policy mode `Apply` |
| v0.29.3 | database | `HeadscaleCompatible=True/Compatible` | Preflight, policy lifecycle, rotation, replay, hosts and redaction described below |
| v0.29.3 | file | `PolicyMode=False/File`, incompatible | Rendering permitted; no policy PUT, even with operator policy mode `Apply` |

An operator-supplied version hint does not override the observed verdict. `SplitDNS` stays
`Unknown/CannotVerify`; these tests do not establish external DNS delegation.

In both releases, a seeded database policy returns an `updatedAt` timestamp; file mode returns
explicit `null`. An empty database returns HTTP 500 with `acl policy not found`, not a mode verdict.
The tests verify these observations through the operator's persisted conditions. These response
shapes are observed behavior, not a documented upstream policy-mode contract.

`TestPolicyLifecycle/v0.29.3` verifies:

- Working-key bootstrap with an empty policy database.
- First policy application and later base-ConfigMap changes.
- DryRun rendering without a policy write.
- Invalid local JSON rejected before any policy PUT.
- Real Headscale validation rejecting an invalid ACL action while retaining the last valid policy.
- Actual retry intervals of approximately 15 and 30 seconds, then recovery to the valid base.

The retry intervals are observed through HTTP responses, with disjoint 12–22 and 25–40 second
acceptance windows. Constant 15/15 or 30/30 retries fail. `retryIn` is a controller log field,
not a CR status field. No test-only retry settings or direct reconciler calls are used.
The v0.28.0 lifecycle row is explicitly skipped because its capability verdict is incompatible.
A passing negative preflight test does not claim functional support for that release.

### Additional real-server scenarios

- `TestKeyRotation`: expires the bootstrap key, then changes `apiKeyLifetime` from 1h to 4h.
  The existing working key becomes rotation-due without changing its expiry metadata.
  The replacement works, the old key is rejected, and bootstrap Secret data stays unchanged.
- The rotation test also restores an old, unsafe full-token prefix annotation.
  A regular Secret-watch reconciliation repairs metadata without changing the working key or expiry.
  Modern `hskey-api-…` tokens, legacy tokens and masked API-list prefixes have separate unit coverage.
- `TestApprovalReplay`: removes a matching approval from an already InSync policy, retaining an unrelated approval.
  A normal generation change restores the union; an unmatched node stays unapproved.
  The test requires **zero additional policy PUTs**: Headscale itself autoapproves routes on policy writes.
  Route setup is white-box: the private Headscale process stops while its temporary SQLite `host_info`
  receives advertised routes. REST reads and approvals use the real server after restart.
  This does not test client route advertisement or packet forwarding.
- `TestIPv4OnlyHosts`: injected ingress status exercises the API-watch/render path.
  Mixed IPv4/IPv6 status produces only an IPv4 hosts entry; removing IPv4 removes the stale entry.
  No live tsnet agent or IPv6 connectivity is tested.
- `TestTestsSrcResolution`: registers a real tagged node, applies tag-sourced policy tests,
  then requires rejection of an impossible port assertion while the live policy stays unchanged.
  Restoring the valid assertion recovers InSync. This verifies upstream semantic validation through
  the render/apply path, not a historical fix-revert experiment.
- `TestNoSecretsInOutput`: checks captured operator logs, Events, CR statuses and Secret metadata
  for known bootstrap, working and both preauth keys. Secret data is intentionally excluded.
  It exercises malformed local HuJSON and real Headscale error bodies that echo the fixture credentials.
  Logs remain in bounded private memory; raw Headscale output is never dumped.
  Adversarial unit tests also cover malformed policy timestamps, codec/transport errors and unknown key formats.

These functionality rows explicitly skip v0.28.0 rather than treating incompatible preflight as support.

## Run Tier 1

Requirements: Linux amd64 or arm64, the project's Go toolchain, Bash, curl, GNU coreutils, tar and sqlite3.
The amd64 matrix is locally exercised; arm64 assets are pinned but still need a native execution run.

```sh
nix-shell
# Downloads checksum-pinned public Headscale and Kubernetes 1.31.0 envtest assets if absent.
task e2e

# One version or scenario:
HEADSCALE_VERSIONS=v0.29.3 task e2e -- -run TestPolicyLifecycle

# An additional API-server version, using already provisioned/trusted envtest binaries:
KUBEBUILDER_ASSETS=/absolute/path/to/envtest-binaries task e2e
```

The launcher caches verified downloads under `$XDG_CACHE_HOME/tailnet-operator-e2e`
(default `~/.cache/tailnet-operator-e2e`). `E2E_HEADSCALE_DIR` can override the Headscale cache root;
those binaries must still match the pinned SHA256 hashes. The envtest archive is verified against
its pinned SHA512 before extraction. An explicit `KUBEBUILDER_ASSETS` override is trusted and is
not reverified by the launcher. Hash sources are the official GitHub release checksum files;
this is checksum verification, not a claim of upstream signature verification.

Both the launcher and Go suite prevent current-context reuse. The suite explicitly sets
`UseExistingCluster=false`, even when `USE_EXISTING_CLUSTER=true` is inherited. Before startup,
the Go suite clears all `ETCD_*` and `TEST_ASSET_*` overrides. These could otherwise select
non-disposable etcd storage/peers or bypass the selected envtest binaries. The admission suite
uses the same guard. Changes affect only the test process, not the invoking shell.
Direct execution requires prepared Headscale assets and an explicit `KUBEBUILDER_ASSETS`:

```sh
go test -tags=e2e ./test/e2e -count=1 -v -timeout=12m
```

Each test row has a 170-second context. Process startup, CLI calls and shutdown have shorter
bounds. Failure exits nonzero; missing binaries and unsupported matrix versions are not skips.
Headscale uses private temporary configuration, SQLite, a Unix socket and loopback HTTP.
Inherited Headscale settings, proxy variables and credentials are not passed to the child.
An inert local DERP map avoids upstream downloads; update checks, logtail and HA probing are off.
Raw server/CLI output is not dumped on failure because it can contain generated credentials.
A transparent loopback proxy records policy PUT status and timing, never headers or bodies.
Processes are stopped before their temporary files are removed. The envtest data is disposable;
no CRD install, Helm install or kubectl request targets an existing cluster.

## Remaining acceptance gates

P1.4 is not complete. MagicDNS rename, the historical `tests` fix-revert experiment and full agent Deployment
integration contracts remain open. No causal `tests.src` fix was identified in the available local history:
the closest lab change introduces the tests block rather than repairing source resolution. The current semantic
regression is not a historical-revert experiment; that gate needs the missing commit/reproducer or an explicit requirement change. Unit tests cover pull-secret and security-context rendering.
Admission fixtures retain their separate `task test-validation` command and are included in the prepared CI gate.

The prepared `.radicle/native.yaml` runs a native Debian Dockerfile `TEST` target before publication.
It supplies Go, Helm and sqlite3 without adding them to the broker runtime.
A fresh Buildah working container executes formatting, vet, uncached unit/chart tests, admission and Tier 1.
Tool/module layers may cache; successful test results cannot bypass execution.
Inputs are limited to tracked source paths, with no signing credentials, host mounts or current kubeconfig.
Native arm64 broker execution and a successful run on main remain acceptance gates.
The mixed image/chart publisher extension must be deployed before this consumer CI can run.

`task e2e-kind` runs [isolated installation and leader-failover tests](../test/e2e-kind/README.md).
Temporary systemd `Delegate=yes` user scopes permit rootless Podman to run the disposable cluster.
Initial installation failures exposed non-executable image artifacts and a zero-duration Tailnet fixture; both were corrected.
No persistent host configuration was changed and no rootful fallback was attempted.

`TestInstall` verifies Helm installation, CRD admission, operator readiness and real Headscale policy convergence.
`TestLeaderFailover` starts two Ready replicas, deletes the Lease holder and changes the base policy.
It requires another leader plus rendered/applied/live policy convergence within 30 seconds.
An earlier run converged in 17.935 seconds; its full script completed in 203 seconds, including cleanup.
The subsequent combined RBAC/metrics run converged in 16.884 seconds. Its Go test stage took 192.059 seconds,
excluding image build and cluster startup; this is not an end-to-end timing comparison.
Three of the initial four integrated runs passed, and the subsequent combined run passed.
One initial run failed during early Helm installation before pods existed; its cause remains unknown.
Owned clusters, image tags and private working directories were removed after these runs.

Counter samples cover the surviving and replacement pods, not the deleted pod's final interval.
The test does not establish external-write fencing or exactly-once policy writes.
The installation/failover runs did not verify HTTP ingress or agent data-plane traffic.
A later HTTP-specific fixture provides the separate evidence below. Nightly-job execution remains unverified.
Local success does not satisfy CI-on-main, three-successful-nights or week-long soak gates.
The recorded combined observability snapshot passed host race tests, both envtest versions and real promtool checks.
It also passed a fresh native amd64 rootless TEST container and isolated kind installation/failover.
That evidence predates the image-audit additions; it does not establish their correctness or live monitoring acceptance.
A later independently exported chart-plus-kind index passed installation in 26.54 seconds and failover in 36.00 seconds,
with policy convergence in 17.393 seconds. The Go stage took 62.630 seconds, excluding build/startup;
its owned cluster, image tags and private directory were independently confirmed absent.

Pinned Syft/Trivy filesystem scans and Cosign 2.5.0 statement-generation checks exposed two audit compatibility bugs.
They concern unversioned Go main modules and insertion of empty provenance metadata. Both have fail-before/fix-after regressions.
A fresh Debian TEST container also exposed jq 1.6's extra empty result when streaming and slurping in one process.
Separate streaming and collection fixed result validation; duplicate-key, trailing-malformed and multiple-document rejection remain tested.
The complete security race suite passed with jq 1.6 and 1.8.1.

The corrected independently exported CI index passed another fresh native-amd64 rootless TEST build and full `hack/ci-test.sh` run.
Build time was 56.813 seconds; the fresh test run took 210.453 seconds.
Unit/security mocks, govulncheck, dashboard/RBAC, Helm, admission 1.31 and real Headscale Tier 1 passed.
Promtool was absent from that container; host rule checks provide separate evidence.
Live-export and six unsupported Headscale 0.28 lifecycle rows remained explicit skips. Owned resources were removed.
This index excludes the unfinished HTTP/TLS changes.

Independent review then found that `buildah from` also enables proxy forwarding by default.
The final specification disables it on both `bud` and `from`.
A real rootless TEST positive control forwarded all eight synthetic proxy variables; the corrected container forwarded none.
Only Bash builtins ran in the positive control. The corrected fresh container passed the full suite under the same synthetic host environment.
Its build took 57.263 seconds and its test run 195.936 seconds, with the same explicit skips and verified cleanup.
An earlier scratch/chroot `network=none` probe stopped at a runtime error; it did not prove proxy isolation.
The successful TEST experiment used normal test networking and makes no network-isolation claim.

The audit and native-pipeline mock suites cover both platforms, failure ordering and cleanup without publication.
These are not registry-image, signed-attestation, native-arm64 or broker-main acceptance results.

### Later HTTP ingress acceptance

The isolated HTTP fixture subsequently passed its full default selection.
It covered real agent/peer HTTPS, Headscale HTTPS, integrated `TailnetIngress`, Pod startup isolation checks and fixture CA projection.
The integrated ingress test passed eight HTTPS body checks through the tailnet and real cert-manager reissuance.
The certificate revision advanced, the leaf changed to a one-hour certificate, and the agent container remained unchanged.
Cleanup and preservation checks passed. This selection is not the complete Tier-2 scenario matrix.

A separate fresh native-amd64 TEST run passed with the HTTP source included.
The live-export admission row and seven unsupported Headscale 0.28 functionality rows were explicit skips;
promtool was absent. Neither run establishes broker-main execution or native-arm64 acceptance.
These recorded runs predate the Tsunaro API-group rename and do not validate a renamed release artifact or upgrade.

Still required: integrated egress reachability/isolation, ingress L4 allowed/denied peers, the remaining HTTP
protocol/ACL/failure cases and restart-no-flap coverage.
API-group/ownership migration rehearsal, nightly execution and production soak also remain open.
Do not delete an existing gateway based on the HTTP happy-path result alone.

### API-group metadata-transfer tests

The per-child primitive in `internal/migration` has passed unit/race tests and isolated Kubernetes 1.31 admission tests.
`TestMigration` runs both API groups in a disposable API server using synthetic legacy-group schemas.
Those schemas reproduce the old ingress's missing `mode` field, but are not a complete historical-release CRD snapshot.

The API-server tests verify:

- Server-side dry-run leaves persisted objects unchanged.
- Transfer preserves child UIDs, Secret bytes, ConfigMap data, allocated Service IPs, workload specs, pod templates and generation.
- Ownership, key-expiry annotations and ConfigMap role labels change together; unsafe legacy prefix annotations are removed.
- Retrying the same in-memory plan performs no write when the exact post-state is already present.
- Stale resourceVersions, recreated children, changed parents and changed post-states stop the transfer.
- A real intervening write between GET and PATCH makes the JSONPatch preconditions reject the transfer.
- The original `tailnet-operator` SSA manager can subsequently apply equivalent Secret/Deployment state without forcing ownership.

Controller regressions reproduce failed key minting with legacy annotations, then reuse transferred working and preauth keys without API calls.
The working-key case includes an expired bootstrap credential. These lifecycle tests use a fake Kubernetes client and a rejecting HTTP server.
They are not a real Headscale migration result.

Envtest runs no garbage collector, Deployment controller or kubelet. These tests do not establish CRD-deletion safety,
agent node-identity continuity, network connectivity, crash recovery or production rollback.
The primitive is not wired into controller reconciliation and has no live CLI.
Full-fleet inventory and a stopped-writer/prune-safe migration rehearsal remain release blockers.
