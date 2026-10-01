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
It waits for two ready Pods and the `tailnet-operator.tsunaro.io` Lease in `tailnet-system`.
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
The pinned kindnet includes NetworkPolicy enforcement. These tests do not establish complete NetworkPolicy behavior or production Cilium equivalence; ICMP delivery is implementation-dependent.

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

The subsequent combined RBAC/metrics run also passed after the readiness-timing correction.

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

## Isolated admission and projection fixture

`TestFixtureCAProjection` is separate from the foundation installer.
It requires a fresh owned-cluster driver with the layered network checks; `hack/e2e-kind.sh` skips it.
Use the separate checked-in driver, with permission for a temporary delegated user scope:

```sh
nix-shell -p kind --run 'systemd-run --user --scope -p Delegate=yes -- bash hack/e2e-kind-projection.sh'
```

It requires Linux, rootless Podman, kind v0.32.0, kubectl, Helm 3, Go, Python 3 and standard shell tools.
Go builds use an already populated module cache, with downloads disabled.
Headscale v0.29.3 must also be cached at `${XDG_CACHE_HOME:-$HOME/.cache}/tailnet-operator-e2e/headscale/0.29.3/headscale-linux-<arch>`.
The runner checks the pinned amd64/arm64 SHA256 before copying it into the local fixture image; it never executes that binary on the host.
Set `GOMODCACHE` explicitly if it differs from `${XDG_STATE_HOME:-$HOME/.local/state}/go/pkg/mod`.
The runner creates fresh resources; it has no reuse, route-repair or privileged fallback mode.
Private evidence remains under `${XDG_STATE_HOME:-$HOME/.local/state}/tailnet-operator/evidence/`.
The reconciler/cert-manager-integrated HTTP test is under runtime validation, not yet accepted; the separate production-agent peer test is described below.
The expanded runner also requires the pinned cert-manager assets described in the integration section.
The optional argument `--http-only` selects only `TestIngressHTTP`.
It retains every cluster, image, ownership and network gate; it is not a full-suite acceptance run.
The node observer exposes exactly three read-only commands (`capture` as UID 65534, `inspect`, `network`); there is no Root observer, no packet capture and no diagnostic mode.
Fixture subprocess cancellation requires Linux 6.9+ process-group pidfds. Unsupported kernels fail closed. Owned process groups are cancelled and pipe draining is bounded; deliberately detached descendants are not process-group containment.
Headscale and the independent peer still use their existing pre-start proofs during setup.
The exact fixed test selection is recorded privately. No custom test regex or reuse mode is accepted.
Do not set the gate marker manually or reuse an existing cluster.

The fixture uses the unchanged `netprobe` source on the owned node and a CNI Pod.
The caller verifies ownership, images, namespace bindings, routes, policy rules and capture freshness before creating application fixtures.
The node capture is authoritative: both IPv4 and IPv6 documentation-address dials must return `ENETUNREACH`.
The Pod capture must return `ENETUNREACH` for IPv6; for IPv4 it may return `timeout` instead.
The Pod routes IPv4 via the node, and the embedded kube-network-policies drops the node's ICMP unreachable reply to a policy-selected Pod before conntrack confirmation, so the SYN times out (`netproof.PodDials`).
Kubernetes NetworkPolicy defines TCP/UDP/SCTP only; this ICMP behaviour is CNI-specific and not an isolation failure.
The node must have no default or gateway route.
Pod default routes are accepted only inside that proven node boundary.

Initial Service-webhook calls failed with `network is unreachable`.
The disposable API server now uses `--enable-aggregator-routing=true`, configured in `kind-http.yaml`.
Kubernetes v1.36.1 applies this flag to admission Service resolution, not only API aggregation.
It dials a Service endpoint while preserving the Service DNS name, SNI and CA verification.
No node route, external DNS forwarding or isolation rule is added or relaxed.
The source establishes resolver selection; it does not establish the failed packet's kernel path.
Source references:

- [Resolver selection](https://github.com/kubernetes/kubernetes/blob/v1.36.1/cmd/kube-apiserver/app/server.go#L283-L303)
- [Webhook TLS identity](https://github.com/kubernetes/kubernetes/blob/v1.36.1/staging/src/k8s.io/apiserver/pkg/util/webhook/client.go#L169-L213)

The test checks:

- HTTPS admission using the owned Service, with wrong-CA rejection and recovery.
- A failing-closed webhook scoped to the owned namespace and matching ingress labels.
  Label selection is fixture wiring, not authorization against namespace writers.
- A public-only, immutable CA ConfigMap and a read-only file mount.
  Its `subPath` is intentional; the rotating `/tls` Secret uses no `subPath`.
- Real kubelet projection at UID/FSGroup **65532**, with certificate/key mode **0440**.
- Certificate replacement, Secret removal, mismatched-pair rejection and recovery without replacing the Pod or container.
- Native API rejection when an update removes `tls.key` from a TLS Secret.
  The absence test instead deletes only its owned Secret with a UID precondition.

The agent-shaped Pod first undergoes dry-run admission.
A later real Create checks optional CA-plus-init injection while an independent Kubernetes scheduling gate keeps that Pod unassigned.
Its placeholder application image is neither loaded nor pulled; no agent process starts.
The test requires the stored init/volume shape to match admission and the application container to remain unchanged.
A real Create with an unexpected image must be forbidden.
The running projection Pod uses an explicitly different observation binary, image and labels.
It reads the admitted volume specification; it does not substitute for the production agent.
This proves admission and projection mechanics, not agent serving, controller reconciliation, cert-manager issuance, tailnet traffic or NetworkPolicy enforcement.

An authorized fresh run passed in **232.72s**, including namespace cleanup but excluding image build and cluster startup.
Parent verification confirmed source hashes, private evidence, removed owned resources and the retained shared node image.
Earlier failed attempts remain recorded and are not counted as successful acceptance.
Private evidence: `p1-kind-http-isolation/projection-verified-d291ece162/` under the evidence root above.
The reviewed source passed again in **267.73s**, with the same scope and verified cleanup.
This run includes strict public-CA parsing and the checked-in `kind-http.yaml`.
A regression test rejects malformed PEM prefixes that `pem.Decode` would otherwise skip before a valid root.
Evidence: `p1-kind-http-isolation/projection-reviewed-efaa541592/`.
The integrated HTTP kind test remains open.

### Per-Pod startup gate

`TestPodNetworkGate` runs an unprivileged init container in a separate observation Pod.
Its application container remains blocked while the host verifies fresh captures from that actual Pod and its owned node.
The check binds runtime ownership, Pod UID, container identity, API metadata and CNI routes.
The node capture must return exactly `ENETUNREACH` for IPv4 and IPv6 documentation addresses; the Pod capture follows the `netproof.PodDials` rule above.
The init helper alone is not a network-isolation proof.

The host approves the exact snapshot hash, Pod UID and a fresh random init epoch.
A wrong hash is rejected without starting the application.
The helper rejects snapshots older than **30 seconds**, checks approval again before exiting, and fails closed after **five minutes**.
Approval also carries the host-proof expiry, **25 seconds** after node capture begins.
Both release and the init's authorization decision enforce that deadline.
This does not guarantee subsequent kubelet scheduling time or ongoing containment.
Private state uses an init-only memory volume; new state directories clear inherited fsGroup setgid bits.
Application image, command and environment are not changed by the gate helper.

A fresh native-amd64 source-runner execution passed both tests:
`TestPodNetworkGate` in **11.65s** and `TestFixtureCAProjection` in **335.65s**.
These durations include namespace cleanup, not build or cluster startup.
Parent verification confirmed recorded source hashes, private evidence and removal of owned resources, with the shared node image retained.
Evidence: `projection-HBb2p8rCRj/` under the new runner's evidence directory.
An earlier projection-only execution of that runner passed in **329.46s** (`projection-WYwfp8NesY/`).
An initial caller gate rejected containerd's date-named archive-import digest alias; that failure and its verified cleanup remain recorded.
Acceptance still requires exact config-digest identity, the expected image tag and the running container's imageID.

Independent review found that the first combined run checked the 25-second host window only before dispatching approval.
Dispatch delay could exceed it while the separate 30-second Pod snapshot limit still held.
A failing regression reproduced this; the approval now carries the deadline for init-side enforcement.
The corrected fresh run passed `TestPodNetworkGate` in **10.98s** and `TestFixtureCAProjection` in **313.59s**.
It additionally rejected a correct-hash approval with an expired host proof.
Evidence: `projection-s21A3HCmi3/`, including private API bindings, runtime inspections, approval bytes and release timestamps.
Parent replay independently checked the classifier, identity bindings and recorded timing; owned resources were confirmed removed.
The follow-up source review found no further concrete blocker in this scoped gate.

The running application in this test is `/hold`, not the production agent.
Optional init injection through the CA webhook is now also checked through real Create on a scheduling-gated, non-running Pod.
That admission result is separate from the production-agent execution checked by `TestAgentHTTPSPeer` below.
The reusable `releaseFixturePod` helper retains separate private evidence under `startup-<PodUID>` for each released Pod.
These gate/projection tests do not establish tsnet startup, integrated HTTP traffic, cert-manager deployment or published-image acceptance.

### Private HTTPS control-plane bootstrap

`TestHeadscaleHTTPS` starts the pinned Headscale v0.29.3 binary only after that actual Pod passes its startup network proof.
Two separately gated `/hold` Pods execute the bounded `controlprobe` helper against the Headscale Service.
The probe checks TLS hostname and chain against exactly the mounted public fixture CA, without proxy, redirects or insecure verification.
The wrong-CA test requires the dedicated exit category for `x509.UnknownAuthorityError`; a generic exec, DNS or transport error does not count.
A subsequent trusted connection must succeed, with no Headscale restart.

The fixture uses database policy, MagicDNS under `fixture.test`, and no external DERP lists, update checks, logtail or HA probes.
Embedded DERP advertises the Service hostname from `server_url`; explicit Pod IPs are unnecessary.
TCP8443 and UDP3478 share the owned Service. Empty DERP address fields mean hostname resolution, not disabled DNS.
This matches [Headscale v0.29.3 region generation](https://github.com/juanfont/headscale/blob/v0.29.3/hscontrol/derp/server/derp_server.go#L73-L148)
and [Tailscale v1.94.1 address semantics](https://github.com/tailscale/tailscale/blob/v1.94.1/tailcfg/derpmap.go#L153-L198).
This bootstrap test does **not** exercise DERP/STUN traffic, tsnet registration or the production operator/agent.

The combined source-runner execution passed Headscale HTTPS in **22.95s**, the observation Pod startup gate in **13.66s**,
and projection plus optional real admission in **335.78s**.
Four actual Pod startup proofs were retained and independently replayed; owned resources were confirmed removed.
Evidence: `projection-JBSBzp2Dsw/` under the runner's private evidence directory.
An earlier attempt rejected the missing namespace ownership label before starting Headscale.
The fixture now binds the real namespace UID; the public-CA ownership guard was not bypassed.
That failure is retained as `projection-oQcPjX0EUk/`, whose separate admission/projection and observation-gate tests passed.

### Production-source agent and independent tsnet peer

`TestAgentHTTPSPeer` runs a separate image containing the unchanged production operator and agent binaries.
Only the agent process starts; explicit fixture Pods and configuration replace controller reconciliation in this test.
The image uses the production bundle layout and the existing system CA file.
Fixture trust arrives through the approved read-only public-CA mount, not an image trust-store modification.

Headscale, the independent `/httppeer` process and the production `/tailnet-agent` each pass their actual Pod startup proof.
A Kubernetes scheduling gate holds the real agent Pod until its stored webhook-injected CA mount and init container are checked.
Admission preserves its application image, command and environment.
The host then releases the injected init through `releaseFixturePod`; it does not bypass that gate.
These fixture Pods use `restartPolicy: Never`; final API observations require unchanged container identities and zero restarts.
The actual agent imageID is bound to the locally built image config and imported archive.

The peer uses its own tsnet identity and `peer.Dial`, not a Pod-IP substitute for the tailnet path.
Four HEAD requests cover assigned Tailnet IPv4 and MagicDNS, each with HTTP/1.1 and HTTP/2.
They require fixture-CA and hostname verification, the expected serving-leaf hash, and a fixed backend response.
The backend checks original Host, path/query, plaintext upstream transport, rewritten forwarding headers and removal of spoofed headers.
The fixture's API proxy uses no kubectl request-timeout query; a separate 10-second subprocess deadline bounds each call.
Headscale readiness uses a bounded non-mutating query before single-attempt user/key creation.

The fresh source run passed `TestAgentHTTPSPeer` in **38.59s**, Headscale HTTPS in **23.72s**,
the observation startup gate in **12.98s**, and projection plus optional admission in **243.85s**.
Durations include namespace cleanup, not builds or cluster startup.
Seven distinct Pod proofs were retained and independently replayed against recorded bindings and deadlines.
Exact owned resources, both image tags and the temporary scope/directory were confirmed removed; the shared node image remained.
Evidence: `projection-X3NG5SsKcl/` under the runner's private evidence directory.

This is source-built agent acceptance, not published-image or native-arm64 acceptance.
The fixture uses an allow-all policy and explicitly supplied Secrets, not cert-manager or the real reconciler.
It does not establish ACL-negative behavior, WebSockets, L4 coexistence, serving-certificate rotation/expiry/recovery, or a particular DERP/STUN path in Kind.
The separate earlier peer, projection and cert-manager-helper results retain their own scopes.
This separate peer check does not establish the reconciler/cert-manager acceptance described below, and does not close all of P1.

### Reconciler and cert-manager integration

`TestIngressHTTP` installs the actual cert-manager v1.21.2 chart, including its controller, cainjector, webhook and startup-check hook.
It retains chart RBAC, ServiceAccounts and admission; only selfsigned/private-CA issuer controllers are enabled, with ambient credentials disabled.
It then installs the operator chart and mounts the public control CA through a fixture-only Deployment patch.
The tested path is real Tailnet/Ingress reconciliation, managed Certificate issuance, a gated generated agent, peer HTTPS and certificate reissuance without an agent restart.
Control trust and the cert-manager serving CA remain separate; the peer's explicit `--serving-ca=cert-manager` mode reads only `/serving-ca/ca.pem` for serving trust.
The fixture does not serialize the control authority's private key into an issuer Secret.

A native-amd64 normal `--http-only` run passed this integrated path in 240.03 seconds.
A subsequent full default suite also passed all five components: agent/peer (37.94s), Headscale HTTPS (23.48s), integrated HTTP/renewal (235.15s), init gate (11.84s), and kubelet projection/admission (299.32s).
The independent peer verifies the exact backend body and sanitized forwarding headers over IP and MagicDNS, using HTTP/1.1 and HTTP/2 with serving-CA and DNS-SAN verification.
The same four checks pass after cert-manager produces a different leaf and advances the Certificate revision.
The test requires a 55–65-minute leaf lifetime, matching reconciled `TLSNotAfter`, unchanged agent Pod/container identity, zero restarts and unchanged Deployment generation.
This is source-fixture acceptance, not published-image, arm64, production-Cilium, migration or soak acceptance.
Integrated ACL-negative, WebSocket and L4 checks are not claimed by this test's result.

The test patches the actual Certificate to `duration: 1h` and `renewBefore: 20m`, then requests the standard `cmctl renew`-style Issuing intent.
In cert-manager v1.21.2, changing an initially omitted duration does not itself force reissuance: request comparison checks duration only when both old and new values are present.
The fixture's `/status` JSON Patch tests Certificate UID/resourceVersion and changes only the Issuing condition; it never creates Ready, a revision, certificate dates or Secret contents.
All other conditions and status fields remain intact. An already advanced revision or current issuance prevents duplicate requests.
Actual issuance and serving checks remain mandatory; a renewal request alone is not success.

The Node-authoritative dial contract above (strict dual `ENETUNREACH` on the node and the policy-free holder; IPv4 `timeout` admitted only for a topologically bound startup Pod with a fresh node proof) was adopted after a packet-metadata comparison: three target windows with SYN but no returning ICMP versus three control windows with SYN and ICMP 3/0. The diagnostic tooling behind that comparison was removed on 2026-10-01; the finding is summarised in the `netproof.PodDials` comment.
Policies remain active and unchanged; there is no pre-policy admission barrier or route/privilege workaround.
Historical failures remain retained, including the first renewal attempt and intermittent projection timeouts.
Two full-suite attempts stopped before tests at the unchanged 90-second CoreDNS rollout deadline; the next fresh run passed without a timeout increase or readiness bypass.
The bootstrap failure cause remains unestablished. Failure-only bounded CoreDNS observations were added to preserve evidence if it recurs.

The cache must contain `chart.tgz` and four OCI archives named `controller.tar`, `cainjector.tar`, `webhook.tar` and `startupapicheck.tar` under:

```text
${XDG_CACHE_HOME:-$HOME/.cache}/tailnet-operator-e2e/cert-manager/v1.21.2/immutable-ref/linux-<arch>/
```

`cert-manager-images.json` pins the chart SHA256 and native amd64/arm64 manifest digests.
The offline `cert-manager-assets.py` validator checks every blob, descriptor, native image config and archive boundary without extracting or executing members.
The OCI descriptor's `org.opencontainers.image.ref.name` must equal its exact `repository@digest`, not only a mutable version tag.
An anonymous preparation command for each locked native image is:

```sh
skopeo copy --src-no-creds --preserve-digests \
  "docker://$repository@$digest" "oci-archive:$archive:$repository@$digest"
```

The runner copies validated assets into its private directory, validates them again, and preloads them before application fixtures.
Every exact digest reference and config ID must resolve through the node's CRI before proceeding; workloads use `imagePullPolicy: Never`.
The disposable-node import uses Kind's transfer-import flags and the snapshotter parsed from the actual containerd configuration, plus an explicit fully qualified repository `--base-name`.
This prevents generated unqualified index aliases from becoming dangling normalized CRI references.
Every CRI-reported reference must also exist literally in the containerd image inventory; CRI inspection alone is insufficient.
Owned CA Certificate children are removed while their controller/webhook still run. CRDs remain through Helm uninstall, as in the upstream default, until the owned cluster is removed.
Caches remain outside the source tree and are retained. These checks establish pinned content identity, not upstream signature verification.
Only native-amd64 assets have been exercised so far.

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
bash -n hack/e2e-kind.sh hack/e2e-kind-projection.sh
shellcheck hack/e2e-kind.sh hack/e2e-kind-projection.sh
python3 -B -I test/e2e-kind/network-gate-test.py
go test -mod=readonly -tags=e2e_kind -count=1 -v ./test/e2e-kind
```

Without runner-owned environment, the foundation, projection, control-plane and agent-peer integration tests skip before making any API request.
`TestConfigGuard` tests rejection of foreign contexts, remote endpoints, proxies and credential helpers.
`TestPolicySampleParser` and `TestHolderPod` test counter parsing and exact Lease-to-Pod mapping without a cluster.
These source-only checks are not a successful Tier 2 execution.
