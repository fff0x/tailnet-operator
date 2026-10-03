# Kind suite: disposable cluster tests

Two runners create a rootless kind cluster, run the tests against it and delete everything they
created. Neither touches an existing kube-context, Docker socket or host configuration.

| Runner | Tests | Typical duration |
| --- | --- | --- |
| `hack/e2e-kind.sh` | `TestInstall`, `TestLeaderFailover` | 3–4 min |
| `hack/e2e-kind-projection.sh` | `TestPodNetworkGate`, `TestFixtureCAProjection`, `TestHeadscaleHTTPS`, `TestAgentHTTPSPeer`, `TestIngressHTTP`, `TestIngressL4` | About 17 min for `--http-only`; full test-process budget 26 min, HTTP-only 18 min, L4-only 10 min (setup/cleanup additional) |

```sh
# kind must be v0.32.0 (its embedded node image is pinned in kind.yaml / kind-http.yaml)
nix-shell -p kind --run 'systemd-run --user --scope -p Delegate=yes -- bash hack/e2e-kind.sh'
nix-shell -p kind --run 'systemd-run --user --scope -p Delegate=yes -- bash hack/e2e-kind-projection.sh'
# Focused L4 acceptance; use --http-only instead for the HTTP/cert-manager path.
nix-shell -p kind --run 'systemd-run --user --scope -p Delegate=yes -- bash hack/e2e-kind-projection.sh --l4-only'
```

## Requirements

- Linux, rootless Podman (`podman info` must report rootless), kind v0.32.0, kubectl, Helm 3, Go,
  Python 3, `timeout`. The user scope needs cgroup delegation (`Delegate=yes`); the runner stops if
  kind reports it missing and never changes sysctls, services or delegation itself.
- Go builds use the populated module cache with downloads disabled (`GOMODCACHE` if it differs from
  `~/.local/state/go/pkg/mod`).
- Headscale 0.29.3 binary at `~/.cache/tailnet-operator-e2e/headscale/0.29.3/headscale-linux-<arch>`
  (SHA256-checked; copied into the fixture image, never executed on the host).
- For the projection runner: cert-manager v1.21.2 chart and images under
  `~/.cache/tailnet-operator-e2e/cert-manager/v1.21.2/immutable-ref/linux-<arch>/` —
  `chart.tgz` plus `controller.tar`, `cainjector.tar`, `webhook.tar`, `startupapicheck.tar` as OCI
  archives whose `ref.name` is the exact `repository@digest` pinned in `cert-manager-images.json`:

  ```sh
  skopeo copy --src-no-creds --preserve-digests "docker://$repository@$digest" "oci-archive:$archive:$repository@$digest"
  ```

  `python3 -B -I cert-manager-assets.py <cache-dir> <arch>` validates the cache offline.

`XDG_CACHE_HOME` and `XDG_STATE_HOME` are honoured. Evidence of each run (sanitized logs, proofs,
timings) is written under `~/.local/state/tailnet-operator/evidence/`; nothing is written into the checkout.

## Safety model

- Random cluster name, private temporary kubeconfig; every kubectl/Helm call selects that context.
- Exit and signal traps delete the owned cluster, labelled containers, local image tags and the
  temporary work directory; cleanup also runs on test failure with its own bounded context.
- `TestConfigGuard` rejects foreign contexts, remote endpoints, proxies and credential helpers; the
  runner rejects root and remote Podman.
- No credentials or raw fixture logs are printed; Headscale keys travel through captured CLI stdout
  and the Kubernetes API only. Failure diagnostics are counts, booleans and fixed categories.
- Images are pinned by digest (`kindest/node:v1.36.1`, `ghcr.io/juanfont/headscale:0.29.3`,
  cert-manager v1.21.2); the operator image is built from the checkout per run and never published.
- Fixture subprocesses are cancelled by process-group pidfd (Linux ≥ 6.9); older kernels fail closed.

## What the tests cover

**`TestInstall`** — Helm install of the local chart, CRDs established, manager ready; real Headscale
0.29.3 (SQLite, embedded DERP, no update checks or logtail) in the cluster; `HeadscaleCompatible=True`
and `PolicyApplied=True/InSync`; the live policy read over Headscale's Unix socket equals the
rendered/applied hashes and the base ACL.

**`TestLeaderFailover`** — same installer, two replicas, Lease `tailnet-operator.tsunaro.io` whose
holder identity maps to a running Pod. Deletes the leader and changes the base ACL at once; within
30 s a different leader must have rendered and applied the new policy and the Headscale CLI must
show it. Metrics are sampled per Pod through the API proxy; the survivor's error counter must be
unchanged and the new Pod's zero.

**`TestPodNetworkGate`** — the per-Pod startup gate used by every fixture Pod below. An unprivileged
init container holds the application until the host has verified a fresh network capture from that
Pod *and* its node: ownership, Pod UID, container identity, routes and the dial contract. The host
approves the exact snapshot hash with a random epoch; approvals expire 25 s after node capture and
snapshots after 30 s; the init fails closed after five minutes.

*Dial contract* (`test/internal/netproof`): the node capture must return `ENETUNREACH` for both IPv4
and IPv6 documentation addresses (no default or gateway route). A policy-selected Pod must return
`ENETUNREACH` for IPv6 and may return `timeout` for IPv4, because kindnet's embedded
kube-network-policies drops the node's ICMP unreachable reply before conntrack confirmation. This is
CNI-specific behaviour, not an isolation failure; the node capture is authoritative.

**`TestFixtureCAProjection`** — the fixture's own admission webhook (fail-closed, scoped to the
owned namespace) over HTTPS with wrong-CA rejection and recovery; a public-only immutable CA
ConfigMap mounted read-only; kubelet projection at UID/FSGroup 65532 with mode 0440; certificate
replacement, Secret removal and mismatched-pair rejection without replacing the Pod; dry-run and
real Create of an agent-shaped, scheduling-gated Pod to verify CA/init injection. The API server
runs with `--enable-aggregator-routing=true` so webhook Service resolution works on the isolated node.

**`TestHeadscaleHTTPS`** — Headscale behind the fixture CA on TCP 8443/UDP 3478; two gated probe
Pods verify hostname and chain against exactly the mounted CA (`x509.UnknownAuthorityError` for the
wrong CA, success for the right one, no restart in between).

**`TestAgentHTTPSPeer`** — the production `/tailnet-agent` binary (unchanged, source-built image)
serving an HTTP expose, and an independent tsnet peer (`/httppeer`) dialling it over the tailnet:
four HEAD requests (Tailnet IPv4 and MagicDNS × HTTP/1.1 and HTTP/2) with CA and hostname
verification, expected leaf hash, fixed backend body, correct Host/forwarding headers and spoofed
headers stripped. Allow-all policy and explicit Secrets; no reconciler.

**`TestIngressHTTP`** — the full path: real cert-manager v1.21.2 (controller, cainjector, webhook,
startup check; self-signed/CA issuers only), the operator chart, a `Tailnet` and a `mode: http`
`TailnetIngress`, managed Certificate issuance, a gated generated agent Pod, the same four peer checks,
then a forced renewal (`duration: 1h`, `renewBefore: 20m`, `Issuing` intent) — the leaf changes, the
Certificate revision advances, `TLSNotAfter` follows, and the agent Pod, container and Deployment
generation stay unchanged.

The backend-TLS phase switches that CR to the fixture's existing HTTPS Headscale Service.
It checks the `http-v2` Pod replacement, real peer HTTP/1.1 and HTTP/2, a projected CA digest change,
wrong/invalid/deleted CA rejection and recovery without another agent restart.
The existing endpoint returns 404 for the peer's fixed path; a proxy-generated 502 is a failure,
not successful upstream acceptance. No new fixture binary, listener or mode is introduced.

**`TestIngressL4`** (`--l4-only` for a focused run) uses the real chart/reconciler, a generated L4 ingress
and two separately authenticated tsnet peers. TCP 8443 forwards to a fixed fixture backend on 8081.
A random nonce and hash response verify byte forwarding through both tailnet IPv4 and MagicDNS.
The generated agent and both peers pass the same pre-start network gates as the HTTP fixture.

One user remains allowed throughout. The other is denied, temporarily added to the allowed group,
then removed again through the operator-owned policy. Positive stages check fresh connections through both address forms.
Each negative stage requires three fresh IPv4 dial timeouts: any connection or unclassified failure fails immediately, without retries.
Only revocation has a separate bounded convergence window before these assertions; initial denial has none.
Unclassified MagicDNS failures do not count as ACL evidence. Positive controls and successful temporary access
help distinguish denial from an unusable peer/backend, but do not prove every ACL behavior.
Final checks require unchanged peer/agent identities and restart counts, an unchanged agent Deployment generation,
and a Ready ingress. `probe-observations.json` retains every attempt, including convergence and failed-run observations.
Probe results expose only bounded booleans and fixed phase/address-kind labels, not credentials or raw network errors.

The peer helper has fixed ports and framing, bounded deadlines/concurrency, strict control JSON and no arbitrary dial mode.
Its optional `--identity=denied` selects one fixed second hostname; it cannot be combined with the serving-CA override.
This runner still preloads verified cert-manager assets for L4-only mode, but that test does not install cert-manager.

Not covered here: NetworkPolicy semantics of production CNIs, DERP/STUN traffic, L4 egress/subnet routing,
L4 coexistence with HTTP, HTTP-specific ACL-negative cases, WebSockets, published images, arm64 execution,
long-running operation, DNS-specific ACL denial, or immediate revocation of new/established connections.
Bounded negative observations are not exhaustive ACL coverage.

## Offline checks

```sh
bash -n hack/e2e-kind.sh hack/e2e-kind-projection.sh && shellcheck hack/e2e-kind.sh hack/e2e-kind-projection.sh
python3 -B -I test/e2e-kind/network-gate-test.py && python3 -B -I test/e2e-kind/cert-manager-assets-test.py
go test -tags=e2e_kind -count=1 ./test/e2e-kind      # cluster tests skip without a runner-owned environment
go test ./test/e2e-kind/cmd/... ./test/internal/...
```

The offline tests cover the config guard, Lease-to-Pod mapping, metrics parsing, kind/Headscale
config rendering, the certificate renewal patch, command lifecycle and the dial contract.

## Layout

| Path | What |
| --- | --- |
| `kind.yaml`, `kind-http.yaml` | cluster configs (pinned node image; the HTTP config adds aggregator routing) |
| `headscale.yaml`, `headscale-http.json` | Headscale fixture configs (HTTP / HTTPS) |
| `Dockerfile`, `Dockerfile.fixture` | operator image from the checkout; fixture image with Headscale and the helpers below |
| `cmd/netprobe`, `cmd/netgate`, `network-gate.py` | node/Pod network capture, init-container gate, host-side verifier |
| `cmd/proofverify`, `cmd/projection`, `cmd/hold`, `cmd/controlprobe`, `cmd/httppeer`, `cmd/fixture` | proof replay, projection observer, placeholder app, TLS probe, tsnet peer, fixture driver |
| `cert-manager-images.json`, `cert-manager-assets.py` | pinned cert-manager digests and the offline cache validator |
| `../internal/{netproof,kindfixture,isolation}` | dial contract, webhook/CA helpers, envtest safety guards |
