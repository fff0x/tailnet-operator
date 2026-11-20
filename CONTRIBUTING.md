# Contributing

Changes are developed in this repository and proposed through its Radicle patch workflow.
Discuss API, permissions, compatibility and migration changes before implementation.
For private vulnerability reports, use [the security policy](docs/explanation/security-model.md), not a public issue.

## Local checks

```sh
nix-shell
task lint test
task chart
# Regenerate when API markers or chart defaults change:
task crds deploy-gen
task security
# Isolated API-server and real Headscale tests; downloads checksum-pinned public assets:
task e2e
# Admission, gateway DNS CAS and durable mint records with explicit local envtest assets:
KUBEBUILDER_ASSETS=/path/to/envtest task test-validation
# Experimental gateway DNS files against a trusted local binary (loopback only):
COREDNS_BINARY=/absolute/path/to/coredns task test-gateway-dns
```

`task ci-local` runs the CI gate the way the CI broker does: it builds the `TEST` stage of the
`Dockerfile` with rootless Podman and runs `hack/ci-test.sh` in a fresh container. The Go, Helm and
`govulncheck` versions are the container's, so a host toolchain that differs from CI cannot change
the result. Run it before a push; the tasks above are the quick loop while you work.

`task security` uses a pinned `govulncheck` version and the current public database.
Review package/module findings even when no reachable symbol makes the command fail.
Do not add broad suppressions to make a failing release pass.

Use `task e2e-kind` for the disposable pod-level installation/failover suite.
It requires local rootless Podman, kind and suitable cgroup delegation.
See [the runner's safety boundaries](https://app.radicle.xyz/nodes/seed.this-is-fine.io/rad:z46fGxuhyvDV57psA8s6Q6PdHJrsX/tree/test/e2e-kind/README.md).

The complete local run is `task e2e-full`: the exact CI gate (`hack/ci-test.sh` — gofmt/vet,
govulncheck, unit, chart, admission against envtest 1.31, Tier 1 against real Headscale 0.28.0 and
0.29.6) followed by every Tier-2 kind suite (`hack/e2e-kind.sh`, the projection runner with its
default, `--rest-only`, `--gateway-preflight-only` and `--gateway-fresh-only` selections). Budget
about 75 minutes; a failing stage stops the run. Each kind stage needs the delegated scope, so
start the whole task inside one:

```sh
# shell.nix pins kind v0.32.0, the release the runners require. GOTOOLCHAIN=auto only until the
# nixpkgs Go matches go.mod — the CI image keeps GOTOOLCHAIN=local.
nix-shell --run 'systemd-run --user --scope -p Delegate=yes -- env GOTOOLCHAIN=auto task e2e-full'
```

CI runs the first stage on every push to `main`; the kind suites run only here, so run
`task e2e-full` before a release and after changes to the agent, gateway or ingress data path.
Do not point tests at your current kube-context. The disposable test cluster may provide
a prerequisite the way the target node does (for example the gateway gate permits the
namespaced `net.ipv4.ip_forward` unsafe sysctl so a fixture pod forwards like a Talos
node); do not change host privileges, add capabilities or relax the pod isolation gate.
The isolated projection runner also offers `--gateway-preflight-only` and
`--gateway-fresh-only`; see the [gateway gates](docs/reference/gateway.md#read-only-kind-prerequisite-gate).
The fresh-Pod selection runs the production fresh controller and verifies bootstrap,
identity across StatefulSet Pod recreation, IPv4 TCP forwarding and known-local DNS
through the gateway tailnet IP. It does not prove adoption, DNS reload or general crash recovery.
A failed capability check is not support evidence and must not be silently skipped.

An integration bug needs a regression test that fails before the correction when a safe reproduction is possible.
Distinguish unit assertions, envtest API behavior, live pods, data-plane traffic and long-running acceptance.
A skipped unsupported row is not a compatibility result. Never substitute mocked success for a real integration gate.
Keep test processes, credentials, downloaded assets and scratch output outside the checkout.

## Dependency updates

`renovate.json` defines updates for Go modules, Dockerfile images and the pinned `govulncheck` tool.
It requests image digest pins and groups tsnet changes for explicit compatibility review. Automerge is disabled.
The configuration does not deploy, schedule or prove a running Renovate service.
Validate changes with `renovate-config-validator --strict renovate.json`.

## Change shape

- Keep commits focused. Separate unrelated dependency, runtime, chart and deployment changes.
- Preserve CRD compatibility and document admission/defaulting changes.
- Generate CRDs and standalone manifests from their sources; do not hand-edit generated copies.
- Test image/agent-image precedence, Secret handling and namespace boundaries when changing chart values.
- Never put credentials or raw sensitive diagnostics in fixtures, screenshots, status, Events or commit messages.
- Preserve `errors.Is`/`errors.As` where callers need classification, without exposing unsafe underlying error text.
- A release needs artifact and signature evidence; successful local tests do not establish publication or rollout.

## Sign-off

Contributions must include a Developer Certificate of Origin sign-off:
[Developer Certificate of Origin 1.1](https://developercertificate.org/).
Add `Signed-off-by: Your Name <your-email>` when you can make that certification.
Git's `--signoff` option adds this trailer; it is different from a cryptographic commit signature.
Do not add somebody else's sign-off or bypass repository signing and verification hooks.
