# Contributing

Changes are developed in this repository and proposed through its Radicle patch workflow.
Discuss API, permissions, compatibility and migration changes before implementation.
For private vulnerability reports, use [the security policy](docs/SECURITY.md), not a public issue.

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
# With explicitly selected local envtest assets:
KUBEBUILDER_ASSETS=/path/to/envtest task test-validation
# Experimental gateway DNS files against a trusted local binary (loopback only):
COREDNS_BINARY=/absolute/path/to/coredns task test-gateway-dns
```

`task security` uses a pinned `govulncheck` version and the current public database.
Review package/module findings even when no reachable symbol makes the command fail.
Do not add broad suppressions to make a failing release pass.

Use `task e2e-kind` for the disposable pod-level installation/failover suite.
It requires local rootless Podman, kind and suitable cgroup delegation.
See [the runner's safety boundaries](test/e2e-kind/README.md).
Do not point tests at your current kube-context or change host privileges to bypass a failing prerequisite.

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
