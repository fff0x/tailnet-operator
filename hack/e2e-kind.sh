#!/usr/bin/env bash
# Disposable Tier 2 foundation. Never selects a remote/rootful runtime or existing cluster.
set +x
set -euo pipefail
umask 077
fail() { printf 'e2e-kind: %s\n' "$*" >&2; exit 1; }
[[ $# == 0 ]] || fail 'no arguments accepted; this runner owns all cluster/context selection'
[[ $(id -u) != 0 ]] || fail 'run as an unprivileged user, not root'
for name in CONTAINER_HOST CONTAINER_CONNECTION DOCKER_HOST DOCKER_CONTEXT; do
  [[ -z ${!name:-} ]] || fail "unset $name; remote/socket/context overrides are forbidden"
done
unset CONTAINER_HOST CONTAINER_CONNECTION DOCKER_HOST DOCKER_CONTEXT CONTAINER_SSHKEY
unset KUBECONFIG KUBERNETES_MASTER KIND_EXPERIMENTAL_PROVIDER KIND_EXPERIMENTAL_DOCKER_NETWORK
unset HTTP_PROXY HTTPS_PROXY ALL_PROXY NO_PROXY http_proxy https_proxy all_proxy no_proxy
export KIND_EXPERIMENTAL_PROVIDER=podman
export GOFLAGS=-mod=readonly GOWORK=off GOTOOLCHAIN="${GOTOOLCHAIN:-local}" CGO_ENABLED=0 TS_NO_LOGS_NO_SUPPORT=1
root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd -P)
for tool in podman kind kubectl helm go timeout; do
  command -v "$tool" >/dev/null || fail "missing $tool (nix-shell supplies the pinned kind)"
done
podman_bin=$(type -P podman)
[[ $("$podman_bin" --remote=false info --format '{{.Host.Security.Rootless}}') == true ]] || fail 'local Podman is not rootless'
# kind.yaml pins this version's verified default node image.
[[ $(kind version) == 'kind v0.33.0 '* ]] || fail 'expected kind v0.33.0; review its default node pin before updating'
case $(uname -m) in x86_64) arch=amd64 ;; aarch64|arm64) arch=arm64 ;; *) fail 'unsupported architecture' ;; esac
work=$(mktemp -d "${TMPDIR:-/tmp}/tn-kind-XXXXXXXXXX")
cluster=$(basename "$work" | tr '[:upper:]' '[:lower:]')
export E2E_KIND_WORK="$work" E2E_KIND_CLUSTER="$cluster" E2E_KIND_CONTEXT="kind-$cluster"
export E2E_KIND_IMAGE="localhost/tailnet-operator-e2e:$cluster"
export E2E_KIND_HEADSCALE_IMAGE="localhost/headscale-e2e:$cluster"
export KUBECONFIG="$work/kubeconfig"
created=false
cleanup() {
  local result=$? id remaining
  trap - EXIT INT TERM
  set +e
  if [[ $created == true ]]; then
    timeout 60 kind delete cluster --name "$cluster" --kubeconfig "$KUBECONFIG" || result=1
    # Include partial startup containers, and only this random cluster's exact label.
    remaining=$("$podman_bin" --remote=false ps -aq --filter "label=io.x-k8s.kind.cluster=$cluster") || result=1
    while IFS= read -r id; do
      [[ -z $id ]] || timeout 30 "$podman_bin" --remote=false rm -f "$id" >/dev/null || result=1
    done <<< "$remaining"
  fi
  "$podman_bin" --remote=false image rm "$E2E_KIND_IMAGE" "$E2E_KIND_HEADSCALE_IMAGE" >/dev/null 2>&1 || true
  rm -rf -- "$work"
  exit "$result"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
# kind invokes podman itself: force every invocation to remain local, even if containers.conf
# has remote defaults. Do not export or consume any Podman/Docker API socket.
mkdir "$work/bin" "$work/image"
printf '#!/usr/bin/env bash\nexec %q --remote=false "$@"\n' "$podman_bin" > "$work/bin/podman"
chmod 700 "$work/bin/podman"
export PATH="$work/bin:$PATH"
# Isolate Helm state too; never read a developer's repository credentials/plugins.
export HELM_CONFIG_HOME="$work/helm/config" HELM_CACHE_HOME="$work/helm/cache" HELM_DATA_HOME="$work/helm/data"
export HELM_PLUGINS="$work/helm/plugins"
printf 'e2e-kind: local rootless Podman verified; creating %s\n' "$cluster"
created=true
if ! timeout 300 kind create cluster --name "$cluster" --kubeconfig "$KUBECONFIG" \
  --config "$root/test/e2e-kind/kind.yaml" --wait 120s --retain; then
  fail 'kind startup blocked; no sudo, delegation, sysctl or systemd changes will be attempted'
fi
chmod 600 "$KUBECONFIG"
kubectl --kubeconfig "$KUBECONFIG" --context "$E2E_KIND_CONTEXT" cluster-info >/dev/null
# Compile this checkout into a temporary context. The root Dockerfile's final /bundle carrier
# is intentionally NOT used as a runnable image. No repository-local binary or scratch output.
cd "$root"
GOOS=linux GOARCH="$arch" go build -trimpath -ldflags='-s -w' -o "$work/image/tailnet-operator" ./cmd/operator
GOOS=linux GOARCH="$arch" go build -trimpath -ldflags='-s -w' -o "$work/image/tailnet-agent" ./cmd/agent
ca=${SSL_CERT_FILE:-/etc/ssl/certs/ca-certificates.crt}
[[ -r $ca ]] || fail 'system CA bundle unavailable'
cp -- "$ca" "$work/image/ca-certificates.crt"
# Keep credentials/work directories private, but allow the image's non-root UID to execute
# root-owned binaries and read its public CA bundle. The runner's umask would otherwise use 0700/0600.
chmod 0755 "$work/image/tailnet-operator" "$work/image/tailnet-agent"
chmod 0644 "$work/image/ca-certificates.crt"
podman build --network=none --pull=never --tag "$E2E_KIND_IMAGE" \
  --file "$root/test/e2e-kind/Dockerfile" "$work/image"
podman save --format docker-archive --output "$work/operator.tar" "$E2E_KIND_IMAGE"
kind load image-archive "$work/operator.tar" --name "$cluster"
# Verified using skopeo inspect --no-creds against the official v0.29.6 GHCR release.
headscale_source=ghcr.io/juanfont/headscale:0.29.6@sha256:cabe84f0699913dbca9320f0883dca7565dd08df3c5be29edfabbebeff763966
podman pull "$headscale_source"
podman image inspect --format 'Headscale provenance: {{.RepoDigests}}' "$headscale_source"
podman tag "$headscale_source" "$E2E_KIND_HEADSCALE_IMAGE"
podman save --format docker-archive --output "$work/headscale.tar" "$E2E_KIND_HEADSCALE_IMAGE"
kind load image-archive "$work/headscale.tar" --name "$cluster"
# UID binds tests to this API server; Go also checks private kubeconfig/context/loopback endpoint.
export E2E_KIND_SYSTEM_UID
E2E_KIND_SYSTEM_UID=$(kubectl --kubeconfig "$KUBECONFIG" --context "$E2E_KIND_CONTEXT" get namespace kube-system -o jsonpath='{.metadata.uid}')
go test -tags=e2e_kind -count=1 -timeout=10m -v ./test/e2e-kind
