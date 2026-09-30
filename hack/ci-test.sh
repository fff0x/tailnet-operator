#!/usr/bin/env bash
# Native TEST-container gate: local processes only, no Docker/Kubernetes socket or credentials.
set -euo pipefail
cd "$(dirname "$0")/.."

for cmd in go gofmt govulncheck helm curl jq sha512sum tar sqlite3; do
  command -v "$cmd" >/dev/null || { echo "required CI tool missing: $cmd" >&2; exit 1; }
done
case "$(uname -s)/$(uname -m)" in
  Linux/x86_64) arch=amd64 ;;
  Linux/aarch64 | Linux/arm64) arch=arm64 ;;
  *) echo 'CI tests support native Linux amd64/arm64 only' >&2; exit 1 ;;
esac

# Never discover a live kube-context, accept live exports or inherit alternate test binaries.
unset LIVE_CR_FILE KUBEBUILDER_ASSETS E2E_HEADSCALE_DIR
export USE_EXISTING_CLUSTER=false GOTOOLCHAIN=local GOFLAGS=-mod=readonly
export HEADSCALE_VERSIONS='v0.28.0 v0.29.3'
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
export KUBECONFIG="$tmp/unused-kubeconfig"

printf '\n== gofmt / vet / unit ==\n'
unformatted=$(gofmt -l cmd internal api test hack)
if [[ -n "$unformatted" ]]; then
  printf 'gofmt required:\n%s\n' "$unformatted" >&2
  exit 1
fi
go vet ./...
printf '\n== govulncheck (reachable symbols) ==\n'
govulncheck ./...
# Disable Go's successful-result cache too, not just the container layer cache.
go test ./... -count=1 -timeout=10m

printf '\n== Helm chart contracts and RBAC reference ==\n'
bash hack/dashboard-lint.sh
bash hack/rbac-diff.sh --check
go test -tags=chart ./test/chart -count=1 -timeout=10m

# Use the same checked-in envtest 1.31 pins as Tier 1. The disposable extraction is
# shared by admission and E2E; hack/e2e.sh verifies/fetches its pinned Headscale assets.
asset="envtest-v1.31.0-linux-$arch.tar.gz"
expected=$(awk -v asset="$asset" '$2 == asset { print $1 }' test/e2e/envtest-checksums.txt)
[[ "$expected" =~ ^[[:xdigit:]]{128}$ ]] || { echo 'missing envtest checksum' >&2; exit 1; }
curl --fail --silent --show-error --location --proto '=https' --proto-redir '=https' \
  --connect-timeout 10 --max-time 180 --retry 2 \
  "https://github.com/kubernetes-sigs/controller-tools/releases/download/envtest-v1.31.0/$asset" \
  --output "$tmp/$asset"
printf '%s  %s\n' "$expected" "$tmp/$asset" | sha512sum -c -
tar -xzf "$tmp/$asset" -C "$tmp"
export KUBEBUILDER_ASSETS="$tmp/controller-tools/envtest"
# Admission also tests the validation script with this pinned kubectl against envtest.
export PATH="$KUBEBUILDER_ASSETS:$PATH"
for binary in kube-apiserver etcd kubectl; do
  [[ -x "$KUBEBUILDER_ASSETS/$binary" ]] || { echo "missing envtest binary: $binary" >&2; exit 1; }
done

printf '\n== Kubernetes 1.31 admission ==\n'
go test -tags=integration ./test/validation -count=1 -v -timeout=10m
printf '\n== Tier 1: real Headscale 0.28.0 / 0.29.3 ==\n'
bash hack/e2e.sh
