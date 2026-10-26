#!/usr/bin/env bash
# Local control-plane E2E only: verified public assets, disposable processes, no kubectl/context.
set -euo pipefail
cd "$(dirname "$0")/.."

case "$(uname -s)/$(uname -m)" in
  Linux/x86_64) arch=amd64 ;;
  Linux/aarch64 | Linux/arm64) arch=arm64 ;;
  *) echo 'Tier 1 currently supports Linux amd64/arm64 only' >&2; exit 1 ;;
esac
raw_versions="${HEADSCALE_VERSIONS:-v0.28.0 v0.29.6}"
read -r -a versions <<< "${raw_versions//$'\n'/ }"
if [[ ${#versions[@]} == 0 ]]; then
  echo 'select at least one HEADSCALE_VERSIONS row' >&2; exit 1
fi
for version in "${versions[@]}"; do
  case "$version" in
    v0.28.0 | v0.29.6) ;;
    *) echo 'HEADSCALE_VERSIONS only supports v0.28.0 and v0.29.6' >&2; exit 1 ;;
  esac
done
export HEADSCALE_VERSIONS="${versions[*]}"
for cmd in curl sha256sum sha512sum tar go sqlite3; do
  command -v "$cmd" >/dev/null || { echo "required tool missing: $cmd" >&2; exit 1; }
done
cache="${XDG_CACHE_HOME:-$HOME/.cache}/tailnet-operator-e2e"
export E2E_HEADSCALE_DIR="${E2E_HEADSCALE_DIR:-$cache/headscale}"
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"; if [[ -n "${stage:-}" ]]; then rm -f "$stage"; fi' EXIT

checksum() {
  local file=$1 asset=$2
  awk -v asset="$asset" '$2 == asset { print $1 }' "$file"
}
verify() {
  local algorithm=$1 expected=$2 file=$3 actual
  [[ -n "$expected" ]] || { echo 'missing pinned asset checksum' >&2; return 1; }
  actual=$("$algorithm" < "$file")
  [[ "${actual%% *}" == "$expected" ]] || { echo "asset checksum mismatch: $file" >&2; return 1; }
}
download() {
  curl --fail --silent --show-error --location --proto '=https' --proto-redir '=https' \
    --connect-timeout 10 --max-time 180 --retry 2 "$1" --output "$2"
}
for version in "${versions[@]}"; do
  asset="headscale_${version#v}_linux_${arch}"
  expected=$(checksum test/e2e/headscale-checksums.txt "$asset")
  target="$E2E_HEADSCALE_DIR/${version#v}/headscale-linux-$arch"
  if [[ ! -f "$target" ]]; then
    download "https://github.com/juanfont/headscale/releases/download/$version/$asset" "$tmp/$asset"
    verify sha256sum "$expected" "$tmp/$asset"
    mkdir -p "$(dirname "$target")"
    chmod 0755 "$tmp/$asset"
    # Stage on the destination filesystem so concurrent readers never see a partial binary.
    stage=$(mktemp "$(dirname "$target")/.download.XXXXXX")
    if ! cp "$tmp/$asset" "$stage" || ! chmod 0755 "$stage" || ! mv -f "$stage" "$target"; then
      rm -f "$stage"
      exit 1
    fi
  fi
  verify sha256sum "$expected" "$target"
done

if [[ -z "${KUBEBUILDER_ASSETS:-}" ]]; then
  asset="envtest-v1.31.0-linux-$arch.tar.gz"
  expected=$(checksum test/e2e/envtest-checksums.txt "$asset")
  archive="$cache/envtest/$asset"
  if [[ ! -f "$archive" ]]; then
    download "https://github.com/kubernetes-sigs/controller-tools/releases/download/envtest-v1.31.0/$asset" "$tmp/$asset"
    verify sha512sum "$expected" "$tmp/$asset"
    mkdir -p "$(dirname "$archive")"
    stage=$(mktemp "$(dirname "$archive")/.download.XXXXXX")
    if ! cp "$tmp/$asset" "$stage" || ! mv -f "$stage" "$archive"; then
      rm -f "$stage"
      exit 1
    fi
  fi
  verify sha512sum "$expected" "$archive"
  mkdir "$tmp/envtest"
  tar -xzf "$archive" -C "$tmp/envtest"
  export KUBEBUILDER_ASSETS="$tmp/envtest/controller-tools/envtest"
fi
# Explicit overrides are for pre-provisioned/trusted assets (e.g. an additional Kubernetes row).
for binary in kube-apiserver etcd kubectl; do
  [[ -x "$KUBEBUILDER_ASSETS/$binary" ]] || { echo "envtest binary missing: $binary" >&2; exit 1; }
done
# TestMain also forces UseExistingCluster=false; do not pass through any user kube-context.
export USE_EXISTING_CLUSTER=false
export KUBECONFIG="$tmp/unused-kubeconfig"
go test -tags=e2e ./test/e2e -count=1 -v -timeout=12m "$@"
