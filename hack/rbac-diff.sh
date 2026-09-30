#!/usr/bin/env bash
# Audit default chart RBAC locally; never reads the current Kubernetes context.
set -euo pipefail
cd "$(dirname "$0")/.."
mode="${1:---check}"
if [[ $# -gt 1 || ( "$mode" != --check && "$mode" != --write ) ]]; then
  printf 'Usage: %s [--check|--write]\n' "$0" >&2
  exit 2
fi
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT
export KUBECONFIG=/dev/null
export HELM_CACHE_HOME="$tmp/cache" HELM_CONFIG_HOME="$tmp/config" HELM_DATA_HOME="$tmp/data"
helm template tailnet-operator charts/tailnet-operator \
  --namespace tailnet-system --kube-version 1.31.0 |
  go run ./hack/rbacdiff > "$tmp/rbac.md"
if [[ "$mode" == --write ]]; then
  cp "$tmp/rbac.md" docs/reference/rbac.md
else
  diff -u docs/reference/rbac.md "$tmp/rbac.md"
fi
