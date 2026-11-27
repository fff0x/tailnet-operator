#!/usr/bin/env bash
# Reject each fixture for its documented validation error, never for missing CRDs/RBAC/connectivity.
# kubectl flags (e.g. --context, --kubeconfig, --namespace) are passed through. No resources persist.
set -euo pipefail
shopt -s nullglob

root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
files=("$root"/deploy/examples/invalid/*.yaml)
if ((${#files[@]} == 0)); then
  echo 'No invalid examples found' >&2
  exit 1
fi

for file in "${files[@]}"; do
  expected="$(awk '/^# ExpectedError: / {sub(/^# ExpectedError: /, ""); print; exit}' "$file")"
  if [[ -z "$expected" ]]; then
    echo "Missing ExpectedError header: $file" >&2
    exit 1
  fi
  # Create avoids accidentally validating a merge with an existing CR of the same name.
  if output="$(kubectl "$@" --request-timeout=15s create --dry-run=server -f "$file" 2>&1)"; then
    echo "UNEXPECTED ACCEPTANCE: $file" >&2
    exit 1
  fi
  if ! grep -Eq '(^The (Tailnet|TailnetEgress|TailnetIngress|TailnetGateway|TailnetSite|TailnetGrant) .* is invalid:|Error from server [(]Invalid[)])' <<<"$output" || ! grep -Fq -- "$expected" <<<"$output"; then
    printf 'WRONG FAILURE: %s\nExpected: %s\n%s\n' "$file" "$expected" "$output" >&2
    exit 1
  fi
  printf 'PASS %s\n' "$(basename -- "$file")"
done
printf 'All %d invalid examples rejected for the expected reason.\n' "${#files[@]}"
