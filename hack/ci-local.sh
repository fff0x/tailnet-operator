#!/usr/bin/env bash
# Local twin of the CI gate: the tracked-file context, the Dockerfile TEST stage and
# hack/ci-test.sh that .radicle/native.yaml runs on the broker, with Podman instead of Buildah.
# The toolchain is the container's, never the host's.
set -euo pipefail
cd "$(dirname "$0")/.."

command -v podman >/dev/null || { echo 'required tool missing: podman' >&2; exit 1; }
# One source for the context: the file list of the broker's run spec.
files=$(sed -n 's/^ *git ls-files -z -- \(.*\) |$/\1/p' .radicle/native.yaml)
[[ -n "$files" ]] || { echo 'no git ls-files context list in .radicle/native.yaml' >&2; exit 1; }

umask 077
tmp=$(mktemp -d)
trap 'rm -rf -- "$tmp"' EXIT
mkdir "$tmp/context"
# shellcheck disable=SC2086 # the list is space-separated paths from the tracked run spec
git ls-files -z -- $files | tar --null -T - -cf - | tar -xf - -C "$tmp/context"

podman build --http-proxy=false --layers --target TEST \
  --iidfile "$tmp/image-id" -f "$tmp/context/Dockerfile" "$tmp/context"
# A fresh container per run, as on the broker: no test result is ever cached.
podman run --rm --http-proxy=false --pull=never "$(<"$tmp/image-id")" bash hack/ci-test.sh
