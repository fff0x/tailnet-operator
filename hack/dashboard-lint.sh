#!/usr/bin/env bash
# Source dashboard contract only: jq, no Go, Grafana or cluster connection.
set -euo pipefail
cd "$(dirname "$0")/.."
if [ "$#" -eq 0 ]; then
  set -- charts/tailnet-operator/files/dashboard.json
fi
for dashboard in "$@"; do
  jq -e '
    def nonempty: type == "string" and test("\\S");
    def panels: .panels[] | recurse(.panels[]?);
    type == "object" and
    (.title | nonempty) and (.description | nonempty) and
    (.panels | type == "array") and
    ([.panels[] | select(.type == "row")] | length == 9) and
    ([panels] | length > 8) and
    all(panels; (.description | nonempty) and (.title | nonempty)) and
    ([panels | .id] as $ids | ($ids | unique | length) == ($ids | length)) and
    any(.__inputs[]; .name == "DS_PROMETHEUS" and .pluginId == "prometheus") and
    ([.templating.list[].name] | contains(["namespace", "tailnet", "kind"]))
  ' "$dashboard" > /dev/null || {
    printf 'Dashboard JSON/description contract failed: %s\n' "$dashboard" >&2
    exit 1
  }
done
