#!/usr/bin/env bash
# Portable CI checks; the broker supplies Helm and kubeconform, not Go or Task.
set -euo pipefail
cd "$(dirname "$0")/.."
chart=charts/tailnet-operator
bash hack/dashboard-lint.sh
helm lint --strict "$chart"
for version in 1.31.0 1.36.0; do
  helm template tailnet-operator "$chart" --namespace tailnet-system --kube-version "$version" |
    kubeconform -kubernetes-version "$version" -strict -ignore-missing-schemas -summary
  helm template tailnet-operator "$chart" --namespace chart-test --kube-version "$version" -f "$chart/ci/full-values.yaml" |
    kubeconform -kubernetes-version "$version" -strict -ignore-missing-schemas -summary
  helm template tailnet-operator "$chart" --namespace chart-test --kube-version "$version" \
    --set monitoring.serviceMonitor.enabled=true --set monitoring.podMonitor.enabled=true \
    --set monitoring.rules.enabled=true --set monitoring.dashboard.enabled=true |
    kubeconform -kubernetes-version "$version" -strict -ignore-missing-schemas -summary
done
# Missing Prometheus/Grafana schemas are deliberately skipped; contract tests inspect these templates.
# This gate does not prove CRD admission, live scraping or Grafana import.
for source in deploy/crds/*.yaml; do
  cmp "$source" "$chart/crds/${source##*/}"
done
# Ensure neither copy contains a stale or additional CRD.
test "$(find deploy/crds -name '*.yaml' | wc -l)" = "$(find "$chart/crds" -name '*.yaml' | wc -l)"
bash hack/deploy-gen.sh --check
