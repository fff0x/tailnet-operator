//go:build chart

package chart

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/yaml"
)

type ruleSpec struct {
	Groups []struct {
		Name  string `json:"name"`
		Rules []struct {
			Alert       string            `json:"alert,omitempty"`
			Record      string            `json:"record,omitempty"`
			Expr        string            `json:"expr"`
			For         string            `json:"for,omitempty"`
			Labels      map[string]string `json:"labels,omitempty"`
			Annotations map[string]string `json:"annotations,omitempty"`
		} `json:"rules"`
	} `json:"groups"`
}

func builtinRules(t *testing.T) ruleSpec {
	t.Helper()
	m := render(t, "monitoring: {rules: {enabled: true}}")
	return decode[struct {
		Spec ruleSpec `json:"spec"`
	}](t, m.one(t, "PrometheusRule")).Spec
}

func TestBundledRules(t *testing.T) {
	spec := builtinRules(t)
	equal(t, "group count", len(spec.Groups), 1)
	rules := spec.Groups[0].Rules
	equal(t, "rule count", len(rules), 15)
	usage, err := os.ReadFile(filepath.Join(chartPath(t), "..", "..", "docs", "USAGE.md"))
	if err != nil {
		t.Fatal(err)
	}
	// Derive Markdown heading anchors, not just matching text or link prefixes.
	anchors := map[string]bool{}
	punctuation := regexp.MustCompile(`[^a-z0-9_ -]`)
	for _, heading := range regexp.MustCompile(`(?m)^#{1,6} +(.+?) *#* *$`).FindAllSubmatch(usage, -1) {
		anchor := punctuation.ReplaceAllString(strings.ToLower(string(heading[1])), "")
		anchors[strings.ReplaceAll(anchor, " ", "-")] = true
	}
	seen := map[string]bool{}
	for _, rule := range rules {
		if seen[rule.Alert] {
			t.Errorf("duplicate alert %s", rule.Alert)
		}
		seen[rule.Alert] = true
		if rule.Expr == "" || rule.Labels["severity"] == "" || rule.Annotations["summary"] == "" || rule.Annotations["description"] == "" || !strings.HasPrefix(rule.Annotations["runbook_url"], "docs/USAGE.md#monitoring-") {
			t.Errorf("incomplete rule: %#v", rule)
		}
		anchor := strings.TrimPrefix(rule.Annotations["runbook_url"], "docs/USAGE.md#")
		if !anchors[anchor] {
			t.Errorf("%s runbook has no Markdown heading anchor in docs/USAGE.md: %s", rule.Alert, anchor)
		}
		if strings.Contains(rule.Expr, "applied_timestamp") {
			t.Error("old applied timestamp does not imply stale policy")
		}
		if rule.Alert == "TailnetReconcileErrors" {
			if !strings.HasSuffix(rule.Expr, ")) > 0.1") {
				t.Errorf("reconcile threshold must be >0.1/s: %s", rule.Expr)
			}
			equal(t, "reconcile duration", rule.For, "10m")
		}
		if rule.Alert == "TailnetNodeOffline" {
			equal(t, "offline predicate", rule.Expr, "min by (kind, namespace, name) (tailnet_node_online) == 0")
			equal(t, "offline duration", rule.For, "5m")
		}
		if rule.Alert == "TailnetPolicyStale" {
			equal(t, "pending predicate", rule.Expr, "max by (tailnet) (tailnet_policy_pending) == 1")
			equal(t, "pending duration", rule.For, "15m")
		}
	}
	for _, name := range []string{"TailnetOperatorDown", "TailnetReconcileErrors", "TailnetHeadscaleAPIErrors", "TailnetResourceNotReady", "TailnetPolicyStale", "TailnetPolicyRejected", "TailnetPolicyApplyErrors", "TailnetPolicyGeneratedDrop", "TailnetApprovalReplays", "TailnetRouteConflict", "TailnetUnmanagedRouteOverlap", "TailnetNodeOffline", "TailnetAPIKeyExpiringSoon", "TailnetEgressAuthKeyExpiringSoon", "TailnetIngressAuthKeyExpiringSoon"} {
		if !seen[name] {
			t.Errorf("missing alert %s", name)
		}
	}
	// Availability and runtime metrics must select the actual metrics Service, including overrides.
	overridden := render(t, "fullnameOverride: custom\nnamespace: metrics-system\nmonitoring: {rules: {enabled: true}}")
	rendered := decode[struct {
		Spec ruleSpec `json:"spec"`
	}](t, overridden.one(t, "PrometheusRule")).Spec
	service := overridden.one(t, "Service")
	for _, rule := range rendered.Groups[0].Rules {
		if rule.Alert == "TailnetOperatorDown" || rule.Alert == "TailnetReconcileErrors" {
			if !strings.Contains(rule.Expr, `service="`+service.Metadata.Name+`"`) || !strings.Contains(rule.Expr, `namespace="`+service.Metadata.Namespace+`"`) {
				t.Errorf("%s does not select actual Service %s/%s: %s", rule.Alert, service.Metadata.Namespace, service.Metadata.Name, rule.Expr)
			}
		}
	}
	m := render(t, `monitoring:
  rules:
    enabled: true
    apiKeyExpiryWarningSeconds: 123
    authKeyExpiryWarningSeconds: 456
    groups:
      - name: custom-only
        rules:
          - alert: Custom
            expr: vector(1)
            annotations:
              summary: '{{ $labels.name }} {{ untouched }}'
`)
	custom := decode[struct {
		Spec ruleSpec `json:"spec"`
	}](t, m.one(t, "PrometheusRule")).Spec
	equal(t, "custom group count", len(custom.Groups), 1)
	equal(t, "custom rule count", len(custom.Groups[0].Rules), 1)
	equal(t, "literal custom annotation", custom.Groups[0].Rules[0].Annotations["summary"], "{{ $labels.name }} {{ untouched }}")
	equal(t, "custom expression unchanged", custom.Groups[0].Rules[0].Expr, "vector(1)")
}

func TestMonitoringExpiryThresholds(t *testing.T) {
	for _, tc := range []struct {
		name, values string
		api, auth    int
	}{
		{"defaults", "", 604800, 86400},
		{"custom", "    apiKeyExpiryWarningSeconds: 123\n    authKeyExpiryWarningSeconds: 456\n", 123, 456},
	} {
		t.Run(tc.name, func(t *testing.T) {
			m := render(t, "monitoring:\n  rules:\n    enabled: true\n"+tc.values)
			spec := decode[struct {
				Spec ruleSpec `json:"spec"`
			}](t, m.one(t, "PrometheusRule")).Spec
			want := map[string]string{
				"TailnetAPIKeyExpiringSoon":         fmt.Sprintf("tailnet_apikey_expires_seconds < %d", tc.api),
				"TailnetEgressAuthKeyExpiringSoon":  fmt.Sprintf("tailnetegress_authkey_expires_seconds < %d", tc.auth),
				"TailnetIngressAuthKeyExpiringSoon": fmt.Sprintf("tailnetingress_authkey_expires_seconds < %d", tc.auth),
			}
			for _, rule := range spec.Groups[0].Rules {
				if expr, ok := want[rule.Alert]; ok {
					equal(t, rule.Alert+" threshold", rule.Expr, expr)
					equal(t, rule.Alert+" duration", rule.For, "5m")
					threshold := strings.Split(expr, " < ")[1]
					if !strings.Contains(rule.Annotations["description"], "Less than "+threshold+" seconds remain.") {
						t.Errorf("%s description does not reflect threshold", rule.Alert)
					}
					delete(want, rule.Alert)
				}
			}
			if len(want) != 0 {
				t.Errorf("missing expiry alerts: %v", want)
			}
		})
	}
	for _, key := range []string{"apiKeyExpiryWarningSeconds", "authKeyExpiryWarningSeconds"} {
		for _, value := range []string{"0", "-1", "0.5", "\"3600\"", "null"} {
			t.Run(key+"="+value, func(t *testing.T) {
				_, err := helmTemplate(t, "monitoring:\n  rules:\n    "+key+": "+value+"\n")
				if err == nil || !strings.Contains(err.Error(), key) {
					t.Fatalf("expected schema rejection for %s=%s, got %v", key, value, err)
				}
			})
		}
	}
	for _, obj := range render(t, "") {
		switch obj.Kind {
		case "PrometheusRule", "ServiceMonitor", "PodMonitor", "GrafanaDashboard":
			t.Errorf("monitoring must remain disabled by default: %s", obj.Kind)
		}
	}
}

func TestBundledDashboard(t *testing.T) {
	bundled, err := os.ReadFile(filepath.Join(chartPath(t), "files", "dashboard.json"))
	if err != nil {
		t.Fatal(err)
	}
	for _, kind := range []string{"GrafanaDashboard", "ConfigMap"} {
		t.Run(kind, func(t *testing.T) {
			m := render(t, "monitoring: {dashboard: {enabled: true, kind: "+kind+"}}")
			obj := m.one(t, kind)
			var data string
			if kind == "ConfigMap" {
				cm := decode[corev1.ConfigMap](t, obj)
				data = cm.Data["tailnet-operator.json"]
				equal(t, "sidecar label", cm.Labels["grafana_dashboard"], "1")
			} else {
				gd := decode[struct {
					Spec struct {
						JSON             string               `json:"json"`
						Folder           string               `json:"folder"`
						Allow            bool                 `json:"allowCrossNamespaceImport"`
						InstanceSelector metav1.LabelSelector `json:"instanceSelector"`
						Datasources      []struct {
							InputName      string `json:"inputName"`
							DatasourceName string `json:"datasourceName"`
						} `json:"datasources"`
					} `json:"spec"`
				}](t, obj)
				data = gd.Spec.JSON
				equal(t, "Grafana API", obj.APIVersion, "grafana.integreatly.org/v1beta1")
				equal(t, "folder", gd.Spec.Folder, "Tailnet")
				equal(t, "cross namespace", gd.Spec.Allow, true)
				equal(t, "Grafana instance", gd.Spec.InstanceSelector.MatchLabels, map[string]string{"grafana.internal/instance": "grafana"})
				if len(gd.Spec.Datasources) != 1 || gd.Spec.Datasources[0].InputName != "DS_PROMETHEUS" || gd.Spec.Datasources[0].DatasourceName != "Prometheus" {
					t.Errorf("datasources: %#v", gd.Spec.Datasources)
				}
			}
			equal(t, "bundled JSON unchanged", data, string(bundled))
			if !json.Valid([]byte(data)) {
				t.Fatal("invalid dashboard JSON")
			}
		})
	}
	m := render(t, `namespace: grafana-system
monitoring:
  dashboard:
    enabled: true
    json: '{"title":"{{ literal }}","panels":[]}'
    folder: Custom
    allowCrossNamespaceImport: false
    instanceSelector: {matchLabels: {team: ops}}
    datasourceName: Site Prometheus
`)
	gd := decode[struct {
		Spec map[string]interface{} `json:"spec"`
	}](t, m.one(t, "GrafanaDashboard"))
	equal(t, "custom JSON unchanged", gd.Spec["json"], interface{}(`{"title":"{{ literal }}","panels":[]}`))
	equal(t, "custom folder", gd.Spec["folder"], interface{}("Custom"))
	equal(t, "custom cross namespace", gd.Spec["allowCrossNamespaceImport"], interface{}(false))
	if !strings.Contains(string(m.one(t, "GrafanaDashboard").data), "Site Prometheus") {
		t.Error("datasource override missing")
	}
}

func TestAgentPodMonitor(t *testing.T) {
	m := render(t, `monitoring:
  podMonitor:
    enabled: true
    labels: {prometheus: site}
    namespaceSelector: {any: false, matchNames: [agents, tenant]}
    interval: 45s
`)
	obj := m.one(t, "PodMonitor")
	pm := decode[struct {
		Spec struct {
			Selector          metav1.LabelSelector `json:"selector"`
			NamespaceSelector struct {
				Any        bool     `json:"any"`
				MatchNames []string `json:"matchNames"`
			} `json:"namespaceSelector"`
			Endpoints []struct {
				Port     string `json:"port"`
				Path     string `json:"path"`
				Interval string `json:"interval"`
			} `json:"podMetricsEndpoints"`
		} `json:"spec"`
	}](t, obj)
	equal(t, "API", obj.APIVersion, "monitoring.coreos.com/v1")
	equal(t, "namespace", obj.Metadata.Namespace, releaseNamespace)
	equal(t, "selector label", obj.Metadata.Labels["prometheus"], "site")
	equal(t, "namespace any", pm.Spec.NamespaceSelector.Any, false)
	equal(t, "namespaces", pm.Spec.NamespaceSelector.MatchNames, []string{"agents", "tenant"})
	for _, name := range []string{"tailnet-egress", "tailnet-ingress", "tailnet-gateway"} {
		if !matches(t, pm.Spec.Selector, map[string]string{"app.kubernetes.io/name": name}) {
			t.Errorf("does not select %s", name)
		}
	}
	for _, name := range []string{"tailnet-operator", "unrelated"} {
		if matches(t, pm.Spec.Selector, map[string]string{"app.kubernetes.io/name": name}) {
			t.Errorf("unexpectedly selects %s", name)
		}
	}
	wantPorts := []string{"health", "kernel-health", "metrics-dns"}
	if len(pm.Spec.Endpoints) != len(wantPorts) {
		t.Fatalf("endpoints: %#v", pm.Spec.Endpoints)
	}
	for i, want := range wantPorts {
		if pm.Spec.Endpoints[i].Port != want || pm.Spec.Endpoints[i].Path != "/metrics" || pm.Spec.Endpoints[i].Interval != "45s" {
			t.Errorf("endpoint[%d]: %#v", i, pm.Spec.Endpoints[i])
		}
	}
	for _, obj := range m {
		if obj.Kind == "NetworkPolicy" || obj.Kind == "ServiceMonitor" || obj.Kind == "PrometheusRule" || obj.Kind == "GrafanaDashboard" {
			t.Errorf("PodMonitor must not enable %s", obj.Kind)
		}
	}
	values := "networkPolicy: {enabled: true, kubeAPICIDRs: [10.96.0.1/32], headscaleCIDRs: [192.0.2.1/32]}\n"
	before := render(t, values).one(t, "NetworkPolicy")
	after := render(t, values+"monitoring: {podMonitor: {enabled: true}}").one(t, "NetworkPolicy")
	equal(t, "PodMonitor must not broaden operator policy", string(after.data), string(before.data))
	serviceMonitor := render(t, "monitoring: {serviceMonitor: {enabled: true}}").one(t, "ServiceMonitor")
	if !strings.Contains(string(serviceMonitor.data), "honorLabels: true") {
		t.Error("CR namespace labels must be preserved")
	}
}

func TestDashboardLint(t *testing.T) {
	path := filepath.Join(chartPath(t), "files", "dashboard.json")
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var dashboard map[string]interface{}
	if err := json.Unmarshal(data, &dashboard); err != nil {
		t.Fatal(err)
	}
	rows := dashboard["panels"].([]interface{})
	equal(t, "dashboard row count", len(rows), 8)
	queries := map[string]bool{}
	gatewayPlaceholder := false
	for _, row := range rows {
		r := row.(map[string]interface{})
		equal(t, "top-level panel type", r["type"], interface{}("row"))
		for _, nested := range r["panels"].([]interface{}) {
			p := nested.(map[string]interface{})
			if p["type"] == "text" && p["title"] == "Gateway / TLS telemetry — planned" {
				gatewayPlaceholder = true
			}
			if targets, ok := p["targets"].([]interface{}); ok {
				for _, target := range targets {
					expr := target.(map[string]interface{})["expr"].(string)
					queries[expr] = true
				}
			}
		}
	}
	for _, expr := range []string{
		`min by (kind, namespace, name) (tailnet_node_online{namespace=~"$namespace",kind=~"$kind"})`,
		`time() - min by (kind, namespace, name) (tailnet_node_last_seen_seconds{namespace=~"$namespace",kind=~"$kind"})`,
		`sum by (reason) (tailnet_resource_condition{namespace=~"$namespace",kind=~"$kind",type="Ready"} == 1)`,
		`sum by (namespace, name) (tailnet_egress_target_state{namespace=~"$namespace",reason="NotApproved"} == 1)`,
		`sum by (name, reason) (tailnet_resource_condition{kind="TailnetSite",type="RouteConflict",reason!="None"} == 1)`,
	} {
		if !queries[expr] {
			t.Errorf("missing dashboard query: %s", expr)
		}
	}
	if !gatewayPlaceholder {
		t.Error("gateway/TLS telemetry must remain an explicit placeholder")
	}
	lint, err := filepath.Abs(filepath.Join("..", "..", "hack", "dashboard-lint.sh"))
	if err != nil {
		t.Fatal(err)
	}
	if out, err := exec.Command("bash", lint, path).CombinedOutput(); err != nil {
		t.Fatalf("lint: %v: %s", err, out)
	}
	for _, location := range []string{"row", "nested"} {
		t.Run(location, func(t *testing.T) {
			if err := json.Unmarshal(data, &dashboard); err != nil {
				t.Fatal(err)
			}
			panel := dashboard["panels"].([]interface{})[0].(map[string]interface{})
			if location == "nested" {
				panel = panel["panels"].([]interface{})[0].(map[string]interface{})
			}
			delete(panel, "description")
			bad, err := json.Marshal(dashboard)
			if err != nil {
				t.Fatal(err)
			}
			path := filepath.Join(t.TempDir(), "invalid.json")
			if err := os.WriteFile(path, bad, 0600); err != nil {
				t.Fatal(err)
			}
			if out, err := exec.Command("bash", lint, path).CombinedOutput(); err == nil {
				t.Fatalf("lint accepted missing %s description: %s", location, out)
			}
		})
	}
}

// This invokes the real Prometheus parser/evaluator, not a string-based substitute.
// The portable broker gate needs only jq/Helm/kubeconform; run this local test with promtool on PATH.
func TestPromtoolMonitoring(t *testing.T) {
	promtool, err := exec.LookPath("promtool")
	if err != nil {
		t.Skip("promtool not installed; run with nix-shell -p prometheus.cli --run 'go test -tags=chart ./test/chart -run TestPromtoolMonitoring -v'")
	}
	dir := t.TempDir()
	spec := builtinRules(t)
	data, err := yaml.Marshal(spec)
	if err != nil {
		t.Fatal(err)
	}
	rulesPath := filepath.Join(dir, "rules.yaml")
	if err := os.WriteFile(rulesPath, data, 0600); err != nil {
		t.Fatal(err)
	}
	if out, err := exec.Command(promtool, "check", "rules", rulesPath).CombinedOutput(); err != nil {
		t.Fatalf("promtool check rules: %v\n%s", err, out)
	}
	fixture, err := os.ReadFile("rules.test.yaml")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "rules.test.yaml"), fixture, 0600); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(promtool, "test", "rules", "rules.test.yaml")
	cmd.Dir = dir
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("promtool test rules: %v\n%s", err, out)
	}

	// Check every dashboard expression with the real PromQL parser after expanding Grafana variables.
	dashboard, err := os.ReadFile(filepath.Join(chartPath(t), "files", "dashboard.json"))
	if err != nil {
		t.Fatal(err)
	}
	type target struct {
		Expr string `json:"expr"`
	}
	type panel struct {
		Targets []target `json:"targets"`
		Panels  []struct {
			Targets []target `json:"targets"`
		} `json:"panels"`
	}
	var parsed struct {
		Panels []panel `json:"panels"`
	}
	if err := json.Unmarshal(dashboard, &parsed); err != nil {
		t.Fatal(err)
	}
	replacer := strings.NewReplacer("$__rate_interval", "5m", "$namespace", ".*", "$tailnet", ".*", "$kind", ".*")
	var records []map[string]string
	for _, row := range parsed.Panels {
		for _, p := range row.Panels {
			for _, target := range p.Targets {
				records = append(records, map[string]string{"record": "dashboard:check", "expr": replacer.Replace(target.Expr)})
			}
		}
	}
	if len(records) == 0 {
		t.Fatal("no dashboard queries checked")
	}
	data, err = yaml.Marshal(map[string]interface{}{"groups": []interface{}{map[string]interface{}{"name": "dashboard-parser-check", "rules": records}}})
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "dashboard-rules.yaml")
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}
	if out, err := exec.Command(promtool, "check", "rules", path).CombinedOutput(); err != nil {
		t.Fatalf("dashboard PromQL parser: %v\n%s", err, out)
	}
}
