//go:build chart

// Package chart tests local Helm rendering only. It never connects to a cluster.
package chart

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	policyv1 "k8s.io/api/policy/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/util/intstr"
	"k8s.io/apimachinery/pkg/util/validation"
	utilyaml "k8s.io/apimachinery/pkg/util/yaml"
	"sigs.k8s.io/yaml"
)

const releaseNamespace = "release-system"

type manifest struct {
	metav1.TypeMeta `json:",inline"`
	Metadata        metav1.ObjectMeta `json:"metadata"`
	data            []byte
}

type manifests []manifest

func chartPath(t *testing.T) string {
	t.Helper()
	path, err := filepath.Abs(filepath.Join("..", "..", "charts", "tailnet-operator"))
	if err != nil {
		t.Fatal(err)
	}
	return path
}

func helmTemplate(t *testing.T, values string, releaseNames ...string) ([]byte, error) {
	t.Helper()
	return helmTemplateWithValidation(t, values, false, releaseNames...)
}

func helmTemplateWithValidation(t *testing.T, values string, skipSchema bool, releaseNames ...string) ([]byte, error) {
	t.Helper()
	helm, err := exec.LookPath("helm")
	if err != nil {
		t.Fatal("chart tests require helm on PATH; install Helm before running go test -tags=chart ./test/chart")
	}
	dir := t.TempDir()
	valuesPath := filepath.Join(dir, "values.yaml")
	if err := os.WriteFile(valuesPath, []byte(values), 0600); err != nil {
		t.Fatal(err)
	}
	// No --validate, --dry-run=server or other flags that contact Kubernetes.
	// An empty kubeconfig also prevents accidentally using the developer's context.
	kubeconfig := filepath.Join(dir, "kubeconfig")
	if err := os.WriteFile(kubeconfig, []byte("apiVersion: v1\nkind: Config\nclusters: []\ncontexts: []\nusers: []\n"), 0600); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	release := "chart-test"
	if len(releaseNames) > 0 {
		release = releaseNames[0]
	}
	args := []string{"template", release, chartPath(t),
		"--namespace", releaseNamespace, "--kube-version", "1.31.0", "--values", valuesPath}
	if skipSchema {
		args = append(args, "--skip-schema-validation")
	}
	cmd := exec.CommandContext(ctx, helm, args...)
	cmd.Env = append(os.Environ(), "KUBECONFIG="+kubeconfig,
		"HELM_CACHE_HOME="+filepath.Join(dir, "cache"),
		"HELM_CONFIG_HOME="+filepath.Join(dir, "config"),
		"HELM_DATA_HOME="+filepath.Join(dir, "data"))
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	if ctx.Err() != nil {
		t.Fatalf("helm template timed out: %v\n%s", ctx.Err(), stderr.String())
	}
	if err != nil {
		return out, fmt.Errorf("helm template: %w\n%s", err, stderr.String())
	}
	return out, nil
}

func render(t *testing.T, values string, releaseNames ...string) manifests {
	t.Helper()
	out, err := helmTemplate(t, values, releaseNames...)
	if err != nil {
		t.Fatal(err)
	}
	reader := utilyaml.NewYAMLReader(bufio.NewReader(bytes.NewReader(out)))
	var result manifests
	for {
		doc, err := reader.Read()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatalf("read rendered YAML: %v", err)
		}
		jsonDoc, err := yaml.YAMLToJSONStrict(doc)
		if err != nil {
			t.Fatalf("parse rendered YAML: %v\n%s", err, doc)
		}
		var obj manifest
		if err := json.Unmarshal(jsonDoc, &obj); err != nil {
			t.Fatalf("decode rendered resource metadata: %v\n%s", err, doc)
		}
		if obj.Kind == "" {
			if len(bytes.TrimSpace(doc)) != 0 {
				t.Fatalf("rendered document has no kind:\n%s", doc)
			}
			continue
		}
		if obj.APIVersion == "" || obj.Metadata.Name == "" {
			t.Fatalf("rendered resource lacks apiVersion/name:\n%s", doc)
		}
		if obj.Kind == "Service" {
			if problems := validation.IsDNS1035Label(obj.Metadata.Name); len(problems) > 0 {
				t.Fatalf("Service name is invalid on Kubernetes 1.31: %v", problems)
			}
		}
		obj.data = doc
		result = append(result, obj)
	}
	return result
}

func (m manifests) one(t *testing.T, kind string) manifest {
	t.Helper()
	var matches []manifest
	for _, obj := range m {
		if obj.Kind == kind {
			matches = append(matches, obj)
		}
	}
	if len(matches) != 1 {
		t.Fatalf("want exactly one %s, got %d", kind, len(matches))
	}
	return matches[0]
}

func (m manifests) named(t *testing.T, kind, name string) manifest {
	t.Helper()
	var matches manifests
	for _, obj := range m {
		if obj.Kind == kind && obj.Metadata.Name == name {
			matches = append(matches, obj)
		}
	}
	return matches.one(t, kind)
}

func decode[T any](t *testing.T, obj manifest) T {
	t.Helper()
	var result T
	if err := yaml.Unmarshal(obj.data, &result); err != nil {
		t.Fatalf("decode %s/%s: %v", obj.Kind, obj.Metadata.Name, err)
	}
	return result
}

func operator(t *testing.T, m manifests) (appsv1.Deployment, corev1.Container) {
	t.Helper()
	dep := decode[appsv1.Deployment](t, m.one(t, "Deployment"))
	if len(dep.Spec.Template.Spec.Containers) != 1 {
		t.Fatalf("want one operator container, got %d", len(dep.Spec.Template.Spec.Containers))
	}
	return dep, dep.Spec.Template.Spec.Containers[0]
}

func envVar(t *testing.T, c corev1.Container, name string) corev1.EnvVar {
	t.Helper()
	var found []corev1.EnvVar
	for _, env := range c.Env {
		if env.Name == name {
			found = append(found, env)
		}
	}
	if len(found) != 1 {
		t.Fatalf("want exactly one %s variable, got %d", name, len(found))
	}
	return found[0]
}

func equal[T any](t *testing.T, what string, got, want T) {
	t.Helper()
	if !reflect.DeepEqual(got, want) {
		t.Errorf("%s: got %#v, want %#v", what, got, want)
	}
}

func matches(t *testing.T, selector metav1.LabelSelector, podLabels map[string]string) bool {
	t.Helper()
	s, err := metav1.LabelSelectorAsSelector(&selector)
	if err != nil {
		t.Fatalf("invalid selector: %v", err)
	}
	return s.Matches(labels.Set(podLabels))
}

func TestNativeCICapabilityGate(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("..", "..", ".radicle", "native.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	var spec struct {
		Shell string `json:"shell"`
	}
	if err := yaml.Unmarshal(data, &spec); err != nil {
		t.Fatal(err)
	}
	gate, _, found := strings.Cut(spec.Shell, "\nbash hack/chart-check.sh")
	if !found {
		t.Fatal("capability gate must precede chart checks and publication")
	}
	for _, tc := range []struct {
		name, marker string
		supported    bool
	}{
		{"neither", "", false},
		{"charts only", "# ci-build-capability: mixed-helm-v1\n", false},
		{"result only", "# ci-build-capability: image-result-v1\n", false},
		{"both", "# ci-build-capability: mixed-helm-v1\n# ci-build-capability: image-result-v1\n", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			marker := tc.marker
			invoked := filepath.Join(dir, "invoked")
			stub := "#!/bin/sh\n" + marker + "touch '" + invoked + "'\nexit 99\n"
			if err := os.WriteFile(filepath.Join(dir, "ci-build"), []byte(stub), 0700); err != nil {
				t.Fatal(err)
			}
			cmd := exec.Command("bash", "-c", gate)
			cmd.Env = []string{"PATH=" + dir + ":" + os.Getenv("PATH"), "HOME=" + dir, "TMPDIR=" + dir}
			out, err := cmd.CombinedOutput()
			if (err == nil) != tc.supported {
				t.Fatalf("supported=%v, gate error=%v: %s", tc.supported, err, out)
			}
			if _, err := os.Stat(invoked); !os.IsNotExist(err) {
				t.Fatalf("capability detection executed the publisher: %v", err)
			}
		})
	}
}

func TestDefaultRender(t *testing.T) {
	m := render(t, "")
	for _, kind := range []string{"Deployment", "ServiceAccount", "Role", "RoleBinding", "Service"} {
		m.one(t, kind)
	}
	for _, kind := range []string{"ClusterRole", "ClusterRoleBinding"} {
		count := 0
		for _, obj := range m {
			if obj.Kind == kind {
				count++
			}
		}
		equal(t, kind+" count", count, 2)
		for _, suffix := range []string{"-crds", "-workloads"} {
			m.named(t, kind, "tailnet-operator"+suffix)
		}
	}
	for _, obj := range m {
		if obj.Kind == "Namespace" || obj.Kind == "PodDisruptionBudget" || obj.Kind == "NetworkPolicy" || obj.Kind == "CiliumNetworkPolicy" || obj.Kind == "ConfigMap" || obj.Kind == "GrafanaDashboard" || strings.HasPrefix(obj.APIVersion, "monitoring.coreos.com/") {
			t.Errorf("default chart unexpectedly renders %s/%s", obj.Kind, obj.Metadata.Name)
		}
	}
	dep, c := operator(t, m)
	equal(t, "deployment namespace", dep.Namespace, releaseNamespace)
	equal(t, "default election flag", c.Args, []string{"--leader-elect=true"})
	equal(t, "adoption-compatible selector", dep.Spec.Selector, &metav1.LabelSelector{MatchLabels: map[string]string{"app.kubernetes.io/name": "tailnet-operator"}})
	if len(dep.Spec.Template.Spec.TopologySpreadConstraints) != 0 {
		t.Error("topology spread must be opt-in")
	}
	sa := m.one(t, "ServiceAccount")
	equal(t, "pod service account", dep.Spec.Template.Spec.ServiceAccountName, sa.Metadata.Name)
	equal(t, "service account namespace", sa.Metadata.Namespace, releaseNamespace)
	svc := decode[corev1.Service](t, m.one(t, "Service"))
	if !labels.SelectorFromSet(svc.Spec.Selector).Matches(labels.Set(dep.Spec.Template.Labels)) || len(svc.Spec.Selector) == 0 {
		t.Error("metrics Service does not select the operator pod")
	}
	if len(svc.Spec.Ports) != 1 || svc.Spec.Ports[0].Name != "metrics" || svc.Spec.Ports[0].Port != 8080 || svc.Spec.Ports[0].TargetPort.String() != "metrics" {
		t.Errorf("unexpected metrics Service ports: %#v", svc.Spec.Ports)
	}
	ns := envVar(t, c, "POD_NAMESPACE")
	if ns.ValueFrom == nil || ns.ValueFrom.FieldRef == nil || ns.ValueFrom.FieldRef.FieldPath != "metadata.namespace" {
		t.Errorf("POD_NAMESPACE must use the downward API: %#v", ns)
	}
	equal(t, "scratch CA bundle", envVar(t, c, "SSL_CERT_FILE").Value, "/ca-certificates.crt")
	equal(t, "default inherited agent image", envVar(t, c, "OPERATOR_IMAGE").Value, c.Image)
	equal(t, "default agent pull secrets", envVar(t, c, "AGENT_IMAGE_PULL_SECRETS").Value, "[]")
	equal(t, "default agent resources", envVar(t, c, "AGENT_RESOURCES").Value, `{"limits":{"memory":"128Mi"},"requests":{"cpu":"10m","memory":"32Mi"}}`)
	equal(t, "default scrape peers", envVar(t, c, "AGENT_SCRAPE_PEERS").Value, "[]")
	// Go's soft memory limit tracks the container limit through the Downward API.
	equal(t, "GOMEMLIMIT source", envVar(t, c, "GOMEMLIMIT").ValueFrom, &corev1.EnvVarSource{ResourceFieldRef: &corev1.ResourceFieldSelector{ContainerName: "operator", Resource: "limits.memory"}})
	equal(t, "default operator memory limit", c.Resources.Limits.Memory().String(), "192Mi")
	_, c = operator(t, render(t, "monitoring: {podMonitor: {scrapeFrom: [{podSelector: {matchLabels: {app: prometheus}}}]}}"))
	equal(t, "scrape peers", envVar(t, c, "AGENT_SCRAPE_PEERS").Value, `[{"podSelector":{"matchLabels":{"app":"prometheus"}}}]`)
}

// Pin the reviewed permission set, not merely a list of expected grants. This
// rejects both widening and accidental narrowing, even if rules are regrouped.
func TestRBACPrivilegesExact(t *testing.T) {
	read := "get list watch"
	status := "get update patch"
	write := "get list watch create update patch delete"
	type grant struct{ group, resources, verbs string }
	workloads := []grant{
		{"", "secrets configmaps", write},
		{"", "pods", read},
		{"apps", "deployments", write},
		{"networking.k8s.io", "networkpolicies", write},
		{"", "events", "create patch"},
	}
	for _, election := range []bool{true, false} {
		t.Run(fmt.Sprintf("election=%t", election), func(t *testing.T) {
			m := render(t, fmt.Sprintf("leaderElection: {enabled: %t}", election))
			local := append([]grant{}, workloads...)
			local = append(local, grant{"", "services", write},
				// Fresh gateway children: create-only plus UID-preconditioned delete for
				// deletionPolicy=Delete teardown; StatefulSets also update (spec.template follows
				// the spec). Never list/watch/escalate/bind.
				grant{"", "serviceaccounts", "get create delete"},
				grant{"apps", "statefulsets", "get create update delete"},
				grant{"policy", "poddisruptionbudgets", "get create delete"},
				grant{"rbac.authorization.k8s.io", "roles rolebindings", "get create delete"},
				// patch only carries the authkey finalizer that expires the pre-auth key on delete.
				grant{"tsunaro.io", "tailnetegresses", read + " patch"},
				grant{"tsunaro.io", "tailnetegresses/status", status},
				grant{"tsunaro.io", "tailnetegresses/finalizers", "update"})
			if election {
				local = append(local, grant{"coordination.k8s.io", "leases", "get list watch create update patch"})
			}
			expected := map[string][]grant{
				"ClusterRole/tailnet-operator-crds": {
					{"tsunaro.io", "tailnets tailnetsites", read},
					// patch only carries a finalizer (gateway teardown, ingress authkey expiry);
					// spec is CEL-guarded.
					{"tsunaro.io", "tailnetgateways tailnetingresses", read + " patch"},
					{"tsunaro.io", "tailnets/status tailnetingresses/status tailnetgateways/status tailnetsites/status", status},
					{"tsunaro.io", "tailnets/finalizers tailnetingresses/finalizers", "update"},
				},
				"ClusterRole/tailnet-operator-workloads": append(append([]grant{}, workloads...),
					grant{"cert-manager.io", "certificates", "get create patch delete"}),
				"Role/tailnet-operator": local,
			}
			roles, bindings := map[string]bool{}, map[string]bool{}
			for _, obj := range m {
				switch obj.Kind {
				case "Role", "ClusterRole":
					role := decode[rbacv1.ClusterRole](t, obj)
					key := obj.Kind + "/" + role.Name
					grants, ok := expected[key]
					if !ok || roles[key] {
						t.Fatalf("unexpected or duplicate role %s", key)
					}
					roles[key] = true
					wantNamespace := ""
					if obj.Kind == "Role" {
						wantNamespace = releaseNamespace
					}
					equal(t, key+" namespace", role.Namespace, wantNamespace)
					if role.AggregationRule != nil {
						t.Error("default roles must not aggregate external privileges")
					}
					want, got := map[string]bool{}, map[string]bool{}
					for _, g := range grants {
						for _, resource := range strings.Fields(g.resources) {
							for _, verb := range strings.Fields(g.verbs) {
								want[g.group+"/"+resource+"/"+verb] = true
							}
						}
					}
					for _, rule := range role.Rules {
						if len(rule.ResourceNames) != 0 || len(rule.NonResourceURLs) != 0 {
							t.Error("default permissions must remain unrestricted by name and have no non-resource URLs")
						}
						for _, field := range [][]string{rule.APIGroups, rule.Resources, rule.Verbs, rule.ResourceNames, rule.NonResourceURLs} {
							for _, value := range field {
								if strings.Contains(value, "*") {
									t.Errorf("wildcard permission in %s: %q", key, value)
								}
							}
						}
						for _, group := range rule.APIGroups {
							for _, resource := range rule.Resources {
								for _, verb := range rule.Verbs {
									got[group+"/"+resource+"/"+verb] = true
								}
							}
						}
					}
					equal(t, key+" exact privileges", got, want)
				case "RoleBinding", "ClusterRoleBinding":
					binding := decode[rbacv1.RoleBinding](t, obj)
					roleKind := strings.TrimSuffix(obj.Kind, "Binding")
					key := roleKind + "/" + binding.Name
					if _, ok := expected[key]; !ok || bindings[key] {
						t.Fatalf("unexpected or duplicate binding %s", key)
					}
					bindings[key] = true
					wantNamespace := ""
					if obj.Kind == "RoleBinding" {
						wantNamespace = releaseNamespace
					}
					equal(t, key+" binding namespace", binding.Namespace, wantNamespace)
					equal(t, key+" roleRef", binding.RoleRef, rbacv1.RoleRef{APIGroup: rbacv1.GroupName, Kind: roleKind, Name: binding.Name})
					equal(t, key+" subjects", binding.Subjects, []rbacv1.Subject{{Kind: "ServiceAccount", Name: "tailnet-operator", Namespace: releaseNamespace}})
				}
			}
			equal(t, "role count", len(roles), len(expected))
			equal(t, "binding count", len(bindings), len(expected))
		})
	}
}

func TestNamespaceAndFullnameOverrides(t *testing.T) {
	m := render(t, `namespace: operator-system
fullnameOverride: custom-operator
monitoring:
  serviceMonitor: {enabled: true}
  rules:
    enabled: true
    groups: [{name: custom, rules: [{record: operator:up, expr: "up"}]}]
  dashboard:
    enabled: true
    kind: ConfigMap
    json: '{"title":"Operator","panels":[]}'
networkPolicy:
  enabled: true
  kubeAPICIDRs: [10.96.0.1/32]
  headscaleCIDRs: [192.0.2.1/32]
`)
	for _, obj := range m {
		if obj.Kind == "Namespace" {
			t.Error("chart must not create a Namespace")
		}
		if obj.Kind != "ClusterRole" && obj.Kind != "ClusterRoleBinding" && obj.Kind != "CustomResourceDefinition" {
			equal(t, obj.Kind+" namespace", obj.Metadata.Namespace, "operator-system")
		}
		if obj.Kind != "CustomResourceDefinition" && obj.Metadata.Name != "custom-operator" && !strings.HasPrefix(obj.Metadata.Name, "custom-operator-") {
			t.Errorf("fullnameOverride not propagated to %s/%s", obj.Kind, obj.Metadata.Name)
		}
	}
	dep, _ := operator(t, m)
	equal(t, "deployment name", dep.Name, "custom-operator")
	equal(t, "service account name", m.one(t, "ServiceAccount").Metadata.Name, "custom-operator")
	equal(t, "pod service account", dep.Spec.Template.Spec.ServiceAccountName, "custom-operator")
	for _, obj := range m {
		if obj.Kind != "RoleBinding" && obj.Kind != "ClusterRoleBinding" {
			continue
		}
		binding := decode[rbacv1.RoleBinding](t, obj)
		equal(t, obj.Kind+" subjects", binding.Subjects, []rbacv1.Subject{{Kind: "ServiceAccount", Name: "custom-operator", Namespace: "operator-system"}})
		equal(t, obj.Kind+" role name", binding.RoleRef.Name, obj.Metadata.Name)
		roleKind := strings.TrimSuffix(obj.Kind, "Binding")
		equal(t, obj.Kind+" role kind", binding.RoleRef.Kind, roleKind)
		equal(t, obj.Kind+" role reference", m.named(t, roleKind, binding.RoleRef.Name).Metadata.Name, binding.RoleRef.Name)
	}
	svc := decode[corev1.Service](t, m.one(t, "Service"))
	if !labels.SelectorFromSet(svc.Spec.Selector).Matches(labels.Set(dep.Spec.Template.Labels)) {
		t.Error("overridden Service selector does not match operator pod")
	}
}

func TestScalarLookingNames(t *testing.T) {
	m := render(t, "fullnameOverride: 'true'\nnamespace: '123'\nmonitoring: {serviceMonitor: {enabled: true}}", "false")
	dep, _ := operator(t, m)
	equal(t, "boolean deployment name", dep.Name, "true")
	equal(t, "numeric namespace", dep.Namespace, "123")
	equal(t, "boolean release label", dep.Labels["app.kubernetes.io/instance"], "false")
	equal(t, "boolean service account", dep.Spec.Template.Spec.ServiceAccountName, "true")
	for _, tc := range []struct{ kind, name string }{
		{"RoleBinding", "true"}, {"ClusterRoleBinding", "true-crds"}, {"ClusterRoleBinding", "true-workloads"},
	} {
		binding := decode[rbacv1.RoleBinding](t, m.named(t, tc.kind, tc.name))
		equal(t, tc.kind+" roleRef", binding.RoleRef.Name, tc.name)
		equal(t, tc.kind+" subjects", binding.Subjects, []rbacv1.Subject{{Kind: "ServiceAccount", Name: "true", Namespace: "123"}})
	}
}

func TestImageResolution(t *testing.T) {
	chartData, err := os.ReadFile(filepath.Join(chartPath(t), "Chart.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	var metadata struct {
		AppVersion string `json:"appVersion"`
	}
	if err := yaml.Unmarshal(chartData, &metadata); err != nil || metadata.AppVersion == "" {
		t.Fatalf("read chart appVersion: %v", err)
	}
	digest := "sha256:" + strings.Repeat("a", 64)
	agentDigest := "sha256:" + strings.Repeat("b", 64)
	for _, tc := range []struct{ name, image, agent, wantOperator, wantAgent string }{
		{"tag inheritance", "{repository: example.com/operator, tag: custom}", "{}", "example.com/operator:custom", "example.com/operator:custom"},
		{"digest precedence and exact inheritance", "{repository: example.com/operator, tag: ignored, digest: " + digest + "}", "{repository: '', tag: '', digest: ''}", "example.com/operator@" + digest, "example.com/operator@" + digest},
		{"appVersion fallback", "{repository: example.com/operator}", "{}", "example.com/operator:" + metadata.AppVersion, "example.com/operator:" + metadata.AppVersion},
		{"repository only uses appVersion", "{repository: example.com/operator, tag: custom, digest: " + digest + "}", "{repository: example.com/agent}", "example.com/operator@" + digest, "example.com/agent:" + metadata.AppVersion},
		{"tag only inherits repository not digest", "{repository: example.com/operator, digest: " + digest + "}", "{tag: agent-tag}", "example.com/operator@" + digest, "example.com/operator:agent-tag"},
		{"digest only inherits repository", "{repository: example.com/operator, tag: custom}", "{digest: " + agentDigest + "}", "example.com/operator:custom", "example.com/operator@" + agentDigest},
		{"independent repository and tag", "{repository: example.com/operator, tag: custom}", "{repository: example.com/agent, tag: agent-tag}", "example.com/operator:custom", "example.com/agent:agent-tag"},
		{"agent digest wins over tag", "{repository: example.com/operator, digest: " + digest + "}", "{repository: example.com/agent, tag: ignored, digest: " + agentDigest + "}", "example.com/operator@" + digest, "example.com/agent@" + agentDigest},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, c := operator(t, render(t, "image: "+tc.image+"\nagentImage: "+tc.agent+"\n"))
			equal(t, "operator image", c.Image, tc.wantOperator)
			equal(t, "agent image", envVar(t, c, "OPERATOR_IMAGE").Value, tc.wantAgent)
		})
	}
}

func TestPullSecretsAndExtraEnv(t *testing.T) {
	dep, c := operator(t, render(t, `imagePullSecrets: [{name: operator-registry}, {name: mirror.example}]
agent:
  imagePullSecrets: [tenant-registry, tenant-mirror]
env:
  extra:
    - {name: EXTRA_SETTING, value: custom}
    - name: EXTRA_SECRET
      valueFrom:
        secretKeyRef: {name: extra-config, key: value}
`))
	equal(t, "operator pull secrets", dep.Spec.Template.Spec.ImagePullSecrets, []corev1.LocalObjectReference{{Name: "operator-registry"}, {Name: "mirror.example"}})
	v := envVar(t, c, "AGENT_IMAGE_PULL_SECRETS")
	var names []string
	if err := json.Unmarshal([]byte(v.Value), &names); err != nil {
		t.Fatalf("AGENT_IMAGE_PULL_SECRETS must be a JSON string array: %v", err)
	}
	equal(t, "agent pull secrets", names, []string{"tenant-registry", "tenant-mirror"})
	equal(t, "extra env", envVar(t, c, "EXTRA_SETTING").Value, "custom")
	equal(t, "extra env valueFrom", envVar(t, c, "EXTRA_SECRET").ValueFrom, &corev1.EnvVarSource{SecretKeyRef: &corev1.SecretKeySelector{LocalObjectReference: corev1.LocalObjectReference{Name: "extra-config"}, Key: "value"}})
}

// TestHeadscaleCATrust: headscale.caConfigMapRef mounts a PEM bundle and points SSL_CERT_DIR at it,
// which Go merges with the SSL_CERT_FILE roots. Unset, the Deployment carries no volume at all.
func TestHeadscaleCATrust(t *testing.T) {
	dep, c := operator(t, render(t, ""))
	equal(t, "default volumes", len(dep.Spec.Template.Spec.Volumes), 0)
	equal(t, "default mounts", len(c.VolumeMounts), 0)
	for _, env := range c.Env {
		if env.Name == "SSL_CERT_DIR" {
			t.Errorf("SSL_CERT_DIR rendered without a CA ConfigMap")
		}
	}

	dep, c = operator(t, render(t, "headscale: {caConfigMapRef: {name: site-ca, key: bundle.pem}}\n"))
	equal(t, "public roots stay", envVar(t, c, "SSL_CERT_FILE").Value, "/ca-certificates.crt")
	equal(t, "cert dir", envVar(t, c, "SSL_CERT_DIR").Value, "/etc/tailnet-operator/ca")
	equal(t, "mounts", c.VolumeMounts, []corev1.VolumeMount{{Name: "headscale-ca", MountPath: "/etc/tailnet-operator/ca", ReadOnly: true}})
	equal(t, "volumes", dep.Spec.Template.Spec.Volumes, []corev1.Volume{{Name: "headscale-ca", VolumeSource: corev1.VolumeSource{
		ConfigMap: &corev1.ConfigMapVolumeSource{
			LocalObjectReference: corev1.LocalObjectReference{Name: "site-ca"},
			Items:                []corev1.KeyToPath{{Key: "bundle.pem", Path: "ca.crt"}},
		},
	}}})
}

func TestAgentResourceValues(t *testing.T) {
	for _, tc := range []struct{ name, values, want string }{
		{"override", "agent: {resources: {requests: {cpu: 25m, memory: 64Mi}, limits: {memory: 256Mi}}}", `{"limits":{"memory":"256Mi"},"requests":{"cpu":"25m","memory":"64Mi"}}`},
		{"null disables", "agent: {resources: null}", `{}`},
		{"empty object retains Helm defaults", "agent: {resources: {}}", `{"limits":{"memory":"128Mi"},"requests":{"cpu":"10m","memory":"32Mi"}}`},
		{"empty maps retain Helm defaults", "agent: {resources: {requests: {}, limits: {}}}", `{"limits":{"memory":"128Mi"},"requests":{"cpu":"10m","memory":"32Mi"}}`},
		{"partial override retains Helm defaults", "agent: {resources: {requests: {cpu: 25m}}}", `{"limits":{"memory":"128Mi"},"requests":{"cpu":"25m","memory":"32Mi"}}`},
		{"remove limit", "agent: {resources: {limits: null}}", `{"requests":{"cpu":"10m","memory":"32Mi"}}`},
		{"remove request key", "agent: {resources: {requests: {cpu: null}}}", `{"limits":{"memory":"128Mi"},"requests":{"memory":"32Mi"}}`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, c := operator(t, render(t, tc.values))
			value := envVar(t, c, "AGENT_RESOURCES").Value
			equal(t, "agent resources JSON", value, tc.want)
			var resources corev1.ResourceRequirements
			if err := json.Unmarshal([]byte(value), &resources); err != nil {
				t.Fatalf("AGENT_RESOURCES must decode as ResourceRequirements: %v", err)
			}
		})
	}
}

func TestHardenedSingletonDefaults(t *testing.T) {
	dep, c := operator(t, render(t, ""))
	if dep.Spec.Replicas == nil || *dep.Spec.Replicas != 1 {
		t.Errorf("operator must have exactly one replica: %v", dep.Spec.Replicas)
	}
	equal(t, "deployment strategy", dep.Spec.Strategy.Type, appsv1.RollingUpdateDeploymentStrategyType)
	if dep.Spec.Template.Spec.TerminationGracePeriodSeconds == nil || *dep.Spec.Template.Spec.TerminationGracePeriodSeconds <= 20 {
		t.Error("pod termination grace must exceed the manager's 20-second drain budget")
	}
	pod := dep.Spec.Template.Spec
	if pod.SecurityContext == nil {
		t.Fatal("pod securityContext is missing")
	}
	psc := pod.SecurityContext
	if psc.RunAsNonRoot == nil || !*psc.RunAsNonRoot || psc.RunAsUser == nil || *psc.RunAsUser <= 0 || psc.RunAsGroup == nil || *psc.RunAsGroup <= 0 {
		t.Errorf("pod must run as an explicit non-root UID/GID: %#v", psc)
	}
	if psc.SeccompProfile == nil || psc.SeccompProfile.Type != corev1.SeccompProfileTypeRuntimeDefault {
		t.Errorf("pod must use RuntimeDefault seccomp: %#v", psc.SeccompProfile)
	}
	if pod.HostNetwork || pod.HostPID || pod.HostIPC {
		t.Error("operator must not share host namespaces")
	}
	sc := c.SecurityContext
	if sc == nil {
		t.Fatal("container securityContext is missing")
	}
	if sc.AllowPrivilegeEscalation == nil || *sc.AllowPrivilegeEscalation || sc.ReadOnlyRootFilesystem == nil || !*sc.ReadOnlyRootFilesystem || (sc.Privileged != nil && *sc.Privileged) {
		t.Errorf("container must disable privilege escalation and use a read-only root filesystem: %#v", sc)
	}
	if sc.Capabilities == nil || !reflect.DeepEqual(sc.Capabilities.Drop, []corev1.Capability{"ALL"}) || len(sc.Capabilities.Add) != 0 {
		t.Errorf("container must drop ALL capabilities and add none: %#v", sc.Capabilities)
	}
	if c.LivenessProbe == nil || c.ReadinessProbe == nil {
		t.Error("operator must have liveness and readiness probes")
	}
}

func TestLeaderElectionContracts(t *testing.T) {
	for _, tc := range []struct {
		name     string
		replicas int32
		election bool
	}{
		{"singleton elected", 1, true},
		{"singleton unelected", 1, false},
		{"two replicas", 2, true},
		{"three replicas", 3, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			m := render(t, fmt.Sprintf("replicas: %d\nleaderElection: {enabled: %t}\nnamespace: operator-ha\nfullnameOverride: custom-operator", tc.replicas, tc.election))
			dep, c := operator(t, m)
			equal(t, "election flag", c.Args, []string{fmt.Sprintf("--leader-elect=%t", tc.election)})
			equal(t, "replicas", *dep.Spec.Replicas, tc.replicas)
			equal(t, "immutable selector", dep.Spec.Selector, &metav1.LabelSelector{MatchLabels: map[string]string{"app.kubernetes.io/name": "tailnet-operator"}})
			if tc.election {
				equal(t, "strategy", dep.Spec.Strategy.Type, appsv1.RollingUpdateDeploymentStrategyType)
				ru := dep.Spec.Strategy.RollingUpdate
				if ru == nil || ru.MaxSurge == nil || ru.MaxUnavailable == nil {
					t.Fatal("rolling update must specify surge and availability budgets")
				}
				equal(t, "max surge", *ru.MaxSurge, intstr.FromInt32(1))
				equal(t, "max unavailable", *ru.MaxUnavailable, intstr.FromInt32(0))
			} else {
				equal(t, "strategy", dep.Spec.Strategy.Type, appsv1.RecreateDeploymentStrategyType)
				if dep.Spec.Strategy.RollingUpdate != nil {
					t.Error("Recreate must not include rolling update settings")
				}
			}
			role := decode[rbacv1.Role](t, m.one(t, "Role"))
			equal(t, "Lease RBAC namespace", role.Namespace, "operator-ha")
			var leaseRules []rbacv1.PolicyRule
			for _, rule := range role.Rules {
				for _, group := range rule.APIGroups {
					if group == "coordination.k8s.io" {
						leaseRules = append(leaseRules, rule)
					}
				}
			}
			if tc.election {
				equal(t, "Lease RBAC", leaseRules, []rbacv1.PolicyRule{{
					APIGroups: []string{"coordination.k8s.io"}, Resources: []string{"leases"},
					Verbs: []string{"get", "list", "watch", "create", "update", "patch"},
				}})
			} else if len(leaseRules) != 0 {
				t.Error("disabled election must not grant Lease permissions")
			}
			for _, obj := range m {
				if obj.Kind != "ClusterRole" {
					continue
				}
				clusterRole := decode[rbacv1.ClusterRole](t, obj)
				for _, rule := range clusterRole.Rules {
					for _, group := range rule.APIGroups {
						if group == "coordination.k8s.io" || group == "*" {
							t.Error("Lease permissions must not be cluster scoped")
						}
					}
				}
			}
			if tc.replicas > 1 {
				pdb := decode[policyv1.PodDisruptionBudget](t, m.one(t, "PodDisruptionBudget"))
				equal(t, "PDB API", pdb.APIVersion, "policy/v1")
				equal(t, "PDB namespace", pdb.Namespace, dep.Namespace)
				equal(t, "PDB name", pdb.Name, dep.Name)
				if pdb.Spec.MinAvailable == nil || pdb.Spec.Selector == nil {
					t.Fatal("PDB must specify minAvailable and selector")
				}
				equal(t, "PDB budget", *pdb.Spec.MinAvailable, intstr.FromInt32(1))
				equal(t, "PDB selector", pdb.Spec.Selector, dep.Spec.Selector)
				if pdb.Spec.MaxUnavailable != nil || !matches(t, *pdb.Spec.Selector, dep.Spec.Template.Labels) {
					t.Error("invalid PDB budget or selector")
				}
			} else {
				for _, obj := range m {
					if obj.Kind == "PodDisruptionBudget" {
						t.Error("singleton must not get a PDB")
					}
				}
			}
		})
	}
}

func TestLeaderElectionTemplateGuard(t *testing.T) {
	// Keep the safety check even when callers explicitly bypass Helm's JSON schema.
	for _, values := range []string{"replicas: 0", "replicas: 2\nleaderElection: {enabled: false}"} {
		_, err := helmTemplateWithValidation(t, values, true)
		if err == nil || !strings.Contains(err.Error(), "replicas") {
			t.Fatalf("template guard failed for %q: %v", values, err)
		}
	}
}

func TestTopologySpreadConstraints(t *testing.T) {
	values, err := os.ReadFile(filepath.Join(chartPath(t), "ci", "full-values.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	m := render(t, string(values))
	dep, _ := operator(t, m)
	m.one(t, "PodDisruptionBudget")
	equal(t, "topology spread", dep.Spec.Template.Spec.TopologySpreadConstraints, []corev1.TopologySpreadConstraint{{
		MaxSkew: 1, TopologyKey: "kubernetes.io/hostname", WhenUnsatisfiable: corev1.ScheduleAnyway,
		LabelSelector: &metav1.LabelSelector{MatchLabels: map[string]string{"app.kubernetes.io/name": "tailnet-operator"}},
	}})
}

func TestInvalidValues(t *testing.T) {
	cases := []struct{ name, values, diagnostic string }{
		{"zero replicas", "replicas: 0", "replicas"},
		{"numeric fullname", "fullnameOverride: '123'", "fullnameOverride"},
		{"digit-leading fullname", "fullnameOverride: '1operator'", "fullnameOverride"},
		{"multiple replicas without election", "replicas: 2\nleaderElection: {enabled: false}", "leaderElection"},
		{"nonboolean election", "leaderElection: {enabled: 'false'}", "leaderElection"},
		{"invalid topology spread", "topologySpreadConstraints: [{maxSkew: 0, topologyKey: '', whenUnsatisfiable: invalid}]", "topologySpreadConstraints"},
		{"operator secret strings", "imagePullSecrets: [registry]", "imagePullSecrets"},
		{"operator secret scalar", "imagePullSecrets: registry", "imagePullSecrets"},
		{"operator duplicate secrets", "imagePullSecrets: [{name: registry}, {name: registry}]", "imagePullSecrets"},
		{"agent duplicate secrets", "agent: {imagePullSecrets: [registry, registry]}", "imagePullSecrets"},
		{"operator secret missing name", "imagePullSecrets: [{}]", "imagePullSecrets"},
		{"operator secret numeric name", "imagePullSecrets: [{name: 123}]", "imagePullSecrets"},
		{"agent secret objects", "agent: {imagePullSecrets: [{name: registry}]}", "imagePullSecrets"},
		{"agent secret scalar", "agent: {imagePullSecrets: registry}", "imagePullSecrets"},
		{"agent secret number", "agent: {imagePullSecrets: [123]}", "imagePullSecrets"},
		{"agent resources scalar", "agent: {resources: invalid}", "resources"},
		{"agent resources array", "agent: {resources: []}", "resources"},
		{"agent resources unknown field", "agent: {resources: {request: {cpu: 10m}}}", "resources"},
		{"agent requests scalar", "agent: {resources: {requests: invalid}}", "requests"},
		{"agent limits array", "agent: {resources: {limits: []}}", "limits"},
		{"agent quantity object", "agent: {resources: {requests: {cpu: {value: 1}}}}", "cpu"},
		{"agent quantity bool", "agent: {resources: {limits: {memory: false}}}", "memory"},
		{"agent quantity negative number", "agent: {resources: {requests: {cpu: -1}}}", "cpu"},
		{"dashboard invalid kind", "monitoring: {dashboard: {enabled: true, kind: Secret}}", "kind"},
		{"podMonitor empty scrape peer", "monitoring: {podMonitor: {scrapeFrom: [{}]}}", "scrapeFrom"},
		{"podMonitor invalid interval", "monitoring: {podMonitor: {enabled: true, interval: invalid}}", "interval"},
		{"podMonitor invalid selector", "monitoring: {podMonitor: {namespaceSelector: {matchLabels: {team: ops}}}}", "namespaceSelector"},
		{"dashboard invalid JSON", "monitoring: {dashboard: {enabled: true, json: 'not JSON'}}", ""},
		{"network policy without CIDRs", "networkPolicy: {enabled: true}", "CIDRs"},
		{"network policy without API CIDRs", "networkPolicy: {enabled: true, headscaleCIDRs: [192.0.2.1/32]}", "kubeAPICIDRs"},
		{"network policy without Headscale CIDRs", "networkPolicy: {enabled: true, kubeAPICIDRs: [10.96.0.1/32]}", "headscaleCIDRs"},
		{"network policy unknown provider", "networkPolicy: {enabled: true, provider: calico}", "provider"},
		{"cilium policy with ipBlock peer", "networkPolicy: {enabled: true, provider: cilium, dnsPeers: [{ipBlock: {cidr: 10.0.0.0/8}}]}", "ipBlock"},
		{"cilium policy without any Headscale egress", "networkPolicy: {enabled: true, provider: cilium, cilium: {headscalePeers: []}}", "headscaleCIDRs"},
	}
	for _, name := range []string{"POD_NAMESPACE", "OPERATOR_IMAGE", "AGENT_IMAGE_PULL_SECRETS", "AGENT_RESOURCES", "SSL_CERT_FILE"} {
		cases = append(cases, struct{ name, values, diagnostic string }{"reserved " + name, "env: {extra: [{name: " + name + ", value: override}]}", name})
	}
	for _, name := range []string{"", "Invalid", "bad_name", "-leading", "trailing-", "bad..name", strings.Repeat("a", 254)} {
		cases = append(cases,
			struct{ name, values, diagnostic string }{"operator invalid secret " + name, fmt.Sprintf("imagePullSecrets: [{name: %q}]", name), "imagePullSecrets"},
			struct{ name, values, diagnostic string }{"agent invalid secret " + name, fmt.Sprintf("agent: {imagePullSecrets: [%q]}", name), "imagePullSecrets"})
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := helmTemplate(t, tc.values)
			if err == nil {
				t.Fatalf("helm template accepted invalid values:\n%s", tc.values)
			}
			if tc.diagnostic != "" && !strings.Contains(err.Error(), tc.diagnostic) {
				t.Errorf("failure should identify %q: %v", tc.diagnostic, err)
			}
		})
	}
}

func TestMonitoringOptIns(t *testing.T) {
	t.Run("ServiceMonitor alone", func(t *testing.T) {
		m := render(t, "monitoring: {serviceMonitor: {enabled: true}}")
		m.one(t, "ServiceMonitor")
		for _, obj := range m {
			if obj.Kind == "PrometheusRule" || obj.Kind == "ConfigMap" || obj.Kind == "GrafanaDashboard" || obj.Kind == "PodMonitor" {
				t.Errorf("ServiceMonitor opt-in must not enable %s", obj.Kind)
			}
		}
	})
	m := render(t, `monitoring:
  serviceMonitor:
    enabled: true
    interval: 45s
    labels: {prometheus: platform}
  rules:
    enabled: true
    groups:
      - name: custom
        rules:
          - alert: OperatorDown
            expr: up == 0
            for: 5m
  dashboard:
    enabled: true
    kind: ConfigMap
    json: '{"title":"Tailnet operator","panels":[]}'
    labels: {grafana_dashboard: "1", team: platform}
`)
	var monitor struct {
		Spec struct {
			Selector  metav1.LabelSelector `json:"selector"`
			Endpoints []struct {
				Port     string `json:"port"`
				Interval string `json:"interval"`
			} `json:"endpoints"`
		} `json:"spec"`
	}
	sm := m.one(t, "ServiceMonitor")
	if err := yaml.Unmarshal(sm.data, &monitor); err != nil {
		t.Fatal(err)
	}
	equal(t, "ServiceMonitor API", sm.APIVersion, "monitoring.coreos.com/v1")
	equal(t, "ServiceMonitor labels", sm.Metadata.Labels["prometheus"], "platform")
	if !matches(t, monitor.Spec.Selector, m.one(t, "Service").Metadata.Labels) {
		t.Error("ServiceMonitor does not select the metrics Service")
	}
	if len(monitor.Spec.Endpoints) != 1 || monitor.Spec.Endpoints[0].Port != "metrics" || monitor.Spec.Endpoints[0].Interval != "45s" {
		t.Errorf("unexpected ServiceMonitor endpoints: %#v", monitor.Spec.Endpoints)
	}
	var rules struct {
		Spec struct {
			Groups []struct {
				Name  string `json:"name"`
				Rules []struct {
					Alert string `json:"alert"`
					Expr  string `json:"expr"`
					For   string `json:"for"`
				} `json:"rules"`
			} `json:"groups"`
		} `json:"spec"`
	}
	pr := m.one(t, "PrometheusRule")
	if err := yaml.Unmarshal(pr.data, &rules); err != nil {
		t.Fatal(err)
	}
	equal(t, "PrometheusRule API", pr.APIVersion, "monitoring.coreos.com/v1")
	if len(rules.Spec.Groups) != 1 || rules.Spec.Groups[0].Name != "custom" || len(rules.Spec.Groups[0].Rules) != 1 {
		t.Fatalf("custom rule groups not preserved: %#v", rules.Spec.Groups)
	}
	rule := rules.Spec.Groups[0].Rules[0]
	if rule.Alert != "OperatorDown" || rule.Expr != "up == 0" || rule.For != "5m" {
		t.Errorf("custom rule not preserved: %#v", rule)
	}
	cm := decode[corev1.ConfigMap](t, m.one(t, "ConfigMap"))
	equal(t, "dashboard sidecar label", cm.Labels["grafana_dashboard"], "1")
	equal(t, "dashboard extra label", cm.Labels["team"], "platform")
	equal(t, "dashboard JSON", cm.Data["tailnet-operator.json"], `{"title":"Tailnet operator","panels":[]}`)
}

// ciliumPolicy decodes the fields the chart renders; no Cilium module is imported.
type ciliumPolicy struct {
	Spec struct {
		EndpointSelector metav1.LabelSelector `json:"endpointSelector"`
		Egress           []struct {
			ToEntities  []string               `json:"toEntities"`
			ToEndpoints []metav1.LabelSelector `json:"toEndpoints"`
			ToCIDR      []string               `json:"toCIDR"`
			ToPorts     []struct {
				Ports []struct{ Port, Protocol string } `json:"ports"`
			} `json:"toPorts"`
		} `json:"egress"`
		Ingress []interface{} `json:"ingress"`
	} `json:"spec"`
}

func TestCiliumNetworkPolicy(t *testing.T) {
	// No CIDRs: the cilium provider needs identities, not addresses.
	m := render(t, `networkPolicy:
  enabled: true
  provider: cilium
  headscalePorts: [8443]
  dnsPeers:
    - namespaceSelector: {matchLabels: {kubernetes.io/metadata.name: dns-system}}
      podSelector: {matchLabels: {app: dns}}
`)
	for _, obj := range m {
		if obj.Kind == "NetworkPolicy" {
			t.Error("provider cilium must not render a NetworkPolicy")
		}
	}
	cnp := decode[ciliumPolicy](t, m.one(t, "CiliumNetworkPolicy"))
	dep, _ := operator(t, m)
	if !matches(t, cnp.Spec.EndpointSelector, dep.Spec.Template.Labels) || reflect.DeepEqual(cnp.Spec.EndpointSelector, metav1.LabelSelector{}) {
		t.Error("CiliumNetworkPolicy must specifically select the operator pod")
	}
	if len(cnp.Spec.Ingress) != 0 {
		t.Error("provider cilium is egress-only; ingress must stay open")
	}
	equal(t, "egress rule count", len(cnp.Spec.Egress), 4)
	hasPort := func(i int, port, protocol string) bool {
		for _, tp := range cnp.Spec.Egress[i].ToPorts {
			for _, p := range tp.Ports {
				if p.Port == port && p.Protocol == protocol {
					return true
				}
			}
		}
		return false
	}
	equal(t, "kube-apiserver entity", cnp.Spec.Egress[0].ToEntities, []string{"kube-apiserver"})
	dns := cnp.Spec.Egress[1].ToEndpoints
	if len(dns) != 1 || dns[0].MatchLabels["app"] != "dns" || dns[0].MatchLabels["k8s:io.cilium.k8s.namespace.labels.kubernetes.io/metadata.name"] != "dns-system" || !hasPort(1, "53", "UDP") || !hasPort(1, "53", "TCP") {
		t.Errorf("DNS peer not translated into Cilium namespace labels: %#v", dns)
	}
	hs := cnp.Spec.Egress[2].ToEndpoints
	if len(hs) != 1 || hs[0].MatchLabels["app.kubernetes.io/name"] != "headscale" || len(hs[0].MatchExpressions) != 0 || !hasPort(2, "8443", "TCP") {
		t.Errorf("Headscale peer must stay scoped to the operator namespace: %#v", hs)
	}
	agents := map[string]bool{}
	for _, sel := range cnp.Spec.Egress[3].ToEndpoints {
		name := sel.MatchLabels["app.kubernetes.io/name"]
		anyNamespace := false
		for _, e := range sel.MatchExpressions {
			anyNamespace = anyNamespace || e.Key == "k8s:io.kubernetes.pod.namespace" && e.Operator == metav1.LabelSelectorOpExists
		}
		agents[name] = anyNamespace
	}
	if _, ok := agents["tailnet-egress"]; !ok || !agents["tailnet-ingress"] || !hasPort(3, "9080", "TCP") {
		t.Errorf("agent scrape rule must cover egress agents and ingress agents in every namespace: %#v", agents)
	}
	// Default cilium render must not add a toCIDR egress — spoke clusters opt
	// in explicitly via headscaleCIDRs; stability for hub clusters (hydra) is
	// what makes the operator upgrade safe.
	for i, e := range cnp.Spec.Egress {
		if len(e.ToCIDR) != 0 {
			t.Errorf("default cilium render leaked a toCIDR egress at index %d: %v", i, e.ToCIDR)
		}
	}
}

func TestCiliumNetworkPolicyRemoteHeadscale(t *testing.T) {
	// Spoke cluster: the Headscale control plane lives outside the cluster. The
	// in-cluster label peer is empty, Headscale is reached by IP via a toCIDR
	// egress on the same headscalePorts. Covers the spoke-cluster gap closed in
	// v0.16.0 (a separately maintained CiliumNetworkPolicy was needed before).
	m := render(t, `networkPolicy:
  enabled: true
  provider: cilium
  headscalePorts: [443]
  cilium:
    headscalePeers: []
  headscaleCIDRs: [91.98.5.30/32]
  dnsPeers:
    - namespaceSelector: {matchLabels: {kubernetes.io/metadata.name: kube-system}}
      podSelector: {matchLabels: {k8s-app: kube-dns}}
`)
	cnp := decode[ciliumPolicy](t, m.one(t, "CiliumNetworkPolicy"))
	var cidrEgress, labelHeadscale int
	var cidrs []string
	for _, e := range cnp.Spec.Egress {
		if len(e.ToCIDR) != 0 {
			cidrEgress++
			cidrs = append(cidrs, e.ToCIDR...)
		}
		for _, sel := range e.ToEndpoints {
			if sel.MatchLabels["app.kubernetes.io/name"] == "headscale" {
				labelHeadscale++
			}
		}
	}
	if cidrEgress != 1 || !reflect.DeepEqual(cidrs, []string{"91.98.5.30/32"}) {
		t.Errorf("expected exactly one toCIDR egress with [91.98.5.30/32], got %d rules %v", cidrEgress, cidrs)
	}
	if labelHeadscale != 0 {
		t.Error("empty cilium.headscalePeers must not render an in-cluster Headscale toEndpoints rule")
	}
	// Port parity: the toCIDR egress carries headscalePorts.
	for _, e := range cnp.Spec.Egress {
		if len(e.ToCIDR) == 0 {
			continue
		}
		found := false
		for _, tp := range e.ToPorts {
			for _, p := range tp.Ports {
				if p.Port == "443" && p.Protocol == "TCP" {
					found = true
				}
			}
		}
		if !found {
			t.Errorf("toCIDR egress missing TCP/443: %#v", e.ToPorts)
		}
	}
}

func TestNetworkPolicy(t *testing.T) {
	t.Run("metrics denied by default", func(t *testing.T) {
		m := render(t, "networkPolicy: {enabled: true, kubeAPICIDRs: [10.96.0.1/32], headscaleCIDRs: [192.0.2.1/32]}")
		np := decode[networkingv1.NetworkPolicy](t, m.one(t, "NetworkPolicy"))
		if len(np.Spec.Ingress) != 0 {
			t.Fatalf("metrics ingress unexpectedly allowed: %#v", np.Spec.Ingress)
		}
	})
	m := render(t, `networkPolicy:
  enabled: true
  kubeAPICIDRs: [10.96.0.1/32]
  kubeAPIPorts: [6443]
  headscaleCIDRs: [192.0.2.1/32]
  headscalePorts: [8443]
  dnsPeers:
    - namespaceSelector: {matchLabels: {kubernetes.io/metadata.name: dns-system}}
      podSelector: {matchLabels: {app: dns}}
  metricsPeers:
    - namespaceSelector: {matchLabels: {kubernetes.io/metadata.name: monitoring}}
      podSelector: {matchLabels: {app: prometheus}}
`)
	np := decode[networkingv1.NetworkPolicy](t, m.one(t, "NetworkPolicy"))
	dep, _ := operator(t, m)
	if !matches(t, np.Spec.PodSelector, dep.Spec.Template.Labels) || reflect.DeepEqual(np.Spec.PodSelector, metav1.LabelSelector{}) {
		t.Error("NetworkPolicy must specifically select the operator pod")
	}
	types := map[networkingv1.PolicyType]bool{}
	for _, typ := range np.Spec.PolicyTypes {
		types[typ] = true
	}
	if !types[networkingv1.PolicyTypeIngress] || !types[networkingv1.PolicyTypeEgress] {
		t.Error("NetworkPolicy must isolate both ingress and egress")
	}
	portsContain := func(ports []networkingv1.NetworkPolicyPort, protocol corev1.Protocol, port int32) bool {
		for _, p := range ports {
			if p.Port != nil && p.Port.IntVal == port && (p.Protocol == nil && protocol == corev1.ProtocolTCP || p.Protocol != nil && *p.Protocol == protocol) {
				return true
			}
		}
		return false
	}
	for _, endpoint := range []struct {
		cidr string
		port int32
	}{{"10.96.0.1/32", 6443}, {"192.0.2.1/32", 8443}} {
		found := false
		for _, rule := range np.Spec.Egress {
			for _, peer := range rule.To {
				if peer.IPBlock != nil && peer.IPBlock.CIDR == endpoint.cidr && portsContain(rule.Ports, corev1.ProtocolTCP, endpoint.port) {
					found = true
				}
			}
		}
		if !found {
			t.Errorf("missing egress to %s:%d", endpoint.cidr, endpoint.port)
		}
	}
	// These are the actual agent labels from internal/controller/resources{,_ingress}.go.
	// Test selector behavior rather than prescribing matchLabels versus matchExpressions.
	for _, name := range []string{"tailnet-egress", "tailnet-ingress"} {
		found := false
		for _, rule := range np.Spec.Egress {
			if !portsContain(rule.Ports, corev1.ProtocolTCP, 9080) {
				continue
			}
			for _, peer := range rule.To {
				if peer.NamespaceSelector == nil || peer.PodSelector == nil {
					continue
				}
				if !reflect.DeepEqual(*peer.NamespaceSelector, metav1.LabelSelector{}) {
					continue
				}
				agentLabels := map[string]string{"app.kubernetes.io/name": name, "app.kubernetes.io/instance": "any-cr", "app.kubernetes.io/managed-by": "tailnet-operator"}
				if matches(t, *peer.PodSelector, agentLabels) && !matches(t, *peer.PodSelector, map[string]string{"app.kubernetes.io/name": "unrelated"}) {
					found = true
				}
			}
		}
		if !found {
			t.Errorf("missing pod-selected TCP/9080 egress to %s agents across all namespaces", name)
		}
	}
	for _, protocol := range []corev1.Protocol{corev1.ProtocolUDP, corev1.ProtocolTCP} {
		found := false
		for _, rule := range np.Spec.Egress {
			for _, peer := range rule.To {
				if peer.NamespaceSelector != nil && peer.PodSelector != nil && matches(t, *peer.NamespaceSelector, map[string]string{"kubernetes.io/metadata.name": "dns-system"}) && matches(t, *peer.PodSelector, map[string]string{"app": "dns"}) && portsContain(rule.Ports, protocol, 53) {
					found = true
				}
			}
		}
		if !found {
			t.Errorf("missing configured DNS egress on %s/53", protocol)
		}
	}
	metrics := false
	for _, rule := range np.Spec.Ingress {
		for _, peer := range rule.From {
			if peer.NamespaceSelector != nil && peer.PodSelector != nil && matches(t, *peer.NamespaceSelector, map[string]string{"kubernetes.io/metadata.name": "monitoring"}) && matches(t, *peer.PodSelector, map[string]string{"app": "prometheus"}) && portsContain(rule.Ports, corev1.ProtocolTCP, 8080) {
				metrics = true
			}
		}
	}
	if !metrics {
		t.Error("missing configured metrics ingress on TCP/8080")
	}
}
