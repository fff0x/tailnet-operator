package main

import (
	"strings"
	"testing"
)

const testRole = `apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata: {name: local, namespace: operator-system}
rules:
  - apiGroups: [""]
    resources: [secrets, configmaps]
    verbs: [patch, get]
    resourceNames: [z-key, a-key]
  - apiGroups: ["apps"]
    resources: [deployments]
    verbs: [list, watch]
`

const testBinding = `apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata: {name: local, namespace: operator-system}
roleRef: {apiGroup: rbac.authorization.k8s.io, kind: Role, name: local}
subjects:
  - {kind: ServiceAccount, name: worker, namespace: operator-system}
  - {kind: Group, name: readers, apiGroup: rbac.authorization.k8s.io}
`

const testClusterRole = `apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata: {name: shared}
rules:
  - apiGroups: ["apps"]
    resources: [deployments]
    verbs: [get]
  - nonResourceURLs: [/version, /healthz]
    verbs: [get]
`

const testClusterBinding = `apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata: {name: shared}
roleRef: {apiGroup: rbac.authorization.k8s.io, kind: ClusterRole, name: shared}
subjects:
  - {kind: ServiceAccount, name: global, namespace: system}
`

func stream(docs ...string) string { return strings.Join(docs, "\n---\n") }

func TestGenerateDeterministic(t *testing.T) {
	first, err := generate(strings.NewReader(stream(testRole, testBinding, testClusterRole, testClusterBinding)))
	if err != nil {
		t.Fatal(err)
	}
	reordered := strings.ReplaceAll(testRole, "[secrets, configmaps]", "[configmaps, secrets]")
	reordered = strings.ReplaceAll(reordered, "[patch, get]", "[get, patch]")
	reordered = strings.ReplaceAll(reordered, "[z-key, a-key]", "[a-key, z-key]")
	reordered = strings.ReplaceAll(reordered, "  - apiGroups: [\"\"]\n    resources: [configmaps, secrets]\n    verbs: [get, patch]\n    resourceNames: [a-key, z-key]\n  - apiGroups: [\"apps\"]\n    resources: [deployments]\n    verbs: [list, watch]", "  - apiGroups: [\"apps\"]\n    resources: [deployments]\n    verbs: [watch, list]\n  - apiGroups: [\"\"]\n    resources: [configmaps, secrets]\n    verbs: [get, patch]\n    resourceNames: [a-key, z-key]")
	reorderedBinding := strings.ReplaceAll(testBinding, "  - {kind: ServiceAccount, name: worker, namespace: operator-system}\n  - {kind: Group, name: readers, apiGroup: rbac.authorization.k8s.io}", "  - {kind: Group, name: readers, apiGroup: rbac.authorization.k8s.io}\n  - {kind: ServiceAccount, name: worker, namespace: operator-system}")
	second, err := generate(strings.NewReader(stream(testClusterBinding, testClusterRole, reorderedBinding, reordered)))
	if err != nil {
		t.Fatal(err)
	}
	if first != second {
		t.Fatalf("output depends on input order:\n%s\nversus:\n%s", first, second)
	}
	for _, want := range []string{
		"| `Role/local` | `operator-system` | `operator-system` | `(core)` | `configmaps`, `secrets` | `get`, `patch` | `a-key`, `z-key` | — |",
		"| `ClusterRole/shared` | — | `cluster-wide` | — | — | `get` | all names | `/healthz`, `/version` |",
		"| `RoleBinding/local` | `operator-system` | `Role/operator-system/local` |",
		"`ServiceAccount/operator-system/worker (apiGroup=)`",
		"`Group//readers (apiGroup=rbac.authorization.k8s.io)`",
		"| `ClusterRoleBinding/shared` | — | `ClusterRole//shared` |",
	} {
		if !strings.Contains(first, want) {
			t.Errorf("missing %q in output:\n%s", want, first)
		}
	}
	if strings.Index(first, "| `ClusterRole/shared`") > strings.Index(first, "| `Role/local`") {
		t.Error("rules must sort by role")
	}
}

func TestNamespacedClusterRoleBindingAndUnboundRoles(t *testing.T) {
	binding := strings.ReplaceAll(testBinding, "kind: Role, name: local", "kind: ClusterRole, name: shared")
	out, err := generate(strings.NewReader(stream(testClusterRole, testRole, binding)))
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"| `ClusterRole/shared` | — | `operator-system` |",
		"| `Role/local` | `operator-system` | not granted |",
		"| `ClusterRole/shared` | — | not granted | — | — | `get` | all names | `/healthz`, `/version` |",
		"| `RoleBinding/local` | `operator-system` | `ClusterRole//shared` |",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q", want)
		}
	}
}

func TestDistinctNamespacesAndEmptySubjects(t *testing.T) {
	otherRole := strings.ReplaceAll(testRole, "operator-system", "tenant")
	otherBinding := strings.ReplaceAll(testBinding, "operator-system", "tenant")
	emptyBinding, _, _ := strings.Cut(otherBinding, "subjects:")
	out, err := generate(strings.NewReader(stream(testRole, otherRole, testBinding, emptyBinding)))
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"| `Role/local` | `operator-system` | `operator-system` |",
		"| `Role/local` | `tenant` | not granted |",
		"| `RoleBinding/local` | `tenant` | `Role/tenant/local` | none |",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q", want)
		}
	}
}

func TestFiltersNonRBACAndEmptyDocuments(t *testing.T) {
	want, err := generate(strings.NewReader(testRole))
	if err != nil {
		t.Fatal(err)
	}
	got, err := generate(strings.NewReader(stream("# empty", "", "apiVersion: v1\nkind: ConfigMap\nmetadata: {name: ignored}", testRole, "")))
	if err != nil {
		t.Fatal(err)
	}
	if got != want {
		t.Error("non-RBAC or empty documents changed output")
	}
}

func TestRejectIncompleteAudit(t *testing.T) {
	for name, input := range map[string]string{
		"empty":                   "",
		"malformed YAML":          "rules: [",
		"missing role":            stream(testRole, strings.ReplaceAll(testBinding, "kind: Role, name: local", "kind: Role, name: missing")),
		"duplicate role":          stream(testRole, testRole),
		"duplicate binding":       stream(testRole, testBinding, testBinding),
		"aggregated role":         testClusterRole + "aggregationRule: {clusterRoleSelectors: []}\n",
		"missing namespace":       strings.ReplaceAll(testRole, ", namespace: operator-system", ""),
		"cluster role namespace":  strings.ReplaceAll(testClusterRole, "name: shared", "name: shared, namespace: wrong"),
		"invalid role group":      stream(testRole, strings.ReplaceAll(testBinding, "apiGroup: rbac.authorization.k8s.io, kind: Role", "apiGroup: wrong, kind: Role")),
		"cluster binding to role": stream(testRole, strings.ReplaceAll(testClusterBinding, "kind: ClusterRole, name: shared", "kind: Role, name: local")),
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := generate(strings.NewReader(input)); err == nil {
				t.Error("accepted incomplete or invalid audit input")
			}
		})
	}
}

func TestCellEscapesAndDoesNotMutate(t *testing.T) {
	values := []string{"z|name", "a`name"}
	if got := cell(values, "none"); got != "`a&#96;name`, `z&#124;name`" {
		t.Fatalf("unexpected cell: %s", got)
	}
	if values[0] != "z|name" {
		t.Error("cell mutated its input")
	}
}
