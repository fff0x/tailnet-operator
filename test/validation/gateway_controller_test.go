//go:build integration

package validation

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"testing"
	"time"

	appsv1 "k8s.io/api/apps/v1"
	authv1 "k8s.io/api/authorization/v1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	utilyaml "k8s.io/apimachinery/pkg/util/yaml"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	"k8s.io/client-go/rest"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/envtest"
	"sigs.k8s.io/controller-runtime/pkg/log/zap"
	"sigs.k8s.io/yaml"

	tnv1 "tsunaro.io/tailnet-operator/api/v1alpha1"
	"tsunaro.io/tailnet-operator/internal/manager"
	"tsunaro.io/tailnet-operator/test/internal/isolation"
)

// Exercises production manager registration and the generated chart RBAC against
// a disposable API server. No kubelet, router, DNS server or GC controller runs:
// this is not a pod/data-plane or real adoption/retention gate.
func TestGatewaySuspendedController(t *testing.T) {
	must := func(err error, message string) {
		t.Helper()
		if err != nil {
			t.Fatal(message) // Never dump API bodies or resource payloads.
		}
	}
	must(isolation.ClearEnvtestOverrides(), "isolate envtest")
	if os.Getenv("KUBEBUILDER_ASSETS") == "" {
		t.Fatal("KUBEBUILDER_ASSETS must point to isolated Kubernetes >=1.31 binaries")
	}
	root, err := filepath.Abs(filepath.Join("..", ".."))
	must(err, "resolve repository")
	useExisting := false
	env := &envtest.Environment{
		UseExistingCluster: &useExisting, CRDDirectoryPaths: []string{filepath.Join(root, "deploy", "crds")},
		ErrorIfCRDPathMissing: true, ControlPlaneStartTimeout: 20 * time.Second, ControlPlaneStopTimeout: 10 * time.Second,
	}
	t.Cleanup(func() { must(env.Stop(), "stop isolated API server") })
	cfg, err := env.Start()
	must(err, "start isolated API server")
	scheme := runtime.NewScheme()
	must(clientgoscheme.AddToScheme(scheme), "register Kubernetes types")
	must(tnv1.AddToScheme(scheme), "register gateway types")
	admin, err := client.New(cfg, client.Options{Scheme: scheme})
	must(err, "construct isolated admin client")
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	t.Cleanup(cancel)
	const namespace = "gateway-controller-test"
	must(admin.Create(ctx, &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: namespace}}), "create test namespace")

	// Use the generated standalone RBAC, which chart tests require to match Helm.
	// Relocate only namespaces; retain every resource, verb and role reference.
	manifest, err := os.Open(filepath.Join(root, "deploy", "operator.yaml"))
	must(err, "open generated operator manifest")
	t.Cleanup(func() { _ = manifest.Close() })
	decoder := utilyaml.NewYAMLOrJSONDecoder(manifest, 4096)
	var account string
	roles := 0
	for {
		var object unstructured.Unstructured
		err := decoder.Decode(&object)
		if err == io.EOF {
			break
		}
		must(err, "decode generated manifest")
		switch object.GetKind() {
		case "Role", "RoleBinding":
			object.SetNamespace(namespace)
		case "ClusterRole", "ClusterRoleBinding":
		default:
			continue
		}
		if object.GetKind() == "RoleBinding" || object.GetKind() == "ClusterRoleBinding" {
			subjects, _, err := unstructured.NestedSlice(object.Object, "subjects")
			must(err, "read generated RBAC subjects")
			if len(subjects) != 1 {
				t.Fatal("unexpected generated RBAC subject count")
			}
			subject, ok := subjects[0].(map[string]any)
			if !ok || subject["kind"] != "ServiceAccount" {
				t.Fatal("unexpected generated RBAC subject")
			}
			name, ok := subject["name"].(string)
			if !ok || name == "" || (account != "" && account != name) {
				t.Fatal("inconsistent generated service account")
			}
			account = name
			subject["namespace"] = namespace
			must(unstructured.SetNestedSlice(object.Object, subjects, "subjects"), "relocate RBAC subjects")
		}
		must(admin.Create(ctx, &object), "install generated RBAC")
		roles++
	}
	if roles != 6 || account == "" {
		t.Fatal("incomplete generated RBAC inventory")
	}
	principal := "system:serviceaccount:" + namespace + ":" + account
	groups := []string{"system:serviceaccounts", "system:serviceaccounts:" + namespace, "system:authenticated"}

	wait := func(message string, check func() bool) {
		t.Helper()
		deadline := time.NewTimer(10 * time.Second)
		defer deadline.Stop()
		tick := time.NewTicker(25 * time.Millisecond)
		defer tick.Stop()
		for !check() {
			select {
			case <-tick.C:
			case <-deadline.C:
				t.Fatal(message)
			case <-ctx.Done():
				t.Fatal("isolated controller test exceeded its deadline")
			}
		}
	}
	allowed := func(group, resource, subresource, verb, ns string) bool {
		review := &authv1.SubjectAccessReview{Spec: authv1.SubjectAccessReviewSpec{
			User: principal, Groups: groups,
			ResourceAttributes: &authv1.ResourceAttributes{Group: group, Resource: resource, Subresource: subresource, Verb: verb, Namespace: ns},
		}}
		must(admin.Create(ctx, review), "evaluate generated authorization")
		return review.Status.Allowed
	}
	wait("gateway read permission did not converge", func() bool { return allowed("tsunaro.io", "tailnetgateways", "", "get", "") })
	for _, verb := range []string{"get", "list", "watch"} {
		if !allowed("tsunaro.io", "tailnetgateways", "", verb, "") {
			t.Fatal("gateway read authorization missing")
		}
	}
	for _, verb := range []string{"get", "update", "patch"} {
		if !allowed("tsunaro.io", "tailnetgateways", "status", verb, "") {
			t.Fatal("gateway status authorization missing")
		}
	}
	// patch is granted for the teardown finalizer only; the code never patches spec.
	if !allowed("tsunaro.io", "tailnetgateways", "", "patch", "") {
		t.Fatal("gateway finalizer patch authorization missing")
	}
	for _, verb := range []string{"create", "update", "delete", "deletecollection"} {
		if allowed("tsunaro.io", "tailnetgateways", "", verb, "") {
			t.Fatal("operator may create, replace or delete gateways")
		}
	}
	for _, verb := range []string{"update", "patch"} {
		if allowed("tsunaro.io", "tailnetgateways", "finalizers", verb, "") {
			t.Fatal("operator has gateway finalizer authorization")
		}
	}
	for _, resource := range []struct{ group, name string }{
		{"", "serviceaccounts"}, {"apps", "statefulsets"}, {"policy", "poddisruptionbudgets"},
		{"rbac.authorization.k8s.io", "roles"}, {"rbac.authorization.k8s.io", "rolebindings"},
	} {
		for _, ns := range []string{namespace, "unrelated-tenant", ""} {
			for _, verb := range []string{"get", "list", "watch", "create", "update", "patch", "delete", "deletecollection", "escalate", "bind"} {
				want := ns == namespace && (verb == "get" || verb == "create" || verb == "delete")
				if got := allowed(resource.group, resource.name, "", verb, ns); got != want {
					t.Fatalf("fresh child authorization %s/%s %s in %q: got %t, want %t", resource.group, resource.name, verb, ns, got, want)
				}
			}
		}
	}

	operatorConfig := rest.CopyConfig(cfg)
	operatorConfig.Impersonate = rest.ImpersonationConfig{UserName: principal, Groups: groups}
	ctrl.SetLogger(zap.New(zap.WriteTo(io.Discard)))
	mgr, err := manager.New(operatorConfig, manager.Options{Namespace: namespace, Image: "example.invalid/not-run:v1.0.0", MetricsBindAddress: "0", HealthProbeBindAddress: "0"})
	must(err, "construct production manager with generated permissions")
	managerCtx, stopManager := context.WithCancel(ctx)
	done := make(chan error, 1)
	go func() { done <- mgr.Start(managerCtx) }()
	t.Cleanup(func() {
		stopManager()
		select {
		case err := <-done:
			must(err, "stop production manager")
		case <-time.After(20 * time.Second):
			t.Fatal("production manager did not stop")
		}
	})
	if !mgr.GetCache().WaitForCacheSync(ctx) {
		t.Fatal("production manager cache did not sync")
	}

	data, err := os.ReadFile(filepath.Join(root, "deploy", "examples", "tailnetgateway.yaml"))
	must(err, "read suspended example")
	var gw tnv1.TailnetGateway
	must(yaml.Unmarshal(data, &gw), "decode suspended example")
	gw.Name = "gateway-status"
	// Deliberately create no Tailnet or bootstrap credential. Suspension must
	// not require either, discover nodes, or create dependent resources.
	must(admin.Create(ctx, &gw), "create suspended gateway")
	key := client.ObjectKeyFromObject(&gw)
	current := func() *tnv1.TailnetGateway {
		obj := &tnv1.TailnetGateway{}
		must(admin.Get(ctx, key, obj), "read test gateway")
		return obj
	}
	settled := func() bool {
		obj := current()
		if obj.Status.ObservedGeneration != obj.Generation || len(obj.Status.Conditions) != 6 {
			return false
		}
		for _, typ := range []string{"Ready", "Registered", "RoutesInSync", "DNSReady", "StaleNodes", "ClusterDNSForward"} {
			c := meta.FindStatusCondition(obj.Status.Conditions, typ)
			want := metav1.ConditionUnknown
			if typ == "Ready" {
				want = metav1.ConditionFalse
			}
			if c == nil || c.Status != want || c.Reason != "Suspended" || c.ObservedGeneration != obj.Generation {
				return false
			}
		}
		return true
	}
	wait("production controller did not report suspension", settled)
	observed := current()
	if len(observed.Finalizers) != 0 || len(observed.OwnerReferences) != 0 || observed.Status.NodeID != "" || observed.Status.RoutePlan.AppliedHash != "" {
		t.Fatal("suspension installed lifecycle hooks or claimed runtime success")
	}
	for _, list := range []client.ObjectList{&corev1.SecretList{}, &corev1.ServiceList{}, &corev1.ConfigMapList{}, &appsv1.StatefulSetList{}} {
		must(admin.List(ctx, list, client.InNamespace(namespace)), "check empty dependency inventory")
		items, err := meta.ExtractList(list)
		must(err, "decode dependency inventory")
		if len(items) != 0 {
			t.Fatal("suspended gateway created child resources")
		}
	}

	// The informer must repair a stale success written through the status API,
	// not filter status-only events with GenerationChangedPredicate.
	must(admin.Status().Patch(ctx, observed, client.RawPatch(types.MergePatchType, []byte(`{"status":{"nodeId":"77","routePlan":{"appliedHash":"historic","pendingHash":"unacknowledged"},"conditions":[{"type":"Ready","status":"True","reason":"Stale","message":"stale fixture","lastTransitionTime":"2025-01-01T00:00:00Z"}]}}`))), "seed stale success")
	wait("status event did not withdraw stale Ready", settled)
	observed = current()
	if observed.Status.NodeID != "77" || observed.Status.RoutePlan.AppliedHash != "historic" || observed.Status.RoutePlan.PendingHash != "unacknowledged" {
		t.Fatal("controller changed last-known runtime observations")
	}
	observed.Spec.Tags = append(observed.Spec.Tags, "tag:test-change")
	must(admin.Update(ctx, observed), "advance gateway generation")
	wait("controller did not observe new generation", settled)
	stable := current()
	for range 5 {
		time.Sleep(50 * time.Millisecond)
		if current().ResourceVersion != stable.ResourceVersion {
			t.Fatal("suspended status produced a write loop")
		}
	}

	// Existing resource sentinels survive CR deletion unchanged. Envtest has no
	// GC controller: unit call guards and unchanged ownerRefs supply the bound,
	// not a claim of live data-plane retention.
	sentinel := &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: string(gw.Spec.StateSecretRef.Name), Namespace: namespace}, Data: map[string][]byte{"state": []byte("synthetic-persistent-state")}}
	must(admin.Create(ctx, sentinel), "create retained state sentinel")
	must(admin.Get(ctx, client.ObjectKeyFromObject(sentinel), sentinel), "read state sentinel")
	before, err := json.Marshal(sentinel)
	must(err, "snapshot state sentinel")
	must(admin.Delete(ctx, stable), "delete suspended gateway")
	wait("gateway deletion was blocked", func() bool { return apierrors.IsNotFound(admin.Get(ctx, key, &tnv1.TailnetGateway{})) })
	must(admin.Get(ctx, client.ObjectKeyFromObject(sentinel), sentinel), "retained state disappeared")
	after, err := json.Marshal(sentinel)
	must(err, "snapshot retained state")
	if !bytes.Equal(before, after) {
		t.Fatal("state sentinel changed during gateway deletion")
	}
}
