//go:build integration

package validation

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	policyv1 "k8s.io/api/policy/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	"k8s.io/utils/ptr"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/envtest"
	"sigs.k8s.io/yaml"
	"tailscale.com/types/key"

	tnv1 "tsunaro.io/tailnet-operator/api/v1alpha1"
	"tsunaro.io/tailnet-operator/internal/controller"
	"tsunaro.io/tailnet-operator/internal/gateway"
	"tsunaro.io/tailnet-operator/internal/headscale"
	"tsunaro.io/tailnet-operator/test/internal/isolation"
)

const gatewayWriterServiceCIDR = "10.0.0.0/16"

// These tests exercise the real reconciler and Kubernetes persistence/admission.
// Headscale is an authenticated REST fixture. Pod status and persistent identity
// are synthetic: no real Headscale, StatefulSet controller, kubelet, forwarding,
// DNS data plane, GC, bootstrap or restart-persistence proof is claimed.
func TestGatewayFreshWriter(t *testing.T) {
	gatewayWriterMust(t, isolation.ClearEnvtestOverrides(), "isolate envtest")
	if os.Getenv("KUBEBUILDER_ASSETS") == "" {
		t.Fatal("explicit isolated envtest assets required")
	}
	root, err := filepath.Abs(filepath.Join("..", ".."))
	gatewayWriterMust(t, err, "resolve repository")
	useExisting := false
	env := &envtest.Environment{UseExistingCluster: &useExisting, CRDDirectoryPaths: []string{filepath.Join(root, "deploy/crds")}, ErrorIfCRDPathMissing: true, ControlPlaneStartTimeout: 20 * time.Second, ControlPlaneStopTimeout: 10 * time.Second}
	// All fixtures share one cluster-wide Service allocator. The default /24
	// lets an earlier LB Service take a later fixture's fixed DNS IP (.51+).
	// A /16 keeps those DNS IPs in the low static band; dynamic LB allocations
	// use the upper band. assertComplete pins this separation without retries.
	env.ControlPlane.GetAPIServer().Configure().Set("service-cluster-ip-range", gatewayWriterServiceCIDR)
	t.Cleanup(func() { gatewayWriterMust(t, env.Stop(), "stop isolated API server") })
	cfg, err := env.Start()
	gatewayWriterMust(t, err, "start isolated API server")
	scheme := runtime.NewScheme()
	gatewayWriterMust(t, clientgoscheme.AddToScheme(scheme), "register Kubernetes types")
	gatewayWriterMust(t, tnv1.AddToScheme(scheme), "register gateway types")
	admin, err := client.New(cfg, client.Options{Scheme: scheme})
	gatewayWriterMust(t, err, "create isolated client")
	fixture, err := os.ReadFile(filepath.Join(root, "deploy/examples/tailnetgateway.yaml"))
	gatewayWriterMust(t, err, "read gateway example")
	ctx, cancel := context.WithTimeout(context.Background(), 180*time.Second)
	t.Cleanup(cancel)
	serial := 0
	newFixture := func(t *testing.T, suspended bool) *gatewayWriterFixture {
		t.Helper()
		serial++
		name := fmt.Sprintf("writer-%02d", serial)
		f := &gatewayWriterFixture{t: t, ctx: ctx, c: admin, ns: name}
		f.hs = &gatewayWriterHeadscale{t: t}
		server := httptest.NewServer(f.hs)
		t.Cleanup(server.Close)
		gatewayWriterMust(t, admin.Create(ctx, &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: name}}), "create writer namespace")
		f.tn = &tnv1.Tailnet{ObjectMeta: metav1.ObjectMeta{Name: name}, Spec: tnv1.TailnetSpec{Server: "https://headscale.example", APIURL: server.URL, APISecretRef: tnv1.SecretKeyRef{Name: "bootstrap"}, APIKeyLifetime: metav1.Duration{Duration: 24 * time.Hour}, DNS: tnv1.DNSSpec{HostsConfigMap: "hosts"}}}
		gatewayWriterMust(t, admin.Create(ctx, f.tn), "admit writer Tailnet")
		gatewayWriterMust(t, admin.Create(ctx, &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: name + "-apikey", Namespace: name}, Data: map[string][]byte{"apiKey": []byte("synthetic-working-token")}}), "create synthetic working API key")
		gatewayWriterMust(t, admin.Create(ctx, &corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Name: "hosts", Namespace: name, Labels: map[string]string{"app.kubernetes.io/managed-by": "tailnet-operator", "tsunaro.io/role": "dns-hosts"}, OwnerReferences: []metav1.OwnerReference{*metav1.NewControllerRef(f.tn, tnv1.GroupVersion.WithKind("Tailnet"))}}, Data: map[string]string{"hosts": "100.64.0.19 app.prod.example.internal\n"}}), "create Tailnet-owned hosts snapshot")
		f.g = &tnv1.TailnetGateway{}
		gatewayWriterMust(t, yaml.Unmarshal(fixture, f.g), "decode writer gateway")
		f.g.Name = name
		f.g.Spec.Suspend = ptr.To(suspended)
		f.g.Spec.TailnetRef.Name = tnv1.GatewayName(name)
		f.g.Spec.Hostname = name
		f.g.Spec.StateSecretRef.Name = tnv1.GatewayName(name + "-state")
		f.g.Spec.DNS.ServiceName = tnv1.GatewayServiceName(name + "-dns")
		f.g.Spec.DNS.ServiceClusterIP = tnv1.GatewayIP(fmt.Sprintf("10.0.0.%d", serial+50))
		f.g.Spec.Service.LoadBalancerIP = tnv1.GatewayIP(fmt.Sprintf("198.51.100.%d", serial+20))
		f.g.Spec.Tags = []string{"tag:mesh", "tag:fabric"}
		f.g.Spec.AuthKeySecretRef = nil
		f.g.Spec.Adoption = nil
		gatewayWriterMust(t, admin.Create(ctx, f.g), "admit writer gateway")
		f.writes = &gatewayWriterClient{Client: admin}
		f.r = &controller.TailnetGatewayReconciler{Client: f.writes, RuntimeClient: f.writes, OperatorNamespace: name}
		return f
	}

	t.Run("suspended creates nothing", func(t *testing.T) {
		f := newFixture(t, true)
		f.reconcile("Suspended")
		f.assertMints(0)
		f.assertNoRuntime()
		if f.writes.writes != 0 {
			t.Fatal("suspended gateway attempted a runtime write")
		}
	})

	t.Run("create once and survive status and metadata revisions", func(t *testing.T) {
		f := newFixture(t, false)
		f.reconcile("Provisioning")
		f.assertComplete()
		f.assertMints(1)
		// The first reconcile already changed Gateway status/RV. Explicit status
		// and metadata changes on both CRs must not invalidate a completed set.
		gatewayWriterMust(t, admin.Get(ctx, client.ObjectKeyFromObject(f.g), f.g), "read gateway before metadata change")
		f.g.Annotations = map[string]string{"test.example/metadata": "changed"}
		gatewayWriterMust(t, admin.Update(ctx, f.g), "update gateway metadata")
		f.g.Status.ServiceIP = "198.51.100.17"
		gatewayWriterMust(t, admin.Status().Update(ctx, f.g), "update gateway status")
		f.tn.Annotations = map[string]string{"test.example/metadata": "changed"}
		gatewayWriterMust(t, admin.Update(ctx, f.tn), "update Tailnet metadata")
		f.tn.Status.Conditions = []metav1.Condition{{Type: "Fixture", Status: metav1.ConditionTrue, Reason: "Synthetic", Message: "Synthetic API status only", LastTransitionTime: metav1.Now()}}
		gatewayWriterMust(t, admin.Status().Update(ctx, f.tn), "update Tailnet status")
		sts := &appsv1.StatefulSet{}
		f.get(f.g.Name, sts)
		sts.Status.ObservedGeneration = sts.Generation
		gatewayWriterMust(t, admin.Status().Update(ctx, sts), "update synthetic StatefulSet status")
		cm := &corev1.ConfigMap{}
		f.get(f.g.Name+"-coredns", cm)
		cm.Annotations = map[string]string{"test.example/metadata": "changed"}
		gatewayWriterMust(t, admin.Update(ctx, cm), "update child metadata without payload drift")
		before, writes := f.snapshot(), f.writes.writes
		f.reconcile("Provisioning")
		f.reconcile("Provisioning")
		f.assertUnchanged(before, writes)
		f.assertMints(1)
	})

	t.Run("ready needs synthetic Pod identity and advertised routes", func(t *testing.T) {
		f := newFixture(t, false)
		f.reconcile("Provisioning")
		f.assertComplete()
		// No kubelet runs. This is an independently constructed identity and
		// test-admin Pod/status, not evidence that the workload can bootstrap.
		node := f.seedSyntheticState()
		f.hs.setNodes([]headscale.Node{node})
		f.reconcile("Provisioning") // No Pod yet, even with matching identity.
		f.createSyntheticReadyPod()
		wrong := node
		wrong.MachineKey = key.NewMachine().Public().String()
		f.hs.setNodes([]headscale.Node{wrong})
		f.reconcile("Provisioning") // PodReady alone cannot attest identity.
		missingRoutes := node
		missingRoutes.AvailableRoutes = nil
		f.hs.setNodes([]headscale.Node{missingRoutes})
		f.reconcile("Provisioning")
		f.hs.setNodes([]headscale.Node{node})
		before, writes := f.snapshot(), f.writes.writes
		f.reconcile("FreshRuntimeReady")
		if f.g.Status.NodeID != node.ID || f.g.Status.IPv4 != "100.64.0.17" || !slices.Equal(f.g.Status.RoutesAdvertised, node.AvailableRoutes) {
			t.Fatal("Ready status is not bound to independently supplied state and routes")
		}
		f.reconcile("FreshRuntimeReady")
		f.assertUnchanged(before, writes)
		f.assertMints(1)
	})

	t.Run("ready with numeric route ordering", func(t *testing.T) {
		f := newFixture(t, false)
		f.g.Spec.Routes.LAN = []tnv1.GatewayPrefix{"10.2.0.0/16", "10.10.0.0/16"}
		gatewayWriterMust(t, admin.Update(ctx, f.g), "set differently ordered route prefixes")
		f.reconcile("Provisioning")
		node := f.seedSyntheticState()
		node.AvailableRoutes = []string{"198.51.100.0/24", "10.10.0.0/16", "10.2.0.0/16"}
		f.hs.setNodes([]headscale.Node{node})
		f.createSyntheticReadyPod()
		f.reconcile("FreshRuntimeReady")
		f.assertMints(1)
	})

	for _, change := range []string{"state replacement", "child payload drift", "child replacement", "auth replacement"} {
		t.Run("blocks "+change, func(t *testing.T) {
			f := newFixture(t, false)
			f.reconcile("Provisioning")
			f.assertComplete()
			switch change {
			case "state replacement", "auth replacement":
				name := string(f.g.Spec.StateSecretRef.Name)
				if change == "auth replacement" {
					name = f.g.Name + "-auth"
				}
				s := &corev1.Secret{}
				f.get(name, s)
				old := s.UID
				gatewayWriterMust(t, admin.Delete(ctx, s), "delete retained Secret as test admin")
				s.ResourceVersion, s.UID = "", ""
				gatewayWriterMust(t, admin.Create(ctx, s), "recreate same Secret payload as test admin")
				if s.UID == old {
					t.Fatal("Secret replacement did not change identity")
				}
			case "child payload drift":
				cm := &corev1.ConfigMap{}
				f.get(f.g.Name+"-coredns", cm)
				cm.Data["Corefile"] += "\n# synthetic drift\n"
				gatewayWriterMust(t, admin.Update(ctx, cm), "change child payload")
			case "child replacement":
				cm := &corev1.ConfigMap{}
				f.get(f.g.Name+"-coredns", cm)
				gatewayWriterMust(t, admin.Delete(ctx, cm), "delete child as test admin")
				cm.ResourceVersion, cm.UID = "", ""
				gatewayWriterMust(t, admin.Create(ctx, cm), "replace child with identical payload")
			}
			before, writes := f.snapshot(), f.writes.writes
			f.reconcile("FreshBlocked")
			f.reconcile("FreshBlocked")
			f.assertUnchanged(before, writes)
			f.assertMints(1)
		})
	}

	for _, occupied := range []string{"state", "auth", "receipt", "service account", "hosts owner", "pod name", "orphan selector"} {
		t.Run("preoccupied "+occupied, func(t *testing.T) {
			f := newFixture(t, false)
			var obj client.Object
			switch occupied {
			case "state":
				obj = &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: string(f.g.Spec.StateSecretRef.Name), Namespace: f.ns}}
			case "auth":
				obj = &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: f.g.Name + "-auth", Namespace: f.ns}}
			case "receipt":
				obj = &corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Name: f.g.Name + "-fresh", Namespace: f.ns}}
			case "service account":
				obj = &corev1.ServiceAccount{ObjectMeta: metav1.ObjectMeta{Name: f.g.Name, Namespace: f.ns}}
			case "pod name", "orphan selector":
				name := f.g.Name + "-0"
				if occupied == "orphan selector" {
					name = "foreign-orphan"
				}
				obj = &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: f.ns, Labels: map[string]string{"tsunaro.io/gateway-uid": string(f.g.UID)}}, Spec: corev1.PodSpec{Containers: []corev1.Container{{Name: "foreign", Image: "fixture.invalid/unused:v1.0.0"}}}}
			case "hosts owner":
				cm := &corev1.ConfigMap{}
				f.get("hosts", cm)
				cm.OwnerReferences[0].UID = "foreign-tailnet"
				gatewayWriterMust(t, admin.Update(ctx, cm), "replace hosts owner with foreign UID")
			}
			if obj != nil {
				gatewayWriterMust(t, admin.Create(ctx, obj), "occupy runtime name")
			}
			before := f.snapshot()
			f.reconcile("FreshBlocked")
			f.reconcile("FreshBlocked")
			f.assertMints(0)
			f.assertUnchanged(before, 0)
		})
	}

	for _, fault := range []string{"lost state create response", "lost auth create response", "partial child create failure"} {
		t.Run(fault, func(t *testing.T) {
			f := newFixture(t, false)
			switch fault {
			case "lost state create response":
				f.writes.failName, f.writes.afterCreate = string(f.g.Spec.StateSecretRef.Name), true
			case "lost auth create response":
				f.writes.failName, f.writes.afterCreate = f.g.Name+"-auth", true
			case "partial child create failure":
				f.writes.failName = f.g.Name + "-coredns"
			}
			f.reconcile("FreshBlocked")
			if !f.writes.failed {
				t.Fatal("fault injection was not exercised")
			}
			state := &corev1.Secret{}
			f.get(string(f.g.Spec.StateSecretRef.Name), state)
			if len(state.Data) != 0 || len(state.OwnerReferences) != 0 {
				t.Fatal("partial failure changed or GC-owned retained state")
			}
			f.absent(f.g.Name+"-fresh", &corev1.ConfigMap{})
			f.absent(f.g.Name, &appsv1.StatefulSet{})
			wantMints := 1
			if fault == "lost state create response" {
				wantMints = 0
				f.absent(f.g.Name+"-auth", &corev1.Secret{})
			} else {
				auth := &corev1.Secret{}
				f.get(f.g.Name+"-auth", auth)
				if auth.Immutable == nil || !*auth.Immutable || len(auth.OwnerReferences) != 0 {
					t.Fatal("partial failure did not retain immutable auth")
				}
			}
			if fault != "partial child create failure" {
				f.absent(f.g.Name+"-auth-receipt", &corev1.ConfigMap{})
			} else {
				f.get(f.g.Name, &corev1.ServiceAccount{})
				f.get(f.g.Name, &rbacv1.Role{})
				f.get(f.g.Name, &rbacv1.RoleBinding{})
			}
			before, writes := f.snapshot(), f.writes.writes
			// A new reconciler has no process-local recovery information. Retained
			// ambiguity must block rather than recover the Create UID from a Get.
			f.r = &controller.TailnetGatewayReconciler{Client: f.writes, RuntimeClient: f.writes, OperatorNamespace: f.ns}
			f.reconcile("FreshBlocked")
			f.reconcile("FreshBlocked")
			f.assertUnchanged(before, writes)
			f.assertMints(wantMints)
		})
	}

	gatewayTeardownCases(t, newFixture)
	gatewayDNSLiveCases(t, newFixture, admin, ctx)
	gatewayUpdateCases(t, newFixture, admin, ctx)
}

func gatewayWriterMust(t *testing.T, err error, message string) {
	t.Helper()
	if err != nil {
		t.Fatal(message)
	} // Never dump REST bodies, Secrets or private state.
}

type gatewayWriterHeadscale struct {
	t     *testing.T
	mu    sync.Mutex
	mints int
	nodes []headscale.Node
	// Teardown observations and fault injection.
	deletedNodes, expiredKeys []string
	failDelete                bool
}

func (h *gatewayWriterHeadscale) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if r.Header.Get("Authorization") != "Bearer synthetic-working-token" {
		h.t.Error("Headscale request did not use the working API credential")
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	switch {
	case r.Method == http.MethodGet && r.URL.Path == "/api/v1/node":
		if err := json.NewEncoder(w).Encode(map[string]any{"nodes": h.nodes}); err != nil {
			h.t.Error("encode synthetic node response")
		}
	case r.Method == http.MethodPost && r.URL.Path == "/api/v1/preauthkey":
		h.mints++
		var req headscale.CreatePreAuthKeyRequest
		decoder := json.NewDecoder(r.Body)
		decoder.DisallowUnknownFields()
		if decoder.Decode(&req) != nil || req.Ephemeral || !req.Reusable || !slices.Equal(req.ACLTags, []string{"tag:fabric", "tag:mesh"}) || !req.Expiration.After(time.Now()) {
			h.t.Error("mint request must be reusable, non-ephemeral, sorted and future-bounded")
			http.Error(w, "invalid synthetic mint", http.StatusBadRequest)
			return
		}
		issued := headscale.PreAuthKey{ID: "9", Key: "synthetic-fresh-registration-key", Reusable: true, Ephemeral: false, ACLTags: slices.Clone(req.ACLTags), Expiration: req.Expiration}
		if err := json.NewEncoder(w).Encode(map[string]any{"preAuthKey": issued}); err != nil {
			h.t.Error("encode synthetic mint response")
		}
	case r.Method == http.MethodDelete && strings.HasPrefix(r.URL.Path, "/api/v1/node/"):
		if h.failDelete {
			http.Error(w, "synthetic outage", http.StatusInternalServerError)
			return
		}
		id := strings.TrimPrefix(r.URL.Path, "/api/v1/node/")
		h.deletedNodes = append(h.deletedNodes, id)
		h.nodes = slices.DeleteFunc(h.nodes, func(n headscale.Node) bool { return n.ID == id })
		_, _ = w.Write([]byte("{}"))
	case r.Method == http.MethodPost && r.URL.Path == "/api/v1/preauthkey/expire":
		var req map[string]string
		if json.NewDecoder(r.Body).Decode(&req) != nil || req["id"] == "" {
			http.Error(w, "invalid synthetic expire", http.StatusBadRequest)
			return
		}
		h.expiredKeys = append(h.expiredKeys, req["id"])
		_, _ = w.Write([]byte("{}"))
	default:
		h.t.Error("unexpected Headscale operation")
		http.Error(w, "unsupported", http.StatusNotFound)
	}
}

func (h *gatewayWriterHeadscale) setNodes(nodes []headscale.Node) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.nodes = nodes
}

// Faults wrap real API persistence. afterCreate simulates the server committing
// the object while its successful response never reaches the reconciler.
type gatewayWriterClient struct {
	client.Client
	failName            string
	afterCreate, failed bool
	writes              int
}

func (c *gatewayWriterClient) Create(ctx context.Context, obj client.Object, opts ...client.CreateOption) error {
	c.writes++
	if obj.GetName() == c.failName && !c.failed {
		c.failed = true
		if c.afterCreate {
			if err := c.Client.Create(ctx, obj, opts...); err != nil {
				return err
			}
		}
		return errors.New("synthetic fixed create failure")
	}
	return c.Client.Create(ctx, obj, opts...)
}
func (c *gatewayWriterClient) Update(ctx context.Context, obj client.Object, opts ...client.UpdateOption) error {
	c.writes++
	return c.Client.Update(ctx, obj, opts...)
}
func (c *gatewayWriterClient) Patch(ctx context.Context, obj client.Object, patch client.Patch, opts ...client.PatchOption) error {
	c.writes++
	return c.Client.Patch(ctx, obj, patch, opts...)
}
func (c *gatewayWriterClient) Delete(ctx context.Context, obj client.Object, opts ...client.DeleteOption) error {
	c.writes++
	return c.Client.Delete(ctx, obj, opts...)
}
func (c *gatewayWriterClient) DeleteAllOf(ctx context.Context, obj client.Object, opts ...client.DeleteAllOfOption) error {
	c.writes++
	return c.Client.DeleteAllOf(ctx, obj, opts...)
}

type gatewayWriterFixture struct {
	t      *testing.T
	ctx    context.Context
	c      client.Client
	ns     string
	g      *tnv1.TailnetGateway
	tn     *tnv1.Tailnet
	hs     *gatewayWriterHeadscale
	writes *gatewayWriterClient
	r      *controller.TailnetGatewayReconciler
}

func (f *gatewayWriterFixture) reconcile(reason string) {
	f.t.Helper()
	_, err := f.r.Reconcile(f.ctx, ctrl.Request{NamespacedName: client.ObjectKeyFromObject(f.g)})
	gatewayWriterMust(f.t, err, "reconcile gateway writer")
	gatewayWriterMust(f.t, f.c.Get(f.ctx, client.ObjectKeyFromObject(f.g), f.g), "read reconciled gateway")
	ready := meta.FindStatusCondition(f.g.Status.Conditions, "Ready")
	want := metav1.ConditionFalse
	if reason == "FreshRuntimeReady" {
		want = metav1.ConditionTrue
	}
	if ready == nil || ready.Reason != reason || ready.Status != want || ready.ObservedGeneration != f.g.Generation {
		// Only bounded reason/status strings, never object or error dumps.
		if ready == nil {
			f.t.Fatal("missing Ready condition")
		}
		f.t.Fatalf("Ready mismatch: want %s/%s, got %s/%s", reason, want, ready.Reason, ready.Status)
	}
}
func (f *gatewayWriterFixture) get(name string, obj client.Object) {
	f.t.Helper()
	gatewayWriterMust(f.t, f.c.Get(f.ctx, client.ObjectKey{Namespace: f.ns, Name: name}, obj), "read expected writer resource")
}
func (f *gatewayWriterFixture) absent(name string, obj client.Object) {
	f.t.Helper()
	if !apierrors.IsNotFound(f.c.Get(f.ctx, client.ObjectKey{Namespace: f.ns, Name: name}, obj)) {
		f.t.Fatal("unexpected or unreadable runtime resource")
	}
}
func (f *gatewayWriterFixture) assertMints(want int) {
	f.t.Helper()
	f.hs.mu.Lock()
	defer f.hs.mu.Unlock()
	if f.hs.mints != want {
		f.t.Fatalf("want %d mints, got %d", want, f.hs.mints)
	}
}
func (f *gatewayWriterFixture) objects() []client.Object {
	name := f.g.Name
	objects := []client.Object{
		&corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: string(f.g.Spec.StateSecretRef.Name)}},
		&corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: name + "-auth"}},
		&corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Name: name + "-auth-receipt"}},
		&corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Name: name + "-fresh"}},
		&corev1.ServiceAccount{ObjectMeta: metav1.ObjectMeta{Name: name}},
		&rbacv1.Role{ObjectMeta: metav1.ObjectMeta{Name: name}},
		&rbacv1.RoleBinding{ObjectMeta: metav1.ObjectMeta{Name: name}},
		&corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Name: name + "-coredns"}},
		&corev1.Service{ObjectMeta: metav1.ObjectMeta{Name: name + "-headless"}},
		&corev1.Service{ObjectMeta: metav1.ObjectMeta{Name: string(f.g.Spec.DNS.ServiceName)}},
		&corev1.Service{ObjectMeta: metav1.ObjectMeta{Name: name}},
		&policyv1.PodDisruptionBudget{ObjectMeta: metav1.ObjectMeta{Name: name}},
		&appsv1.StatefulSet{ObjectMeta: metav1.ObjectMeta{Name: name}},
	}
	for _, obj := range objects {
		obj.SetNamespace(f.ns)
	}
	return objects
}
func (f *gatewayWriterFixture) assertNoRuntime() {
	f.t.Helper()
	for _, obj := range f.objects() {
		f.absent(obj.GetName(), obj)
	}
}
func (f *gatewayWriterFixture) snapshot() map[string]string {
	f.t.Helper()
	out := map[string]string{}
	for _, obj := range f.objects() {
		err := f.c.Get(f.ctx, client.ObjectKeyFromObject(obj), obj)
		if apierrors.IsNotFound(err) {
			continue
		}
		gatewayWriterMust(f.t, err, "snapshot retained resource")
		out[fmt.Sprintf("%T/%s", obj, obj.GetName())] = string(obj.GetUID()) + "/" + obj.GetResourceVersion()
	}
	return out
}
func (f *gatewayWriterFixture) assertUnchanged(before map[string]string, writes int) {
	f.t.Helper()
	if f.writes.writes != writes || !reflect.DeepEqual(before, f.snapshot()) {
		f.t.Fatal("reconciliation wrote or replaced retained runtime resources")
	}
}
func (f *gatewayWriterFixture) assertComplete() {
	f.t.Helper()
	for _, obj := range f.objects() {
		f.get(obj.GetName(), obj)
		if obj.GetUID() == "" || len(obj.GetOwnerReferences()) != 0 {
			f.t.Fatal("writer child lacks API identity or has GC ownership")
		}
	}
	// Exercise the real allocator, not a client override of rendered Services.
	// Reverting to envtest's default /24 fails this check deterministically,
	// rather than waiting for a random collision with a later fixture's DNS IP.
	lb := &corev1.Service{}
	f.get(f.g.Name, lb)
	dynamicIP, err := netip.ParseAddr(lb.Spec.ClusterIP)
	dnsRange := netip.MustParsePrefix("10.0.0.0/24")
	if err != nil || !netip.MustParsePrefix(gatewayWriterServiceCIDR).Contains(dynamicIP) || dnsRange.Contains(dynamicIP) ||
		!dnsRange.Contains(netip.MustParseAddr(string(f.g.Spec.DNS.ServiceClusterIP))) {
		f.t.Fatal("fixture Service allocator must separate dynamic LB and fixed DNS addresses")
	}
	state := &corev1.Secret{}
	f.get(string(f.g.Spec.StateSecretRef.Name), state)
	if len(state.Data) != 0 || state.Immutable != nil && *state.Immutable {
		f.t.Fatal("initial state must be empty and mutable")
	}
	auth := &corev1.Secret{}
	f.get(f.g.Name+"-auth", auth)
	if auth.Immutable == nil || !*auth.Immutable {
		f.t.Fatal("auth Secret must be immutable")
	}
	cm := &corev1.ConfigMap{}
	f.get(f.g.Name+"-fresh", cm)
	if cm.Immutable == nil || !*cm.Immutable {
		f.t.Fatal("completion receipt must be immutable")
	}
	var receipt struct {
		Scope    map[string]string          `json:"scope"`
		StateUID types.UID                  `json:"stateUID"`
		Auth     gateway.GatewayAuthReceipt `json:"auth"`
		Objects  []struct {
			Kind   string    `json:"kind"`
			Name   string    `json:"name"`
			UID    types.UID `json:"uid"`
			Digest string    `json:"digest"`
		} `json:"objects"`
		Routes []string `json:"routes"`
	}
	gatewayWriterMust(f.t, json.Unmarshal([]byte(cm.Data["receipt.json"]), &receipt), "decode completion receipt")
	if receipt.StateUID != state.UID || receipt.Auth.UID != auth.UID || receipt.Auth.KeyID != "9" || len(receipt.Objects) != 10 || receipt.Scope["gatewayUID"] != string(f.g.UID) || receipt.Scope["tailnetUID"] != string(f.tn.UID) {
		f.t.Fatal("completion receipt did not capture original API identities")
	}
	// Format 3 pins identity hashes, never generations or full specs.
	hex64 := func(v string) bool { b, err := hex.DecodeString(v); return err == nil && len(b) == sha256.Size }
	if len(receipt.Scope) != 7 || receipt.Scope["format"] != "3" || receipt.Scope["gatewayName"] != f.g.Name || receipt.Scope["tailnetName"] != f.tn.Name ||
		!hex64(receipt.Scope["gatewayIdentitySHA256"]) || !hex64(receipt.Scope["tailnetIdentitySHA256"]) {
		f.t.Fatal("completion scope is not the identity-only format 3")
	}
	seen := map[string]bool{}
	for _, ref := range receipt.Objects {
		id := ref.Kind + "/" + ref.Name
		if seen[id] || ref.UID == "" || len(ref.Digest) != 64 {
			f.t.Fatal("invalid child receipt identity or digest")
		}
		seen[id] = true
		found := false
		for _, obj := range f.objects()[2:] {
			gvks, _, err := f.c.Scheme().ObjectKinds(obj)
			gatewayWriterMust(f.t, err, "identify expected child kind")
			if gvks[0].Kind == ref.Kind && obj.GetName() == ref.Name {
				f.get(ref.Name, obj)
				found = obj.GetUID() == ref.UID
				encoded, err := json.Marshal(obj)
				gatewayWriterMust(f.t, err, "encode admitted child payload")
				var payload map[string]any
				gatewayWriterMust(f.t, json.Unmarshal(encoded, &payload), "decode admitted child payload")
				for _, field := range []string{"apiVersion", "kind", "metadata", "status"} {
					delete(payload, field)
				}
				// Container images and the tailscale TS_ROUTES follow the spec
				// (UpdateWorkloadRevision); the receipt binds every other field.
				if ref.Kind == "StatefulSet" {
					spec, _ := payload["spec"].(map[string]any)
					template, _ := spec["template"].(map[string]any)
					podSpec, _ := template["spec"].(map[string]any)
					for _, key := range []string{"initContainers", "containers"} {
						list, _ := podSpec[key].([]any)
						for _, item := range list {
							c := item.(map[string]any)
							delete(c, "image")
							if c["name"] == "tailscale" {
								env, _ := c["env"].([]any)
								for _, e := range env {
									if e := e.(map[string]any); e["name"] == "TS_ROUTES" {
										delete(e, "value")
									}
								}
							}
						}
					}
				}
				// The derived DNS zone is reconciled live from the Tailnet hosts
				// source, so the completion fingerprint excludes it; the fresh
				// writer and this re-computation drop the same key.
				if ref.Kind == "ConfigMap" && strings.HasSuffix(ref.Name, "-coredns") {
					if data, ok := payload["data"].(map[string]any); ok {
						delete(data, "zone.db")
					}
				}
				encoded, err = json.Marshal(payload)
				gatewayWriterMust(f.t, err, "encode exact child payload digest")
				hash := sha256.Sum256(encoded)
				if ref.Digest != hex.EncodeToString(hash[:]) {
					f.t.Fatal("receipt digest does not cover exact admitted child payload")
				}
				break
			}
		}
		if !found {
			f.t.Fatal("receipt child UID not captured from created API object")
		}
	}
	if len(receipt.Routes) != 2 || !slices.Equal(receipt.Routes, []string{"192.0.2.0/24", "198.51.100.0/24"}) {
		f.t.Fatal("receipt did not retain advertised route plan")
	}
}
func (f *gatewayWriterFixture) seedSyntheticState() headscale.Node {
	f.t.Helper()
	machine, node := key.NewMachine(), key.NewNode()
	machineText, err := machine.MarshalText()
	gatewayWriterMust(f.t, err, "generate synthetic machine state")
	nodeText, err := node.MarshalText()
	gatewayWriterMust(f.t, err, "generate synthetic node state")
	profile, err := json.Marshal(map[string]any{"ControlURL": f.tn.Spec.Server, "Config": map[string]string{"PrivateNodeKey": string(nodeText)}})
	gatewayWriterMust(f.t, err, "encode synthetic profile")
	state := &corev1.Secret{}
	f.get(string(f.g.Spec.StateSecretRef.Name), state)
	state.Data = map[string][]byte{"_machinekey": machineText, "_current-profile": []byte("profile-abc123"), "profile-abc123": profile}
	gatewayWriterMust(f.t, f.c.Update(f.ctx, state), "seed synthetic independent persistent identity")
	return headscale.Node{ID: "17", GivenName: f.g.Spec.Hostname, MachineKey: machine.Public().String(), NodeKey: node.Public().String(), Online: true, Tags: []string{"tag:fabric", "tag:mesh"}, IPAddresses: []string{"100.64.0.17"}, PreAuthKey: &headscale.NodeAuthKey{ID: "9"}, AvailableRoutes: []string{"192.0.2.0/24", "198.51.100.0/24"}}
}
func (f *gatewayWriterFixture) createSyntheticReadyPod() {
	f.t.Helper()
	sts := &appsv1.StatefulSet{}
	f.get(f.g.Name, sts)
	pod := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: f.g.Name + "-0", Namespace: f.ns, Labels: sts.Spec.Template.Labels, OwnerReferences: []metav1.OwnerReference{*metav1.NewControllerRef(sts, appsv1.SchemeGroupVersion.WithKind("StatefulSet"))}}, Spec: *sts.Spec.Template.Spec.DeepCopy()}
	gatewayWriterMust(f.t, f.c.Create(f.ctx, pod), "admit synthetic Pod without kubelet")
	pod.Status.Phase = corev1.PodRunning
	pod.Status.Conditions = []corev1.PodCondition{{Type: corev1.PodReady, Status: corev1.ConditionTrue}}
	for _, container := range pod.Spec.Containers {
		pod.Status.ContainerStatuses = append(pod.Status.ContainerStatuses, corev1.ContainerStatus{Name: container.Name, Image: container.Image, ImageID: "synthetic-image", Ready: true, State: corev1.ContainerState{Running: &corev1.ContainerStateRunning{StartedAt: metav1.Now()}}})
	}
	gatewayWriterMust(f.t, f.c.Status().Update(f.ctx, pod), "synthesize Ready status without kubelet")
}
