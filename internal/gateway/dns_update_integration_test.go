//go:build integration

package gateway

import (
	"context"
	"errors"
	"net/netip"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/rest"
	"k8s.io/utils/ptr"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/envtest"

	tnv1 "tsunaro.io/tailnet-operator/api/v1alpha1"
)

// dnsAPIExerciseClient changes only the in-memory suspend observation; stored
// fixtures remain suspended. This is a ConfigMap CAS experiment, NOT evidence
// that a suspended CR may write DNS.
// All UIDs, resourceVersions, reads and writes otherwise come from the API server.
// Hooks force deterministic races; they never manufacture API conflict errors.
type dnsAPIExerciseClient struct {
	client.Client
	beforeUpdate func(client.Object)
	afterGet     func(client.Object)
	attempts     int
	conflicts    int
}

func (c *dnsAPIExerciseClient) Get(ctx context.Context, key client.ObjectKey, obj client.Object, opts ...client.GetOption) error {
	if err := c.Client.Get(ctx, key, obj, opts...); err != nil {
		return err
	}
	if g, ok := obj.(*tnv1.TailnetGateway); ok {
		g.Spec.Suspend = ptr.To(false)
	}
	if c.afterGet != nil {
		c.afterGet(obj)
	}
	return nil
}

func (c *dnsAPIExerciseClient) Update(ctx context.Context, obj client.Object, opts ...client.UpdateOption) error {
	c.attempts++
	if c.beforeUpdate != nil {
		c.beforeUpdate(obj)
	}
	err := c.Client.Update(ctx, obj, opts...)
	if apierrors.IsConflict(err) {
		c.conflicts++
	}
	return err
}

func TestDNSUpdateAPICAS(t *testing.T) {
	// Do not discover an existing cluster or inherit alternate executable/etcd
	// settings. These changes are confined to this dedicated test process.
	for _, variable := range os.Environ() {
		name, _, _ := strings.Cut(variable, "=")
		if strings.HasPrefix(name, "ETCD_") || strings.HasPrefix(name, "TEST_ASSET_") {
			if err := os.Unsetenv(name); err != nil {
				t.Fatal("clear envtest override")
			}
		}
	}
	assets := os.Getenv("KUBEBUILDER_ASSETS")
	if !filepath.IsAbs(assets) {
		t.Fatal("explicit absolute isolated envtest assets required")
	}
	env := &envtest.Environment{
		UseExistingCluster: ptr.To(false), BinaryAssetsDirectory: assets,
		CRDDirectoryPaths: []string{filepath.Join("..", "..", "deploy", "crds")}, ErrorIfCRDPathMissing: true,
		ControlPlaneStartTimeout: 30 * time.Second, ControlPlaneStopTimeout: 10 * time.Second,
	}
	t.Cleanup(func() {
		if err := env.Stop(); err != nil {
			t.Error("stop isolated DNS API server")
		}
	})
	cfg, err := env.Start()
	if err != nil {
		t.Fatal("start isolated DNS API server")
	}
	scheme := runtime.NewScheme()
	for _, add := range []func(*runtime.Scheme) error{corev1.AddToScheme, tnv1.AddToScheme} {
		if err := add(scheme); err != nil {
			t.Fatal("register DNS API types")
		}
	}
	newClient := func(t *testing.T) client.Client {
		t.Helper()
		c, err := client.New(rest.CopyConfig(cfg), client.Options{Scheme: scheme})
		if err != nil {
			t.Fatal("construct isolated DNS client")
		}
		return c
	}
	admin := newClient(t)
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	t.Cleanup(cancel)
	must := func(t *testing.T, err error) {
		t.Helper()
		if err != nil {
			t.Fatal("DNS API fixture operation failed")
		}
	}
	readMap := func(t *testing.T, key client.ObjectKey) *corev1.ConfigMap {
		t.Helper()
		cm := &corev1.ConfigMap{}
		must(t, admin.Get(ctx, key, cm))
		return cm
	}
	// Start above serial 1 so a reset or an increment based on stale memory
	// cannot accidentally satisfy the assertions.
	fixture := func(t *testing.T, name string) (*tnv1.TailnetGateway, *corev1.ConfigMap, *corev1.ConfigMap) {
		t.Helper()
		in := freshInspectionFixture(t)
		g, tn, source := in.Fresh.Gateway, in.Fresh.Tailnet, in.Hosts
		g.Name, g.UID, g.ResourceVersion = name, "", ""
		g.Spec.TailnetRef.Name = tnv1.GatewayName(name)
		tn.Name, tn.UID, tn.ResourceVersion = name, "", ""
		tn.Spec.APISecretRef = tnv1.SecretKeyRef{Name: "unused-bootstrap"}
		tn.Spec.APIKeyLifetime = metav1.Duration{Duration: 24 * time.Hour}
		must(t, admin.Create(ctx, &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: name}}))
		must(t, admin.Create(ctx, tn))
		must(t, admin.Create(ctx, g))
		source.Namespace, source.UID, source.ResourceVersion = name, "", ""
		source.OwnerReferences[0].Name, source.OwnerReferences[0].UID = tn.Name, tn.UID
		must(t, admin.Create(ctx, source))
		target := &corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{
			Name: g.Name + "-coredns", Namespace: name,
			Labels:      map[string]string{gatewayUIDLabel: string(g.UID), "app.kubernetes.io/managed-by": "tailnet-operator"},
			Annotations: map[string]string{"example.com/retain": "initial"},
		}}
		setDNSAPIRevision(t, target, g, source.Data["hosts"], 7)
		must(t, admin.Create(ctx, target))
		if target.UID == "" || target.ResourceVersion == "" {
			t.Fatal("API did not assign target identity")
		}
		return g, source, target
	}
	changeSource := func(t *testing.T, source *corev1.ConfigMap, hosts string) {
		t.Helper()
		current := readMap(t, client.ObjectKeyFromObject(source))
		current.Data["hosts"] = hosts
		must(t, admin.Update(ctx, current))
	}
	assertRevision := func(t *testing.T, target *corev1.ConfigMap, serial uint32, record string) *corev1.ConfigMap {
		t.Helper()
		current := readMap(t, client.ObjectKeyFromObject(target))
		revision, err := ReadDNSRevision(current, "tail.example")
		if err != nil || revision.Serial != serial || current.UID != target.UID || !strings.Contains(current.Data[DNSZoneFile], record) {
			t.Fatal("persisted DNS revision, identity or payload mismatch")
		}
		return current
	}

	t.Run("activation-admitted-but-stored-suspension-blocks", func(t *testing.T) {
		g, source, target := fixture(t, "dns-suspended")
		changeSource(t, source, "203.0.113.9 changed.tail.example\n")
		active := g.DeepCopy()
		active.Spec.Suspend = ptr.To(false)
		must(t, admin.Update(ctx, active, client.DryRunAll))
		if active.Spec.Suspend == nil || *active.Spec.Suspend {
			t.Fatal("real admission did not preserve explicit activation")
		}
		must(t, admin.Get(ctx, client.ObjectKeyFromObject(g), g))
		if g.Spec.Suspend == nil || !*g.Spec.Suspend {
			t.Fatal("dry-run activation changed stored suspension")
		}
		if err := UpdateDNSRevision(ctx, admin, g.Name, g.Name); !errors.Is(err, ErrDNSWriteBlocked) {
			t.Fatal("real suspended observation permitted DNS write")
		}
		got := readMap(t, client.ObjectKeyFromObject(target))
		if !reflect.DeepEqual(got, target) {
			t.Fatal("suspended DNS target changed")
		}
	})

	t.Run("conflict-recomputes-source-and-serial", func(t *testing.T) {
		g, source, target := fixture(t, "dns-concurrent")
		changeSource(t, source, "203.0.113.8 intermediate.tail.example\n")
		c := &dnsAPIExerciseClient{Client: newClient(t)}
		c.beforeUpdate = func(client.Object) {
			c.beforeUpdate = nil
			// Use a distant serial to distinguish re-reading the winner from
			// merely incrementing a cached serial once more.
			changeSource(t, source, "203.0.113.9 winner.tail.example\n")
			current := readMap(t, client.ObjectKeyFromObject(target))
			setDNSAPIRevision(t, current, g, "203.0.113.9 winner.tail.example\n", 42)
			current.Annotations["example.com/retain"] = "concurrent"
			must(t, admin.Update(ctx, current))
			// The losing writer must re-read this further source change, too.
			changeSource(t, source, "203.0.113.10 final.tail.example\n")
		}
		must(t, UpdateDNSRevision(ctx, c, g.Name, g.Name))
		if c.attempts != 2 || c.conflicts != 1 {
			t.Fatal("expected one real API resourceVersion conflict and retry")
		}
		got := assertRevision(t, target, 43, "final.tail.example. 30 IN A 203.0.113.10")
		if got.Annotations["example.com/retain"] != "concurrent" || strings.Contains(got.Data[DNSZoneFile], "intermediate.tail.example") {
			t.Fatal("retry lost concurrent metadata or used a stale source")
		}
		// A new client/helper invocation has no previous in-memory revision.
		restarted := &dnsAPIExerciseClient{Client: newClient(t)}
		must(t, UpdateDNSRevision(ctx, restarted, g.Name, g.Name))
		if restarted.attempts != 0 || readMap(t, client.ObjectKeyFromObject(target)).ResourceVersion != got.ResourceVersion {
			t.Fatal("unchanged persisted revision churned after client restart")
		}
	})

	t.Run("conflict-to-noop-preserves-winner", func(t *testing.T) {
		g, source, target := fixture(t, "dns-converged")
		const desired = "203.0.113.9 winner.tail.example\n"
		changeSource(t, source, desired)
		c := &dnsAPIExerciseClient{Client: newClient(t)}
		var winner *corev1.ConfigMap
		c.beforeUpdate = func(client.Object) {
			c.beforeUpdate = nil
			winner = readMap(t, client.ObjectKeyFromObject(target))
			setDNSAPIRevision(t, winner, g, desired, 42)
			must(t, admin.Update(ctx, winner))
		}
		must(t, UpdateDNSRevision(ctx, c, g.Name, g.Name))
		if c.attempts != 1 || c.conflicts != 1 {
			t.Fatal("converged conflict caused another write")
		}
		got := assertRevision(t, target, 42, "winner.tail.example. 30 IN A 203.0.113.9")
		if !reflect.DeepEqual(got, winner) {
			t.Fatal("conflict-to-noop changed the winner's revision")
		}
	})

	t.Run("source-recheck-discards-stale-render", func(t *testing.T) {
		g, source, target := fixture(t, "dns-source-race")
		changeSource(t, source, "203.0.113.8 stale.tail.example\n")
		c := &dnsAPIExerciseClient{Client: newClient(t)}
		c.afterGet = func(obj client.Object) {
			if _, ok := obj.(*corev1.ConfigMap); ok && obj.GetName() == source.Name {
				c.afterGet = nil
				// Leave the first returned snapshot stale; its next real GET must
				// discover the changed API resourceVersion before any target write.
				changeSource(t, source, "203.0.113.11 fresh.tail.example\n")
			}
		}
		must(t, UpdateDNSRevision(ctx, c, g.Name, g.Name))
		if c.attempts != 1 || c.conflicts != 0 {
			t.Fatal("source race reached the target writer before revalidation")
		}
		assertRevision(t, target, 8, "fresh.tail.example. 30 IN A 203.0.113.11")
	})

	t.Run("conflict-budget-is-bounded", func(t *testing.T) {
		g, source, target := fixture(t, "dns-exhausted")
		changeSource(t, source, "203.0.113.12 blocked.tail.example\n")
		c := &dnsAPIExerciseClient{Client: newClient(t)}
		c.beforeUpdate = func(client.Object) {
			current := readMap(t, client.ObjectKeyFromObject(target))
			current.Annotations["example.com/retain"] = strconv.Itoa(c.attempts)
			must(t, admin.Update(ctx, current))
		}
		if err := UpdateDNSRevision(ctx, c, g.Name, g.Name); !errors.Is(err, ErrDNSWriteConflict) || c.attempts != 3 || c.conflicts != 3 {
			t.Fatal("real API conflicts did not stop at the retry budget")
		}
		got := assertRevision(t, target, 7, "app.tail.example")
		if !reflect.DeepEqual(got.Data, target.Data) || got.Annotations["example.com/retain"] != "3" {
			t.Fatal("exhausted CAS overwrote the target")
		}
	})

	t.Run("source-recheck-budget-is-bounded", func(t *testing.T) {
		g, source, target := fixture(t, "dns-source-exhausted")
		changeSource(t, source, "203.0.113.8 initial.tail.example\n")
		c := &dnsAPIExerciseClient{Client: newClient(t)}
		sourceReads := 0
		c.afterGet = func(obj client.Object) {
			if _, ok := obj.(*corev1.ConfigMap); !ok || obj.GetName() != source.Name {
				return
			}
			sourceReads++
			if sourceReads%2 == 1 {
				// Invalidate every initial snapshot, not the recheck GET.
				changeSource(t, source, "203.0.113.8 changed"+strconv.Itoa(sourceReads)+".tail.example\n")
			}
		}
		if err := UpdateDNSRevision(ctx, c, g.Name, g.Name); !errors.Is(err, ErrDNSWriteConflict) || sourceReads != 6 || c.attempts != 0 {
			t.Fatal("source revalidation did not stop after three invalidated snapshots")
		}
		if !reflect.DeepEqual(readMap(t, client.ObjectKeyFromObject(target)), target) {
			t.Fatal("exhausted source revalidation changed the target")
		}
	})

	t.Run("deleted-target-is-not-recreated", func(t *testing.T) {
		g, source, target := fixture(t, "dns-deleted")
		changeSource(t, source, "203.0.113.13 blocked.tail.example\n")
		c := &dnsAPIExerciseClient{Client: newClient(t)}
		c.beforeUpdate = func(client.Object) { must(t, admin.Delete(ctx, target)) }
		if err := UpdateDNSRevision(ctx, c, g.Name, g.Name); !errors.Is(err, ErrDNSWriteBlocked) || c.attempts != 1 {
			t.Fatal("missing target was not blocked")
		}
		if err := admin.Get(ctx, client.ObjectKeyFromObject(target), &corev1.ConfigMap{}); !apierrors.IsNotFound(err) {
			t.Fatal("DNS update recreated the missing target")
		}
	})

	t.Run("immutable-target-is-not-replaced", func(t *testing.T) {
		g, source, target := fixture(t, "dns-immutable")
		target.Immutable = ptr.To(true)
		must(t, admin.Update(ctx, target))
		changeSource(t, source, "203.0.113.14 blocked.tail.example\n")
		c := &dnsAPIExerciseClient{Client: newClient(t)}
		if err := UpdateDNSRevision(ctx, c, g.Name, g.Name); !errors.Is(err, ErrDNSWriteBlocked) || c.attempts != 1 || c.conflicts != 0 {
			t.Fatal("immutable target rejection was retried or ignored")
		}
		if !reflect.DeepEqual(readMap(t, client.ObjectKeyFromObject(target)), target) {
			t.Fatal("immutable target changed")
		}
	})
}

func setDNSAPIRevision(t *testing.T, cm *corev1.ConfigMap, g *tnv1.TailnetGateway, hosts string, serial uint32) {
	t.Helper()
	in := DNSInputs{Config: g.Spec.DNS, ServerIP: string(g.Spec.Service.LoadBalancerIP), Hosts: hosts, Serial: serial, BindAddresses: []netip.Addr{netip.IPv4Unspecified()}}
	plan, err := PlanDNSRevision(in, nil)
	if err != nil {
		t.Fatal("plan synthetic API DNS revision")
	}
	files, err := RenderDNS(in)
	if err != nil {
		t.Fatal("render synthetic API DNS revision")
	}
	cm.Data = map[string]string{"Corefile": files.Corefile, DNSZoneFile: files.ZoneFile}
	cm.Annotations[DNSSerialAnnotation] = strconv.FormatUint(uint64(serial), 10)
	cm.Annotations[DNSHashAnnotation] = plan.ContentHash
}
