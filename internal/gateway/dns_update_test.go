package gateway

import (
	"context"
	"errors"
	"net/netip"
	"strings"
	"testing"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/utils/ptr"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	tnv1 "tsunaro.io/tailnet-operator/api/v1alpha1"
)

type dnsUpdateClient struct {
	client.Client
	updates      int
	conflictOnce bool
}

func (c *dnsUpdateClient) Update(ctx context.Context, obj client.Object, opts ...client.UpdateOption) error {
	c.updates++
	if c.conflictOnce {
		c.conflictOnce = false
		cm := &corev1.ConfigMap{}
		if err := c.Client.Get(ctx, client.ObjectKeyFromObject(obj), cm); err != nil {
			return err
		}
		cm.Labels["other.example/harmless"] = "concurrent"
		if err := c.Client.Update(ctx, cm); err != nil {
			return err
		}
	}
	return c.Client.Update(ctx, obj, opts...)
}

func dnsUpdateFixture(t *testing.T) *dnsUpdateClient {
	t.Helper()
	in := freshInspectionFixture(t)
	g, tn, source := in.Fresh.Gateway, in.Fresh.Tailnet, in.Hosts
	g.Spec.Suspend = ptr.To(false) // Synthetic bypass; CRD admission still rejects this.
	g.Spec.DNS.Image = "coredns/coredns:1.14.6"
	dnsInput := DNSInputs{Config: g.Spec.DNS, ServerIP: string(g.Spec.Service.LoadBalancerIP), Hosts: source.Data["hosts"], BindAddresses: []netip.Addr{netip.IPv4Unspecified()}}
	plan, err := PlanDNSRevision(dnsInput, nil)
	if err != nil {
		t.Fatal(err)
	}
	dnsInput.Serial = plan.Serial
	files, err := RenderDNS(dnsInput)
	if err != nil {
		t.Fatal(err)
	}
	target := &corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Name: "router-coredns", Namespace: "operator", UID: "target-uid", ResourceVersion: "14",
		Labels:      map[string]string{gatewayUIDLabel: string(g.UID), "app.kubernetes.io/managed-by": "tailnet-operator"},
		Annotations: map[string]string{DNSSerialAnnotation: "1", DNSHashAnnotation: plan.ContentHash}},
		Data: map[string]string{"Corefile": files.Corefile, DNSZoneFile: files.ZoneFile}}
	scheme := runtime.NewScheme()
	for _, add := range []func(*runtime.Scheme) error{corev1.AddToScheme, tnv1.AddToScheme} {
		if err := add(scheme); err != nil {
			t.Fatal(err)
		}
	}
	return &dnsUpdateClient{Client: fake.NewClientBuilder().WithScheme(scheme).WithObjects(g, tn, source, target).Build()}
}

func TestDNSUpdateCASAndNoop(t *testing.T) {
	ctx := context.Background()
	c := dnsUpdateFixture(t)
	if err := UpdateDNSRevision(ctx, c, "router", "operator"); err != nil || c.updates != 0 {
		t.Fatal("unchanged DNS produced a write")
	}
	key := types.NamespacedName{Name: "tailnet-hosts", Namespace: "operator"}
	source := &corev1.ConfigMap{}
	if c.Get(ctx, key, source) != nil {
		t.Fatal("missing source")
	}
	source.Data["hosts"] += "203.0.113.3\tnew.tail.example\n"
	if err := c.Client.Update(ctx, source); err != nil {
		t.Fatal(err)
	}
	c.conflictOnce = true
	if err := UpdateDNSRevision(ctx, c, "router", "operator"); err != nil || c.updates != 2 {
		t.Fatalf("conflict was not recomputed from fresh reads: %v", err)
	}
	target := &corev1.ConfigMap{}
	if c.Get(ctx, types.NamespacedName{Name: "router-coredns", Namespace: "operator"}, target) != nil {
		t.Fatal("updated DNS unavailable")
	}
	got, err := ReadDNSRevision(target, "tail.example")
	if err != nil || got.Serial != 2 || !strings.Contains(target.Data[DNSZoneFile], "new.tail.example. 30 IN A 203.0.113.3") {
		t.Fatal("hosts-only update lost the serial or zone data")
	}
	if err := UpdateDNSRevision(ctx, c, "router", "operator"); err != nil || c.updates != 2 {
		t.Fatal("restart churned the persisted revision")
	}
}

func TestDNSUpdateNeverCreatesOrAdopts(t *testing.T) {
	ctx := context.Background()
	for name, mutate := range map[string]func(context.Context, *dnsUpdateClient){
		"suspended": func(ctx context.Context, c *dnsUpdateClient) {
			g := &tnv1.TailnetGateway{}
			_ = c.Get(ctx, types.NamespacedName{Name: "router"}, g)
			g.Spec.Suspend = ptr.To(true)
			_ = c.Client.Update(ctx, g)
		},
		"missing target": func(ctx context.Context, c *dnsUpdateClient) {
			cm := &corev1.ConfigMap{}
			_ = c.Get(ctx, types.NamespacedName{Name: "router-coredns", Namespace: "operator"}, cm)
			_ = c.Client.Delete(ctx, cm)
		},
		"foreign target": func(ctx context.Context, c *dnsUpdateClient) {
			cm := &corev1.ConfigMap{}
			_ = c.Get(ctx, types.NamespacedName{Name: "router-coredns", Namespace: "operator"}, cm)
			cm.Labels[gatewayUIDLabel] = "foreign"
			_ = c.Client.Update(ctx, cm)
		},
		"missing revision": func(ctx context.Context, c *dnsUpdateClient) {
			cm := &corev1.ConfigMap{}
			_ = c.Get(ctx, types.NamespacedName{Name: "router-coredns", Namespace: "operator"}, cm)
			delete(cm.Annotations, DNSHashAnnotation)
			_ = c.Client.Update(ctx, cm)
		},
		"foreign hosts": func(ctx context.Context, c *dnsUpdateClient) {
			cm := &corev1.ConfigMap{}
			_ = c.Get(ctx, types.NamespacedName{Name: "tailnet-hosts", Namespace: "operator"}, cm)
			cm.OwnerReferences[0].UID = "foreign"
			_ = c.Client.Update(ctx, cm)
		},
	} {
		t.Run(name, func(t *testing.T) {
			c := dnsUpdateFixture(t)
			mutate(ctx, c)
			if err := UpdateDNSRevision(ctx, c, "router", "operator"); !errors.Is(err, ErrDNSWriteBlocked) || c.updates != 0 {
				t.Fatalf("unsafe DNS update accepted: %v", err)
			}
		})
	}
}
