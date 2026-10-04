package gateway

import (
	"context"
	"errors"
	"testing"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	policyv1 "k8s.io/api/policy/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	tnv1 "tsunaro.io/tailnet-operator/api/v1alpha1"
)

type freshReadGuard struct {
	client.Reader
	denyKind, denyName string
	gets, lists        int
}

func (r *freshReadGuard) Get(ctx context.Context, key client.ObjectKey, obj client.Object, opts ...client.GetOption) error {
	r.gets++
	if freshObjectKind(obj) == r.denyKind && key.Name == r.denyName {
		return errors.New("private-provider-read-error-do-not-emit")
	}
	return r.Reader.Get(ctx, key, obj, opts...)
}

func (r *freshReadGuard) List(ctx context.Context, list client.ObjectList, opts ...client.ListOption) error {
	r.lists++
	return r.Reader.List(ctx, list, opts...)
}

func freshTestReader(t *testing.T, extra ...client.Object) *freshReadGuard {
	t.Helper()
	in := freshInspectionFixture(t)
	s := runtime.NewScheme()
	for _, register := range []func(*runtime.Scheme) error{corev1.AddToScheme, appsv1.AddToScheme, policyv1.AddToScheme, rbacv1.AddToScheme, tnv1.AddToScheme} {
		if err := register(s); err != nil {
			t.Fatal(err)
		}
	}
	objects := []client.Object{in.Fresh.Gateway, in.Fresh.Tailnet, in.State, in.Hosts}
	objects = append(objects, extra...)
	return &freshReadGuard{Reader: fake.NewClientBuilder().WithScheme(s).WithObjects(objects...).Build()}
}

func TestInspectFreshFromReaderIsAlwaysBlocked(t *testing.T) {
	r := freshTestReader(t)
	got, err := InspectFreshFromReader(context.Background(), r, "router", "operator", 1, nil)
	if !errors.Is(err, ErrFreshProvenance) || got.StateUID != types.UID("empty-state-uid") || got.HostsVersion == "" || r.gets != 13 || r.lists != 2 {
		t.Fatalf("read-only inventory unexpectedly authorized or skipped reads: %v", err)
	}
	// Even an apparently absent node is not authentication provenance.
	if _, err := InspectFreshFromReader(context.Background(), freshTestReader(t), "router", "operator", 1, []string{"another"}); !errors.Is(err, ErrFreshProvenance) {
		t.Fatal("node absence authorized a writer")
	}
	if _, err := InspectFreshFromReader(context.Background(), freshTestReader(t), "router", "operator", 1, []string{"router"}); !errors.Is(err, ErrFreshConflict) {
		t.Fatal("colliding Headscale name ignored")
	}
}

func TestInspectFreshFromReaderDistinguishesUnknownFromAbsent(t *testing.T) {
	// A retained Service is never treated as fresh, even if it carries the
	// gateway label; the separate adoption protocol is required.
	occupied := &corev1.Service{}
	occupied.Name, occupied.Namespace = "router", "operator"
	occupied.Labels = map[string]string{gatewayUIDLabel: "fixture-uid"}
	if got, err := InspectFreshFromReader(context.Background(), freshTestReader(t, occupied), "router", "operator", 1, nil); !errors.Is(err, ErrFreshConflict) || got != (FreshInspection{}) {
		t.Fatal("retained name accepted")
	}
	for _, tc := range []struct{ kind, name string }{{"Service", "router"}, {"ConfigMap", "router-coredns"}} {
		r := freshTestReader(t)
		r.denyKind, r.denyName = tc.kind, tc.name
		got, err := InspectFreshFromReader(context.Background(), r, "router", "operator", 1, nil)
		if !errors.Is(err, ErrFreshSnapshot) || got != (FreshInspection{}) || err.Error() != ErrFreshSnapshot.Error() {
			t.Fatal("unreadable resource name was treated as absent or leaked provider error")
		}
	}
	if got, err := InspectFreshFromReader(context.Background(), freshTestReader(t), "router", "other-namespace", 1, nil); !errors.Is(err, ErrFreshSnapshot) || got != (FreshInspection{}) {
		t.Fatal("missing state silently treated as empty")
	}
	if got, err := InspectFreshFromReader(context.Background(), nil, "router", "operator", 1, nil); !errors.Is(err, ErrFreshSnapshot) || got != (FreshInspection{}) {
		t.Fatal("nil reader accepted")
	}
}
