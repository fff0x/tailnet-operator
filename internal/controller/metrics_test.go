package controller

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"reflect"
	goruntime "runtime"
	"sync"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"
	tnv1 "this-is-fine.io/tailnet-operator/api/v1alpha1"
	"this-is-fine.io/tailnet-operator/internal/headscale"
	operatormetrics "this-is-fine.io/tailnet-operator/internal/metrics"
)

func gatheredValue(t *testing.T, reg *prometheus.Registry, name string) (float64, int) {
	t.Helper()
	fs, err := reg.Gather()
	if err != nil {
		t.Fatal(err)
	}
	total := 0.0
	count := 0
	for _, f := range fs {
		if f.GetName() == name {
			for _, m := range f.Metric {
				count++
				if m.Gauge != nil {
					total += m.Gauge.GetValue()
				}
				if m.Counter != nil {
					total += m.Counter.GetValue()
				}
			}
		}
	}
	return total, count
}
func TestMetricsOnlyAfterPersistedStatus(t *testing.T) {
	scheme := runtime.NewScheme()
	_ = tnv1.AddToScheme(scheme)
	eg := &tnv1.TailnetEgress{ObjectMeta: metav1.ObjectMeta{Name: "eg", Namespace: "ns", Generation: 1}}
	reg := prometheus.NewPedanticRegistry()
	m, err := operatormetrics.Register(reg)
	if err != nil {
		t.Fatal(err)
	}
	fail := true
	c := fake.NewClientBuilder().WithScheme(scheme).WithStatusSubresource(eg).WithObjects(eg).WithInterceptorFuncs(interceptor.Funcs{
		SubResourceUpdate: func(ctx context.Context, c client.Client, sub string, obj client.Object, opts ...client.SubResourceUpdateOption) error {
			if fail {
				return errors.New("status write failed")
			}
			return c.SubResource(sub).Update(ctx, obj, opts...)
		},
	}).Build()
	if err := c.Get(context.Background(), client.ObjectKeyFromObject(eg), eg); err != nil {
		t.Fatal(err)
	}
	setCond(&eg.Status.Conditions, 1, "Ready", metav1.ConditionTrue, "Ready", "ok")
	if err := updateObservedStatus(context.Background(), c, m, eg); err == nil {
		t.Fatal("wanted update failure")
	}
	if _, n := gatheredValue(t, reg, "tailnet_resource_ready"); n != 0 {
		t.Fatal("unpersisted success emitted")
	}
	fail = false
	if err := updateObservedStatus(context.Background(), c, m, eg); err != nil {
		t.Fatal(err)
	}
	if v, n := gatheredValue(t, reg, "tailnet_resource_ready"); v != 1 || n != 1 {
		t.Fatal("persisted status not emitted")
	}
	fail = true
	setCond(&eg.Status.Conditions, 1, "Ready", metav1.ConditionFalse, "NoTailnet", "missing")
	if err := updateObservedStatus(context.Background(), c, m, eg); err == nil {
		t.Fatal("wanted update failure")
	}
	if v, _ := gatheredValue(t, reg, "tailnet_resource_ready"); v != 1 {
		t.Fatal("failed write changed persisted metrics")
	}
	if err := c.Delete(context.Background(), eg); err != nil {
		t.Fatal(err)
	}
	r := TailnetEgressReconciler{Client: c, Metrics: m}
	if _, err := r.Reconcile(context.Background(), ctrl.Request{NamespacedName: client.ObjectKeyFromObject(eg)}); err != nil {
		t.Fatal(err)
	}
	if _, n := gatheredValue(t, reg, "tailnet_resource_ready"); n != 0 {
		t.Fatal("NotFound did not delete metrics")
	}
	assertObservedStatusLocksEmpty(t)
}

func TestUpdateObservedStatusIndependentObjects(t *testing.T) {
	for _, tc := range []struct {
		name string
		obj  client.Object
	}{
		{"name", &tnv1.TailnetEgress{ObjectMeta: metav1.ObjectMeta{Name: "b", Namespace: "ns"}}},
		{"namespace", &tnv1.TailnetEgress{ObjectMeta: metav1.ObjectMeta{Name: "a", Namespace: "other"}}},
		{"kind", &tnv1.TailnetIngress{ObjectMeta: metav1.ObjectMeta{Name: "a", Namespace: "ns"}}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			a := &tnv1.TailnetEgress{ObjectMeta: metav1.ObjectMeta{Name: "a", Namespace: "ns"}}
			blocked := make(chan struct{})
			var release sync.Once
			defer release.Do(func() { close(blocked) })
			entered := make(chan struct{})
			c := fake.NewClientBuilder().WithInterceptorFuncs(interceptor.Funcs{
				SubResourceUpdate: func(_ context.Context, _ client.Client, _ string, obj client.Object, _ ...client.SubResourceUpdateOption) error {
					if obj == a {
						close(entered)
						<-blocked
					}
					return nil
				},
			}).Build()
			aDone, bDone := make(chan error, 1), make(chan error, 1)
			go func() { aDone <- updateObservedStatus(context.Background(), c, nil, a) }()
			<-entered
			go func() { bDone <- updateObservedStatus(context.Background(), c, nil, tc.obj) }()
			select {
			case err := <-bDone:
				if err != nil {
					t.Fatal(err)
				}
			case <-time.After(5 * time.Second):
				t.Fatal("unrelated status update blocked behind A")
			}
			release.Do(func() { close(blocked) })
			if err := <-aDone; err != nil {
				t.Fatal(err)
			}
			assertObservedStatusLocksEmpty(t)
		})
	}
}

func TestUpdateObservedStatusSerializesSameObject(t *testing.T) {
	first := &tnv1.Tailnet{ObjectMeta: metav1.ObjectMeta{Name: "shared", Generation: 1, ResourceVersion: "opaque-first"}}
	setCond(&first.Status.Conditions, 1, "Ready", metav1.ConditionTrue, "Ready", "ok")
	second := first.DeepCopy()
	second.ResourceVersion = "opaque-second"
	setCond(&second.Status.Conditions, 1, "Ready", metav1.ConditionFalse, "NotReady", "not ready")
	reg := prometheus.NewPedanticRegistry()
	m, err := operatormetrics.Register(reg)
	if err != nil {
		t.Fatal(err)
	}
	blocked := make(chan struct{})
	var release sync.Once
	defer release.Do(func() { close(blocked) })
	entered, secondEntered := make(chan struct{}), make(chan struct{})
	c := fake.NewClientBuilder().WithInterceptorFuncs(interceptor.Funcs{
		SubResourceUpdate: func(_ context.Context, _ client.Client, _ string, obj client.Object, _ ...client.SubResourceUpdateOption) error {
			if obj == first {
				close(entered)
				<-blocked
			} else {
				close(secondEntered)
				if v, n := gatheredValue(t, reg, "tailnet_resource_ready"); v != 1 || n != 1 {
					return errors.New("second write started before first observation")
				}
			}
			return nil
		},
	}).Build()
	done := make(chan error, 2)
	go func() { done <- updateObservedStatus(context.Background(), c, m, first) }()
	<-entered
	go func() { done <- updateObservedStatus(context.Background(), c, m, second) }()
	key := observedStatusKey{kind: reflect.TypeOf(first), name: client.ObjectKeyFromObject(first)}
	deadline := time.NewTimer(5 * time.Second)
	defer deadline.Stop()
	tick := time.NewTicker(time.Millisecond)
	defer tick.Stop()
	for {
		observedStatusLocks.mu.Lock()
		entry := observedStatusLocks.entries[key]
		retained := entry != nil && entry.refs == 2
		observedStatusLocks.mu.Unlock()
		if retained {
			break
		}
		select {
		case <-secondEntered:
			t.Fatal("same-resource writes overlapped")
		case <-deadline.C:
			t.Fatal("waiting caller did not retain the shared entry")
		case <-tick.C:
		}
	}
	select {
	case <-secondEntered:
		t.Fatal("same-resource writes overlapped")
	default:
	}
	release.Do(func() { close(blocked) })
	for range 2 {
		if err := <-done; err != nil {
			t.Fatal(err)
		}
	}
	if v, n := gatheredValue(t, reg, "tailnet_resource_ready"); v != 0 || n != 1 {
		t.Fatal("final metrics do not reflect the last successful write")
	}
	assertObservedStatusLocksEmpty(t)
}

func assertObservedStatusLocksEmpty(t *testing.T) {
	t.Helper()
	observedStatusLocks.mu.Lock()
	defer observedStatusLocks.mu.Unlock()
	if n := len(observedStatusLocks.entries); n != 0 {
		t.Errorf("status lock entries leaked: %d", n)
	}
}

func TestUpdateObservedStatusLockCleanupConcurrent(t *testing.T) {
	var mu sync.Mutex
	active := make(map[client.ObjectKey]bool)
	writeErr := errors.New("status write failed")
	c := fake.NewClientBuilder().WithInterceptorFuncs(interceptor.Funcs{
		SubResourceUpdate: func(_ context.Context, _ client.Client, _ string, obj client.Object, _ ...client.SubResourceUpdateOption) error {
			key := client.ObjectKeyFromObject(obj)
			mu.Lock()
			if active[key] {
				t.Error("same-object lock entry split during cleanup")
			}
			active[key] = true
			mu.Unlock()
			// Yield while holding the object lock to exercise waiter retention.
			goruntime.Gosched()
			mu.Lock()
			delete(active, key)
			mu.Unlock()
			return writeErr
		},
	}).Build()
	var wg sync.WaitGroup
	for worker := range 16 {
		wg.Go(func() {
			for i := range 100 {
				obj := &tnv1.Tailnet{ObjectMeta: metav1.ObjectMeta{Name: fmt.Sprintf("resource-%d-%d", i, worker%4)}}
				if err := updateObservedStatus(context.Background(), c, nil, obj); err != writeErr {
					t.Errorf("status error = %v, want %v", err, writeErr)
				}
			}
		})
	}
	wg.Wait()
	assertObservedStatusLocksEmpty(t)
}

func TestEarlyFailureAndPolicyStatusMetrics(t *testing.T) {
	scheme := runtime.NewScheme()
	_ = tnv1.AddToScheme(scheme)
	_ = corev1.AddToScheme(scheme)
	eg := &tnv1.TailnetEgress{ObjectMeta: metav1.ObjectMeta{Name: "eg", Namespace: "ns", Generation: 1}}
	in := &tnv1.TailnetIngress{ObjectMeta: metav1.ObjectMeta{Name: "in", Namespace: "ns", Generation: 1}}
	tn := &tnv1.Tailnet{ObjectMeta: metav1.ObjectMeta{Name: "tn", Generation: 1}}
	eg.Spec.TailnetRef.Name = "missing"
	in.Spec.TailnetRef.Name = "missing"
	c := fake.NewClientBuilder().WithScheme(scheme).WithStatusSubresource(eg, in, tn).WithObjects(eg, in, tn).Build()
	reg := prometheus.NewPedanticRegistry()
	m, err := operatormetrics.Register(reg)
	if err != nil {
		t.Fatal(err)
	}
	er := TailnetEgressReconciler{Client: c, Metrics: m}
	ir := TailnetIngressReconciler{Client: c, Metrics: m}
	for _, tc := range []struct {
		obj       client.Object
		reconcile func(context.Context, ctrl.Request) (ctrl.Result, error)
	}{{eg, er.Reconcile}, {in, ir.Reconcile}} {
		if _, err := tc.reconcile(context.Background(), ctrl.Request{NamespacedName: client.ObjectKeyFromObject(tc.obj)}); err != nil {
			t.Fatal(err)
		}
	}
	if v, n := gatheredValue(t, reg, "tailnet_resource_condition"); v != 2 || n != 2 {
		t.Fatal("early failure reasons not emitted")
	}
	pr := TailnetPolicyReconciler{Client: c, Metrics: m}
	if err := pr.status(context.Background(), "tn", func(tn *tnv1.Tailnet) {
		tn.Status.Policy = &tnv1.PolicyStatus{Generated: tnv1.PolicyGenerated{Tags: 1, Grants: 2, Routes: 3}}
		setCond(&tn.Status.Conditions, 1, "PolicyRendered", metav1.ConditionTrue, "Rendered", "safe")
	}); err != nil {
		t.Fatal(err)
	}
	if v, n := gatheredValue(t, reg, "tailnet_policy_generated"); v != 6 || n != 3 {
		t.Fatal("persisted policy counts missing")
	}
	if _, n := gatheredValue(t, reg, "tailnet_resource_ready"); n != 2 {
		t.Fatal("Tailnet invented Ready")
	}
}

func TestMintVerifyExpireObserver(t *testing.T) {
	calls := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/v1/apikey":
			if r.Method == "GET" {
				w.WriteHeader(401)
			} else {
				_, _ = w.Write([]byte(`{"apiKey":"abcdefg.secret"}`))
			}
		case "/api/v1/apikey/expire":
			_, _ = w.Write([]byte(`{}`))
		default:
			t.Error("unexpected request")
		}
	}))
	defer srv.Close()
	r := TailnetReconciler{}
	_, _, err := r.mintAndVerify(context.Background(), srv.URL, "bootstrap", time.Hour, time.Now(), func(method, path string, code int, elapsed time.Duration) { calls++ })
	if !headscale.IsUnauthorized(err) || calls != 3 {
		t.Fatalf("mint/verify/expire observations: %d, %v", calls, err)
	}
}

func TestReplayCountsOnlySuccessfulNewRoutes(t *testing.T) {
	fail := true
	approved := false
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "GET" {
			body := `{"nodes":[{"id":"1","tags":["tag:router"],"availableRoutes":["10.0.0.1/32","10.0.0.1/32","10.0.0.2/32"]}]}`
			if approved {
				body = `{"nodes":[{"id":"1","tags":["tag:router"],"availableRoutes":["10.0.0.1/32","10.0.0.2/32"],"approvedRoutes":["10.0.0.1/32","10.0.0.2/32"]}]}`
			}
			_, _ = w.Write([]byte(body))
			return
		}
		if fail {
			w.WriteHeader(500)
			return
		}
		approved = true
		_, _ = w.Write([]byte(`{}`))
	}))
	defer srv.Close()
	reg := prometheus.NewPedanticRegistry()
	m, err := operatormetrics.Register(reg)
	if err != nil {
		t.Fatal(err)
	}
	r := TailnetPolicyReconciler{Metrics: m}
	tn := &tnv1.Tailnet{ObjectMeta: metav1.ObjectMeta{Name: "tn"}}
	hs := headscale.New(srv.URL, "token", m.Headscale(tn.Name))
	policy := []byte(`{"autoApprovers":{"routes":{"10.0.0.0/24":["tag:router"]}}}`)
	r.approveRoutes(context.Background(), hs, tn, policy)
	if v, _ := gatheredValue(t, reg, "tailnet_route_approvals_replayed_total"); v != 0 {
		t.Fatal("failed approval counted")
	}
	fail = false
	r.approveRoutes(context.Background(), hs, tn, policy)
	if v, _ := gatheredValue(t, reg, "tailnet_route_approvals_replayed_total"); v != 2 {
		t.Fatal("successful unique route count", v)
	}
	r.approveRoutes(context.Background(), hs, tn, policy)
	if v, _ := gatheredValue(t, reg, "tailnet_route_approvals_replayed_total"); v != 2 {
		t.Fatal("already approved routes counted")
	}
}
