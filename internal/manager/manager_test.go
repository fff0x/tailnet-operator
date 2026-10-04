package manager

import (
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/rest"

	tnv1 "tsunaro.io/tailnet-operator/api/v1alpha1"
)

func TestRuntimeOptions(t *testing.T) {
	for _, tt := range []struct {
		name string
		opts Options
		want bool
	}{
		{name: "zero"},
		{name: "explicit false", opts: Options{LeaderElection: false}},
		{name: "enabled", opts: Options{LeaderElection: true}, want: true},
	} {
		t.Run(tt.name, func(t *testing.T) {
			tt.opts.Namespace = "operator-test"
			tt.opts.MetricsBindAddress = "0"
			tt.opts.HealthProbeBindAddress = "0"
			scheme := runtime.NewScheme()
			got := runtimeOptions(tt.opts, scheme)
			if got.LeaderElection != tt.want || got.LeaderElectionID != "tailnet-operator.tsunaro.io" || got.LeaderElectionNamespace != tt.opts.Namespace || got.LeaderElectionResourceLock != "leases" {
				t.Fatal("unexpected leader-election configuration")
			}
			if got.LeaderElectionReleaseOnCancel {
				t.Fatal("early Lease release can expose overlapping workers after a drain timeout")
			}
			for name, timing := range map[string]struct {
				got  *time.Duration
				want time.Duration
			}{
				"lease":    {got.LeaseDuration, 15 * time.Second},
				"renew":    {got.RenewDeadline, 10 * time.Second},
				"retry":    {got.RetryPeriod, 2 * time.Second},
				"shutdown": {got.GracefulShutdownTimeout, 20 * time.Second},
			} {
				if timing.got == nil || *timing.got != timing.want {
					t.Errorf("unexpected %s timing: %v", name, timing.got)
				}
			}
			if got.Scheme != scheme || got.Metrics.BindAddress != "0" || got.HealthProbeBindAddress != "0" {
				t.Fatal("scheme or test listeners changed")
			}
			if len(got.Cache.ByObject) != 9 || len(got.Cache.DefaultNamespaces) != 0 {
				t.Fatal("cache object scopes changed")
			}
			gatewayCached := false
			for obj, scope := range got.Cache.ByObject {
				if _, ok := obj.(*tnv1.TailnetGateway); ok {
					gatewayCached = true
				}
				switch obj.(type) {
				case *tnv1.TailnetEgress, *corev1.Service:
					if len(scope.Namespaces) != 1 {
						t.Fatalf("%T must be operator-namespace scoped", obj)
					}
					if _, ok := scope.Namespaces[tt.opts.Namespace]; !ok {
						t.Fatalf("%T has wrong namespace", obj)
					}
				default:
					if scope.Namespaces != nil {
						t.Fatalf("%T must remain cluster scoped", obj)
					}
				}
			}
			if !gatewayCached {
				t.Fatal("cluster-scoped gateway cache is missing")
			}
		})
	}
}

func TestExplicitConfigRequired(t *testing.T) {
	t.Setenv("KUBECONFIG", "/must-not-be-read")
	if _, err := New(nil, Options{Namespace: "operator"}); err == nil {
		t.Fatal("nil REST config accepted")
	}
	if _, err := New(&rest.Config{Host: "https://must-not-be-contacted.invalid"}, Options{}); err == nil {
		t.Fatal("empty namespace accepted")
	}
}
