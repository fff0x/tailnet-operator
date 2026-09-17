// Command tailnet-operator is the control plane. It watches Tailnet (cluster-scoped) and
// TailnetEgress (namespaced, only in its own namespace), mints and rotates Headscale keys, and
// writes the per-CR agent Deployment + Services. It never speaks tailscale — the agent does.
package main

import (
	"os"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	"k8s.io/apimachinery/pkg/runtime"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/cache"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/healthz"
	"sigs.k8s.io/controller-runtime/pkg/log/zap"
	metricsserver "sigs.k8s.io/controller-runtime/pkg/metrics/server"

	tnv1 "fr0st.dev/tailnet-operator/api/v1alpha1"
	"fr0st.dev/tailnet-operator/internal/controller"
)

func main() {
	ctrl.SetLogger(zap.New())
	l := ctrl.Log.WithName("setup")

	scheme := runtime.NewScheme()
	if err := clientgoscheme.AddToScheme(scheme); err != nil {
		l.Error(err, "add clientgo scheme")
		os.Exit(1)
	}
	if err := tnv1.AddToScheme(scheme); err != nil {
		l.Error(err, "add tailnet scheme")
		os.Exit(1)
	}

	ns := os.Getenv("POD_NAMESPACE")
	if ns == "" {
		l.Error(nil, "POD_NAMESPACE is required")
		os.Exit(1)
	}
	image := os.Getenv("OPERATOR_IMAGE") // agent default = operator's own image

	// Namespace-scoped cache for everything namespaced: the operator only ever touches its own
	// namespace, so a Role suffices and the cache stays small. Tailnet is cluster-scoped and left
	// unfiltered — a later cluster-scoped TailnetIngress would watch the whole cluster the same way.
	nsCfg := map[string]cache.Config{ns: {}}
	byObject := map[client.Object]cache.ByObject{
		&tnv1.TailnetEgress{}:         {Namespaces: nsCfg},
		&corev1.Secret{}:              {Namespaces: nsCfg},
		&corev1.ConfigMap{}:           {Namespaces: nsCfg},
		&corev1.Service{}:             {Namespaces: nsCfg},
		&corev1.Pod{}:                 {Namespaces: nsCfg},
		&appsv1.Deployment{}:          {Namespaces: nsCfg},
		&networkingv1.NetworkPolicy{}: {Namespaces: nsCfg},
	}

	mgr, err := ctrl.NewManager(ctrl.GetConfigOrDie(), ctrl.Options{
		Scheme:                 scheme,
		Cache:                  cache.Options{ByObject: byObject},
		Metrics:                metricsserver.Options{BindAddress: ":8080"},
		HealthProbeBindAddress: ":8081",
	})
	if err != nil {
		l.Error(err, "create manager")
		os.Exit(1)
	}

	if err := (&controller.TailnetReconciler{
		Client:            mgr.GetClient(),
		Scheme:            mgr.GetScheme(),
		OperatorNamespace: ns,
	}).SetupWithManager(mgr); err != nil {
		l.Error(err, "setup Tailnet controller")
		os.Exit(1)
	}
	if err := (&controller.TailnetEgressReconciler{
		Client:            mgr.GetClient(),
		Scheme:            mgr.GetScheme(),
		OperatorNamespace: ns,
		OperatorImage:     image,
	}).SetupWithManager(mgr); err != nil {
		l.Error(err, "setup TailnetEgress controller")
		os.Exit(1)
	}

	if err := mgr.AddHealthzCheck("healthz", healthz.Ping); err != nil {
		l.Error(err, "add healthz")
		os.Exit(1)
	}
	if err := mgr.AddReadyzCheck("readyz", healthz.Ping); err != nil {
		l.Error(err, "add readyz")
		os.Exit(1)
	}

	l.Info("starting tailnet-operator", "namespace", ns)
	if err := mgr.Start(ctrl.SetupSignalHandler()); err != nil {
		l.Error(err, "manager exited")
		os.Exit(1)
	}
}
