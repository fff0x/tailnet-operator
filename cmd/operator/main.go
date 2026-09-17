// Command tailnet-operator is the control plane. It watches Tailnet (cluster-scoped), TailnetEgress
// (namespaced, in its own namespace) and TailnetIngress (namespaced, in any tenant namespace), mints
// and rotates Headscale keys, and writes the per-CR agent Deployment + children. It never speaks
// tailscale — the agent does.
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

	// Egress lives only in the operator namespace, so its CR and its Services stay namespace-scoped
	// (a Role suffices, the cache stays small). Ingress CRs live in tenant namespaces and own
	// children there, so TailnetIngress and the child types it manages (Secret/ConfigMap/Deployment/
	// NetworkPolicy/Pod) are cached cluster-wide — this is the deliberate RBAC/cache widening the
	// egress path avoids (see deploy/rbac.yaml). Service stays namespaced: only egress creates one.
	nsCfg := map[string]cache.Config{ns: {}}
	byObject := map[client.Object]cache.ByObject{
		&tnv1.TailnetEgress{}:         {Namespaces: nsCfg},
		&corev1.Service{}:             {Namespaces: nsCfg},
		&tnv1.TailnetIngress{}:        {},
		&corev1.Secret{}:              {},
		&corev1.ConfigMap{}:           {},
		&corev1.Pod{}:                 {},
		&appsv1.Deployment{}:          {},
		&networkingv1.NetworkPolicy{}: {},
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
	if err := (&controller.TailnetIngressReconciler{
		Client:            mgr.GetClient(),
		Scheme:            mgr.GetScheme(),
		OperatorNamespace: ns,
		OperatorImage:     image,
	}).SetupWithManager(mgr); err != nil {
		l.Error(err, "setup TailnetIngress controller")
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
