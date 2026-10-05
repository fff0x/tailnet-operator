// Package manager wires the production controllers and their cache scopes. Integration tests
// use the same constructor with an explicit, isolated API-server configuration.
package manager

import (
	"fmt"
	"time"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/dynamic"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	"k8s.io/client-go/rest"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/cache"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/healthz"
	runtimemetrics "sigs.k8s.io/controller-runtime/pkg/metrics"
	metricsserver "sigs.k8s.io/controller-runtime/pkg/metrics/server"

	tnv1 "tsunaro.io/tailnet-operator/api/v1alpha1"
	"tsunaro.io/tailnet-operator/internal/controller"
	operatormetrics "tsunaro.io/tailnet-operator/internal/metrics"
)

// LeaderElectionID is shared by every replica, independent of Helm release names.
const LeaderElectionID = "tailnet-operator.tsunaro.io"

// Options contains runtime inputs, not environment lookups. Use "0" to disable test listeners.
// The zero value disables election so isolated integration tests must opt in explicitly.
type Options struct {
	Namespace              string
	LeaderElection         bool
	Image                  string
	AgentImagePullSecrets  []string
	AgentResources         corev1.ResourceRequirements
	MetricsBindAddress     string
	HealthProbeBindAddress string
}

// New requires an explicit REST config; it never discovers the user's current kube-context.
// With election enabled, the caller must exit the process when Start returns. A shutdown
// timeout or leadership loss can leave workers running until process exit.
func New(cfg *rest.Config, opts Options) (ctrl.Manager, error) {
	if cfg == nil {
		return nil, fmt.Errorf("REST config is required")
	}
	if opts.Namespace == "" {
		return nil, fmt.Errorf("operator namespace is required")
	}
	scheme := runtime.NewScheme()
	if err := clientgoscheme.AddToScheme(scheme); err != nil {
		return nil, fmt.Errorf("add clientgo scheme: %w", err)
	}
	if err := tnv1.AddToScheme(scheme); err != nil {
		return nil, fmt.Errorf("add tailnet scheme: %w", err)
	}

	mgr, err := ctrl.NewManager(cfg, runtimeOptions(opts, scheme))
	if err != nil {
		return nil, fmt.Errorf("create manager: %w", err)
	}
	// This constructor makes no cert-manager API request. Missing CRDs never block
	// manager startup or external-Secret/L4 operation; issuer workflows check lazily.
	certificateClient, err := dynamic.NewForConfig(cfg)
	if err != nil {
		return nil, fmt.Errorf("create optional certificate client: %w", err)
	}
	metrics, err := operatormetrics.Register(runtimemetrics.Registry)
	if err != nil {
		return nil, fmt.Errorf("register operator metrics: %w", err)
	}
	// Gateway provenance/exclusivity must never read from informer snapshots.
	gatewayClient, err := client.New(cfg, client.Options{Scheme: scheme})
	if err != nil {
		return nil, fmt.Errorf("create uncached gateway client: %w", err)
	}
	setups := []struct {
		name  string
		setup func(ctrl.Manager) error
	}{
		{"Tailnet", (&controller.TailnetReconciler{
			Metrics: metrics, Client: mgr.GetClient(), Scheme: scheme, OperatorNamespace: opts.Namespace,
		}).SetupWithManager},
		{"TailnetEgress", (&controller.TailnetEgressReconciler{
			AgentResources: *opts.AgentResources.DeepCopy(),
			Metrics:        metrics, Client: mgr.GetClient(), Scheme: scheme, OperatorNamespace: opts.Namespace,
			OperatorImage: opts.Image, AgentImagePullSecrets: append([]string(nil), opts.AgentImagePullSecrets...),
		}).SetupWithManager},
		{"TailnetIngress", (&controller.TailnetIngressReconciler{
			AgentResources: *opts.AgentResources.DeepCopy(),
			Metrics:        metrics, Client: mgr.GetClient(), Scheme: scheme, OperatorNamespace: opts.Namespace,
			Certificates: certificateClient, SecretReader: mgr.GetAPIReader(),
			OperatorImage: opts.Image, AgentImagePullSecrets: append([]string(nil), opts.AgentImagePullSecrets...),
		}).SetupWithManager},
		{"TailnetGateway", (&controller.TailnetGatewayReconciler{
			Client: mgr.GetClient(), RuntimeClient: gatewayClient, OperatorNamespace: opts.Namespace,
		}).SetupWithManager},
		{"TailnetDNS", (&controller.TailnetDNSReconciler{
			Client: mgr.GetClient(), Scheme: scheme, OperatorNamespace: opts.Namespace,
		}).SetupWithManager},
		{"TailnetPolicy", (&controller.TailnetPolicyReconciler{
			Metrics: metrics, Client: mgr.GetClient(), Scheme: scheme, OperatorNamespace: opts.Namespace,
			Recorder: mgr.GetEventRecorderFor("tailnet-operator"),
		}).SetupWithManager},
	}
	for _, s := range setups {
		if err := s.setup(mgr); err != nil {
			return nil, fmt.Errorf("setup %s controller: %w", s.name, err)
		}
	}
	if err := mgr.AddHealthzCheck("healthz", healthz.Ping); err != nil {
		return nil, fmt.Errorf("add healthz: %w", err)
	}
	if err := mgr.AddReadyzCheck("readyz", healthz.Ping); err != nil {
		return nil, fmt.Errorf("add readyz: %w", err)
	}
	return mgr, nil
}

func runtimeOptions(opts Options, scheme *runtime.Scheme) ctrl.Options {
	// Egress and its Services are namespace-scoped. Ingress and the shared child types are
	// cluster-wide, matching the chart RBAC. This is shared by production and envtest.
	nsCfg := map[string]cache.Config{opts.Namespace: {}}
	byObject := map[client.Object]cache.ByObject{
		&tnv1.TailnetEgress{}:         {Namespaces: nsCfg},
		&corev1.Service{}:             {Namespaces: nsCfg},
		&tnv1.TailnetIngress{}:        {},
		&tnv1.TailnetGateway{}:        {},
		&corev1.Secret{}:              {},
		&corev1.ConfigMap{}:           {},
		&corev1.Pod{}:                 {},
		&appsv1.Deployment{}:          {},
		&networkingv1.NetworkPolicy{}: {},
	}
	lease, renew, retry := 15*time.Second, 10*time.Second, 2*time.Second
	shutdown := 20 * time.Second
	return ctrl.Options{
		Scheme:                     scheme,
		Cache:                      cache.Options{ByObject: byObject},
		Metrics:                    metricsserver.Options{BindAddress: opts.MetricsBindAddress},
		HealthProbeBindAddress:     opts.HealthProbeBindAddress,
		LeaderElection:             opts.LeaderElection,
		LeaderElectionID:           LeaderElectionID,
		LeaderElectionNamespace:    opts.Namespace,
		LeaderElectionResourceLock: "leases",
		LeaseDuration:              &lease,
		RenewDeadline:              &renew,
		RetryPeriod:                &retry,
		GracefulShutdownTimeout:    &shutdown,
		// controller-runtime v0.25.1 renews during graceful shutdown, then cancels election.
		// Keep the Lease until expiry: a drain timeout does not prove all workers stopped.
		// main must exit immediately when Start returns, especially after leadership loss.
		LeaderElectionReleaseOnCancel: false,
	}
}
