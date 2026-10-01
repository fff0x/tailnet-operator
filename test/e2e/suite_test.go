//go:build e2e

package e2e

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/envtest"
	"sigs.k8s.io/controller-runtime/pkg/log/zap"

	"tsunaro.io/tailnet-operator/internal/manager"
	"tsunaro.io/tailnet-operator/test/internal/isolation"
)

const namespace = "operator-e2e"

var (
	kube     client.Client // uncached assertions against the disposable API server
	versions []string
	root     string
	// Never tee raw manager logs to stderr: redaction tests inspect this private capture first.
	operatorLogs logCapture
)

func TestMain(m *testing.M) { os.Exit(runSuite(m)) }

func runSuite(m *testing.M) (code int) {
	code = 1
	if err := isolation.ClearEnvtestOverrides(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		return
	}
	var err error
	root, err = filepath.Abs(filepath.Join("..", ".."))
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return
	}
	versions = strings.Fields(os.Getenv("HEADSCALE_VERSIONS"))
	if len(versions) == 0 {
		versions = []string{"v0.28.0", "v0.29.3"}
	}
	for _, v := range versions {
		if v != "v0.28.0" && v != "v0.29.3" {
			fmt.Fprintln(os.Stderr, "unsupported HEADSCALE_VERSIONS row; use v0.28.0 and/or v0.29.3")
			return
		}
		if _, err := headscaleBinary(v); err != nil {
			fmt.Fprintln(os.Stderr, err)
			return
		}
	}
	assets := os.Getenv("KUBEBUILDER_ASSETS")
	if assets == "" {
		fmt.Fprintln(os.Stderr, "set KUBEBUILDER_ASSETS to envtest binaries for Kubernetes >=1.31")
		return
	}
	useExistingCluster := false // Never honor USE_EXISTING_CLUSTER, even if exported by a developer.
	env := &envtest.Environment{
		UseExistingCluster:       &useExistingCluster,
		BinaryAssetsDirectory:    assets,
		CRDDirectoryPaths:        []string{filepath.Join(root, "deploy", "crds")},
		ErrorIfCRDPathMissing:    true,
		ControlPlaneStartTimeout: 20 * time.Second,
		ControlPlaneStopTimeout:  10 * time.Second,
	}
	// Register cleanup before startup, including failed/partial API-server startup.
	defer func() {
		if err := env.Stop(); err != nil {
			fmt.Fprintln(os.Stderr, "stop isolated envtest:", err)
			code = 1
		}
	}()
	cfg, err := env.Start()
	if err != nil {
		fmt.Fprintln(os.Stderr, "start isolated envtest:", err)
		return
	}
	ctrl.SetLogger(zap.New(zap.WriteTo(&operatorLogs)))
	mgr, err := manager.New(cfg, manager.Options{
		Namespace: namespace, Image: "example.invalid/operator:e2e",
		MetricsBindAddress: "0", HealthProbeBindAddress: "0",
	})
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return
	}
	kube, err = client.New(cfg, client.Options{Scheme: mgr.GetScheme()})
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if err := kube.Create(ctx, &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: namespace}}); err != nil {
		fmt.Fprintln(os.Stderr, err)
		return
	}
	done := make(chan error, 1)
	go func() { done <- mgr.Start(ctx) }()
	defer func() {
		cancel()
		select {
		case err := <-done:
			if err != nil {
				fmt.Fprintln(os.Stderr, "manager exited:", err)
				code = 1
			}
		case <-time.After(20 * time.Second):
			fmt.Fprintln(os.Stderr, "manager shutdown timed out")
			code = 1
		}
	}()
	syncCtx, stopSync := context.WithTimeout(ctx, 30*time.Second)
	defer stopSync()
	if !mgr.GetCache().WaitForCacheSync(syncCtx) {
		fmt.Fprintln(os.Stderr, "manager cache did not sync")
		return
	}
	return m.Run()
}
