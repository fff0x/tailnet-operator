//go:build e2e_kind

package e2ekind

import (
	"bytes"
	"context"
	_ "embed"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/go-logr/logr"
	appsv1 "k8s.io/api/apps/v1"
	coordinationv1 "k8s.io/api/coordination/v1"
	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/tools/clientcmd"
	clientcmdapi "k8s.io/client-go/tools/clientcmd/api"
	"sigs.k8s.io/controller-runtime/pkg/client"
	controllog "sigs.k8s.io/controller-runtime/pkg/log"

	tnv1 "tsunaro.io/tailnet-operator/api/v1alpha1"
	"tsunaro.io/tailnet-operator/internal/policy"
)

const namespace = "tailnet-system"
const basePolicy = `{"tagOwners":{"tag:fabric":[]},"acls":[{"action":"accept","src":["*"],"dst":["192.0.2.1:443"]}]}`

//go:embed headscale.yaml
var headscaleManifest string

// validateConfig rejects fallback contexts, credential helpers, proxies and remote endpoints
// before any API request. The runner supplies a private config from a new rootless kind cluster.
func validateConfig(cfg *clientcmdapi.Config, cluster string) error {
	if !regexp.MustCompile(`^tn-kind-[a-z0-9]{10}$`).MatchString(cluster) {
		return fmt.Errorf("invalid owned cluster name")
	}
	name := "kind-" + cluster
	if cfg.CurrentContext != name || len(cfg.Contexts) != 1 || len(cfg.Clusters) != 1 || len(cfg.AuthInfos) != 1 {
		return fmt.Errorf("expected exactly one owned context, cluster and identity")
	}
	ctx := cfg.Contexts[name]
	if ctx == nil || ctx.Cluster != name || ctx.AuthInfo != name {
		return fmt.Errorf("context does not select owned cluster and identity")
	}
	c, a := cfg.Clusters[name], cfg.AuthInfos[name]
	if c == nil || a == nil {
		return fmt.Errorf("owned cluster or identity missing")
	}
	u, err := url.Parse(c.Server)
	if err != nil || u.Scheme != "https" || u.Hostname() != "127.0.0.1" || u.Port() == "" || u.User != nil || u.Path != "" || u.RawQuery != "" || u.Fragment != "" {
		return fmt.Errorf("API server must use the owned loopback HTTPS port")
	}
	port, portErr := strconv.Atoi(u.Port())
	if _, _, err := net.SplitHostPort(u.Host); err != nil || portErr != nil || port < 1 || port > 65535 {
		return fmt.Errorf("invalid API port")
	}
	if c.ProxyURL != "" || c.InsecureSkipTLSVerify || c.TLSServerName != "" || c.CertificateAuthority != "" || len(c.CertificateAuthorityData) == 0 {
		return fmt.Errorf("expected inline verified cluster CA, no proxy or TLS override")
	}
	if a.Exec != nil || a.AuthProvider != nil || a.Token != "" || a.TokenFile != "" || a.Username != "" || a.Password != "" || a.Impersonate != "" || len(a.ImpersonateGroups) != 0 || len(a.ImpersonateUserExtra) != 0 || a.ImpersonateUID != "" || a.ClientCertificate != "" || a.ClientKey != "" || len(a.ClientCertificateData) == 0 || len(a.ClientKeyData) == 0 {
		return fmt.Errorf("expected inline kind client certificates only")
	}
	return nil
}

type fixture struct {
	kube                           client.WithWatch
	work, config, cluster, context string
	policy                         string // independently verified installed Headscale policy
}

func ownedFixture(t *testing.T) *fixture {
	t.Helper()
	work := os.Getenv("E2E_KIND_WORK")
	if work == "" {
		t.Skip("run hack/e2e-kind.sh; direct invocation never uses an existing cluster")
	}
	cluster := os.Getenv("E2E_KIND_CLUSTER")
	config := filepath.Join(work, "kubeconfig")
	if !filepath.IsAbs(work) || filepath.Base(work) == "." || os.Getenv("KUBECONFIG") != config || os.Getenv("E2E_KIND_CONTEXT") != "kind-"+cluster {
		t.Fatal("runner's private paths/context missing")
	}
	for _, path := range []string{work, config} {
		info, err := os.Lstat(path)
		if err != nil || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm()&0077 != 0 {
			t.Fatal("runner paths must be private and not symlinks")
		}
	}
	cfg, err := clientcmd.LoadFromFile(config)
	if err != nil {
		t.Fatal("cannot load private kubeconfig")
	}
	if err := validateConfig(cfg, cluster); err != nil {
		t.Fatal(err)
	}
	rest, err := clientcmd.NewNonInteractiveClientConfig(*cfg, "kind-"+cluster, &clientcmd.ConfigOverrides{}, nil).ClientConfig()
	if err != nil {
		t.Fatal("cannot configure owned cluster client")
	}
	rest.Timeout = 10 * time.Second
	// No inherited HTTP proxy may redirect a private API request.
	rest.Proxy = func(*http.Request) (*url.URL, error) { return nil, nil }
	scheme := runtime.NewScheme()
	for _, add := range []func(*runtime.Scheme) error{corev1.AddToScheme, appsv1.AddToScheme, coordinationv1.AddToScheme, networkingv1.AddToScheme, tnv1.AddToScheme} {
		if err := add(scheme); err != nil {
			t.Fatal(err)
		}
	}
	// Only our allowlisted diagnostics may reach test output, including on slow runs.
	controllog.SetLogger(logr.Discard())
	kube, err := client.NewWithWatch(rest, client.Options{Scheme: scheme})
	if err != nil {
		t.Fatal("create owned client failed")
	}
	var system corev1.Namespace
	if err := kube.Get(t.Context(), client.ObjectKey{Name: "kube-system"}, &system); err != nil || os.Getenv("E2E_KIND_SYSTEM_UID") == "" || string(system.UID) != os.Getenv("E2E_KIND_SYSTEM_UID") {
		t.Fatal("API server identity differs from runner-owned cluster")
	}
	return &fixture{kube: kube, work: work, config: config, cluster: cluster, context: "kind-" + cluster}
}

// child never logs arguments, stdin, stderr or raw stdout. In particular the runtime-created
// Headscale API key is captured only in memory, never a command argument or diagnostic artifact.
func (f *fixture) child(t *testing.T, input string, binary string, args ...string) []byte {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), 150*time.Second)
	defer cancel()
	out, err := f.command(ctx, input, binary, args...)
	if err != nil {
		if binary == "helm" {
			f.diagnoseWorkloads(t)
		}
		t.Fatalf("%s fixture operation failed (arguments/output withheld): %v", binary, err)
	}
	return out
}

// command also supports the failover deadline and cleanup after t.Context is cancelled.
// All callers select the already validated owned kubeconfig and context explicitly.
func (f *fixture) command(ctx context.Context, input, binary string, args ...string) ([]byte, error) {
	cmd := exec.CommandContext(ctx, binary, args...)
	cleanup, err := configureCommandLifecycle(cmd)
	if err != nil {
		return nil, err
	}
	defer cleanup()
	cmd.Env = []string{"PATH=" + os.Getenv("PATH"), "HOME=" + f.work, "TMPDIR=" + f.work, "LANG=C.UTF-8", "TS_NO_LOGS_NO_SUPPORT=1"}
	for _, key := range []string{"HELM_CONFIG_HOME", "HELM_CACHE_HOME", "HELM_DATA_HOME", "HELM_PLUGINS"} {
		cmd.Env = append(cmd.Env, key+"="+filepath.Join(f.work, key))
	}
	cmd.Stdin = strings.NewReader(input)
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	err = cmd.Run()
	nodeObserverFailure := binary == filepath.Join(f.work, "node-observation")
	if err != nil && (nodeObserverFailure || (binary == "kubectl" && slices.Contains(args, "/netgate"))) {
		prefix := "netgate-failure-*.private.log"
		if nodeObserverFailure {
			prefix = "node-observer-failure-*.private.log"
		}
		root := os.Getenv("E2E_KIND_NET_EVIDENCE")
		if info, e := os.Lstat(root); e == nil && filepath.IsAbs(root) && info.IsDir() && info.Mode()&os.ModeSymlink == 0 && info.Mode().Perm()&0077 == 0 {
			if file, e := os.CreateTemp(root, prefix); e == nil {
				raw := stderr.Bytes()
				if len(raw) > 16384 {
					raw = raw[len(raw)-16384:]
				}
				_, _ = file.Write(raw)
				_ = file.Close()
			}
		}
	}
	if err != nil && binary == "helm" {
		// Keep bounded raw diagnostics only in the owned runner's private evidence.
		// Public errors below still contain fixed categories, never parser input.
		root := os.Getenv("E2E_KIND_NET_EVIDENCE")
		if info, e := os.Lstat(root); e == nil && filepath.IsAbs(root) && info.IsDir() && info.Mode()&os.ModeSymlink == 0 && info.Mode().Perm()&0077 == 0 {
			if file, e := os.CreateTemp(root, "helm-failure-*.private.log"); e == nil {
				raw := stderr.Bytes()
				if len(raw) > 65536 {
					raw = raw[len(raw)-65536:]
				}
				_, _ = file.Write(raw)
				_ = file.Close()
			}
		}
		// Never return Helm's raw diagnostics: only fixed categories from stderr.
		for _, category := range []string{"Kubernetes cluster unreachable", "no matches for kind", "already exists", "cannot re-use a name", "schema", "permission denied", "forbidden", "timed out", "failed to create", "failed to download", "unable to build kubernetes objects", "Internal error", "connection refused", "file name too long"} {
			if bytes.Contains(stderr.Bytes(), []byte(category)) {
				err = fmt.Errorf("%w (category: %s)", err, category)
			}
		}
	}
	return stdout.Bytes(), err
}

// diagnoseWorkloads emits only counts, booleans and fixed error categories. Raw Pod messages,
// Events and operator logs can contain credentials; even failure diagnostics must not dump them.
func (f *fixture) diagnoseWorkloads(t *testing.T) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	var deployments appsv1.DeploymentList
	if err := f.kube.List(ctx, &deployments, client.InNamespace(namespace)); err != nil {
		t.Log("diagnostic: Deployment lookup failed")
	} else {
		for i, d := range deployments.Items {
			t.Logf("diagnostic: Deployment %d generation=%d observed=%d ready=%d available=%d updated=%d", i,
				d.Generation, d.Status.ObservedGeneration, d.Status.ReadyReplicas, d.Status.AvailableReplicas, d.Status.UpdatedReplicas)
		}
	}
	var pods corev1.PodList
	if err := f.kube.List(ctx, &pods, client.InNamespace(namespace), client.MatchingLabels{"app.kubernetes.io/name": "tailnet-operator"}); err != nil {
		t.Log("diagnostic: operator Pod lookup failed")
		return
	}
	t.Logf("diagnostic: operator Pods=%d", len(pods.Items))
	for i, pod := range pods.Items {
		for j, c := range pod.Status.ContainerStatuses {
			t.Logf("diagnostic: Pod %d container %d ready=%t restarts=%d waiting=%t terminated=%t", i, j,
				c.Ready, c.RestartCount, c.State.Waiting != nil, c.State.Terminated != nil)
			if c.State.Waiting != nil {
				for _, reason := range []string{"ImagePullBackOff", "ErrImagePull", "ContainerCreating", "CrashLoopBackOff", "CreateContainerConfigError", "CreateContainerError", "RunContainerError"} {
					if c.State.Waiting.Reason == reason {
						t.Log("diagnostic:", reason)
					}
				}
			}
			if c.State.Terminated != nil {
				t.Logf("diagnostic: exitCode=%d", c.State.Terminated.ExitCode)
			}
		}
		cmd := exec.CommandContext(ctx, "kubectl", "--kubeconfig", f.config, "--context", f.context,
			"--namespace", namespace, "logs", pod.Name, "--limit-bytes=16384", "--tail=50")
		cmd.Env = []string{"PATH=" + os.Getenv("PATH"), "HOME=" + f.work}
		var logs bytes.Buffer
		cmd.Stdout, cmd.Stderr = &logs, io.Discard
		if err := cmd.Run(); err == nil {
			for _, category := range []string{"forbidden", "permission denied", "connection refused", "no such file or directory", "exec format error", "failed to acquire lease", "successfully acquired lease", "Starting Controller"} {
				if bytes.Contains(logs.Bytes(), []byte(category)) {
					t.Log("diagnostic: operator log category:", category)
				}
			}
		}
	}
}

func (f *fixture) kubectl(t *testing.T, input string, args ...string) []byte {
	t.Helper()
	return f.child(t, input, "kubectl", append([]string{"--kubeconfig", f.config, "--context", f.context, "--request-timeout=10s", "--namespace", namespace}, args...)...)
}

func (f *fixture) headscale(t *testing.T, args ...string) []byte {
	t.Helper()
	return f.kubectl(t, "", append([]string{"exec", "headscale", "--", "/ko-app/headscale", "--config", "/etc/headscale/config.yaml"}, args...)...)
}

func eventually(t *testing.T, label string, check func() bool) {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), 90*time.Second)
	defer cancel()
	for {
		if check() {
			return
		}
		select {
		case <-ctx.Done():
			t.Fatalf("timed out waiting for %s", label)
		case <-time.After(time.Second):
		}
	}
}

func TestInstall(t *testing.T) {
	installFixture(t)
}

// Each top-level test installs independently; cleanup completes before the next test.
// Never use t.Parallel: the disposable cluster has one fixed release/namespace.
func installFixture(t *testing.T) *fixture {
	t.Helper()
	f := ownedFixture(t)
	t.Cleanup(func() { f.cleanup(t) })
	image := os.Getenv("E2E_KIND_IMAGE")
	hsImage := os.Getenv("E2E_KIND_HEADSCALE_IMAGE")
	if image != "localhost/tailnet-operator-e2e:"+f.cluster || hsImage != "localhost/headscale-e2e:"+f.cluster {
		t.Fatal("expected runner-owned local image tags")
	}
	root, err := filepath.Abs(filepath.Join("..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	values, _ := json.Marshal(map[string]any{
		"image":    map[string]any{"repository": "localhost/tailnet-operator-e2e", "tag": f.cluster, "pullPolicy": "Never"},
		"replicas": 1, "leaderElection": map[string]any{"enabled": true},
		"networkPolicy": map[string]any{"enabled": false},
	})
	t.Log("gate: chart install, CRDs and manager readiness")
	f.child(t, string(values), "helm", "install", "tailnet-operator", filepath.Join(root, "charts", "tailnet-operator"),
		"--kubeconfig", f.config, "--kube-context", f.context, "--namespace", namespace, "--create-namespace", "--wait", "--timeout", "120s", "--values", "-")
	for _, name := range []string{"tailnets", "tailnetegresses", "tailnetingresses"} {
		f.kubectl(t, "", "wait", "--for=condition=Established", "--timeout=30s", "crd/"+name+".tsunaro.io")
	}
	var deployment appsv1.Deployment
	if err := f.kube.Get(t.Context(), client.ObjectKey{Namespace: namespace, Name: "tailnet-operator"}, &deployment); err != nil || deployment.Status.ReadyReplicas != 1 || deployment.Status.ObservedGeneration != deployment.Generation {
		t.Fatal("chart manager is not Ready at its current generation")
	}
	t.Log("gate: real Headscale readiness and bootstrap")
	f.kubectl(t, strings.ReplaceAll(headscaleManifest, "HEADSCALE_IMAGE", hsImage), "apply", "-f", "-")
	f.kubectl(t, "", "wait", "--for=condition=Ready", "--timeout=90s", "pod/headscale")
	if !strings.Contains(string(f.headscale(t, "version")), "0.29.6") {
		t.Fatal("Headscale runtime version is not 0.29.6")
	}
	f.headscale(t, "policy", "set", "--file", "/etc/headscale/seed-policy.json")
	var key string
	if err := json.Unmarshal(f.headscale(t, "apikeys", "create", "--expiration", "1h", "--output", "json"), &key); err != nil || key == "" {
		t.Fatal("Headscale did not return an API-key JSON string")
	}
	secret := &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: "headscale-bootstrap", Namespace: namespace}, StringData: map[string]string{"apiKey": key}}
	if err := f.kube.Create(t.Context(), secret); err != nil {
		t.Fatal("create bootstrap Secret failed (details withheld)")
	}
	base := &corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Name: "headscale-policy", Namespace: namespace}, Data: map[string]string{"policy": basePolicy}}
	if err := f.kube.Create(t.Context(), base); err != nil {
		t.Fatal("create base policy failed")
	}
	tn := &tnv1.Tailnet{ObjectMeta: metav1.ObjectMeta{Name: "fixture"}, Spec: tnv1.TailnetSpec{
		Server: "https://unused.invalid", APIURL: "http://headscale.tailnet-system.svc:8080",
		APISecretRef:   tnv1.SecretKeyRef{Name: "headscale-bootstrap", Key: "apiKey"},
		APIKeyLifetime: metav1.Duration{Duration: time.Hour}, // a typed zero duration serializes as 0s, not omission
		Policy:         tnv1.PolicySpec{BaseConfigMap: "headscale-policy", Mode: "Apply", TagOwners: []string{"tag:fabric"}, RouteApprovers: []string{"tag:fabric"}},
	}}
	if err := f.kube.Create(t.Context(), tn); err != nil {
		t.Fatalf("create Tailnet failed: invalid=%t forbidden=%t conflict=%t (details withheld)",
			apierrors.IsInvalid(err), apierrors.IsForbidden(err), apierrors.IsConflict(err))
	}
	t.Log("gate: Headscale compatibility and policy convergence")
	eventually(t, "HeadscaleCompatible and applied policy", func() bool {
		if f.kube.Get(t.Context(), client.ObjectKey{Name: tn.Name}, tn) != nil {
			return false
		}
		return meta.IsStatusConditionTrue(tn.Status.Conditions, "HeadscaleCompatible") && meta.IsStatusConditionTrue(tn.Status.Conditions, "PolicyApplied")
	})
	// Requeue without changing policy content; InSync must compare the real server policy.
	if err := f.kube.Get(t.Context(), client.ObjectKeyFromObject(base), base); err != nil {
		t.Fatal("get base policy failed")
	}
	base.Annotations = map[string]string{"e2e-kind/recheck": "1"}
	if err := f.kube.Update(t.Context(), base); err != nil {
		t.Fatal("requeue policy comparison failed")
	}
	eventually(t, "PolicyApplied/InSync", func() bool {
		if f.kube.Get(t.Context(), client.ObjectKey{Name: tn.Name}, tn) != nil {
			return false
		}
		c := meta.FindStatusCondition(tn.Status.Conditions, "PolicyApplied")
		return c != nil && c.Status == metav1.ConditionTrue && c.Reason == "InSync" && c.ObservedGeneration == tn.Generation
	})
	// Independent live-policy read through the real server's Unix CLI, not only CR status.
	// v0.29.6 policy get prints raw HuJSON; it deliberately ignores --output.
	canonical, err := policy.Normalize(f.headscale(t, "policy", "get"))
	if err != nil {
		t.Fatal("live policy is not valid JSON")
	}
	var live struct {
		ACLs []struct {
			Action string   `json:"action"`
			Dst    []string `json:"dst"`
		} `json:"acls"`
	}
	if err := json.Unmarshal([]byte(canonical), &live); err != nil || len(live.ACLs) != 1 || live.ACLs[0].Action != "accept" || len(live.ACLs[0].Dst) != 1 || live.ACLs[0].Dst[0] != "192.0.2.1:443" {
		t.Fatal("live policy does not preserve the base ACL")
	}
	if tn.Status.Policy == nil || tn.Status.Policy.AppliedHash != policy.Hash(canonical) || tn.Status.Policy.RenderedHash != policy.Hash(canonical) {
		t.Fatal("Headscale policy does not match rendered/applied hashes")
	}
	var egress tnv1.TailnetEgressList
	var ingress tnv1.TailnetIngressList
	if err := f.kube.List(t.Context(), &egress); err != nil {
		t.Fatal("list egress CRs failed")
	}
	if err := f.kube.List(t.Context(), &ingress); err != nil {
		t.Fatal("list ingress CRs failed")
	}
	if len(egress.Items)+len(ingress.Items) != 0 {
		t.Fatal("foundation must not create data-plane agents")
	}
	f.policy = canonical
	return f
}

func (f *fixture) cleanup(t *testing.T) {
	t.Helper()
	start := time.Now()
	// Cleanup uses a fresh bounded context: testing cancels t.Context before Cleanup.
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	clean := true
	step := func(label, binary string, args ...string) {
		if _, err := f.command(ctx, "", binary, args...); err != nil {
			clean = false
			t.Errorf("cleanup: %s failed (output withheld)", label)
		}
	}
	step("Tailnet deletion", "kubectl", "--kubeconfig", f.config, "--context", f.context,
		"--request-timeout=10s", "delete", "tailnet", "fixture", "--ignore-not-found", "--wait=true", "--timeout=20s")
	step("Helm uninstall", "helm", "uninstall", "tailnet-operator", "--kubeconfig", f.config,
		"--kube-context", f.context, "--namespace", namespace, "--ignore-not-found", "--wait", "--timeout=30s")
	step("namespace deletion", "kubectl", "--kubeconfig", f.config, "--context", f.context,
		"--request-timeout=10s", "delete", "namespace", namespace, "--ignore-not-found", "--wait=true", "--timeout=35s")
	var ns corev1.Namespace
	var tn tnv1.Tailnet
	if !apierrors.IsNotFound(f.kube.Get(ctx, client.ObjectKey{Name: namespace}, &ns)) ||
		!apierrors.IsNotFound(f.kube.Get(ctx, client.ObjectKey{Name: "fixture"}, &tn)) {
		clean = false
		t.Error("cleanup: fixture resources still present or absence could not be verified")
	}
	t.Logf("cleanup: Tailnet, release and namespace verified=%t in %s", clean, time.Since(start).Round(time.Millisecond))
}
