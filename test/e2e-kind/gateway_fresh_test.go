//go:build e2e_kind

package e2ekind

import (
	"bufio"
	"context"
	"crypto/tls"
	"crypto/x509"
	_ "embed"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"regexp"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	policyv1 "k8s.io/api/policy/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/tools/clientcmd"
	"k8s.io/utils/ptr"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"

	tnv1 "tsunaro.io/tailnet-operator/api/v1alpha1"
	"tsunaro.io/tailnet-operator/internal/controller"
	"tsunaro.io/tailnet-operator/internal/gateway"
	"tsunaro.io/tailnet-operator/internal/headscale"
	"tsunaro.io/tailnet-operator/test/internal/kindfixture"
)

//go:embed gateway-images.json
var gatewayImageLock []byte

func gatewayFixtureImages(t *testing.T) map[string]string {
	t.Helper()
	root := os.Getenv("E2E_KIND_NET_EVIDENCE")
	var lock struct {
		Images map[string]struct {
			Repository string            `json:"repository"`
			Platforms  map[string]string `json:"platforms"`
		} `json:"images"`
	}
	var report struct {
		Architecture string `json:"architecture"`
		Images       map[string]struct {
			Reference string `json:"reference"`
		} `json:"images"`
	}
	read := func(name string, dst any) {
		t.Helper()
		b, err := os.ReadFile(filepath.Join(root, name))
		if err != nil || len(b) > 1<<20 || json.Unmarshal(b, dst) != nil {
			t.Fatal("gateway image evidence unavailable")
		}
	}
	if json.Unmarshal(gatewayImageLock, &lock) != nil {
		t.Fatal("gateway image lock invalid")
	}
	read("gateway-assets.json", &report)
	if report.Architecture != runtime.GOARCH || len(report.Images) != 2 {
		t.Fatal("gateway image platform mismatch")
	}
	images := make(map[string]string)
	for _, role := range []string{"tailscale", "coredns"} {
		pin := lock.Images[role]
		ref := pin.Repository + "@" + pin.Platforms[runtime.GOARCH]
		if pin.Platforms[runtime.GOARCH] == "" || report.Images[role].Reference != ref {
			t.Fatal("gateway image pin mismatch")
		}
		var verified struct {
			Pinned  bool `json:"pinnedConfigAndReference"`
			Aliases bool `json:"allCRIReferencesExistLiterally"`
		}
		read("gateway-"+role+"-import-verified.json", &verified)
		if !verified.Pinned || !verified.Aliases {
			t.Fatal("gateway image import not verified")
		}
		images[role] = ref
	}
	return images
}

func verifiedGatewayImageIDs(ref, config, actualConfig string, digests []string) ([]string, bool) {
	if config == "" || config != actualConfig || len(digests) == 0 || len(digests) > 8 || !slices.Contains(digests, ref) {
		return nil, false
	}
	repo, _, found := strings.Cut(ref, "@")
	if !found {
		return nil, false
	}
	pattern := regexp.MustCompile(`^` + regexp.QuoteMeta(repo) + `@sha256:[0-9a-f]{64}$`)
	seen := map[string]bool{}
	for _, digest := range digests {
		if seen[digest] || !pattern.MatchString(digest) {
			return nil, false
		}
		seen[digest] = true
	}
	return slices.Clone(digests), true
}

func gatewayFixtureImageIDs(t *testing.T, images map[string]string) map[string][]string {
	t.Helper()
	root := os.Getenv("E2E_KIND_NET_EVIDENCE")
	read := func(name string, dst any) {
		t.Helper()
		b, err := os.ReadFile(filepath.Join(root, name))
		if err != nil || len(b) > 1<<20 || json.Unmarshal(b, dst) != nil {
			t.Fatal("gateway CRI identity evidence unavailable")
		}
	}
	var report struct {
		Images map[string]struct {
			Config string `json:"configDigest"`
		} `json:"images"`
	}
	read("gateway-assets.json", &report)
	out := map[string][]string{}
	for _, role := range []string{"tailscale", "coredns"} {
		var cri struct {
			Status struct {
				ID      string   `json:"id"`
				Digests []string `json:"repoDigests"`
			} `json:"status"`
		}
		read("gateway-"+role+"-cri-image.json", &cri)
		ids, ok := verifiedGatewayImageIDs(images[role], report.Images[role].Config, cri.Status.ID, cri.Status.Digests)
		if !ok {
			t.Fatal("gateway runtime image aliases are not config-bound")
		}
		out[role] = ids
	}
	return out
}

// Headscale CLI v0.29.3 uses encoding/json on protobuf structs: numeric IDs
// and snake_case fields. Kept for the unchanged independent forwarding proof.
func decodeGatewayCLINodes(b []byte) ([]headscale.Node, bool) {
	var rows []struct {
		ID              uint64   `json:"id"`
		MachineKey      string   `json:"machine_key"`
		NodeKey         string   `json:"node_key"`
		GivenName       string   `json:"given_name"`
		Online          bool     `json:"online"`
		IPAddresses     []string `json:"ip_addresses"`
		Tags            []string `json:"tags"`
		AvailableRoutes []string `json:"available_routes"`
		ApprovedRoutes  []string `json:"approved_routes"`
		PreAuthKey      *struct {
			ID        uint64 `json:"id"`
			Ephemeral bool   `json:"ephemeral"`
		} `json:"pre_auth_key"`
	}
	if len(b) == 0 || len(b) > 1<<20 || json.Unmarshal(b, &rows) != nil {
		return nil, false
	}
	out := make([]headscale.Node, 0, len(rows))
	for _, row := range rows {
		if row.ID == 0 {
			return nil, false
		}
		n := headscale.Node{ID: strconv.FormatUint(row.ID, 10), MachineKey: row.MachineKey, NodeKey: row.NodeKey, GivenName: row.GivenName, Online: row.Online, IPAddresses: row.IPAddresses, Tags: row.Tags, AvailableRoutes: row.AvailableRoutes, ApprovedRoutes: row.ApprovedRoutes}
		if row.PreAuthKey != nil {
			if row.PreAuthKey.ID == 0 {
				return nil, false
			}
			n.PreAuthKey = &headscale.NodeAuthKey{ID: strconv.FormatUint(row.PreAuthKey.ID, 10), Ephemeral: row.PreAuthKey.Ephemeral}
		}
		out = append(out, n)
	}
	return out, true
}

// This wrapper is test-only: production creates every resource. Only the
// StatefulSet Create payload receives the same fixture changes as the former
// manually created Pod. Its admitted payload/UID is returned to the real writer
// and therefore covered by the production completion fingerprint.
type gatewayFixtureClient struct {
	client.Client
	gatewayName         string
	gatewayUID          types.UID
	publicCA, gateImage string
}

func (c *gatewayFixtureClient) Create(ctx context.Context, obj client.Object, opts ...client.CreateOption) error {
	if sts, ok := obj.(*appsv1.StatefulSet); ok {
		if sts.Name != c.gatewayName || sts.Namespace != namespace || sts.Labels["tsunaro.io/gateway-uid"] != string(c.gatewayUID) {
			return fmt.Errorf("gateway fixture StatefulSet scope rejected")
		}
		p := &corev1.Pod{ObjectMeta: *sts.Spec.Template.ObjectMeta.DeepCopy(), Spec: *sts.Spec.Template.Spec.DeepCopy()}
		if p.Spec.SecurityContext == nil || len(p.Spec.Containers) != 2 || p.Spec.Containers[0].Name != "tailscale" || len(p.Spec.InitContainers) != 1 {
			return fmt.Errorf("gateway fixture Pod shape rejected")
		}
		p.Spec.SecurityContext.Sysctls = []corev1.Sysctl{{Name: "net.ipv4.ip_forward", Value: "1"}}
		p.Spec.SecurityContext.FSGroup = ptr.To(int64(65532))
		p.Spec.TerminationGracePeriodSeconds = ptr.To(int64(1))
		for i := range p.Spec.Containers {
			p.Spec.Containers[i].ImagePullPolicy = corev1.PullNever
		}
		p.Spec.InitContainers[0].ImagePullPolicy = corev1.PullNever
		p.Spec.Containers[0].Env = append(p.Spec.Containers[0].Env, corev1.EnvVar{Name: "SSL_CERT_FILE", Value: "/control-ca/ca.pem"}, corev1.EnvVar{Name: "TS_NO_LOGS_NO_SUPPORT", Value: "1"})
		p.Spec.Containers[0].VolumeMounts = append(p.Spec.Containers[0].VolumeMounts, corev1.VolumeMount{Name: "control-ca", MountPath: "/control-ca", ReadOnly: true})
		p.Spec.Volumes = append(p.Spec.Volumes, fixtureConfigVolume("control-ca", c.publicCA))
		if err := kindfixture.AddGatewayNetworkGate(p, c.gateImage); err != nil {
			return fmt.Errorf("gateway fixture startup wiring rejected")
		}
		sts.Spec.Template.Spec = p.Spec
	}
	return c.Client.Create(ctx, obj, opts...)
}

// Loopback HTTP is a test-only trust bridge for the unmodified production REST
// client. The upstream HTTPS connection verifies the public fixture CA and DNS
// identity; no global transport, system trust, or insecure TLS is used.
func gatewayFixtureAPI(t *testing.T, ctx context.Context, pf *httpPeerFixture) string {
	t.Helper()
	raw, err := clientcmd.LoadFromFile(pf.f.config)
	if err != nil || validateConfig(raw, pf.f.cluster) != nil {
		t.Fatal("owned port-forward kubeconfig rejected")
	}
	current := &corev1.Pod{}
	if pf.f.kube.Get(ctx, client.ObjectKeyFromObject(pf.hs), current) != nil || current.UID != pf.hs.UID || current.DeletionTimestamp != nil {
		t.Fatal("owned Headscale Pod changed before port-forward")
	}
	forwardCtx, cancel := context.WithCancel(ctx)
	t.Cleanup(cancel)
	cmd := exec.CommandContext(forwardCtx, "kubectl", "--kubeconfig", pf.f.config, "--context", pf.f.context, "--request-timeout=0", "-n", namespace,
		"port-forward", "--address=127.0.0.1", "--pod-running-timeout=30s", "pod/"+pf.hs.Name, ":8443")
	cleanup, err := configureCommandLifecycle(cmd)
	if err != nil {
		t.Fatal("owned port-forward lifecycle unavailable")
	}
	t.Cleanup(cleanup)
	// No inherited proxies, alternate kubeconfigs or credential helpers.
	cmd.Env = []string{"PATH=" + os.Getenv("PATH"), "HOME=" + pf.f.work, "TMPDIR=" + pf.f.work, "LANG=C.UTF-8"}
	cmd.Stderr = io.Discard
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal("owned port-forward output unavailable")
	}
	if cmd.Start() != nil {
		t.Fatal("owned port-forward start failed")
	}
	ready, done := make(chan string, 1), make(chan struct{})
	go func() {
		scanner := bufio.NewScanner(stdout)
		scanner.Buffer(make([]byte, 1024), 1024)
		if scanner.Scan() {
			if endpoint, ok := gatewayForwardEndpoint(scanner.Text()); ok {
				ready <- endpoint
			}
		}
		_, _ = io.Copy(io.Discard, stdout)
		_ = cmd.Wait()
		close(done)
	}()
	t.Cleanup(func() { cancel(); <-done })
	var endpoint string
	select {
	case endpoint = <-ready:
	case <-done:
		t.Fatal("owned port-forward failed")
	case <-time.After(30 * time.Second):
		t.Fatal("owned port-forward readiness timed out")
	case <-ctx.Done():
		t.Fatal("owned port-forward timed out")
	}
	upstream, _ := url.Parse(endpoint)
	proxy := gatewayFixtureProxy(t, upstream, pf.ca.PublicPEM())
	server := httptest.NewServer(proxy)
	t.Cleanup(server.Close)
	return server.URL
}

func gatewayForwardEndpoint(line string) (string, bool) {
	match := regexp.MustCompile(`^Forwarding from 127\.0\.0\.1:([0-9]+) -> 8443$`).FindStringSubmatch(line)
	if len(match) != 2 {
		return "", false
	}
	port, err := strconv.ParseUint(match[1], 10, 16)
	if err != nil || port == 0 {
		return "", false
	}
	return "https://127.0.0.1:" + strconv.FormatUint(port, 10), true
}

func gatewayFixtureProxy(t *testing.T, upstream *url.URL, publicCA []byte) *httputil.ReverseProxy {
	t.Helper()
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(publicCA) {
		t.Fatal("gateway fixture public CA rejected")
	}
	transport := &http.Transport{TLSClientConfig: &tls.Config{RootCAs: roots, ServerName: "fixture-headscale.tailnet-system.svc", MinVersion: tls.VersionTLS12}, TLSHandshakeTimeout: 5 * time.Second, ResponseHeaderTimeout: 15 * time.Second}
	t.Cleanup(transport.CloseIdleConnections)
	proxy := httputil.NewSingleHostReverseProxy(upstream)
	proxy.Transport = transport
	proxy.ErrorHandler = func(w http.ResponseWriter, _ *http.Request, _ error) {
		http.Error(w, "fixture control API unavailable", http.StatusBadGateway)
	}
	return proxy
}

type gatewayCompletionEvidence struct {
	StateUID types.UID                  `json:"stateUID"`
	Auth     gateway.GatewayAuthReceipt `json:"auth"`
	Routes   []string                   `json:"routes"`
	Objects  []struct {
		Kind string    `json:"kind"`
		Name string    `json:"name"`
		UID  types.UID `json:"uid"`
	} `json:"objects"`
}

func gatewayFixtureReceipt(completed, auth *corev1.ConfigMap, g *tnv1.TailnetGateway) (gatewayCompletionEvidence, bool) {
	var receipt gatewayCompletionEvidence
	for _, cm := range []*corev1.ConfigMap{completed, auth} {
		if cm == nil || cm.UID == "" || cm.Namespace != namespace || cm.Immutable == nil || !*cm.Immutable || cm.DeletionTimestamp != nil ||
			cm.Labels["tsunaro.io/gateway-uid"] != string(g.UID) || cm.Labels["app.kubernetes.io/managed-by"] != "tailnet-operator" {
			return receipt, false
		}
	}
	if completed.Name != g.Name+"-fresh" || auth.Name != g.Name+"-auth-receipt" || len(completed.Data["receipt.json"]) > 1<<20 ||
		json.Unmarshal([]byte(completed.Data["receipt.json"]), &receipt) != nil || receipt.StateUID == "" || len(receipt.Objects) != 10 ||
		receipt.Auth.SecretName != g.Name+"-auth" || receipt.Auth.UID == "" || receipt.Auth.Version == "" ||
		receipt.Auth.KeyID != auth.Data["keyID"] || string(receipt.Auth.UID) != auth.Data["secretUID"] ||
		receipt.Auth.SecretName != auth.Data["secretName"] || receipt.Auth.Version != auth.Data["secretVersion"] ||
		receipt.Auth.Expires.UTC().Format(time.RFC3339) != auth.Data["expires"] {
		return receipt, false
	}
	id, err := strconv.ParseUint(receipt.Auth.KeyID, 10, 64)
	if err != nil || id == 0 || !receipt.Auth.Expires.After(time.Now().Add(23*time.Hour)) || receipt.Auth.Expires.After(time.Now().Add(24*time.Hour+time.Minute)) {
		return receipt, false
	}
	for _, obj := range receipt.Objects {
		if obj.Kind == "ConfigMap" && obj.Name == auth.Name && obj.UID == auth.UID {
			return receipt, true
		}
	}
	return receipt, false
}

func (r gatewayCompletionEvidence) ownsStatefulSet(sts *appsv1.StatefulSet) bool {
	for _, obj := range r.Objects {
		if obj.Kind == "StatefulSet" && obj.Name == sts.Name && obj.UID != "" && obj.UID == sts.UID {
			return true
		}
	}
	return false
}

func TestGatewayFreshPod(t *testing.T) {
	if os.Getenv("E2E_KIND_HTTP_NETWORK_GATE") == "" {
		t.Skip("requires isolated gateway runner")
	}
	images := gatewayFixtureImages(t)
	pf := newPeerFixture(t, nil, "gateway-fresh")
	f := pf.f
	if rbacv1.AddToScheme(f.kube.Scheme()) != nil || policyv1.AddToScheme(f.kube.Scheme()) != nil {
		t.Fatal("gateway resource scheme unavailable")
	}
	ctx, cancel := context.WithTimeout(t.Context(), 7*time.Minute)
	defer cancel()
	dataPlane := newGatewayDataPlane(t, pf)
	create := func(obj client.Object) {
		t.Helper()
		if err := f.kube.Create(ctx, obj); err != nil {
			t.Fatalf("gateway fixture create failed (invalid=%t notFound=%t forbidden=%t noMatch=%t)", apierrors.IsInvalid(err), apierrors.IsNotFound(err), apierrors.IsForbidden(err), meta.IsNoMatchError(err))
		}
	}
	// Only the disposable API receives CRDs. The real gateway reconciler writes
	// the runtime and Kubernetes' StatefulSet controller creates both Pods.
	f.child(t, "", "kubectl", "--kubeconfig", f.config, "--context", f.context, "apply", "-f", "../../deploy/crds")
	for _, resource := range []string{"tailnets", "tailnetgateways"} {
		f.child(t, "", "kubectl", "--kubeconfig", f.config, "--context", f.context, "wait", "--for=condition=Established", "--timeout=30s", "crd/"+resource+".tsunaro.io")
	}
	apiURL := gatewayFixtureAPI(t, ctx, pf)
	tn := &tnv1.Tailnet{ObjectMeta: metav1.ObjectMeta{Name: "gateway-fixture"}, Spec: tnv1.TailnetSpec{Server: "https://fixture-headscale.tailnet-system.svc:8443", APIURL: apiURL, APISecretRef: tnv1.SecretKeyRef{Name: "unused-bootstrap"}, APIKeyLifetime: metav1.Duration{Duration: 24 * time.Hour}, DNS: tnv1.DNSSpec{HostsConfigMap: "gateway-hosts"}}}
	create(tn)
	var apiKey string
	if json.Unmarshal(pf.cli("apikeys", "create", "--expiration", "1h", "--output", "json"), &apiKey) != nil || apiKey == "" {
		t.Fatal("gateway working API credential unavailable")
	}
	create(&corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: tn.Name + "-apikey", Namespace: namespace}, Data: map[string][]byte{"apiKey": []byte(apiKey)}})
	hs := headscale.New(apiURL, apiKey)
	apiKey = ""
	create(&corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Name: tn.Spec.DNS.HostsConfigMap, Namespace: namespace,
		Labels:          map[string]string{"app.kubernetes.io/managed-by": "tailnet-operator", "tsunaro.io/role": "dns-hosts"},
		OwnerReferences: []metav1.OwnerReference{*metav1.NewControllerRef(tn, tnv1.GroupVersion.WithKind("Tailnet"))}},
		Data: map[string]string{"hosts": "198.51.100.8 app.tail.example\n"}})
	g := &tnv1.TailnetGateway{ObjectMeta: metav1.ObjectMeta{Name: "gateway-fixture"}, Spec: tnv1.TailnetGatewaySpec{
		TailnetRef: tnv1.GatewayLocalReference{Name: tnv1.GatewayName(tn.Name)}, Hostname: "gateway-fixture", Suspend: ptr.To(false),
		StateSecretRef: tnv1.GatewayLocalReference{Name: "gateway-state"},
		Image:          tnv1.GatewayImage(images["tailscale"]), Tags: []string{"tag:fabric"},
		Routes:  tnv1.GatewayRoutes{LAN: []tnv1.GatewayPrefix{tnv1.GatewayPrefix(dataPlane.prefix)}},
		Service: tnv1.GatewayService{LoadBalancerIP: "198.51.100.17", TailnetLBCIDR: "198.51.100.0/24"},
		DNS:     tnv1.GatewayDNS{Zone: "tail.example", ServiceName: "gateway-dns", ServiceClusterIP: "10.96.0.54", Image: tnv1.GatewayImage(images["coredns"])},
	}}
	create(g)
	if g.Spec.Suspend == nil || *g.Spec.Suspend || g.Spec.AuthKeySecretRef != nil {
		t.Fatal("fresh gateway admission changed controller-mint intent")
	}
	c := &gatewayFixtureClient{Client: f.kube, gatewayName: g.Name, gatewayUID: g.UID, publicCA: pf.public.Name, gateImage: pf.image}
	r := &controller.TailnetGatewayReconciler{Client: c, RuntimeClient: c, OperatorNamespace: namespace}
	reconcile := func() {
		t.Helper()
		if _, err := r.Reconcile(ctx, ctrl.Request{NamespacedName: client.ObjectKeyFromObject(g)}); err != nil {
			t.Fatal("real gateway reconciliation failed")
		}
		if f.kube.Get(ctx, client.ObjectKeyFromObject(g), g) != nil {
			t.Fatal("gateway status unavailable")
		}
		if ready := meta.FindStatusCondition(g.Status.Conditions, "Ready"); ready == nil || ready.Reason != "Provisioning" && ready.Reason != "FreshRuntimeReady" {
			t.Fatal("real gateway reconciliation blocked")
		}
	}
	reconcile()
	// The immutable completion record retains Create-response UIDs. Never
	// manufacture initial provenance from a Get of the current state Secret.
	completed, authRecord := &corev1.ConfigMap{}, &corev1.ConfigMap{}
	if f.kube.Get(ctx, client.ObjectKey{Namespace: namespace, Name: g.Name + "-fresh"}, completed) != nil ||
		f.kube.Get(ctx, client.ObjectKey{Namespace: namespace, Name: g.Name + "-auth-receipt"}, authRecord) != nil {
		t.Fatal("controller completion receipts missing")
	}
	receipt, ok := gatewayFixtureReceipt(completed, authRecord, g)
	if !ok {
		t.Fatal("controller completion provenance rejected")
	}
	expectedRoutes := []string{dataPlane.prefix, string(g.Spec.Service.TailnetLBCIDR)}
	slices.Sort(expectedRoutes)
	if !slices.Equal(receipt.Routes, expectedRoutes) {
		t.Fatal("controller route plan differs from fixture inputs")
	}
	stateUID, keyID := receipt.StateUID, receipt.Auth.KeyID
	state := &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: string(g.Spec.StateSecretRef.Name), Namespace: namespace}}
	sts := &appsv1.StatefulSet{}
	if f.kube.Get(ctx, client.ObjectKey{Namespace: namespace, Name: g.Name}, sts) != nil || !receipt.ownsStatefulSet(sts) {
		t.Fatal("controller-created StatefulSet provenance rejected")
	}
	var first gateway.GatewayStateBinding
	var previousUID types.UID
	for _, phase := range []string{"initial", "recreated"} {
		p := &corev1.Pod{}
		eventually(t, "distinct StatefulSet-created gateway Pod", func() bool {
			reconcile()
			if f.kube.Get(ctx, client.ObjectKey{Namespace: namespace, Name: g.Name + "-0"}, p) != nil || p.UID == "" || p.UID == previousUID || p.DeletionTimestamp != nil {
				return false
			}
			owner := metav1.GetControllerOf(p)
			if owner == nil || owner.Kind != "StatefulSet" || owner.Name != sts.Name || owner.UID != sts.UID {
				return false
			}
			if meta.IsStatusConditionTrue(g.Status.Conditions, "Ready") {
				t.Fatal("gateway Ready before fixture startup release")
			}
			return true
		})
		// Capture only bounded private diagnostics; never read or log the state
		// Secret's data or Headscale credential responses during cleanup.
		t.Cleanup(func() {
			if !t.Failed() {
				return
			}
			cleanup, stop := context.WithTimeout(context.Background(), 15*time.Second)
			defer stop()
			current := &corev1.Pod{}
			if f.kube.Get(cleanup, client.ObjectKeyFromObject(p), current) == nil && current.UID == p.UID {
				pf.save("failed-gateway-"+phase+"-pod.json", current)
				for _, previous := range []bool{false, true} {
					args := []string{"--kubeconfig", f.config, "--context", f.context, "--request-timeout=5s", "-n", namespace, "logs", p.Name, "-c", "tailscale", "--tail=100", "--limit-bytes=16384"}
					if previous {
						args = append(args, "--previous")
					}
					b, err := f.command(cleanup, "", "kubectl", args...)
					// Raw fixture diagnostics stay private, like the existing
					// Headscale fixture logs. Never print them or Secret data.
					if err == nil {
						file, openErr := os.OpenFile(filepath.Join(pf.root, "failed-gateway-"+phase+"-tailscale-previous-"+strconv.FormatBool(previous)+".private.log"), os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
						if openErr == nil {
							_, _ = file.Write(b)
							_ = file.Close()
						}
					}
					categories := map[string]bool{"logReadSucceeded": err == nil}
					for _, category := range []string{"permission denied", "operation not permitted", "read-only file system", "no such file or directory", "x509", "forbidden", "context deadline exceeded", "failed to create tun", "network is unreachable", "no route to host", "tailscale up failed", "kubernetes", "nftables", "iptables"} {
						categories[category] = strings.Contains(strings.ToLower(string(b)), category)
					}
					pf.save("failed-gateway-"+phase+"-tailscale-previous-"+strconv.FormatBool(previous)+"-categories.json", categories)
				}
			}
		})
		releaseGatewayFixturePod(t, f, p, images)
		released := p.DeepCopy()
		var binding gateway.GatewayStateBinding
		eventually(t, "gateway persistent state bound to real Headscale node", func() bool {
			reconcile()
			if !meta.IsStatusConditionTrue(g.Status.Conditions, "Ready") || g.Status.ObservedGeneration != g.Generation {
				return false
			}
			if f.kube.Get(ctx, client.ObjectKeyFromObject(p), p) != nil || !gatewayProcessesStable(released, p) {
				return false
			}
			if f.kube.Get(ctx, client.ObjectKeyFromObject(state), state) != nil {
				return false
			}
			nodes, err := hs.ListNodes(ctx)
			if err != nil {
				t.Fatal("Headscale REST node observation failed")
			}
			binding, err = gateway.VerifyGatewayState(g, tn, state, namespace, stateUID, nodes, keyID)
			if err != nil || g.Status.NodeID != binding.NodeID || g.Status.IPv4 != binding.IPv4 {
				return false
			}
			for _, n := range nodes {
				if n.ID == binding.NodeID {
					routes := slices.Clone(n.AvailableRoutes)
					slices.Sort(routes)
					if !slices.Equal(routes, receipt.Routes) {
						return false
					}
				}
			}
			for _, c := range p.Status.ContainerStatuses {
				if !c.Ready {
					return false
				}
			}
			return true
		})
		if phase == "initial" {
			first = binding
		} else if binding.NodeID != first.NodeID || binding.IPv4 != first.IPv4 || binding.StateUID != first.StateUID {
			t.Fatal("gateway identity changed after Pod recreation")
		}
		dataPlane.prove(t, phase, p, binding)
		pf.save("gateway-"+phase+"-result.json", map[string]any{"controllerReady": true, "statefulSetOwned": true, "stateBound": true, "stateUIDRetained": binding.StateUID == stateUID, "nodeID": binding.NodeID, "ipv4": binding.IPv4, "podUID": p.UID, "kernelPreflightPassed": true, "imagesBound": true, "routesAdvertised": receipt.Routes, "routesForwarded": true, "knownLocalDNSVerified": true})
		if phase == "initial" {
			if err := f.kube.Delete(ctx, p, client.Preconditions{UID: &p.UID}); err != nil {
				t.Fatal("remove only owned gateway Pod")
			}
			previousUID = p.UID // StatefulSet controller, not this test, recreates it.
		}
	}
	t.Log("gate: production fresh controller Ready, StatefulSet-created kernel Pod/preflight/images, non-ephemeral state binding and identity retained across recreation; real IPv4 /32 TCP forwarding with approval/revocation and distinct native control, known local UDP/TCP DNS via gateway tailnet IP; no IPv6 or adoption proof")
}

func gatewayProcessesStable(before, actual *corev1.Pod) bool {
	if before == nil || actual == nil || before.UID == "" || before.UID != actual.UID || actual.DeletionTimestamp != nil || !reflect.DeepEqual(before.Spec, actual.Spec) {
		return false
	}
	for _, pair := range [][2][]corev1.ContainerStatus{{before.Status.InitContainerStatuses, actual.Status.InitContainerStatuses}, {before.Status.ContainerStatuses, actual.Status.ContainerStatuses}} {
		if len(pair[0]) != 2 || len(pair[1]) != 2 {
			return false
		}
		seen := map[string]bool{}
		for _, current := range pair[1] {
			if seen[current.Name] {
				return false
			}
			seen[current.Name] = true
			found := false
			for _, old := range pair[0] {
				if old.Name == current.Name {
					found = old.ContainerID != "" && old.ContainerID == current.ContainerID && old.ImageID == current.ImageID && current.RestartCount == 0 && reflect.DeepEqual(old.State, current.State) && reflect.DeepEqual(old.LastTerminationState, current.LastTerminationState)
				}
			}
			if !found {
				return false
			}
		}
	}
	return true
}
