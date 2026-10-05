//go:build e2e_kind

package e2ekind

import (
	"context"
	_ "embed"
	"encoding/json"
	"os"
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
	"k8s.io/utils/ptr"
	"sigs.k8s.io/controller-runtime/pkg/client"

	tnv1 "tsunaro.io/tailnet-operator/api/v1alpha1"
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

// Headscale CLI v0.29.3 uses encoding/json on protobuf structs: numeric IDs,
// snake_case fields, and seconds/nanos timestamps. REST uses a different shape.
type gatewayCLIKey struct {
	ID         uint64   `json:"id"`
	Key        string   `json:"key"`
	Reusable   bool     `json:"reusable"`
	Ephemeral  bool     `json:"ephemeral"`
	Tags       []string `json:"acl_tags"`
	Expiration struct {
		Seconds int64 `json:"seconds"`
		Nanos   int32 `json:"nanos"`
	} `json:"expiration"`
}

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
		n := headscale.Node{ID: strconv.FormatUint(row.ID, 10), MachineKey: row.MachineKey, NodeKey: row.NodeKey, GivenName: row.GivenName, Online: row.Online, IPAddresses: row.IPAddresses, Tags: row.Tags, AvailableRoutes: row.AvailableRoutes}
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
	create := func(obj client.Object) {
		t.Helper()
		if err := f.kube.Create(ctx, obj); err != nil {
			t.Fatalf("gateway fixture create failed (invalid=%t notFound=%t forbidden=%t noMatch=%t)", apierrors.IsInvalid(err), apierrors.IsNotFound(err), apierrors.IsForbidden(err), meta.IsNoMatchError(err))
		}
	}
	// Only the disposable API receives CRDs. No operator/StatefulSet controller
	// is asked to reconcile a gateway; the test admin explicitly creates it.
	f.child(t, "", "kubectl", "--kubeconfig", f.config, "--context", f.context, "apply", "-f", "../../deploy/crds")
	for _, resource := range []string{"tailnets", "tailnetgateways"} {
		f.child(t, "", "kubectl", "--kubeconfig", f.config, "--context", f.context, "wait", "--for=condition=Established", "--timeout=30s", "crd/"+resource+".tsunaro.io")
	}
	tn := &tnv1.Tailnet{ObjectMeta: metav1.ObjectMeta{Name: "gateway-fixture"}, Spec: tnv1.TailnetSpec{Server: "https://fixture-headscale.tailnet-system.svc:8443", APISecretRef: tnv1.SecretKeyRef{Name: "unused-bootstrap"}, APIKeyLifetime: metav1.Duration{Duration: 24 * time.Hour}}}
	create(tn)
	g := &tnv1.TailnetGateway{ObjectMeta: metav1.ObjectMeta{Name: "gateway-fixture"}, Spec: tnv1.TailnetGatewaySpec{
		TailnetRef: tnv1.GatewayLocalReference{Name: tnv1.GatewayName(tn.Name)}, Hostname: "gateway-fixture", Suspend: ptr.To(true),
		StateSecretRef: tnv1.GatewayLocalReference{Name: "gateway-state"}, AuthKeySecretRef: &tnv1.GatewayAuthKeyReference{Name: "gateway-auth", Key: "TS_AUTHKEY"},
		Image: tnv1.GatewayImage(images["tailscale"]), Tags: []string{"tag:fabric"},
		Routes:  tnv1.GatewayRoutes{LAN: []tnv1.GatewayPrefix{"192.0.2.0/24"}},
		Service: tnv1.GatewayService{LoadBalancerIP: "198.51.100.17", TailnetLBCIDR: "198.51.100.0/24"},
		DNS:     tnv1.GatewayDNS{Zone: "tail.example", ServiceName: "gateway-dns", ServiceClusterIP: "10.96.0.54", Image: tnv1.GatewayImage(images["coredns"])},
	}}
	create(g)
	plan, err := gateway.RenderFresh(gateway.FreshInputs{Gateway: g, Tailnet: tn, Namespace: namespace, DNSSerial: 1, Hosts: "198.51.100.8 app.tail.example\n"})
	if err != nil {
		t.Fatal("render admitted fresh gateway")
	}
	state := &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: string(g.Spec.StateSecretRef.Name), Namespace: namespace}, Type: corev1.SecretTypeOpaque}
	create(state)
	stateUID := state.UID
	// A tagged key has no user owner in Headscale 0.29. This is a disposable
	// fixture credential, not the unimplemented production mint/writer path.
	var key gatewayCLIKey
	if json.Unmarshal(pf.cli("preauthkeys", "create", "--tags", "tag:fabric", "--reusable", "--expiration", "1h", "--output", "json"), &key) != nil || key.ID == 0 || key.Key == "" || !key.Reusable || key.Ephemeral || !reflect.DeepEqual(key.Tags, []string{"tag:fabric"}) {
		t.Fatal("persistent gateway fixture key rejected")
	}
	expires := time.Unix(key.Expiration.Seconds, int64(key.Expiration.Nanos))
	if expires.Before(time.Now().Add(30*time.Minute)) || expires.After(time.Now().Add(65*time.Minute)) {
		t.Fatal("gateway fixture key expiration rejected")
	}
	create(&corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: "gateway-auth", Namespace: namespace}, Immutable: ptr.To(true), Type: corev1.SecretTypeOpaque, Data: map[string][]byte{"TS_AUTHKEY": []byte(key.Key)}})
	key.Key = "" // Never serialize a credential into evidence.
	var template *corev1.Pod
	for _, obj := range plan.Objects {
		if sts, ok := obj.(*appsv1.StatefulSet); ok {
			template = &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "gateway-fixture-0", Namespace: namespace, Labels: sts.Spec.Template.Labels}, Spec: *sts.Spec.Template.Spec.DeepCopy()}
			continue
		}
		create(obj)
	}
	if template == nil {
		t.Fatal("fresh Pod template missing")
	}
	// Explicit fixture-only changes: verified preloaded images, public control
	// CA, Talos-equivalent forwarding, and fsGroup for the unprivileged gate's
	// private EmptyDir. Token/state mounts remain exclusive to Tailscale.
	template.Spec.SecurityContext.Sysctls = []corev1.Sysctl{{Name: "net.ipv4.ip_forward", Value: "1"}}
	template.Spec.SecurityContext.FSGroup = ptr.To(int64(65532))
	template.Spec.TerminationGracePeriodSeconds = ptr.To(int64(1))
	for i := range template.Spec.Containers {
		template.Spec.Containers[i].ImagePullPolicy = corev1.PullNever
	}
	template.Spec.InitContainers[0].ImagePullPolicy = corev1.PullNever
	template.Spec.Containers[0].Env = append(template.Spec.Containers[0].Env, corev1.EnvVar{Name: "SSL_CERT_FILE", Value: "/control-ca/ca.pem"}, corev1.EnvVar{Name: "TS_NO_LOGS_NO_SUPPORT", Value: "1"})
	template.Spec.Containers[0].VolumeMounts = append(template.Spec.Containers[0].VolumeMounts, corev1.VolumeMount{Name: "control-ca", MountPath: "/control-ca", ReadOnly: true})
	template.Spec.Volumes = append(template.Spec.Volumes, fixtureConfigVolume("control-ca", pf.public.Name))
	if kindfixture.AddGatewayNetworkGate(template, pf.image) != nil {
		t.Fatal("gateway startup wiring rejected")
	}
	var first gateway.GatewayStateBinding
	for _, phase := range []string{"initial", "recreated"} {
		p := template.DeepCopy()
		create(p)
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
			if f.kube.Get(ctx, client.ObjectKeyFromObject(p), p) != nil || !gatewayProcessesStable(released, p) {
				return false
			}
			if f.kube.Get(ctx, client.ObjectKeyFromObject(state), state) != nil {
				return false
			}
			nodes, ok := decodeGatewayCLINodes(pf.cli("nodes", "list", "--output", "json"))
			if !ok {
				t.Fatal("Headscale CLI node shape rejected")
			}
			var err error
			binding, err = gateway.VerifyGatewayState(g, tn, state, namespace, stateUID, nodes, strconv.FormatUint(key.ID, 10))
			if err != nil {
				return false
			}
			for _, n := range nodes {
				if n.ID == binding.NodeID {
					routes := slices.Clone(n.AvailableRoutes)
					slices.Sort(routes)
					if !slices.Equal(routes, plan.Routes.Routes) {
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
		pf.save("gateway-"+phase+"-result.json", map[string]any{"stateBound": true, "stateUIDRetained": binding.StateUID == stateUID, "nodeID": binding.NodeID, "ipv4": binding.IPv4, "podUID": p.UID, "kernelPreflightPassed": true, "imagesBound": true, "routesAdvertised": plan.Routes.Routes, "routesForwarded": false})
		if phase == "initial" {
			if err := f.kube.Delete(ctx, p, client.Preconditions{UID: &p.UID}); err != nil {
				t.Fatal("remove only owned gateway Pod")
			}
			eventually(t, "owned gateway Pod deleted before recreation", func() bool {
				return apierrors.IsNotFound(f.kube.Get(ctx, client.ObjectKeyFromObject(p), &corev1.Pod{}))
			})
		}
	}
	t.Log("gate: real fresh kernel Pod/preflight/images, non-ephemeral state-to-node binding, advertised route union and identity retained after Pod recreation; no route forwarding, live DNS or adoption proof")
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
