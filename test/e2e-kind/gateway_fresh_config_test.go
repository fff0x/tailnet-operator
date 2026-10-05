//go:build e2e_kind

package e2ekind

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/utils/ptr"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	tnv1 "tsunaro.io/tailnet-operator/api/v1alpha1"
	"tsunaro.io/tailnet-operator/internal/gateway"
	"tsunaro.io/tailnet-operator/test/internal/kindfixture"
)

func TestGatewayControllerFixtureMutation(t *testing.T) {
	g := &tnv1.TailnetGateway{ObjectMeta: metav1.ObjectMeta{Name: "router", UID: "gateway-uid"}, Spec: tnv1.TailnetGatewaySpec{
		TailnetRef: tnv1.GatewayLocalReference{Name: "tailnet"}, Hostname: "router", Replicas: 1, DeletionPolicy: "Retain",
		StateSecretRef: tnv1.GatewayLocalReference{Name: "router-state"}, AuthKeySecretRef: &tnv1.GatewayAuthKeyReference{Name: "router-auth", Key: "TS_AUTHKEY"},
		Image: tnv1.GatewayImage("ghcr.io/tailscale/tailscale@sha256:" + strings.Repeat("1", 64)), Tags: []string{"tag:fabric"},
		Routes:  tnv1.GatewayRoutes{LAN: []tnv1.GatewayPrefix{"192.0.2.0/24"}},
		Service: tnv1.GatewayService{LoadBalancerIP: "198.51.100.1", TailnetLBCIDR: "198.51.100.0/24"},
		DNS:     tnv1.GatewayDNS{Zone: "tail.example", ServiceName: "router-dns", ServiceClusterIP: "10.96.0.53", Image: tnv1.GatewayImage("docker.io/coredns/coredns@sha256:" + strings.Repeat("2", 64))},
	}}
	plan, err := gateway.RenderFresh(gateway.FreshInputs{Namespace: namespace, Gateway: g, Tailnet: &tnv1.Tailnet{ObjectMeta: metav1.ObjectMeta{Name: "tailnet"}, Spec: tnv1.TailnetSpec{Server: "https://headscale.example"}}, DNSSerial: 1})
	if err != nil {
		t.Fatal("fixture render failed")
	}
	scheme := runtime.NewScheme()
	if corev1.AddToScheme(scheme) != nil || appsv1.AddToScheme(scheme) != nil {
		t.Fatal("fixture scheme unavailable")
	}
	c := &gatewayFixtureClient{Client: fake.NewClientBuilder().WithScheme(scheme).Build(), gatewayName: g.Name, gatewayUID: g.UID, publicCA: "fixture-control-ca", gateImage: gatewayTestGate}
	for _, obj := range plan.Objects {
		sts, ok := obj.(*appsv1.StatefulSet)
		if !ok {
			continue
		}
		before := sts.DeepCopy()
		foreign := sts.DeepCopy()
		foreign.Name = "foreign"
		if c.Create(t.Context(), foreign) == nil {
			t.Fatal("foreign StatefulSet accepted")
		}
		if err := c.Create(t.Context(), sts); err != nil {
			t.Fatal(err)
		}
		stored := &appsv1.StatefulSet{}
		if c.Get(t.Context(), client.ObjectKeyFromObject(sts), stored) != nil {
			t.Fatal("StatefulSet was not delegated to Create")
		}
		p := &corev1.Pod{Spec: stored.Spec.Template.Spec}
		if kindfixture.ValidateGatewayNetworkGate(p, gatewayTestGate) != nil || p.Spec.SecurityContext.FSGroup == nil || *p.Spec.SecurityContext.FSGroup != 65532 ||
			!reflect.DeepEqual(p.Spec.SecurityContext.Sysctls, []corev1.Sysctl{{Name: "net.ipv4.ip_forward", Value: "1"}}) || *p.Spec.TerminationGracePeriodSeconds != 1 {
			t.Fatal("fixture startup changes missing")
		}
		if !reflect.DeepEqual(sts.Spec.Template.Spec, stored.Spec.Template.Spec) || !reflect.DeepEqual(stored.Spec.Selector, before.Spec.Selector) ||
			stored.Spec.ServiceName != before.Spec.ServiceName || stored.Spec.Template.Spec.ServiceAccountName != before.Spec.Template.Spec.ServiceAccountName {
			t.Fatal("fixture changed identity or hid admitted template from writer")
		}
		for _, container := range append(p.Spec.Containers, p.Spec.InitContainers...) {
			if container.ImagePullPolicy != corev1.PullNever {
				t.Fatal("fixture image could be pulled")
			}
		}
		for _, v := range before.Spec.Template.Spec.Volumes {
			found := false
			for _, actual := range p.Spec.Volumes {
				if reflect.DeepEqual(actual, v) {
					found = true
				}
			}
			if !found {
				t.Fatal("production token/state volume changed")
			}
		}
	}
	secret := &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: "untouched", Namespace: namespace}, Data: map[string][]byte{"apiKey": []byte("synthetic")}}
	before := secret.DeepCopy()
	if c.Create(t.Context(), secret) != nil || !reflect.DeepEqual(secret.Data, before.Data) || len(secret.Labels) != 0 {
		t.Fatal("non-StatefulSet Create mutated")
	}
}

func TestGatewayFixtureForwardEndpoint(t *testing.T) {
	if endpoint, ok := gatewayForwardEndpoint("Forwarding from 127.0.0.1:43210 -> 8443"); !ok || endpoint != "https://127.0.0.1:43210" {
		t.Fatal("owned port rejected")
	}
	for _, line := range []string{"Forwarding from 0.0.0.0:43210 -> 8443", "Forwarding from [::1]:43210 -> 8443", "Forwarding from 127.0.0.1:0 -> 8443", "Forwarding from 127.0.0.1:65536 -> 8443", "Forwarding from 127.0.0.1:43210 -> 8080", "Forwarding from 127.0.0.1:43210 -> 8443 trailing", ""} {
		if _, ok := gatewayForwardEndpoint(line); ok {
			t.Fatal("unowned port-forward endpoint accepted")
		}
	}
}

func TestGatewayFixtureVerifiedControlTLS(t *testing.T) {
	ca, err := kindfixture.NewAuthority(time.Now())
	if err != nil {
		t.Fatal("fixture CA unavailable")
	}
	cert, key, _, err := ca.Issue("fixture-headscale.tailnet-system.svc", time.Now(), time.Now().Add(20*time.Minute))
	if err != nil {
		t.Fatal("fixture certificate unavailable")
	}
	pair, err := tls.X509KeyPair(cert, key)
	if err != nil {
		t.Fatal("fixture certificate rejected")
	}
	upstream := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer synthetic" {
			http.Error(w, "missing credential", http.StatusUnauthorized)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	upstream.Config.ErrorLog = log.New(io.Discard, "", 0)
	upstream.TLS = &tls.Config{Certificates: []tls.Certificate{pair}, MinVersion: tls.VersionTLS12}
	upstream.StartTLS()
	t.Cleanup(upstream.Close)
	u, _ := url.Parse(upstream.URL)
	wrong, err := kindfixture.NewAuthority(time.Now())
	if err != nil {
		t.Fatal("wrong CA unavailable")
	}
	originalTransport := http.DefaultTransport
	for _, tc := range []struct {
		name   string
		ca     []byte
		status int
	}{{"verified", ca.PublicPEM(), http.StatusNoContent}, {"wrong CA", wrong.PublicPEM(), http.StatusBadGateway}} {
		t.Run(tc.name, func(t *testing.T) {
			proxy := gatewayFixtureProxy(t, u, tc.ca)
			req := httptest.NewRequest(http.MethodGet, "http://127.0.0.1/api/v1/node", nil)
			req.Header.Set("Authorization", "Bearer synthetic")
			response := httptest.NewRecorder()
			proxy.ServeHTTP(response, req)
			if response.Code != tc.status || strings.Contains(response.Body.String(), "synthetic") {
				t.Fatal("verified TLS or redaction contract failed")
			}
		})
	}
	if http.DefaultTransport != originalTransport {
		t.Fatal("global transport changed")
	}
}

func TestGatewayFixtureReceiptProvenance(t *testing.T) {
	g := &tnv1.TailnetGateway{ObjectMeta: metav1.ObjectMeta{Name: "router", UID: "gateway-uid"}}
	auth := gateway.GatewayAuthReceipt{SecretName: "router-auth", UID: "auth-create-uid", Version: "3", KeyID: "7", Expires: time.Now().Add(24 * time.Hour).UTC().Truncate(time.Second)}
	objects := []map[string]string{{"kind": "ConfigMap", "name": "router-auth-receipt", "uid": "auth-receipt-uid"}, {"kind": "StatefulSet", "name": "router", "uid": "sts-create-uid"}}
	for len(objects) < 10 {
		objects = append(objects, map[string]string{"kind": "fixture"})
	}
	payload := map[string]any{"stateUID": "state-create-uid", "auth": auth, "objects": objects, "routes": []string{"198.51.100.0/24"}}
	data, _ := json.Marshal(payload)
	metadata := metav1.ObjectMeta{Namespace: namespace, Labels: map[string]string{"tsunaro.io/gateway-uid": string(g.UID), "app.kubernetes.io/managed-by": "tailnet-operator"}}
	completed := &corev1.ConfigMap{ObjectMeta: *metadata.DeepCopy(), Immutable: ptr.To(true), Data: map[string]string{"receipt.json": string(data)}}
	completed.Name, completed.UID = "router-fresh", "completion-uid"
	record := &corev1.ConfigMap{ObjectMeta: *metadata.DeepCopy(), Immutable: ptr.To(true), Data: map[string]string{"keyID": auth.KeyID, "secretUID": string(auth.UID), "secretName": auth.SecretName, "secretVersion": auth.Version, "expires": auth.Expires.Format(time.RFC3339)}}
	record.Name, record.UID = "router-auth-receipt", "auth-receipt-uid"
	receipt, ok := gatewayFixtureReceipt(completed, record, g)
	if !ok || receipt.StateUID != "state-create-uid" || receipt.Auth.KeyID != "7" {
		t.Fatal("public controller receipt rejected")
	}
	sts := &appsv1.StatefulSet{ObjectMeta: metav1.ObjectMeta{Name: "router", UID: "sts-create-uid"}}
	if !receipt.ownsStatefulSet(sts) {
		t.Fatal("created workload rejected")
	}
	sts.UID = "replacement"
	if receipt.ownsStatefulSet(sts) {
		t.Fatal("replacement workload accepted")
	}
	for name, mutate := range map[string]func(*corev1.ConfigMap, *corev1.ConfigMap){
		"mutable completion":   func(c, a *corev1.ConfigMap) { c.Immutable = ptr.To(false) },
		"mutable auth record":  func(c, a *corev1.ConfigMap) { a.Immutable = ptr.To(false) },
		"foreign auth ID":      func(c, a *corev1.ConfigMap) { a.Data["keyID"] = "8" },
		"replaced auth record": func(c, a *corev1.ConfigMap) { a.UID = "replacement" },
		"replaced auth Secret": func(c, a *corev1.ConfigMap) { a.Data["secretUID"] = "replacement" },
		"missing state provenance": func(c, a *corev1.ConfigMap) {
			c.Data["receipt.json"] = strings.ReplaceAll(c.Data["receipt.json"], "state-create-uid", "")
		},
		"foreign gateway": func(c, a *corev1.ConfigMap) { c.Labels["tsunaro.io/gateway-uid"] = "foreign" },
	} {
		t.Run(name, func(t *testing.T) {
			c, a := completed.DeepCopy(), record.DeepCopy()
			mutate(c, a)
			if _, ok := gatewayFixtureReceipt(c, a, g); ok {
				t.Fatal("unbound receipt accepted")
			}
		})
	}
}

func TestGatewayRuntimeImageAliases(t *testing.T) {
	p, images := gatewayStartupFixture(t)
	ref := images["tailscale"]
	alias := "ghcr.io/tailscale/tailscale@sha256:" + strings.Repeat("3", 64)
	ids, ok := verifiedGatewayImageIDs(ref, "expected-config", "expected-config", []string{alias, ref})
	if !ok {
		t.Fatal("verified archive-index alias rejected")
	}
	g, err := newGatewayStartup(p, gatewayTestNode, gatewayTestGate, images)
	if err != nil {
		t.Fatal(err)
	}
	g.imageIDs["tailscale"] = ids
	p.Status = gatewayStartedStatus(images)
	p.Status.InitContainerStatuses[1].ImageID = alias
	p.Status.ContainerStatuses[0].ImageID = alias
	if !g.started(p, "containerd://gate", []string{gatewayTestGateDigest}) {
		t.Fatal("config-bound runtime alias rejected")
	}
	for _, digests := range [][]string{{alias}, {ref, ref}, {ref, "foreign@sha256:" + strings.Repeat("3", 64)}, {ref, "malformed"}, nil} {
		if _, ok := verifiedGatewayImageIDs(ref, "expected-config", "expected-config", digests); ok {
			t.Fatal("unbound alias accepted")
		}
	}
	if _, ok := verifiedGatewayImageIDs(ref, "expected-config", "foreign-config", []string{ref}); ok {
		t.Fatal("foreign image configuration accepted")
	}
}

func TestGatewayCLIIdentityDecoder(t *testing.T) {
	// Exact encoding/json protobuf shape from Headscale 0.29.3 CLI, not REST.
	b := []byte(`[{"id":12,"machine_key":"mkey:public","node_key":"nodekey:public","given_name":"router","online":true,"ip_addresses":["100.64.0.1"],"tags":["tag:fabric"],"available_routes":["192.0.2.0/24"],"approved_routes":["192.0.2.0/24"],"pre_auth_key":{"id":7}}]`)
	nodes, ok := decodeGatewayCLINodes(b)
	if !ok || len(nodes) != 1 || nodes[0].ID != "12" || nodes[0].MachineKey != "mkey:public" || nodes[0].NodeKey != "nodekey:public" || nodes[0].GivenName != "router" || !nodes[0].Online || nodes[0].PreAuthKey == nil || nodes[0].PreAuthKey.ID != "7" || nodes[0].PreAuthKey.Ephemeral || !reflect.DeepEqual(nodes[0].IPAddresses, []string{"100.64.0.1"}) || !reflect.DeepEqual(nodes[0].AvailableRoutes, []string{"192.0.2.0/24"}) || !reflect.DeepEqual(nodes[0].ApprovedRoutes, []string{"192.0.2.0/24"}) {
		t.Fatal("CLI public identity conversion failed")
	}
	for _, bad := range []string{`[{"id":"12"}]`, `[{"id":0}]`, `[{"id":12,"pre_auth_key":{}}]`, `{"nodes":[]}`, `[{"id":12}] trailing`, strings.Repeat("x", (1<<20)+1)} {
		if _, ok := decodeGatewayCLINodes([]byte(bad)); ok {
			t.Fatal("invalid CLI shape accepted")
		}
	}
	nodes, ok = decodeGatewayCLINodes([]byte(`[{"id":12}]`))
	if !ok || nodes[0].PreAuthKey != nil || nodes[0].Online {
		t.Fatal("absent CLI fields fabricated")
	}
}

func TestGatewayProcessContinuity(t *testing.T) {
	p, images := gatewayStartupFixture(t)
	p.Status = gatewayStartedStatus(images)
	if !gatewayProcessesStable(p, p.DeepCopy()) {
		t.Fatal("unchanged gateway rejected")
	}
	for name, change := range map[string]func(*corev1.Pod){
		"uid":          func(p *corev1.Pod) { p.UID = "recreated" },
		"image":        func(p *corev1.Pod) { p.Status.ContainerStatuses[0].ImageID = "foreign" },
		"process":      func(p *corev1.Pod) { p.Status.ContainerStatuses[1].ContainerID = "new" },
		"init process": func(p *corev1.Pod) { p.Status.InitContainerStatuses[1].ContainerID = "new" },
		"restart":      func(p *corev1.Pod) { p.Status.ContainerStatuses[0].RestartCount = 1 },
		"duplicate":    func(p *corev1.Pod) { p.Status.ContainerStatuses[1] = p.Status.ContainerStatuses[0] },
		"terminated": func(p *corev1.Pod) {
			p.Status.ContainerStatuses[1].State = corev1.ContainerState{Terminated: &corev1.ContainerStateTerminated{}}
		},
		"spec": func(p *corev1.Pod) { p.Spec.Containers[0].Args = []string{"different"} },
	} {
		t.Run(name, func(t *testing.T) {
			current := p.DeepCopy()
			change(current)
			if gatewayProcessesStable(p, current) {
				t.Fatal("unproved process change accepted")
			}
		})
	}
}

func TestGatewayFreshRunnerSelection(t *testing.T) {
	path, err := filepath.Abs("../../hack/e2e-kind-projection.sh")
	if err != nil {
		t.Fatal("runner path unavailable")
	}
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal("runner source unavailable")
	}
	for _, required := range []string{
		"elif [[ $# == 1 && $1 == --gateway-fresh-only ]]; then\n    test_pattern='^TestGatewayFreshPod$'\n    test_timeout=10m\n    gateway_only=true",
		"gateway-images.json test/e2e-kind/gateway-assets*.py",
		`cmp "$out/gateway-cache.json" "$out/gateway-assets.json"`,
		`"$fixture/gateway-assets.py" --check-import`,
		`crictl inspecti "$ref" > "$out/gateway-$component-cri-image.json"`,
		"httppeer,kernelcheck,gatewayprobe}/*.go",
		"kindfixture,kernelcheck,gatewayprobe}/*.go",
		"httppeer kernelcheck gatewayprobe; do",
		"httppeer,kernelcheck,gatewayprobe}",
		`len(s.splitlines())==12 and s.count("statically linked")==12`,
	} {
		if !strings.Contains(string(b), required) {
			t.Fatal("gateway runner bound selection/provenance missing")
		}
	}
	for _, args := range [][]string{{"--gateway-fresh-only", "--repair"}, {"--gateway-fresh-only", "--http-only"}, {"--gateway-fresh-only", "--image=foreign"}} {
		ctx, cancel := context.WithTimeout(t.Context(), 3*time.Second)
		cmd := exec.CommandContext(ctx, "bash", append([]string{path}, args...)...)
		cmd.Env = []string{"PATH=" + os.Getenv("PATH")}
		out, err := cmd.CombinedOutput()
		cancel()
		if e, ok := err.(*exec.ExitError); !ok || e.ExitCode() != 2 || string(out) != "projection: stage=preflight result=rejected\n" {
			t.Fatal("unsupported gateway invocation reached runtime lookup")
		}
	}
}
