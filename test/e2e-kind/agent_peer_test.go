//go:build e2e_kind

package e2ekind

import (
	"context"
	"encoding/json"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"

	admissionv1 "k8s.io/api/admissionregistration/v1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/intstr"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"tailscale.com/ipn/ipnstate"
	"tsunaro.io/tailnet-operator/test/internal/kindfixture"
)

func httpFixturePod(name, image string) *corev1.Pod {
	yes, no := true, false
	uid := int64(65532)
	grace := int64(1)
	return &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: namespace, Labels: map[string]string{"fixture-app": name}}, Spec: corev1.PodSpec{
		AutomountServiceAccountToken: &no, EnableServiceLinks: &no, TerminationGracePeriodSeconds: &grace, RestartPolicy: corev1.RestartPolicyNever,
		SecurityContext: &corev1.PodSecurityContext{RunAsUser: &uid, RunAsGroup: &uid, RunAsNonRoot: &yes, FSGroup: &uid, SeccompProfile: &corev1.SeccompProfile{Type: corev1.SeccompProfileTypeRuntimeDefault}},
		Containers:      []corev1.Container{{Name: "application", Image: image, ImagePullPolicy: corev1.PullNever, SecurityContext: &corev1.SecurityContext{AllowPrivilegeEscalation: &no, ReadOnlyRootFilesystem: &yes, Capabilities: &corev1.Capabilities{Drop: []corev1.Capability{"ALL"}}}, Resources: corev1.ResourceRequirements{Requests: corev1.ResourceList{corev1.ResourceCPU: resource.MustParse("50m"), corev1.ResourceMemory: resource.MustParse("64Mi")}, Limits: corev1.ResourceList{corev1.ResourceCPU: resource.MustParse("500m"), corev1.ResourceMemory: resource.MustParse("256Mi")}}}},
	}}
}
func fixtureConfigVolume(name, config string) corev1.Volume {
	return corev1.Volume{Name: name, VolumeSource: corev1.VolumeSource{ConfigMap: &corev1.ConfigMapVolumeSource{LocalObjectReference: corev1.LocalObjectReference{Name: config}}}}
}
func fixtureStateVolume(name, size string) corev1.Volume {
	q := resource.MustParse(size)
	return corev1.Volume{Name: name, VolumeSource: corev1.VolumeSource{EmptyDir: &corev1.EmptyDirVolumeSource{SizeLimit: &q}}}
}

// A nonzero kubectl request timeout adds ?timeout=... to the API proxy URL,
// which reaches the strict fixture HTTP server. The caller instead bounds the
// entire subprocess with a 10-second context.
func peerProxyArgs(config, context, pod string, port int, path string, post bool) []string {
	args := []string{"--kubeconfig", config, "--context", context, "--request-timeout=0"}
	url := fmt.Sprintf("/api/v1/namespaces/%s/pods/%s:%d/proxy/%s", namespace, pod, port, path)
	if post {
		return append(args, "create", "--raw", url, "-f", "-")
	}
	return append(args, "get", "--raw", url)
}

func TestPeerProxyHasNoForwardedTimeout(t *testing.T) {
	for _, post := range []bool{false, true} {
		args := peerProxyArgs("private-config", "owned-context", "http-peer", 9081, "probe", post)
		if args[4] != "--request-timeout=0" || strings.Contains(strings.Join(args, " "), "?") {
			t.Fatal("proxy adds a backend query")
		}
		if post && !reflect.DeepEqual(args[len(args)-2:], []string{"-f", "-"}) {
			t.Fatal("probe body input changed")
		}
	}
}

func fixtureTLSVolume(name, secret string) corev1.Volume {
	mode := int32(0440)
	return corev1.Volume{Name: name, VolumeSource: corev1.VolumeSource{Secret: &corev1.SecretVolumeSource{SecretName: secret, DefaultMode: &mode}}}
}

const httpFixtureUser = "fixture"

// A scope keeps one test's evidence files from colliding with another's; save() opens them O_EXCL.
// The list stays explicit so an unreviewed caller cannot write outside its own directory.
var peerEvidenceScopes = []string{"ingress-l4", "gateway-fresh", "restart-no-flap", "magicdns-rename", "egress-reach"}

type httpPeerFixture struct {
	f                       *fixture
	ns                      *corev1.Namespace
	ca                      *kindfixture.Authority
	public                  *corev1.ConfigMap
	hs, peer                *corev1.Pod
	root, image, agentImage string
	create                  func(client.Object)
	save                    func(string, any)
	tlsSecret               func(string, string) string
	cli                     func(...string) []byte
	auth                    func(string)
	keyEnv                  func(string) corev1.EnvVar
	proxy                   func(string, int, string, string) ([]byte, error)
}

func newHTTPPeerFixture(t *testing.T) *httpPeerFixture {
	return newHTTPPeerFixtureWithServingCA(t, nil)
}

func newHTTPPeerFixtureWithServingCA(t *testing.T, servingCA []byte) *httpPeerFixture {
	return newPeerFixture(t, servingCA, "")
}

func newPeerFixture(t *testing.T, servingCA []byte, evidenceScope string) *httpPeerFixture {
	t.Helper()
	if evidenceScope != "" && (!slices.Contains(peerEvidenceScopes, evidenceScope) || servingCA != nil) {
		t.Fatal("unsupported peer evidence scope")
	}
	if os.Getenv("E2E_KIND_HTTP_NETWORK_GATE") == "" {
		t.Skip("requires owned isolated HTTP runner")
	}
	f := ownedFixture(t)
	image, agentImage := os.Getenv("E2E_KIND_FIXTURE_IMAGE"), os.Getenv("E2E_KIND_AGENT_IMAGE")
	if os.Getenv("E2E_KIND_HTTP_NETWORK_GATE") != "passed" || image != "localhost/tn-source-netprobe:"+f.cluster || agentImage != "localhost/tailnet-operator-e2e:"+f.cluster {
		t.Fatal("owned images/network gate required")
	}
	if admissionv1.AddToScheme(f.kube.Scheme()) != nil {
		t.Fatal("admission scheme unavailable")
	}
	root := os.Getenv("E2E_KIND_NET_EVIDENCE")
	info, err := os.Lstat(root)
	if err != nil || !filepath.IsAbs(root) || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm()&0077 != 0 {
		t.Fatal("private peer evidence missing")
	}
	if servingCA != nil || evidenceScope != "" {
		if servingCA != nil {
			evidenceScope = "ingress-http"
		}
		root = filepath.Join(root, evidenceScope)
		if os.Mkdir(root, 0700) != nil {
			t.Fatal("exclusive integrated evidence unavailable")
		}
	}
	save := func(name string, v any) {
		t.Helper()
		b, err := json.Marshal(v)
		if err != nil {
			t.Fatal("peer evidence encoding failed")
		}
		file, err := os.OpenFile(filepath.Join(root, name), os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
		if err != nil {
			t.Fatal("peer evidence create failed")
		}
		_, e := file.Write(b)
		ce := file.Close()
		if e != nil || ce != nil {
			t.Fatal("peer evidence write failed")
		}
	}
	ns := &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: namespace}}
	if f.kube.Create(t.Context(), ns) != nil {
		t.Fatal("peer namespace create failed")
	}
	var hook *admissionv1.MutatingWebhookConfiguration
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
		defer cancel()
		if hook != nil && hook.UID != "" {
			if err := f.kube.Delete(ctx, hook, client.Preconditions{UID: &hook.UID}); err != nil && !apierrors.IsNotFound(err) {
				t.Error("peer webhook cleanup failed")
			}
		}
		if t.Failed() {
			for _, name := range []string{"fixture-headscale", "http-agent", "http-peer"} {
				var p corev1.Pod
				if f.kube.Get(ctx, client.ObjectKey{Namespace: namespace, Name: name}, &p) == nil {
					save("failed-"+name+"-pod.json", p)
				}
				for _, container := range []string{"application", "agent", kindfixture.NetworkGateContainer} {
					b, _ := f.command(ctx, "", "kubectl", "--kubeconfig", f.config, "--context", f.context, "--request-timeout=5s", "-n", namespace, "logs", name, "-c", container, "--tail=100", "--limit-bytes=32768")
					file, err := os.OpenFile(filepath.Join(root, "failed-"+name+"-"+container+".private.log"), os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
					if err == nil {
						_, _ = file.Write(b)
						_ = file.Close()
					}
				}
			}
		}
		if err := f.kube.Delete(ctx, ns, client.Preconditions{UID: &ns.UID}); err != nil && !apierrors.IsNotFound(err) {
			t.Error("peer namespace cleanup failed")
			return
		}
		for {
			if apierrors.IsNotFound(f.kube.Get(ctx, client.ObjectKey{Name: namespace}, &corev1.Namespace{})) {
				t.Log("gate: owned peer namespace removed")
				return
			}
			select {
			case <-ctx.Done():
				t.Error("peer namespace cleanup timed out")
				return
			case <-time.After(time.Second):
			}
		}
	})
	if ns.Labels == nil {
		ns.Labels = map[string]string{}
	}
	ns.Labels[kindfixture.OwnerLabel] = string(ns.UID)
	if f.kube.Update(t.Context(), ns) != nil {
		t.Fatal("peer namespace ownership failed")
	}
	create := func(o client.Object) {
		t.Helper()
		if f.kube.Create(t.Context(), o) != nil {
			t.Fatal("owned peer resource create failed")
		}
	}
	ca, err := kindfixture.NewAuthority(time.Now())
	if err != nil {
		t.Fatal("peer authority failed")
	}
	public, err := kindfixture.PublicCAConfigMap(ns, "fixture-control-ca", ca.PublicPEM(), time.Now())
	if err != nil {
		t.Fatal("peer public CA rejected")
	}
	create(public)
	if servingCA != nil {
		serving, err := kindfixture.PublicCAConfigMap(ns, "fixture-serving-ca", servingCA, time.Now())
		if err != nil {
			t.Fatal("separate public serving CA rejected")
		}
		create(serving)
	}
	tlsSecret := func(name, dns string) string {
		t.Helper()
		cert, key, hash, err := ca.Issue(dns, time.Now(), time.Now().Add(20*time.Minute))
		if err != nil {
			t.Fatal("peer leaf failed")
		}
		create(&corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: namespace}, Type: corev1.SecretTypeTLS, Data: map[string][]byte{"tls.crt": cert, "tls.key": key}})
		return hash
	}
	tlsSecret("headscale-tls", "fixture-headscale.tailnet-system.svc")
	yes := true
	seedPolicy := `{"acls":[{"action":"accept","src":["*"],"dst":["*:*"]}]}`
	if evidenceScope == "gateway-fresh" {
		seedPolicy = `{"tagOwners":{"tag:fabric":[]},"acls":[{"action":"accept","src":["*"],"dst":["*:*"]}]}`
	}
	create(&corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Name: "headscale-https-config", Namespace: namespace}, Immutable: &yes, Data: map[string]string{"config.json": headscaleHTTPConfig, "seed-policy.json": seedPolicy}})
	hs := httpFixturePod("fixture-headscale", image)
	a := &hs.Spec.Containers[0]
	a.Command = []string{"/headscale"}
	a.Args = []string{"--config", "/headscale-config/config.json", "serve"}
	a.Env = []corev1.EnvVar{{Name: "TS_NO_LOGS_NO_SUPPORT", Value: "1"}, {Name: "TMPDIR", Value: "/tmp"}}
	a.VolumeMounts = []corev1.VolumeMount{{Name: "config", MountPath: "/headscale-config", ReadOnly: true}, {Name: "tls", MountPath: "/headscale-tls", ReadOnly: true}, {Name: "state", MountPath: "/state"}, {Name: "tmp", MountPath: "/tmp"}}
	hs.Spec.Volumes = []corev1.Volume{fixtureConfigVolume("config", "headscale-https-config"), fixtureTLSVolume("tls", "headscale-tls"), fixtureStateVolume("state", "64Mi"), fixtureStateVolume("tmp", "16Mi")}
	if kindfixture.AddNetworkGate(hs, image) != nil {
		t.Fatal("peer control startup gate failed")
	}
	create(&corev1.Service{ObjectMeta: metav1.ObjectMeta{Name: hs.Name, Namespace: namespace}, Spec: corev1.ServiceSpec{Selector: hs.Labels, Ports: []corev1.ServicePort{{Name: "https", Port: 8443, TargetPort: intstr.FromInt32(8443)}, {Name: "stun", Protocol: corev1.ProtocolUDP, Port: 3478, TargetPort: intstr.FromInt32(3478)}}}})
	create(hs)
	releaseFixturePod(t, f, hs)
	tryCLI := func(args ...string) ([]byte, error) {
		ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
		defer cancel()
		base := []string{"--kubeconfig", f.config, "--context", f.context, "--request-timeout=8s", "-n", namespace, "exec", hs.Name, "-c", "application", "--", "/headscale", "--config", "/headscale-config/config.json"}
		b, err := f.command(ctx, "", "kubectl", append(base, args...)...)
		if err != nil || len(b) > 1<<20 {
			return nil, fmt.Errorf("private Headscale CLI failed")
		}
		return b, nil
	}
	// Container Running is not Unix-socket/API readiness. Retry only this
	// non-mutating operation, never user or credential creation.
	eventually(t, "Headscale local API ready", func() bool {
		b, err := tryCLI("users", "list", "--output", "json")
		var users []json.RawMessage
		return err == nil && json.Unmarshal(b, &users) == nil
	})
	cli := func(args ...string) []byte {
		t.Helper()
		b, err := tryCLI(args...)
		if err != nil {
			t.Fatal("private Headscale CLI failed")
		}
		return b
	}
	cli("policy", "set", "--file", "/headscale-config/seed-policy.json")
	var user struct {
		ID uint64 `json:"id"`
	}
	if json.Unmarshal(cli("users", "create", httpFixtureUser, "--output", "json"), &user) != nil || user.ID == 0 {
		t.Fatal("fixture user missing")
	}
	auth := func(name string) {
		t.Helper()
		var key struct {
			Key string `json:"key"`
		}
		if json.Unmarshal(cli("preauthkeys", "create", "--user", fmt.Sprint(user.ID), "--expiration", "1h", "--output", "json"), &key) != nil || key.Key == "" {
			t.Fatal("fixture auth creation failed")
		}
		create(&corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: namespace}, Data: map[string][]byte{"key": []byte(key.Key)}})
	}
	// The kernel gateway needs the same verified HTTPS control plane, but no
	// userspace HTTP peer or agent-only admission webhook. Keep those unchanged
	// for existing callers and never inject their pod mutation into a gateway.
	if evidenceScope == "gateway-fresh" {
		return &httpPeerFixture{f: f, ns: ns, ca: ca, public: public, hs: hs, root: root, image: image, agentImage: agentImage, create: create, save: save, tlsSecret: tlsSecret, cli: cli, auth: auth}
	}
	auth("http-peer-auth")
	keyEnv := func(name string) corev1.EnvVar {
		return corev1.EnvVar{Name: "TS_AUTHKEY", ValueFrom: &corev1.EnvVarSource{SecretKeyRef: &corev1.SecretKeySelector{LocalObjectReference: corev1.LocalObjectReference{Name: name}, Key: "key"}}}
	}
	peer := httpFixturePod("http-peer", image)
	peer.Spec.Containers[0].Command = []string{"/httppeer"}
	peer.Spec.Containers[0].Args = []string{"--fixture=p1.8-http"}
	peer.Spec.Containers[0].Env = []corev1.EnvVar{keyEnv("http-peer-auth")}
	peer.Spec.Containers[0].VolumeMounts = []corev1.VolumeMount{{Name: "ca", MountPath: "/control-ca", ReadOnly: true}, {Name: "state", MountPath: "/state"}}
	peer.Spec.Volumes = []corev1.Volume{fixtureConfigVolume("ca", "fixture-control-ca"), fixtureStateVolume("state", "32Mi")}
	if servingCA != nil {
		peer.Spec.Containers[0].Args = append(peer.Spec.Containers[0].Args, "--serving-ca=cert-manager")
		peer.Spec.Containers[0].VolumeMounts = append(peer.Spec.Containers[0].VolumeMounts, corev1.VolumeMount{Name: "serving-ca", MountPath: "/serving-ca", ReadOnly: true})
		peer.Spec.Volumes = append(peer.Spec.Volumes, fixtureConfigVolume("serving-ca", "fixture-serving-ca"))
	}
	if kindfixture.AddNetworkGate(peer, image) != nil {
		t.Fatal("peer startup gate failed")
	}
	create(peer)
	releaseFixturePod(t, f, peer)
	proxy := func(pod string, port int, path string, input string) ([]byte, error) {
		ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
		defer cancel()
		return f.command(ctx, input, "kubectl", peerProxyArgs(f.config, f.context, pod, port, path, input != "")...)
	}
	eventually(t, "independent tsnet peer Running", func() bool { _, err := proxy(peer.Name, 9081, "readyz", ""); return err == nil })
	create(&corev1.Service{ObjectMeta: metav1.ObjectMeta{Name: "fixture-backend", Namespace: namespace}, Spec: corev1.ServiceSpec{Selector: peer.Labels, Ports: []corev1.ServicePort{{Name: "http", Port: 8080, TargetPort: intstr.FromInt32(8080)}}}})
	// Same fixture webhook as projection acceptance, now admitting the real
	// production-source agent image. Only CA mount and startup gate are injected.
	tlsSecret("fixture-admission-tls", "fixture-admission."+namespace+".svc")
	server := httpFixturePod("fixture-admission", image)
	server.Spec.Containers[0].Command = []string{"/fixture"}
	server.Spec.Containers[0].Args = []string{"--mode=admission", "--fixture=p1.8-http", "--namespace=" + namespace, "--agent-image=" + agentImage, "--ca-config-map=fixture-control-ca", "--tls-cert=/fixture-tls/tls.crt", "--tls-key=/fixture-tls/tls.key", "--network-gate-image=" + image}
	server.Spec.Containers[0].VolumeMounts = []corev1.VolumeMount{{Name: "tls", MountPath: "/fixture-tls", ReadOnly: true}}
	server.Spec.Volumes = []corev1.Volume{fixtureTLSVolume("tls", "fixture-admission-tls")}
	server.Spec.Containers[0].ReadinessProbe = &corev1.Probe{ProbeHandler: corev1.ProbeHandler{HTTPGet: &corev1.HTTPGetAction{Path: "/readyz", Port: intstr.FromInt32(9443), Scheme: corev1.URISchemeHTTPS}}, PeriodSeconds: 1}
	create(server)
	create(&corev1.Service{ObjectMeta: metav1.ObjectMeta{Name: server.Name, Namespace: namespace}, Spec: corev1.ServiceSpec{Selector: server.Labels, Ports: []corev1.ServicePort{{Port: 443, TargetPort: intstr.FromInt32(9443)}}}})
	eventually(t, "peer admission server Ready", func() bool {
		return f.kube.Get(t.Context(), client.ObjectKeyFromObject(server), server) == nil && len(server.Status.ContainerStatuses) == 1 && server.Status.ContainerStatuses[0].Ready
	})
	hook, err = kindfixture.AgentCAWebhook(ns, "fixture-peer-ca-"+f.cluster, ca.PublicPEM(), time.Now())
	if err != nil {
		t.Fatal("peer webhook rejected")
	}
	create(hook)
	// Admission configuration observation is asynchronous. Before any caller
	// may create a CR whose controller spawns an agent, prove this API server
	// actually invokes the fail-closed webhook. The preview is never persisted.
	barrier := httpFixturePod("agent-admission-barrier", agentImage)
	barrier.Labels = map[string]string{"app.kubernetes.io/name": "tailnet-ingress", "app.kubernetes.io/managed-by": "tailnet-operator"}
	barrier.Spec.Containers[0].Name = "agent"
	barrier.Spec.Containers[0].Command = []string{"/tailnet-agent"}
	barrier.Spec.Containers[0].Env = []corev1.EnvVar{{Name: "AGENT_MODE", Value: "ingress"}, {Name: "SSL_CERT_FILE", Value: "/ca-certificates.crt"}}
	barrier.Spec.SchedulingGates = []corev1.PodSchedulingGate{{Name: "fixture.tsunaro.io/admission-only"}}
	eventually(t, "shared agent admission armed", func() bool {
		preview := barrier.DeepCopy()
		return f.kube.Create(t.Context(), preview, client.DryRunAll) == nil && len(preview.Spec.InitContainers) == 1 &&
			preview.Spec.InitContainers[0].Name == kindfixture.NetworkGateContainer && preview.Spec.InitContainers[0].Image == image &&
			preview.Spec.Containers[0].Image == agentImage && reflect.DeepEqual(preview.Spec.Containers[0].Command, barrier.Spec.Containers[0].Command) && reflect.DeepEqual(preview.Spec.Containers[0].Env, barrier.Spec.Containers[0].Env)
	})
	return &httpPeerFixture{
		f: f, ns: ns, ca: ca, public: public, hs: hs, peer: peer,
		root: root, image: image, agentImage: agentImage,
		create: create, save: save, tlsSecret: tlsSecret, cli: cli,
		auth: auth, keyEnv: keyEnv, proxy: proxy,
	}
}

// TestAgentHTTPSPeer deliberately exercises production-agent source without a
// reconciler or cert-manager. Pods/config are explicit fixtures, not CR status.
func TestAgentHTTPSPeer(t *testing.T) {
	fixture := newHTTPPeerFixture(t)
	f, hs, peer := fixture.f, fixture.hs, fixture.peer
	root, agentImage := fixture.root, fixture.agentImage
	create, save, tlsSecret := fixture.create, fixture.save, fixture.tlsSecret
	auth, keyEnv, proxy := fixture.auth, fixture.keyEnv, fixture.proxy
	auth("http-agent-auth")
	leafHash := tlsSecret("http-agent-serving", "http-agent.fixture.test")
	targets := map[string]any{"version": 1, "targets": []map[string]any{{"name": "http", "address": "fixture-backend.tailnet-system.svc", "port": 8080, "listenPort": 443, "mode": "http", "configID": strings.Repeat("a", 64), "dnsName": "http-agent.fixture.test", "certFile": "/tls/tls.crt", "keyFile": "/tls/tls.key"}}}
	rawTargets, _ := json.Marshal(targets)
	create(&corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Name: "http-agent-targets", Namespace: namespace}, Data: map[string]string{"targets.json": string(rawTargets)}})
	agent := httpFixturePod("http-agent", agentImage)
	agent.Labels = map[string]string{"app.kubernetes.io/name": "tailnet-ingress", "app.kubernetes.io/managed-by": "tailnet-operator"}
	agent.Spec.SchedulingGates = []corev1.PodSchedulingGate{{Name: "fixture.tsunaro.io/verify-admission"}}
	ac := &agent.Spec.Containers[0]
	ac.Name = "agent"
	ac.Command = []string{"/tailnet-agent"}
	ac.Env = []corev1.EnvVar{{Name: "AGENT_MODE", Value: "ingress"}, {Name: "CONTROL_URL", Value: "https://fixture-headscale.tailnet-system.svc:8443"}, {Name: "TS_HOSTNAME", Value: "http-agent"}, {Name: "TS_DEBUG_MTU", Value: "1200"}, {Name: "PROBE_INTERVAL", Value: "2s"}, {Name: "TARGETS_FILE", Value: "/config/targets.json"}, {Name: "SSL_CERT_FILE", Value: "/ca-certificates.crt"}, {Name: "TS_STATE_DIR", Value: "/state"}, {Name: "HOME", Value: "/state"}, keyEnv("http-agent-auth")}
	ac.VolumeMounts = []corev1.VolumeMount{{Name: "targets", MountPath: "/config", ReadOnly: true}, {Name: "state", MountPath: "/state"}, {Name: "tls", MountPath: "/tls", ReadOnly: true}}
	agent.Spec.Volumes = []corev1.Volume{fixtureConfigVolume("targets", "http-agent-targets"), fixtureStateVolume("state", "32Mi"), fixtureTLSVolume("tls", "http-agent-serving")}
	// Wait for actual admission registration without starting an ungated agent.
	eventually(t, "agent admission armed", func() bool {
		preview := agent.DeepCopy()
		return f.kube.Create(t.Context(), preview, client.DryRunAll) == nil && len(preview.Spec.InitContainers) == 1
	})
	beforeAgent := agent.DeepCopy()
	create(agent)
	if len(agent.Spec.InitContainers) != 1 || agent.Spec.Containers[0].Image != beforeAgent.Spec.Containers[0].Image || !reflect.DeepEqual(agent.Spec.Containers[0].Command, beforeAgent.Spec.Containers[0].Command) || !reflect.DeepEqual(agent.Spec.Containers[0].Env, beforeAgent.Spec.Containers[0].Env) {
		t.Fatal("real agent admission missing gate or changed application")
	}
	save("agent-admitted.json", agent)
	schedulingBase := agent.DeepCopy()
	agent.Spec.SchedulingGates = nil
	if f.kube.Patch(t.Context(), agent, client.MergeFromWithOptions(schedulingBase, client.MergeFromWithOptimisticLock{})) != nil {
		t.Fatal("verified admission scheduling release failed")
	}
	releaseFixturePod(t, f, agent)
	// Bind the actual app image to the locally built production-layout archive,
	// independently of the separately verified init image.
	var local []struct {
		ID string `json:"Id"`
	}
	var cri struct {
		Status struct {
			ID      string   `json:"id"`
			Tags    []string `json:"repoTags"`
			Digests []string `json:"repoDigests"`
		} `json:"status"`
	}
	lb, le := os.ReadFile(filepath.Join(root, "agent-image.json"))
	cb, ce := os.ReadFile(filepath.Join(root, "agent-cri-image.json"))
	if le != nil || ce != nil || json.Unmarshal(lb, &local) != nil || json.Unmarshal(cb, &cri) != nil || len(local) != 1 || cri.Status.ID != "sha256:"+strings.TrimPrefix(local[0].ID, "sha256:") {
		t.Fatal("production image config identity differs")
	}
	tagged, matched := false, false
	for _, v := range cri.Status.Tags {
		tagged = tagged || v == agentImage
	}
	for _, v := range cri.Status.Digests {
		matched = matched || v == agent.Status.ContainerStatuses[0].ImageID
	}
	if !tagged || !matched {
		t.Fatal("production app image identity differs")
	}
	var status ipnstate.Status
	eventually(t, "actual production agent Running", func() bool {
		b, err := proxy(agent.Name, 9080, "status", "")
		return err == nil && len(b) < 1<<20 && json.Unmarshal(b, &status) == nil && status.BackendState == "Running" && len(status.TailscaleIPs) > 0
	})
	var tailIP string
	for _, ip := range status.TailscaleIPs {
		if ip.Is4() && netip.MustParsePrefix("100.64.0.0/10").Contains(ip) {
			tailIP = ip.String()
		}
	}
	if tailIP == "" || status.Self == nil || strings.TrimSuffix(status.Self.DNSName, ".") != "http-agent.fixture.test" {
		t.Fatal("assigned tailnet identity missing")
	}
	eventually(t, "agent local TLS and backend readiness", func() bool { _, err := proxy(agent.Name, 9080, "healthz", ""); return err == nil })
	type response struct {
		OK      bool   `json:"ok"`
		Status  int    `json:"status"`
		Major   int    `json:"httpMajor"`
		ALPN    string `json:"alpn"`
		Leaf    string `json:"leafSHA256"`
		Backend bool   `json:"backendVerified"`
	}
	results := []response{}
	for _, target := range []string{tailIP, "http-agent.fixture.test"} {
		for _, h2 := range []bool{false, true} {
			var got response
			eventually(t, "real peer verified HTTP", func() bool {
				input, _ := json.Marshal(map[string]any{"target": target, "http2": h2})
				b, err := proxy(peer.Name, 9081, "probe", string(input))
				return err == nil && len(b) < 4096 && json.Unmarshal(b, &got) == nil && got.OK && got.Status == 200 && got.Backend && got.Leaf == leafHash && ((h2 && got.Major == 2 && got.ALPN == "h2") || (!h2 && got.Major == 1))
			})
			results = append(results, got)
		}
	}
	for _, started := range []*corev1.Pod{hs, peer, agent} {
		var current corev1.Pod
		if f.kube.Get(t.Context(), client.ObjectKeyFromObject(started), &current) != nil || current.UID != started.UID || len(current.Status.ContainerStatuses) != 1 || len(current.Status.InitContainerStatuses) != 1 {
			t.Fatal("peer fixture identity unavailable")
		}
		c, init := current.Status.ContainerStatuses[0], current.Status.InitContainerStatuses[0]
		if c.ContainerID != started.Status.ContainerStatuses[0].ContainerID || c.RestartCount != 0 || c.State.Running == nil || init.RestartCount != 0 || init.State.Terminated == nil || init.State.Terminated.ExitCode != 0 {
			t.Fatal("peer fixture process identity changed")
		}
		save("peer-final-"+started.Name+".json", &current)
	}
	save("agent-peer-http-result.json", map[string]any{"httpChecks": results, "verifiedProductionImage": true, "actualAdmittedInitReleased": true, "reconcilerTested": false, "certManagerTested": false, "aclNegativeTested": false})
	t.Log("gate: admitted production-source agent and independent tsnet peer; assigned-IP/MagicDNS HTTP1+HTTP2, verified leaf and forwarding headers")
}
