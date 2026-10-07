//go:build e2e_kind

package e2ekind

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/netip"
	"reflect"
	"slices"
	"testing"
	"time"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/fields"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/watch"
	"sigs.k8s.io/controller-runtime/pkg/client"

	tnv1 "tsunaro.io/tailnet-operator/api/v1alpha1"
	"tsunaro.io/tailnet-operator/internal/certificates"
	"tsunaro.io/tailnet-operator/test/internal/kindfixture"
)

// Keep both existing backend identities: the strict plain-HTTP fixture returns
// a verified 200/body, while the verified Headscale HTTPS endpoint returns 404.
// No extra listeners, trust bypasses or synthetic controller status are needed.
func testIngressVirtualHosts(t *testing.T, x *httpPeerFixture, ingress *tnv1.TailnetIngress, agent *corev1.Pod, certificateUID types.UID, previousLeaf string) {
	f := x.f
	const primary = "http-agent.fixture.test"
	const second = "admin.fixture.test"
	const alias = "admin-tailnet-system.fixture.test"
	wantNames := []string{primary, second, alias}
	slices.Sort(wantNames)
	oldPod := agent.DeepCopy()
	var dep appsv1.Deployment
	if f.kube.Get(t.Context(), ingressAgentKey(ingress), &dep) != nil || !metav1.IsControlledBy(&dep, ingress) || dep.Spec.Template.Annotations["tsunaro.io/agent-config-protocol"] != "http-v2" || dep.Status.ReadyReplicas != 1 {
		t.Fatal("ready v2 predecessor missing")
	}
	deploymentUID, ingressUID := dep.UID, ingress.UID
	// Watch from the current RV before patching: polling can miss the brief real
	// scale-zero acknowledgement. Read only; the Deployment controller owns status.
	ctx, cancel := context.WithTimeout(t.Context(), 150*time.Second)
	defer cancel()
	stream, err := f.kube.Watch(ctx, &appsv1.DeploymentList{}, &client.ListOptions{
		Namespace: namespace, FieldSelector: fields.OneTermEqualSelector("metadata.name", dep.Name),
		Raw: &metav1.ListOptions{ResourceVersion: dep.ResourceVersion},
	})
	if err != nil {
		t.Fatal("owned Deployment watch unavailable")
	}
	defer stream.Stop()
	base := ingress.DeepCopy()
	verifiedBackend := *ingress.Spec.Exposes[0].DeepCopy()
	verifiedBackend.Name, verifiedBackend.DNSLabel, verifiedBackend.Alias = "admin", "admin", true
	ingress.Spec.Exposes = []tnv1.Expose{
		{Name: "http", Mode: "http", Port: 443, Backend: tnv1.Backend{Service: "fixture-backend", Port: 8080}},
		verifiedBackend,
		{Name: "tcp", Mode: "l4", Port: 8443, Backend: tnv1.Backend{Service: "fixture-backend", Port: 8081}},
	}
	if f.kube.Patch(t.Context(), ingress, client.MergeFromWithOptions(base, client.MergeFromWithOptimisticLock{})) != nil {
		t.Fatal("two HTTP exposes plus L4 configuration rejected")
	}
	drained := false
	var observations []*appsv1.Deployment
	defer func() { x.save("virtual-host-retirement.private.json", observations) }()
watchTransition:
	for {
		select {
		case <-ctx.Done():
			t.Fatal("real v2 to v3 retirement timed out")
		case event, open := <-stream.ResultChan():
			if !open || event.Type == watch.Error || event.Type == watch.Deleted {
				t.Fatal("retirement watch ended without proof")
			}
			if event.Type == watch.Bookmark {
				continue
			}
			current, ok := event.Object.(*appsv1.Deployment)
			if !ok || current.UID != deploymentUID || !metav1.IsControlledBy(current, ingress) || len(observations) >= 128 {
				t.Fatal("retirement observation identity or bound differs")
			}
			observations = append(observations, current.DeepCopy())
			protocol := current.Spec.Template.Annotations["tsunaro.io/agent-config-protocol"]
			if protocol == "http-v2" && current.Spec.Replicas != nil && *current.Spec.Replicas == 0 && current.Status.ObservedGeneration >= current.Generation && current.Status.Replicas == 0 {
				drained = true
			}
			if protocol == "http-v3" {
				if !drained {
					t.Fatal("v3 installed before observed v2 scale-zero acknowledgement")
				}
				dep = *current.DeepCopy()
				break watchTransition
			}
		}
	}
	stream.Stop()
	eventually(t, "v3 replacement alone in the unchanged admitted startup gate", func() bool {
		if !apierrors.IsNotFound(f.kube.Get(t.Context(), client.ObjectKeyFromObject(oldPod), &corev1.Pod{})) {
			return false
		}
		var pods corev1.PodList
		if f.kube.List(t.Context(), &pods, client.InNamespace(namespace), client.MatchingLabels{"app.kubernetes.io/name": "tailnet-ingress", "app.kubernetes.io/instance": ingress.Name}) != nil || len(pods.Items) != 1 {
			return false
		}
		p := pods.Items[0]
		if p.UID == oldPod.UID || p.DeletionTimestamp != nil || len(p.Spec.InitContainers) != 1 || p.Spec.InitContainers[0].Name != kindfixture.NetworkGateContainer || len(p.Status.InitContainerStatuses) != 1 || p.Status.InitContainerStatuses[0].State.Running == nil {
			return false
		}
		owner := metav1.GetControllerOf(&p)
		if owner == nil || owner.Kind != "ReplicaSet" {
			return false
		}
		var rs appsv1.ReplicaSet
		if f.kube.Get(t.Context(), client.ObjectKey{Namespace: namespace, Name: owner.Name}, &rs) != nil || rs.UID != owner.UID || !metav1.IsControlledBy(&rs, &dep) {
			return false
		}
		*agent = p
		return true
	})
	if len(agent.Spec.Containers) != 1 || len(dep.Spec.Template.Spec.Containers) != 1 {
		t.Fatal("v3 agent application shape differs")
	}
	actual, desired := agent.Spec.Containers[0], dep.Spec.Template.Spec.Containers[0]
	if actual.Image != x.agentImage || actual.Image != desired.Image || !reflect.DeepEqual(actual.Command, desired.Command) || !reflect.DeepEqual(actual.Args, desired.Args) || !reflect.DeepEqual(actual.Env, desired.Env) {
		t.Fatal("admission changed v3 application fields")
	}
	x.save("virtual-host-agent-admitted.json", agent)
	releaseFixturePod(t, f, agent)
	started := agent.DeepCopy()
	eventually(t, "two HTTP exposes plus L4 current-generation Ready", func() bool {
		if f.kube.Get(t.Context(), client.ObjectKeyFromObject(ingress), ingress) != nil || ingress.UID != ingressUID || ingress.Status.ObservedGeneration != ingress.Generation || len(ingress.Status.Exposes) != 3 {
			return false
		}
		for _, name := range []string{"TLSReady", "BackendsReachable", "Ready"} {
			c := meta.FindStatusCondition(ingress.Status.Conditions, name)
			if c == nil || c.Status != metav1.ConditionTrue || c.ObservedGeneration != ingress.Generation {
				return false
			}
		}
		return true
	})
	certs := &unstructured.UnstructuredList{}
	certs.SetAPIVersion("cert-manager.io/v1")
	certs.SetKind("CertificateList")
	if f.kube.List(t.Context(), certs, client.InNamespace(namespace)) != nil {
		t.Fatal("Certificate inventory unavailable")
	}
	owned := 0
	for i := range certs.Items {
		cert := &certs.Items[i]
		if !metav1.IsControlledBy(cert, ingress) {
			continue
		}
		owned++
		names, _, err := unstructured.NestedStringSlice(cert.Object, "spec", "dnsNames")
		slices.Sort(names)
		secretName, _, _ := unstructured.NestedString(cert.Object, "spec", "secretName")
		if err != nil || !slices.Equal(names, wantNames) || cert.GetUID() != certificateUID || cert.GetDeletionTimestamp() != nil || !cmReady(cert) || secretName != ingress.Status.TLSSecretName {
			t.Fatal("owned Certificate identity, SAN union or issuance differs")
		}
		x.save("virtual-host-certificate.json", cert)
	}
	if owned != 1 {
		t.Fatal("expected exactly one ingress-owned Certificate")
	}
	var secret corev1.Secret
	if f.kube.Get(t.Context(), client.ObjectKey{Namespace: namespace, Name: ingress.Status.TLSSecretName}, &secret) != nil {
		t.Fatal("virtual-host serving Secret missing")
	}
	pair, err := certificates.ParseServingPair(secret.Data["tls.crt"], secret.Data["tls.key"], primary)
	if err != nil {
		t.Fatal("virtual-host serving pair invalid")
	}
	sans := slices.Clone(pair.Leaf.DNSNames)
	slices.Sort(sans)
	if !slices.Equal(sans, wantNames) {
		t.Fatal("issued leaf SAN union differs")
	}
	sum := sha256.Sum256(pair.Leaf.Raw)
	leaf := hex.EncodeToString(sum[:])
	if leaf == previousLeaf {
		t.Fatal("SAN expansion did not reissue the serving leaf")
	}
	var target string
	for _, value := range ingress.Status.TailnetIPs {
		ip, err := netip.ParseAddr(value)
		if err == nil && ip.Is4() && netip.MustParsePrefix("100.64.0.0/10").Contains(ip) {
			target = value
		}
	}
	if target == "" {
		t.Fatal("v3 tailnet IPv4 missing")
	}
	type observation struct {
		SNI, Host string
		HTTP2     bool
		OK        bool   `json:"ok"`
		Status    int    `json:"status"`
		Major     int    `json:"httpMajor"`
		ALPN      string `json:"alpn"`
		Leaf      string `json:"leafSHA256"`
		Backend   bool   `json:"backendVerified"`
	}
	var results []observation
	check := func(sni, host string, h2 bool, status int, backend bool, retry bool) {
		t.Helper()
		var got observation
		probe := func() bool {
			got = observation{SNI: sni, Host: host, HTTP2: h2}
			raw, _ := json.Marshal(map[string]any{"target": target, "http2": h2, "sni": sni, "host": host})
			b, err := x.proxy(x.peer.Name, 9081, "probe", string(raw))
			return err == nil && len(b) <= 4096 && json.Unmarshal(b, &got) == nil && got.Status == status && got.Backend == backend && got.OK == backend && got.Leaf == leaf && ((!h2 && got.Major == 1 && got.ALPN == "http/1.1") || (h2 && got.Major == 2 && got.ALPN == "h2"))
		}
		if retry {
			eventually(t, "SNI selects expected real backend with issued leaf", probe)
		} else if !probe() {
			t.Fatal("Host/SNI mismatch was not rejected with verified HTTP 421")
		}
		results = append(results, got)
	}
	defer func() { x.save("virtual-host-http.private.json", results) }()
	checkIngressL4Coexistence(t, x, ingress, "virtual-hosts-before")
	for _, h2 := range []bool{false, true} {
		check(primary, primary, h2, 200, true, true)
		check(second, second, h2, 404, false, true)
		check(alias, alias, h2, 404, false, true)
		// Positive controls converged first. A successful mismatched request is
		// never retried into a pass, nor is a dial/TLS failure counted as rejection.
		check(primary, second, h2, 421, false, false)
		check(second, primary, h2, 421, false, false)
		check(alias, primary, h2, 421, false, false)
	}
	checkIngressL4Coexistence(t, x, ingress, "virtual-hosts-after")
	checkIngressWebSocket(t, x, ingress, leaf, "virtual-hosts")
	if f.kube.Get(t.Context(), client.ObjectKeyFromObject(agent), agent) != nil || agent.UID != started.UID || len(agent.Status.ContainerStatuses) != 1 || agent.Status.ContainerStatuses[0].ContainerID != started.Status.ContainerStatuses[0].ContainerID || agent.Status.ContainerStatuses[0].RestartCount != 0 {
		t.Fatal("v3 agent restarted during routing checks")
	}
	x.save("virtual-host-ingress.json", ingress)
	x.save("virtual-host-agent-final.json", agent)
	x.save("virtual-host-result.json", map[string]any{"realV2ScaleZeroObserved": drained, "oldPodAbsentBeforeV3GateRelease": true, "singleOwnedCertificate": true, "issuedSANs": sans, "http1AndHTTP2": true, "distinctBackends": true, "aliasRouted": true, "hostSNIMismatchRejected": true, "l4CoexistenceTested": true, "webSocketsTested": true})
	t.Log("gate: observed real v2 scale-zero retirement, gated v3 replacement, two SNI backends + alias, HTTP1/HTTP2 Host!=SNI rejection, one owned Certificate and issued SAN union")
}
