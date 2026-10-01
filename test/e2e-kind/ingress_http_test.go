//go:build e2e_kind

package e2ekind

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/netip"
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"sigs.k8s.io/controller-runtime/pkg/client"

	tnv1 "this-is-fine.io/tailnet-operator/api/v1alpha1"
	"this-is-fine.io/tailnet-operator/internal/certificates"
	"this-is-fine.io/tailnet-operator/test/internal/kindfixture"
)

// The renderer deliberately rejects empty ACL/grant bases. This inert
// documentation-address rule satisfies that guard without granting the peer
// access to an agent; only the reconciled ingress rule can grant that access.
const ingressHTTPBasePolicy = `{"tagOwners":{},"acls":[{"action":"accept","src":["autogroup:member"],"dst":["192.0.2.1:443"]}]}`

// TestIngressHTTP uses the actual chart, ServiceAccounts, reconcilers and
// cert-manager issuance. Fixture-only mounts trust the private control server;
// every Headscale/tsnet Pod still requires its actual pre-start network proof.
func TestIngressHTTP(t *testing.T) {
	if os.Getenv("E2E_KIND_HTTP_NETWORK_GATE") == "" {
		t.Skip("requires owned isolated HTTP runner")
	}
	root, err := filepath.Abs(filepath.Join("..", ".."))
	if err != nil {
		t.Fatal("chart source unavailable")
	}
	if info, err := os.Stat(filepath.Join(root, "charts", "tailnet-operator", "Chart.yaml")); err != nil || !info.Mode().IsRegular() {
		t.Fatal("test package working directory does not resolve chart source")
	}
	bootstrap := ownedFixture(t)
	servingCA := installFixtureCertManager(t, bootstrap)
	x := newHTTPPeerFixtureWithServingCA(t, servingCA)
	f := x.f
	var tn *tnv1.Tailnet
	var ingress *tnv1.TailnetIngress
	installed := false
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 150*time.Second)
		defer cancel()
		if t.Failed() {
			if tn != nil {
				var current tnv1.Tailnet
				if f.kube.Get(ctx, client.ObjectKeyFromObject(tn), &current) == nil && current.UID == tn.UID {
					x.save("failed-tailnet.private.json", &current)
				}
			}
			if ingress != nil {
				var current tnv1.TailnetIngress
				if f.kube.Get(ctx, client.ObjectKeyFromObject(ingress), &current) == nil && current.UID == ingress.UID {
					x.save("failed-ingress.private.json", &current)
				}
			}
			var pods corev1.PodList
			if f.kube.List(ctx, &pods, client.InNamespace(namespace)) == nil && len(pods.Items) <= 16 {
				x.save("failed-namespace-pods.private.json", &pods)
			}
			logs, _ := f.command(ctx, "", "kubectl", "--kubeconfig", f.config, "--context", f.context, "--request-timeout=5s", "--namespace", namespace, "logs", "deployment/tailnet-operator", "--all-pods=true", "--all-containers=true", "--tail=150", "--limit-bytes=65536")
			if file, err := os.OpenFile(filepath.Join(os.Getenv("E2E_KIND_NET_EVIDENCE"), "ingress-http", "failed-operator.private.log"), os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600); err == nil {
				_, _ = file.Write(logs)
				_ = file.Close()
			}
		}
		remove := func(o client.Object) {
			if o == nil || o.GetUID() == "" {
				return
			}
			uid := o.GetUID()
			if err := f.kube.Delete(ctx, o, client.Preconditions{UID: &uid}); err != nil && !apierrors.IsNotFound(err) {
				t.Error("integrated CR cleanup failed")
				return
			}
			for {
				if apierrors.IsNotFound(f.kube.Get(ctx, client.ObjectKeyFromObject(o), o)) {
					return
				}
				select {
				case <-ctx.Done():
					t.Error("integrated CR finalizer cleanup timed out")
					return
				case <-time.After(time.Second):
				}
			}
		}
		if ingress != nil {
			remove(ingress)
		}
		if tn != nil {
			remove(tn)
		}
		if installed {
			if _, err := f.command(ctx, "", "helm", "uninstall", "tailnet-operator", "--kubeconfig", f.config, "--kube-context", f.context, "--namespace", namespace, "--wait", "--timeout", "90s"); err != nil {
				t.Error("integrated operator cleanup failed")
			}
		}
	})
	values, _ := json.Marshal(map[string]any{"image": map[string]any{"repository": "localhost/tailnet-operator-e2e", "tag": f.cluster, "pullPolicy": "Never"}, "replicas": 1, "leaderElection": map[string]any{"enabled": true}, "networkPolicy": map[string]any{"enabled": false}})
	installed = true
	f.child(t, string(values), "helm", "install", "tailnet-operator", filepath.Join(root, "charts", "tailnet-operator"), "--kubeconfig", f.config, "--kube-context", f.context, "--namespace", namespace, "--wait", "--timeout", "120s", "--values", "-")
	var operator appsv1.Deployment
	if f.kube.Get(t.Context(), client.ObjectKey{Namespace: namespace, Name: "tailnet-operator"}, &operator) != nil {
		t.Fatal("installed operator missing")
	}
	original := operator.DeepCopy()
	if kindfixture.AddOperatorCA(&operator, x.ns, x.public, x.agentImage) != nil {
		t.Fatal("fixture operator CA rejected")
	}
	if f.kube.Patch(t.Context(), &operator, client.MergeFromWithOptions(original, client.MergeFromWithOptimisticLock{})) != nil {
		t.Fatal("fixture operator CA patch failed")
	}
	eventually(t, "chart operator with private control trust Ready", func() bool {
		return f.kube.Get(t.Context(), client.ObjectKeyFromObject(&operator), &operator) == nil && operator.Status.ObservedGeneration == operator.Generation && operator.Status.ReadyReplicas == 1 && operator.Status.UpdatedReplicas == 1 && operator.Status.Replicas == 1
	})
	x.save("operator-with-fixture-ca.json", &operator)
	var key string
	if json.Unmarshal(x.cli("apikeys", "create", "--expiration", "1h", "--output", "json"), &key) != nil || key == "" {
		t.Fatal("private control API credential missing")
	}
	x.create(&corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: "headscale-bootstrap", Namespace: namespace}, StringData: map[string]string{"apiKey": key}})
	x.create(&corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Name: "headscale-policy", Namespace: namespace}, Data: map[string]string{"policy": ingressHTTPBasePolicy}})
	tn = &tnv1.Tailnet{ObjectMeta: metav1.ObjectMeta{Name: "fixture"}, Spec: tnv1.TailnetSpec{
		Server: "https://fixture-headscale.tailnet-system.svc:8443", APIURL: "https://fixture-headscale.tailnet-system.svc:8443",
		APISecretRef: tnv1.SecretKeyRef{Name: "headscale-bootstrap", Key: "apiKey"}, APIKeyLifetime: metav1.Duration{Duration: time.Hour}, AuthKeyLifetime: metav1.Duration{Duration: time.Hour},
		Proxy:  tnv1.ProxySpec{ProbeInterval: metav1.Duration{Duration: 2 * time.Second}},
		DNS:    tnv1.DNSSpec{IngressNameTemplate: "{name}.fixture.test"},
		Policy: tnv1.PolicySpec{BaseConfigMap: "headscale-policy", Mode: "Apply", TagOwners: []string{httpFixtureUser + "@"}, RouteApprovers: []string{httpFixtureUser + "@"}, IngressSourceAllowlist: []string{"autogroup:member"}},
	}}
	x.create(tn)
	eventually(t, "real Tailnet compatibility and policy applied", func() bool {
		return f.kube.Get(t.Context(), client.ObjectKeyFromObject(tn), tn) == nil && meta.IsStatusConditionTrue(tn.Status.Conditions, "HeadscaleCompatible") && meta.IsStatusConditionTrue(tn.Status.Conditions, "PolicyApplied")
	})
	ingress = &tnv1.TailnetIngress{ObjectMeta: metav1.ObjectMeta{Name: "http-agent", Namespace: namespace}, Spec: tnv1.TailnetIngressSpec{
		TailnetRef: tnv1.TailnetRef{Name: tn.Name}, Hostname: "http-agent", AllowFrom: []string{"autogroup:member"},
		TLS:     &tnv1.IngressTLS{IssuerRef: &tnv1.TLSIssuerReference{Name: "fixture-serving", Kind: "ClusterIssuer", Group: "cert-manager.io"}},
		Exposes: []tnv1.Expose{{Name: "http", Mode: "http", Port: 443, Backend: tnv1.Backend{Service: "fixture-backend", Port: 8080}}},
	}}
	x.create(ingress)
	var agent corev1.Pod
	var deployment appsv1.Deployment
	eventually(t, "controller-created agent blocked in admitted init", func() bool {
		if f.kube.Get(t.Context(), client.ObjectKeyFromObject(ingress), ingress) != nil || f.kube.Get(t.Context(), client.ObjectKeyFromObject(ingress), &deployment) != nil {
			return false
		}
		owner := metav1.GetControllerOf(&deployment)
		if owner == nil || owner.UID != ingress.UID || owner.Kind != "TailnetIngress" {
			return false
		}
		var pods corev1.PodList
		if f.kube.List(t.Context(), &pods, client.InNamespace(namespace), client.MatchingLabels{"app.kubernetes.io/name": "tailnet-ingress", "app.kubernetes.io/instance": ingress.Name}) != nil || len(pods.Items) != 1 {
			return false
		}
		p := pods.Items[0]
		if p.DeletionTimestamp != nil || len(p.Spec.InitContainers) != 1 || p.Spec.InitContainers[0].Name != kindfixture.NetworkGateContainer || len(p.Status.InitContainerStatuses) != 1 || p.Status.InitContainerStatuses[0].State.Running == nil {
			return false
		}
		ref := metav1.GetControllerOf(&p)
		if ref == nil || ref.Kind != "ReplicaSet" {
			return false
		}
		var rs appsv1.ReplicaSet
		if f.kube.Get(t.Context(), client.ObjectKey{Name: ref.Name, Namespace: namespace}, &rs) != nil || rs.UID != ref.UID {
			return false
		}
		parent := metav1.GetControllerOf(&rs)
		if parent == nil || parent.Kind != "Deployment" || parent.UID != deployment.UID {
			return false
		}
		agent = p
		return true
	})
	if len(agent.Spec.Containers) != 1 || len(deployment.Spec.Template.Spec.Containers) != 1 {
		t.Fatal("agent container shape differs")
	}
	a, desired := agent.Spec.Containers[0], deployment.Spec.Template.Spec.Containers[0]
	if a.Image != x.agentImage || a.Image != desired.Image || !reflect.DeepEqual(a.Command, desired.Command) || !reflect.DeepEqual(a.Args, desired.Args) || !reflect.DeepEqual(a.Env, desired.Env) {
		t.Fatal("admission changed controller application fields")
	}
	x.save("controller-agent-admitted.json", &agent)
	x.save("controller-agent-deployment.json", &deployment)
	releaseFixturePod(t, f, &agent)
	initialPod := agent.DeepCopy()
	initialGeneration := deployment.Generation
	initialIngressUID := ingress.UID
	ready := func() bool {
		if f.kube.Get(t.Context(), client.ObjectKeyFromObject(ingress), ingress) != nil {
			return false
		}
		tls := meta.FindStatusCondition(ingress.Status.Conditions, "TLSReady")
		r := meta.FindStatusCondition(ingress.Status.Conditions, "Ready")
		return ingress.UID == initialIngressUID && ingress.DeletionTimestamp == nil && ingress.Status.ObservedGeneration == ingress.Generation && tls != nil && tls.Status == metav1.ConditionTrue && tls.ObservedGeneration == ingress.Generation && r != nil && r.Status == metav1.ConditionTrue && r.ObservedGeneration == ingress.Generation && ingress.Status.DNSName == "http-agent.fixture.test" && len(ingress.Status.TailnetIPs) > 0 && ingress.Status.TLSSecretName != "" && ingress.Status.TLSNotAfter != nil
	}
	eventually(t, "reconciler HTTP and TLS Ready at current generation", ready)
	cert := cmObject("Certificate", namespace, ingress.Name+"-tls", nil)
	if f.kube.Get(t.Context(), client.ObjectKeyFromObject(cert), cert) != nil || !cmReady(cert) {
		t.Fatal("actual ingress Certificate not Ready")
	}
	owner := metav1.GetControllerOf(cert)
	if owner == nil || owner.UID != ingress.UID || owner.Kind != "TailnetIngress" {
		t.Fatal("Certificate owner differs")
	}
	initialCertificateUID := cert.GetUID()
	type leafObservation struct {
		hash                string
		notBefore, notAfter time.Time
	}
	currentLeaf := func() leafObservation {
		t.Helper()
		var secret corev1.Secret
		if f.kube.Get(t.Context(), client.ObjectKey{Namespace: namespace, Name: ingress.Status.TLSSecretName}, &secret) != nil {
			t.Fatal("managed serving Secret missing")
		}
		pair, err := certificates.ParseServingPair(secret.Data["tls.crt"], secret.Data["tls.key"], ingress.Status.DNSName)
		if err != nil {
			t.Fatal("managed serving pair invalid")
		}
		sum := sha256.Sum256(pair.Leaf.Raw)
		return leafObservation{hex.EncodeToString(sum[:]), pair.Leaf.NotBefore, pair.Leaf.NotAfter}
	}
	initialLeaf := currentLeaf()
	initialRevision, foundRevision, revisionErr := unstructured.NestedInt64(cert.Object, "status", "revision")
	if revisionErr != nil || !foundRevision || initialRevision < 1 {
		t.Fatal("initial issued Certificate revision missing")
	}
	x.save("issued-certificate-initial.private.json", cert)
	type response struct {
		OK      bool   `json:"ok"`
		Status  int    `json:"status"`
		Major   int    `json:"httpMajor"`
		ALPN    string `json:"alpn"`
		Leaf    string `json:"leafSHA256"`
		Backend bool   `json:"backendVerified"`
	}
	tailIP := ""
	for _, s := range ingress.Status.TailnetIPs {
		a, err := netip.ParseAddr(s)
		if err == nil && a.Is4() && netip.MustParsePrefix("100.64.0.0/10").Contains(a) {
			tailIP = s
		}
	}
	if tailIP == "" {
		t.Fatal("reconciled tailnet IPv4 missing")
	}
	probes := func(leaf string) []response {
		t.Helper()
		results := []response{}
		for _, target := range []string{tailIP, "http-agent.fixture.test"} {
			for _, h2 := range []bool{false, true} {
				var got response
				eventually(t, "issued-certificate real peer HTTPS", func() bool {
					raw, _ := json.Marshal(map[string]any{"target": target, "http2": h2})
					b, err := x.proxy(x.peer.Name, 9081, "probe", string(raw))
					return err == nil && len(b) <= 4096 && json.Unmarshal(b, &got) == nil && got.OK && got.Status == 200 && got.Backend && got.Leaf == leaf && ((h2 && got.Major == 2 && got.ALPN == "h2") || (!h2 && got.Major == 1))
				})
				results = append(results, got)
			}
		}
		return results
	}
	beforeResults := probes(initialLeaf.hash)
	x.save("initial-http.private.json", beforeResults)
	// Preserve cert-manager-managed renewal fields. A previously omitted
	// duration does not trigger RequestChanged on nil -> 1h in cert-manager;
	// use its regular manual-renewal intent, never fabricate Ready or a leaf.
	base := cert.DeepCopy()
	if unstructured.SetNestedField(cert.Object, "1h", "spec", "duration") != nil || unstructured.SetNestedField(cert.Object, "20m", "spec", "renewBefore") != nil {
		t.Fatal("rotation fixture invalid")
	}
	if f.kube.Patch(t.Context(), cert, client.MergeFromWithOptions(base, client.MergeFromWithOptimisticLock{})) != nil {
		t.Fatal("real Certificate duration update failed")
	}
	x.save("requested-renewal-certificate.private.json", cert)
	requestFixtureCertificateRenewal(t, f, cert, ingress, initialRevision)
	var rotatedLeaf leafObservation
	eventually(t, "real cert-manager reissuance", func() bool {
		if f.kube.Get(t.Context(), client.ObjectKeyFromObject(cert), cert) != nil || cert.GetUID() != initialCertificateUID || cert.GetDeletionTimestamp() != nil || !cmReady(cert) {
			return false
		}
		revision, found, err := unstructured.NestedInt64(cert.Object, "status", "revision")
		rotatedLeaf = currentLeaf()
		return err == nil && found && revision > initialRevision && rotatedLeaf.hash != initialLeaf.hash
	})
	afterResults := probes(rotatedLeaf.hash)
	x.save("rotated-http.private.json", afterResults)
	eventually(t, "reconciler refreshed issued certificate status", func() bool {
		return ready() && ingress.Status.TLSNotAfter.Time.Equal(rotatedLeaf.notAfter) && !rotatedLeaf.notAfter.Equal(initialLeaf.notAfter)
	})
	lifetime := rotatedLeaf.notAfter.Sub(rotatedLeaf.notBefore)
	if lifetime < 55*time.Minute || lifetime > 65*time.Minute {
		t.Fatal("rotated leaf does not have the requested bounded one-hour lifetime")
	}
	if f.kube.Get(t.Context(), client.ObjectKeyFromObject(cert), cert) != nil || cert.GetUID() != initialCertificateUID || cert.GetDeletionTimestamp() != nil || !cmReady(cert) {
		t.Fatal("final current-generation Certificate missing")
	}
	duration, _, _ := unstructured.NestedString(cert.Object, "spec", "duration")
	renewal, _, _ := unstructured.NestedString(cert.Object, "spec", "renewBefore")
	d, de := time.ParseDuration(duration)
	r, re := time.ParseDuration(renewal)
	if de != nil || re != nil || d != time.Hour || r != 20*time.Minute {
		t.Fatal("operator changed unmanaged certificate renewal fields")
	}
	if f.kube.Get(t.Context(), client.ObjectKeyFromObject(&agent), &agent) != nil || agent.UID != initialPod.UID || len(agent.Status.ContainerStatuses) != 1 || agent.Status.ContainerStatuses[0].ContainerID != initialPod.Status.ContainerStatuses[0].ContainerID || agent.Status.ContainerStatuses[0].RestartCount != 0 {
		t.Fatal("certificate rotation replaced/restarted agent")
	}
	if f.kube.Get(t.Context(), client.ObjectKeyFromObject(&deployment), &deployment) != nil || deployment.Generation != initialGeneration {
		t.Fatal("certificate rotation changed agent template")
	}
	x.save("issued-certificate-final.json", cert)
	x.save("reconciled-ingress-final.json", ingress)
	x.save("agent-final.json", &agent)
	x.save("result.json", map[string]any{"realChartAndReconciler": true, "realCertManagerIssuance": true, "webhookAdmittedAgentGateExecuted": true, "initialHTTP": beforeResults, "rotatedHTTP": afterResults, "sameAgentAcrossRotation": true, "aclNegativeTested": false, "webSocketsTested": false, "l4Tested": false})
	t.Log("gate: real chart/reconciler/cert-manager, generated agent gate, peer HTTP1+HTTP2 and actual issued-certificate rotation without agent restart")
}
