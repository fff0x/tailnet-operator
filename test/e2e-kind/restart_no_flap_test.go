//go:build e2e_kind

package e2ekind

import (
	"context"
	"encoding/json"
	"net/netip"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/intstr"
	"sigs.k8s.io/controller-runtime/pkg/client"

	tnv1 "tsunaro.io/tailnet-operator/api/v1alpha1"
	"tsunaro.io/tailnet-operator/test/internal/kindfixture"
)

// tailnetFixture is the starting point the CR-driven P1.4 gates share: the chart installed from
// this tree, fixture trust patched into the operator, and a Tailnet whose policy has been applied.
// Callers register their own CRs with track() so each is deleted, and its finalizer awaited, before
// the Tailnet and the release go away. TestIngressL4 keeps its own copy of this sequence because
// its ACL phases also need the policy ConfigMap and a second peer.
type tailnetFixture struct {
	tn    *tnv1.Tailnet
	track func(o client.Object, evidence string)
}

func setupTailnetFixture(t *testing.T, x *httpPeerFixture) *tailnetFixture {
	t.Helper()
	f := x.f
	var tn *tnv1.Tailnet
	type tracked struct {
		object   client.Object
		evidence string
	}
	var crs []tracked
	installed := false
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 150*time.Second)
		defer cancel()
		if t.Failed() {
			for _, c := range append(crs, tracked{tn, "failed-tailnet.private.json"}) {
				if c.object == nil || c.object.GetUID() == "" {
					continue
				}
				current, ok := c.object.DeepCopyObject().(client.Object)
				if ok && f.kube.Get(ctx, client.ObjectKeyFromObject(c.object), current) == nil && current.GetUID() == c.object.GetUID() {
					x.save(c.evidence, current)
				}
			}
			logs, _ := f.command(ctx, "", "kubectl", "--kubeconfig", f.config, "--context", f.context, "--request-timeout=5s", "--namespace", namespace, "logs", "deployment/tailnet-operator", "--all-pods=true", "--all-containers=true", "--tail=150", "--limit-bytes=65536")
			x.save("failed-operator.private.json", map[string]string{"logs": string(logs)})
		}
		remove := func(o client.Object) {
			if o == nil || o.GetUID() == "" {
				return
			}
			uid := o.GetUID()
			if err := f.kube.Delete(ctx, o, client.Preconditions{UID: &uid}); err != nil && !apierrors.IsNotFound(err) {
				t.Error("shared CR cleanup failed")
				return
			}
			for !apierrors.IsNotFound(f.kube.Get(ctx, client.ObjectKeyFromObject(o), o)) {
				select {
				case <-ctx.Done():
					t.Error("shared CR finalizer cleanup timed out")
					return
				case <-time.After(time.Second):
				}
			}
		}
		for i := len(crs) - 1; i >= 0; i-- {
			remove(crs[i].object)
		}
		remove(tn)
		if installed {
			if _, err := f.command(ctx, "", "helm", "uninstall", "tailnet-operator", "--kubeconfig", f.config, "--kube-context", f.context, "--namespace", namespace, "--wait", "--timeout", "90s"); err != nil {
				t.Error("shared operator cleanup failed")
			}
		}
	})
	root, err := filepath.Abs(filepath.Join("..", ".."))
	if err != nil {
		t.Fatal("chart path unavailable")
	}
	// Leader election stays on: the Lease is how a caller proves the replacement manager is actually
	// running its controllers rather than merely reporting a Ready probe.
	values, _ := json.Marshal(map[string]any{"image": map[string]any{"repository": "localhost/tailnet-operator-e2e", "tag": f.cluster, "pullPolicy": "Never"}, "replicas": 1, "leaderElection": map[string]any{"enabled": true}, "networkPolicy": map[string]any{"enabled": false}})
	installed = true
	f.child(t, string(values), "helm", "install", "tailnet-operator", filepath.Join(root, "charts", "tailnet-operator"), "--kubeconfig", f.config, "--kube-context", f.context, "--namespace", namespace, "--wait", "--timeout", "120s", "--values", "-")
	var operator appsv1.Deployment
	if f.kube.Get(t.Context(), client.ObjectKey{Namespace: namespace, Name: "tailnet-operator"}, &operator) != nil {
		t.Fatal("shared operator missing")
	}
	original := operator.DeepCopy()
	if kindfixture.AddOperatorCA(&operator, x.ns, x.public, x.agentImage) != nil || f.kube.Patch(t.Context(), &operator, client.MergeFromWithOptions(original, client.MergeFromWithOptimisticLock{})) != nil {
		t.Fatal("shared fixture operator trust failed")
	}
	eventually(t, "shared operator Ready with fixture trust", func() bool {
		return f.kube.Get(t.Context(), client.ObjectKeyFromObject(&operator), &operator) == nil && operator.Status.ObservedGeneration == operator.Generation && operator.Status.Replicas == 1 && operator.Status.UpdatedReplicas == 1 && operator.Status.ReadyReplicas == 1
	})
	var key string
	if json.Unmarshal(x.cli("apikeys", "create", "--expiration", "1h", "--output", "json"), &key) != nil || key == "" {
		t.Fatal("shared private API credential unavailable")
	}
	x.create(&corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: "headscale-bootstrap", Namespace: namespace}, StringData: map[string]string{"apiKey": key}})
	policy := &corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Name: "headscale-policy", Namespace: namespace}, Data: map[string]string{"policy": l4BasePolicy(false)}}
	x.create(policy)
	tn = &tnv1.Tailnet{ObjectMeta: metav1.ObjectMeta{Name: "fixture"}, Spec: tnv1.TailnetSpec{
		Server: "https://fixture-headscale.tailnet-system.svc:8443", APIURL: "https://fixture-headscale.tailnet-system.svc:8443",
		APISecretRef: tnv1.SecretKeyRef{Name: "headscale-bootstrap", Key: "apiKey"}, APIKeyLifetime: metav1.Duration{Duration: time.Hour}, AuthKeyLifetime: metav1.Duration{Duration: time.Hour},
		Proxy: tnv1.ProxySpec{ProbeInterval: metav1.Duration{Duration: 2 * time.Second}}, DNS: tnv1.DNSSpec{IngressNameTemplate: "{name}.fixture.test"},
		Policy: tnv1.PolicySpec{BaseConfigMap: policy.Name, Mode: "Apply", TagOwners: []string{httpFixtureUser + "@"}, RouteApprovers: []string{httpFixtureUser + "@"}, IngressSourceAllowlist: []string{"group:*"}},
	}}
	x.create(tn)
	eventually(t, "shared initial policy applied", func() bool {
		return f.kube.Get(t.Context(), client.ObjectKeyFromObject(tn), tn) == nil && meta.IsStatusConditionTrue(tn.Status.Conditions, "HeadscaleCompatible") && meta.IsStatusConditionTrue(tn.Status.Conditions, "PolicyApplied") && tn.Status.Policy != nil && tn.Status.Policy.AppliedHash != "" && tn.Status.Policy.AppliedHash == tn.Status.Policy.RenderedHash
	})
	return &tailnetFixture{tn: tn, track: func(o client.Object, evidence string) { crs = append(crs, tracked{o, evidence}) }}
}

// l4Ingress adds to that one Ready L4 TailnetIngress whose agent has passed the startup gate.
type l4Ingress struct {
	tn         *tnv1.Tailnet
	ingress    *tnv1.TailnetIngress
	agent      corev1.Pod
	deployment appsv1.Deployment
	target     string // the agent's tailnet IPv4, the address the peer dials
	ready      func() bool
}

// tailnetIPv4 picks the CR's tailnet IPv4 out of its status; that is the address a peer dials.
func tailnetIPv4(addresses []string) string {
	for _, raw := range addresses {
		if ip, err := netip.ParseAddr(raw); err == nil && ip.Is4() && netip.MustParsePrefix("100.64.0.0/10").Contains(ip) {
			return raw
		}
	}
	return ""
}

func setupL4Ingress(t *testing.T, x *httpPeerFixture, hostname string) *l4Ingress {
	t.Helper()
	f := x.f
	base := setupTailnetFixture(t, x)
	tn := base.tn
	var backend corev1.Service
	if f.kube.Get(t.Context(), client.ObjectKey{Namespace: namespace, Name: "fixture-backend"}, &backend) != nil {
		t.Fatal("shared L4 backend service missing")
	}
	beforeService := backend.DeepCopy()
	backend.Spec.Ports = append(backend.Spec.Ports, corev1.ServicePort{Name: "l4", Port: 8081, TargetPort: intstr.FromInt32(8081)})
	if f.kube.Patch(t.Context(), &backend, client.MergeFromWithOptions(beforeService, client.MergeFromWithOptimisticLock{})) != nil {
		t.Fatal("shared L4 backend port failed")
	}
	ingress := &tnv1.TailnetIngress{ObjectMeta: metav1.ObjectMeta{Name: "http-agent", Namespace: namespace}, Spec: tnv1.TailnetIngressSpec{
		TailnetRef: tnv1.TailnetRef{Name: tn.Name}, Hostname: hostname, AllowFrom: []string{"group:l4-allowed"},
		Exposes: []tnv1.Expose{{Name: "tcp", Mode: "l4", Port: 8443, Backend: tnv1.Backend{Service: backend.Name, Port: 8081}}},
	}}
	x.create(ingress)
	base.track(ingress, "failed-ingress.private.json")
	out := &l4Ingress{tn: tn, ingress: ingress}
	eventually(t, "shared L4 generated agent held at real startup gate", func() bool {
		if f.kube.Get(t.Context(), ingressAgentKey(ingress), &out.deployment) != nil {
			return false
		}
		owner := metav1.GetControllerOf(&out.deployment)
		if owner == nil || owner.Kind != "TailnetIngress" || owner.UID != ingress.UID {
			return false
		}
		var pods corev1.PodList
		if f.kube.List(t.Context(), &pods, client.InNamespace(namespace), client.MatchingLabels{"app.kubernetes.io/name": "tailnet-ingress", "app.kubernetes.io/instance": ingress.Name}) != nil || len(pods.Items) != 1 {
			return false
		}
		p := pods.Items[0]
		if p.DeletionTimestamp != nil || len(p.Status.InitContainerStatuses) != 1 || p.Status.InitContainerStatuses[0].State.Running == nil {
			return false
		}
		out.agent = p
		return true
	})
	releaseFixturePod(t, f, &out.agent)
	// The published name comes from dns.ingressNameTemplate and the CR name (ingress_names.go), not
	// from spec.hostname: the hostname is the node's tailnet identity, dnsName the record clients use.
	out.ready = func() bool {
		if f.kube.Get(t.Context(), client.ObjectKeyFromObject(ingress), ingress) != nil {
			return false
		}
		return ingress.Status.ObservedGeneration == ingress.Generation && meta.IsStatusConditionTrue(ingress.Status.Conditions, "Ready") && ingress.Status.DNSName == ingress.Name+".fixture.test"
	}
	eventually(t, "shared L4 reconciled ingress Ready", out.ready)
	out.target = tailnetIPv4(ingress.Status.TailnetIPs)
	if out.target == "" {
		t.Fatal("shared L4 tailnet IPv4 missing")
	}
	// The CR turns Ready on the node being online and the backends probed; the kubelet's readiness
	// probe (20s period) may still be behind, so the released pod is awaited, not asserted.
	eventually(t, "shared L4 agent container Ready", func() bool {
		return f.kube.Get(t.Context(), client.ObjectKeyFromObject(&out.agent), &out.agent) == nil && len(out.agent.Status.ContainerStatuses) == 1 && out.agent.Status.ContainerStatuses[0].Ready
	})
	return out
}

// probeL4Exchange converges on the peer completing the nonce/digest exchange through the agent.
// A failed attempt is a retry, not a result: registration and netmap propagation are asynchronous.
func probeL4Exchange(t *testing.T, x *httpPeerFixture, label, address string) l4Observation {
	t.Helper()
	var got l4Observation
	eventually(t, "peer completes the bounded L4 exchange ("+label+")", func() bool {
		input, _ := json.Marshal(map[string]string{"target": address})
		b, err := x.proxy(x.peer.Name, 9081, "probe-l4", string(input))
		var raw struct {
			OK        *bool `json:"ok"`
			Connected *bool `json:"connected"`
			TimedOut  *bool `json:"timedOut"`
		}
		if err != nil || len(b) > 1024 || json.Unmarshal(b, &raw) != nil || raw.OK == nil || raw.Connected == nil || raw.TimedOut == nil {
			return false
		}
		got = l4Observation{*raw.OK, *raw.Connected, *raw.TimedOut}
		return got.OK && got.Connected && !got.TimedOut
	})
	return got
}

type conditionState struct {
	Status     string `json:"status"`
	Reason     string `json:"reason"`
	Transition string `json:"lastTransitionTime"`
	Observed   int64  `json:"observedGeneration"`
}

// conditionStates keys by type and keeps lastTransitionTime: that field is the instrument. It only
// moves when a condition actually flips, so comparing it catches a flip that went back before the
// next sample. Resolution is one second, which is why the caller also samples continuously.
func conditionStates(conditions []metav1.Condition) map[string]conditionState {
	out := make(map[string]conditionState, len(conditions))
	for _, c := range conditions {
		out[c.Type] = conditionState{string(c.Status), c.Reason, c.LastTransitionTime.UTC().Format(time.RFC3339), c.ObservedGeneration}
	}
	return out
}

// TestRestartNoFlap is the P0.2 proof: restarting the operator must not flip a healthy CR's
// conditions. The subject is deliberately the operator, not the agent — an agent restart is a real
// interruption (TestIngressIdentityPersists covers what it keeps), and the fixture holds every
// replacement pod in the startup gate.
func TestRestartNoFlap(t *testing.T) {
	x := newPeerFixture(t, nil, "restart-no-flap")
	f := x.f
	l4 := setupL4Ingress(t, x, "http-agent")
	before := probeL4Exchange(t, x, "before-restart", l4.target)

	baseline := conditionStates(l4.ingress.Status.Conditions)
	if len(baseline) == 0 || baseline["Ready"].Status != string(metav1.ConditionTrue) || baseline["Registered"].Status != string(metav1.ConditionTrue) {
		t.Fatal("baseline ingress conditions are not a healthy starting point")
	}
	generation := l4.ingress.Generation
	agentDeploymentGeneration := l4.deployment.Generation
	agent := l4.agent.DeepCopy()

	type drift struct {
		Phase   string                    `json:"phase"`
		Elapsed string                    `json:"elapsed"`
		States  map[string]conditionState `json:"states"`
	}
	var drifts []drift
	var samples int
	start := time.Now()
	phase := "pre-restart"
	// Every sample is a full comparison against the baseline, so a changed status, reason,
	// observedGeneration or transition time is recorded — not only an outright Ready=False.
	sample := func() {
		samples++
		var current tnv1.TailnetIngress
		if f.kube.Get(t.Context(), client.ObjectKeyFromObject(l4.ingress), &current) != nil {
			drifts = append(drifts, drift{phase, time.Since(start).Round(time.Millisecond).String(), nil})
			return
		}
		if states := conditionStates(current.Status.Conditions); !reflect.DeepEqual(states, baseline) || current.Generation != generation {
			drifts = append(drifts, drift{phase, time.Since(start).Round(time.Millisecond).String(), states})
		}
	}
	settle := func(window time.Duration) {
		deadline := time.Now().Add(window)
		for time.Now().Before(deadline) {
			sample()
			time.Sleep(time.Second)
		}
	}
	// A quiet window first: without it a flap during the restart could not be distinguished from a
	// CR that churns on its own at this probeInterval.
	settle(10 * time.Second)
	if len(drifts) != 0 {
		x.save("condition-drift.json", drifts)
		t.Fatalf("ingress conditions already churned before the restart: %d of %d samples", len(drifts), samples)
	}

	previousHolder := f.holder(t.Context())
	previousOperators := f.readyOperatorPods(t.Context())
	if previousHolder == "" || len(previousOperators) != 1 {
		t.Fatal("single ready operator holding the election Lease required")
	}
	phase = "restart"
	if _, err := f.command(t.Context(), "", "kubectl", "--kubeconfig", f.config, "--context", f.context, "--request-timeout=15s", "--namespace", namespace, "rollout", "restart", "deployment/tailnet-operator"); err != nil {
		t.Fatal("operator rollout restart rejected")
	}
	var replacement corev1.Pod
	var holder string
	eventually(t, "replacement operator Ready and holding the election Lease", func() bool {
		sample()
		pods := f.readyOperatorPods(t.Context())
		if len(pods) != 1 || pods[0].UID == previousOperators[0].UID {
			return false
		}
		holder = f.holder(t.Context())
		mapped, ok := holderPod(holder, pods)
		if !ok || mapped.UID != pods[0].UID {
			return false
		}
		replacement = pods[0]
		return true
	})
	if holder == previousHolder {
		t.Fatal("election Lease identity did not change across the restart")
	}
	// 35s is one full requeue interval plus slack. The flip P0.2 describes appears on the restarted
	// operator's first reconcile, which is after it took the Lease, not while it was starting.
	phase = "post-restart"
	settle(35 * time.Second)

	after := probeL4Exchange(t, x, "after-restart", l4.target)
	var current tnv1.TailnetIngress
	if f.kube.Get(t.Context(), client.ObjectKeyFromObject(l4.ingress), &current) != nil {
		t.Fatal("ingress unreadable after the restart")
	}
	final := conditionStates(current.Status.Conditions)
	x.save("result.json", map[string]any{
		"realChartAndReconciler": true, "subject": "operator", "samples": samples,
		"conditionDrift": drifts, "baselineConditions": baseline, "finalConditions": final,
		"leaseIdentityChanged": holder != previousHolder, "operatorPodReplaced": replacement.UID != previousOperators[0].UID,
		"exchangeBefore": before, "exchangeAfter": after, "agentRestartTested": false,
	})
	if len(drifts) != 0 {
		t.Fatalf("operator restart flapped the ingress conditions: %d of %d samples drifted", len(drifts), samples)
	}
	if !reflect.DeepEqual(final, baseline) || current.Generation != generation {
		t.Fatal("ingress conditions differ after the restart")
	}
	if f.kube.Get(t.Context(), client.ObjectKeyFromObject(&l4.deployment), &l4.deployment) != nil || l4.deployment.Generation != agentDeploymentGeneration {
		t.Fatal("operator restart rewrote the agent Deployment template")
	}
	if f.kube.Get(t.Context(), client.ObjectKeyFromObject(agent), agent) != nil || agent.UID != l4.agent.UID ||
		len(agent.Status.ContainerStatuses) != 1 || agent.Status.ContainerStatuses[0].ContainerID != l4.agent.Status.ContainerStatuses[0].ContainerID ||
		agent.Status.ContainerStatuses[0].RestartCount != 0 {
		t.Fatal("operator restart replaced or restarted the agent Pod")
	}
	t.Log("gate: operator Pod replaced and Lease identity changed; ingress conditions identical including lastTransitionTime across a 45s sampled window; agent Pod and template untouched; L4 exchange works before and after")
}
