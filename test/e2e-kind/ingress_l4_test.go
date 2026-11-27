//go:build e2e_kind

package e2ekind

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math"
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

func l4BasePolicy(includeDenied bool) string {
	members := []string{httpFixtureUser + "@"}
	if includeDenied {
		members = append(members, "fixture-denied@")
	}
	data, _ := json.Marshal(map[string]any{
		"groups": map[string][]string{"group:l4-allowed": members}, "tagOwners": map[string]any{},
		"acls": []map[string]any{{"action": "accept", "src": []string{"autogroup:member"}, "dst": []string{"192.0.2.1:443"}}},
	})
	return string(data)
}

func TestL4PolicyFixture(t *testing.T) {
	for _, allowed := range []bool{false, true} {
		var policy struct {
			Groups map[string][]string `json:"groups"`
			ACLs   []struct {
				Dst []string `json:"dst"`
			} `json:"acls"`
		}
		if json.Unmarshal([]byte(l4BasePolicy(allowed)), &policy) != nil || len(policy.ACLs) != 1 || !reflect.DeepEqual(policy.ACLs[0].Dst, []string{"192.0.2.1:443"}) {
			t.Fatal("base must not grant access to the real fixture destination")
		}
		want := []string{httpFixtureUser + "@"}
		if allowed {
			want = append(want, "fixture-denied@")
		}
		if len(policy.Groups) != 1 || !reflect.DeepEqual(policy.Groups["group:l4-allowed"], want) {
			t.Fatal("fixture group differs")
		}
	}
}

type l4Observation struct {
	OK        bool   `json:"ok"`
	Connected bool   `json:"connected"`
	TimedOut  bool   `json:"timedOut"`
	DialError string `json:"dialError"`
}

const l4NegativeSamples = 3

// The HTTP ACL rule: only a TCP dial that timed out or found no route is a denial. A refused or
// reset dial, a cancellation and every unclassified failure prove nothing about the policy.
func l4Denied(got l4Observation) bool {
	switch got.DialError {
	case "timeout":
		return got == (l4Observation{TimedOut: true, DialError: "timeout"})
	case "noRoute", "unreachable":
		return got == (l4Observation{DialError: got.DialError})
	default:
		return false
	}
}

func knownL4DialError(category string) bool {
	switch category {
	case "", "timeout", "noRoute", "unreachable", "refused", "reset", "canceled", "other":
		return true
	}
	return false
}

// requireL4Denials never retries a contradictory or unclassified observation.
// Each invocation of probe must open a fresh connection and record its result.
func requireL4Denials(probe func() (l4Observation, error)) error {
	for range l4NegativeSamples {
		got, err := probe()
		if err != nil {
			return errors.New("L4 negative probe unavailable")
		}
		if !l4Denied(got) {
			return errors.New("L4 negative probe connected or lacked a timeout/no-route dial error")
		}
	}
	return nil
}

func TestL4NegativeAssertions(t *testing.T) {
	timeout := l4Observation{TimedOut: true, DialError: "timeout"}
	noRoute := l4Observation{DialError: "noRoute"}
	unreachable := l4Observation{DialError: "unreachable"}
	success := l4Observation{OK: true, Connected: true}
	for _, tc := range []struct {
		name         string
		observations []l4Observation
		probeError   bool
		wantCalls    int
		wantSuccess  bool
	}{
		{name: "three fresh timeouts", observations: []l4Observation{timeout, timeout, timeout}, wantCalls: 3, wantSuccess: true},
		{name: "success then failure cannot pass", observations: []l4Observation{success, timeout, timeout}, wantCalls: 1},
		{name: "timeout then success cannot pass", observations: []l4Observation{timeout, success, timeout}, wantCalls: 2},
		{name: "connected without exchange", observations: []l4Observation{{Connected: true}}, wantCalls: 1},
		{name: "timeout after connect", observations: []l4Observation{{Connected: true, TimedOut: true}}, wantCalls: 1},
		{name: "timeout and no-route mix", observations: []l4Observation{noRoute, timeout, unreachable}, wantCalls: 3, wantSuccess: true},
		{name: "unclassified failure", observations: []l4Observation{{}}, wantCalls: 1},
		{name: "refused", observations: []l4Observation{{DialError: "refused"}}, wantCalls: 1},
		{name: "reset", observations: []l4Observation{{DialError: "reset"}}, wantCalls: 1},
		{name: "canceled", observations: []l4Observation{{DialError: "canceled"}}, wantCalls: 1},
		{name: "other", observations: []l4Observation{{DialError: "other"}}, wantCalls: 1},
		{name: "timeout flag without category", observations: []l4Observation{{TimedOut: true}}, wantCalls: 1},
		{name: "no route with timeout flag", observations: []l4Observation{{TimedOut: true, DialError: "noRoute"}}, wantCalls: 1},
		{name: "inconsistent success", observations: []l4Observation{{OK: true, TimedOut: true}}, wantCalls: 1},
		{name: "probe transport failure", probeError: true, wantCalls: 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			calls := 0
			err := requireL4Denials(func() (l4Observation, error) {
				calls++
				if tc.probeError {
					return l4Observation{}, errors.New("fixture probe unavailable")
				}
				if calls > len(tc.observations) {
					t.Fatal("negative check retried or exceeded its fixed sample count")
				}
				return tc.observations[calls-1], nil
			})
			if (err == nil) != tc.wantSuccess || calls != tc.wantCalls {
				t.Fatalf("success=%t calls=%d; want success=%t calls=%d", err == nil, calls, tc.wantSuccess, tc.wantCalls)
			}
		})
	}
}

// TestIngressL4 uses a real CR and two independently authenticated tsnet peers.
// A bounded nonce/hash exchange proves byte forwarding, not just TCP connect.
// Deny -> allow -> deny for the second user separates ACL effects from a broken
// peer or backend; the first user stays allowed throughout. No production CNI,
// egress subnet routing, HTTP coexistence or arbitrary-port coverage is claimed.
func TestIngressL4(t *testing.T) {
	x := newPeerFixture(t, nil, "ingress-l4")
	f := x.f
	var tn *tnv1.Tailnet
	var ingress *tnv1.TailnetIngress
	var grants []*tnv1.TailnetGrant
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
		}
		remove := func(o client.Object) {
			if o.GetUID() == "" {
				return
			}
			uid := o.GetUID()
			if err := f.kube.Delete(ctx, o, client.Preconditions{UID: &uid}); err != nil && !apierrors.IsNotFound(err) {
				t.Error("L4 CR cleanup failed")
				return
			}
			for !apierrors.IsNotFound(f.kube.Get(ctx, client.ObjectKeyFromObject(o), o)) {
				select {
				case <-ctx.Done():
					t.Error("L4 CR finalizer cleanup timed out")
					return
				case <-time.After(time.Second):
				}
			}
		}
		for _, grant := range grants {
			remove(grant)
		}
		if ingress != nil {
			remove(ingress)
		}
		if tn != nil {
			remove(tn)
		}
		if installed {
			if _, err := f.command(ctx, "", "helm", "uninstall", "tailnet-operator", "--kubeconfig", f.config, "--kube-context", f.context, "--namespace", namespace, "--wait", "--timeout", "90s"); err != nil {
				t.Error("L4 operator cleanup failed")
			}
		}
	})
	root, err := filepath.Abs(filepath.Join("..", ".."))
	if err != nil {
		t.Fatal("chart path unavailable")
	}
	values, _ := json.Marshal(map[string]any{"image": map[string]any{"repository": "localhost/tailnet-operator-e2e", "tag": f.cluster, "pullPolicy": "Never"}, "replicas": 1, "networkPolicy": map[string]any{"enabled": false}})
	installed = true
	f.child(t, string(values), "helm", "install", "tailnet-operator", filepath.Join(root, "charts", "tailnet-operator"), "--kubeconfig", f.config, "--kube-context", f.context, "--namespace", namespace, "--wait", "--timeout", "120s", "--values", "-")
	var operator appsv1.Deployment
	if f.kube.Get(t.Context(), client.ObjectKey{Namespace: namespace, Name: "tailnet-operator"}, &operator) != nil {
		t.Fatal("L4 operator missing")
	}
	original := operator.DeepCopy()
	if kindfixture.AddOperatorCA(&operator, x.ns, x.public, x.agentImage) != nil || f.kube.Patch(t.Context(), &operator, client.MergeFromWithOptions(original, client.MergeFromWithOptimisticLock{})) != nil {
		t.Fatal("L4 fixture operator trust failed")
	}
	eventually(t, "L4 operator Ready with fixture trust", func() bool {
		return f.kube.Get(t.Context(), client.ObjectKeyFromObject(&operator), &operator) == nil && operator.Status.ObservedGeneration == operator.Generation && operator.Status.Replicas == 1 && operator.Status.UpdatedReplicas == 1 && operator.Status.ReadyReplicas == 1
	})
	var key string
	if json.Unmarshal(x.cli("apikeys", "create", "--expiration", "1h", "--output", "json"), &key) != nil || key == "" {
		t.Fatal("L4 private API credential unavailable")
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
	policyReady := func() bool {
		return f.kube.Get(t.Context(), client.ObjectKeyFromObject(tn), tn) == nil && meta.IsStatusConditionTrue(tn.Status.Conditions, "HeadscaleCompatible") && meta.IsStatusConditionTrue(tn.Status.Conditions, "PolicyApplied") && tn.Status.Policy != nil && tn.Status.Policy.AppliedHash != "" && tn.Status.Policy.AppliedHash == tn.Status.Policy.RenderedHash
	}
	eventually(t, "L4 initial policy applied", policyReady)
	var backend corev1.Service
	if f.kube.Get(t.Context(), client.ObjectKey{Namespace: namespace, Name: "fixture-backend"}, &backend) != nil {
		t.Fatal("L4 backend service missing")
	}
	beforeService := backend.DeepCopy()
	backend.Spec.Ports = append(backend.Spec.Ports, corev1.ServicePort{Name: "l4", Port: 8081, TargetPort: intstr.FromInt32(8081)})
	if f.kube.Patch(t.Context(), &backend, client.MergeFromWithOptions(beforeService, client.MergeFromWithOptimisticLock{})) != nil {
		t.Fatal("L4 backend port failed")
	}
	ingress = &tnv1.TailnetIngress{ObjectMeta: metav1.ObjectMeta{Name: "http-agent", Namespace: namespace}, Spec: tnv1.TailnetIngressSpec{
		TailnetRef: tnv1.TailnetRef{Name: tn.Name}, Hostname: "http-agent", AllowFrom: []string{"group:l4-allowed"},
		Exposes: []tnv1.Expose{{Name: "tcp", Mode: "l4", Port: 8443, Backend: tnv1.Backend{Service: backend.Name, Port: 8081}}},
	}}
	x.create(ingress)
	var agent corev1.Pod
	var deployment appsv1.Deployment
	eventually(t, "L4 generated agent held at real startup gate", func() bool {
		if f.kube.Get(t.Context(), ingressAgentKey(ingress), &deployment) != nil {
			return false
		}
		owner := metav1.GetControllerOf(&deployment)
		if owner == nil || owner.Kind != "TailnetIngress" || owner.UID != ingress.UID {
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
		if f.kube.Get(t.Context(), client.ObjectKey{Namespace: namespace, Name: ref.Name}, &rs) != nil || rs.UID != ref.UID {
			return false
		}
		parent := metav1.GetControllerOf(&rs)
		if parent == nil || parent.UID != deployment.UID {
			return false
		}
		agent = p
		return true
	})
	if len(agent.Spec.Containers) != 1 || len(deployment.Spec.Template.Spec.Containers) != 1 {
		t.Fatal("L4 application container shape differs")
	}
	a, desired := agent.Spec.Containers[0], deployment.Spec.Template.Spec.Containers[0]
	if a.Image != x.agentImage || a.Image != desired.Image || !reflect.DeepEqual(a.Command, desired.Command) || !reflect.DeepEqual(a.Args, desired.Args) || !reflect.DeepEqual(a.Env, desired.Env) {
		t.Fatal("L4 admission changed application fields")
	}
	releaseFixturePod(t, f, &agent)
	ready := func() bool {
		return f.kube.Get(t.Context(), client.ObjectKeyFromObject(ingress), ingress) == nil && ingress.Status.ObservedGeneration == ingress.Generation && meta.IsStatusConditionTrue(ingress.Status.Conditions, "Ready") && ingress.Status.DNSName == "http-agent.fixture.test"
	}
	eventually(t, "L4 reconciled ingress Ready", ready)
	var target string
	for _, raw := range ingress.Status.TailnetIPs {
		ip, err := netip.ParseAddr(raw)
		if err == nil && ip.Is4() && netip.MustParsePrefix("100.64.0.0/10").Contains(ip) {
			target = raw
		}
	}
	if target == "" {
		t.Fatal("L4 tailnet IPv4 missing")
	}
	var deniedUser struct {
		ID uint64 `json:"id"`
	}
	if json.Unmarshal(x.cli("users", "create", "fixture-denied", "--output", "json"), &deniedUser) != nil || deniedUser.ID == 0 {
		t.Fatal("separate denied user missing")
	}
	var deniedKey struct {
		Key string `json:"key"`
	}
	if json.Unmarshal(x.cli("preauthkeys", "create", "--user", fmt.Sprint(deniedUser.ID), "--expiration", "1h", "--output", "json"), &deniedKey) != nil || deniedKey.Key == "" {
		t.Fatal("separate denied peer key missing")
	}
	x.create(&corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: "denied-peer-auth", Namespace: namespace}, StringData: map[string]string{"key": deniedKey.Key}})
	denied := httpFixturePod("denied-peer", x.image)
	denied.Spec.Containers[0].Command = []string{"/httppeer"}
	denied.Spec.Containers[0].Args = []string{"--fixture=p1.8-http", "--identity=denied"}
	denied.Spec.Containers[0].Env = []corev1.EnvVar{x.keyEnv("denied-peer-auth")}
	denied.Spec.Containers[0].VolumeMounts = []corev1.VolumeMount{{Name: "ca", MountPath: "/control-ca", ReadOnly: true}, {Name: "state", MountPath: "/state"}}
	denied.Spec.Volumes = []corev1.Volume{fixtureConfigVolume("ca", "fixture-control-ca"), fixtureStateVolume("state", "32Mi")}
	if kindfixture.AddNetworkGate(denied, x.image) != nil {
		t.Fatal("denied peer startup gate failed")
	}
	x.create(denied)
	releaseFixturePod(t, f, denied)
	eventually(t, "independent denied peer registered", func() bool { _, err := x.proxy(denied.Name, 9081, "readyz", ""); return err == nil })
	identities := []*corev1.Pod{&agent, x.peer, denied}
	initial := make([]corev1.Pod, len(identities))
	for i, pod := range identities {
		if f.kube.Get(t.Context(), client.ObjectKeyFromObject(pod), pod) != nil || len(pod.Status.ContainerStatuses) != 1 || !pod.Status.ContainerStatuses[0].Ready {
			t.Fatal("L4 peer or agent identity unavailable")
		}
		initial[i] = *pod.DeepCopy()
	}
	generation := deployment.Generation
	results := map[string][]l4Observation{}
	type probeRecord struct {
		Phase   string `json:"phase"`
		Address string `json:"addressKind"`
		Valid   bool   `json:"valid"`
		l4Observation
	}
	var observations []probeRecord
	// Keep every attempt, including convergence and observations from failed runs.
	t.Cleanup(func() { x.save("probe-observations.json", observations) })
	probeOnce := func(label, pod, address string) (l4Observation, error) {
		t.Helper()
		kind := "ipv4"
		if address != target {
			kind = "magicDNS"
		}
		input, _ := json.Marshal(map[string]string{"target": address})
		b, err := x.proxy(pod, 9081, "probe-l4", string(input))
		var raw struct {
			OK        *bool   `json:"ok"`
			Connected *bool   `json:"connected"`
			TimedOut  *bool   `json:"timedOut"`
			DialError *string `json:"dialError"`
		}
		valid := err == nil && len(b) <= 1024 && json.Unmarshal(b, &raw) == nil && raw.OK != nil && raw.Connected != nil && raw.TimedOut != nil && raw.DialError != nil
		var got l4Observation
		if valid {
			got = l4Observation{OK: *raw.OK, Connected: *raw.Connected, TimedOut: *raw.TimedOut, DialError: *raw.DialError}
			valid = knownL4DialError(got.DialError) && got.Connected == (got.DialError == "") && (!got.OK || (got.Connected && !got.TimedOut))
		}
		observations = append(observations, probeRecord{Phase: label, Address: kind, Valid: valid, l4Observation: got})
		if !valid {
			return got, errors.New("L4 peer probe unavailable or malformed")
		}
		return got, nil
	}
	probeAllowed := func(label, pod string) {
		t.Helper()
		for _, address := range []string{target, "http-agent.fixture.test"} {
			var got l4Observation
			eventually(t, "L4 allowed peer completes bounded exchange", func() bool {
				var err error
				got, err = probeOnce(label, pod, address)
				return err == nil && got.OK && got.Connected && !got.TimedOut
			})
			results[label] = append(results[label], got)
		}
	}
	probeDenied := func(label string) {
		t.Helper()
		// Only fresh IPv4 dial timeouts or no-route errors count. Unclassified MagicDNS lookup failures
		// are not ACL proof; DNS forwarding is checked in the positive phases.
		if err := requireL4Denials(func() (l4Observation, error) {
			got, err := probeOnce(label, denied.Name, target)
			results[label] = append(results[label], got)
			return got, err
		}); err != nil {
			t.Fatal(err)
		}
	}
	setAllowed := func(allow bool) {
		t.Helper()
		if !policyReady() || f.kube.Get(t.Context(), client.ObjectKeyFromObject(policy), policy) != nil {
			t.Fatal("current L4 policy unavailable")
		}
		oldHash := tn.Status.Policy.AppliedHash
		before := policy.DeepCopy()
		policy.Data["policy"] = l4BasePolicy(allow)
		if f.kube.Patch(t.Context(), policy, client.MergeFromWithOptions(before, client.MergeFromWithOptimisticLock{})) != nil {
			t.Fatal("fixture membership change rejected")
		}
		eventually(t, "changed L4 membership applied", func() bool { return policyReady() && tn.Status.Policy.AppliedHash != oldHash })
	}
	probeAllowed("allowed-before", x.peer.Name)
	probeDenied("denied-before")
	probeAllowed("allowed-during-denial", x.peer.Name)
	setAllowed(true)
	probeAllowed("denied-user-now-allowed", denied.Name)
	probeAllowed("original-user-still-allowed", x.peer.Name)
	setAllowed(false)
	// Policy application precedes asynchronous peer updates. Only revocation
	// gets a bounded convergence window, recorded separately from assertions.
	converge := func(label string) {
		t.Helper()
		eventually(t, "L4 revocation converges before fixed negative assertions", func() bool {
			got, err := probeOnce(label, denied.Name, target)
			if err != nil || (!got.Connected && !l4Denied(got)) {
				t.Fatal("L4 revocation probe unavailable or unclassified")
			}
			return l4Denied(got)
		})
	}
	converge("revocation-convergence")
	probeDenied("denied-again")
	probeAllowed("allowed-after", x.peer.Name)
	grantIs := func(grant *tnv1.TailnetGrant, reason string) bool {
		if f.kube.Get(t.Context(), client.ObjectKeyFromObject(grant), grant) != nil {
			return false
		}
		c := meta.FindStatusCondition(grant.Status.Conditions, "Ready")
		return c != nil && c.ObservedGeneration == grant.Generation && c.Reason == reason
	}
	newGrant := func(name string, port int32, lifetime time.Duration) *tnv1.TailnetGrant {
		t.Helper()
		grant := &tnv1.TailnetGrant{ObjectMeta: metav1.ObjectMeta{Name: name}, Spec: tnv1.TailnetGrantSpec{
			TailnetRef: tnv1.TailnetRef{Name: tn.Name}, Sources: []string{"fixture-denied@"}, Target: tnv1.GrantTarget{Tag: ingress.Status.Tag}, Ports: []int32{port},
		}}
		if lifetime > 0 {
			grant.Spec.ExpiresAt = &metav1.Time{Time: time.Now().Add(lifetime)}
		}
		x.create(grant)
		grants = append(grants, grant)
		eventually(t, "grant applied", func() bool { return grantIs(grant, "Granted") })
		return grant
	}
	// A held connection stays open across control requests. Every exchange on it is kept with its
	// time relative to expiresAt of the grant under test, including those of a failed run.
	type holdRecord struct {
		Variant  string  `json:"variant"`
		Phase    string  `json:"phase"`
		Role     string  `json:"role"`
		Start    float64 `json:"startSeconds"`
		End      float64 `json:"endSeconds"`
		Valid    bool    `json:"valid"`
		OK       bool    `json:"ok"`
		Held     bool    `json:"held"`
		TimedOut bool    `json:"timedOut"`
	}
	var holds []holdRecord
	t.Cleanup(func() { x.save("hold-observations.json", holds) })
	seconds := func(at, expiry time.Time) float64 { return math.Round(at.Sub(expiry).Seconds()*10) / 10 }
	holdInput, _ := json.Marshal(map[string]string{"target": target})
	holdOpen := func(variant, role, pod string, expiry time.Time) {
		t.Helper()
		eventually(t, "L4 held connection opened with a first exchange", func() bool {
			start := time.Now()
			b, err := x.proxy(pod, 9081, "hold-l4", string(holdInput))
			var got l4Observation
			valid := err == nil && len(b) <= 1024 && json.Unmarshal(b, &got) == nil
			holds = append(holds, holdRecord{Variant: variant, Phase: "open", Role: role, Start: seconds(start, expiry), End: seconds(time.Now(), expiry), Valid: valid, OK: got.OK, Held: got.Connected, TimedOut: got.TimedOut})
			return valid && got == (l4Observation{OK: true, Connected: true})
		})
	}
	holdExchange := func(variant, phase, role, pod string, expiry time.Time) holdRecord {
		t.Helper()
		start := time.Now()
		b, err := x.proxy(pod, 9081, "hold-l4-exchange", string(holdInput))
		var raw struct {
			OK       *bool `json:"ok"`
			Held     *bool `json:"held"`
			TimedOut *bool `json:"timedOut"`
		}
		got := holdRecord{Variant: variant, Phase: phase, Role: role, Start: seconds(start, expiry), End: seconds(time.Now(), expiry)}
		if err == nil && len(b) <= 1024 && json.Unmarshal(b, &raw) == nil && raw.OK != nil && raw.Held != nil && raw.TimedOut != nil {
			got.Valid, got.OK, got.Held, got.TimedOut = !*raw.OK || (*raw.Held && !*raw.TimedOut), *raw.OK, *raw.Held, *raw.TimedOut
		}
		holds = append(holds, got)
		if !got.Valid {
			t.Fatal("L4 held-connection probe unavailable or malformed")
		}
		return got
	}
	// revocationPhase: the denied user has just been admitted. One connection of each user is
	// opened and exchanged on while revoke withdraws the access at about ref; revoke returns when
	// the operator has applied the withdrawal. The allowed user's connection is the control and
	// must never fail. The denied user's connection must work until ref and must fail no later
	// than 5 s after fresh dials are denied: the agent ends a connection that its packet filter
	// would not admit again. While the two nodes are still peers the failure must not be a
	// timeout, which separates a connection that the agent closed from one that only stalled.
	revocationPhase := func(variant string, peers bool, ref time.Time, revoke func(round func(string))) map[string]any {
		t.Helper()
		probeAllowed(variant+"-active", denied.Name)
		holdOpen(variant, "control", x.peer.Name, ref)
		holdOpen(variant, "subject", denied.Name, ref)
		summary := map[string]any{"lastSuccessSeconds": nil, "firstFailureSeconds": nil, "failureTimedOut": nil}
		alive := true
		round := func(phase string) {
			t.Helper()
			if !holdExchange(variant, phase, "control", x.peer.Name, ref).OK {
				t.Fatal("held connection of the allowed user failed")
			}
			if !alive {
				return
			}
			got := holdExchange(variant, phase, "subject", denied.Name, ref)
			if got.OK {
				summary["lastSuccessSeconds"] = got.End
				return
			}
			if got.Start < -2 {
				t.Fatal("held connection of the admitted user failed before the revocation")
			}
			alive = false
			summary["firstFailureSeconds"], summary["failureTimedOut"] = got.Start, got.TimedOut
		}
		revoke(round)
		summary["revocationAppliedSeconds"] = seconds(time.Now(), ref)
		// One-second samples first: a denied dial below can take 5 s and would hide when the
		// connection ended.
		for range 5 {
			if !alive {
				break
			}
			round("revoked")
			time.Sleep(time.Second)
		}
		converge(variant + "-convergence")
		denial := time.Now()
		summary["newConnectionsDeniedSeconds"] = seconds(denial, ref)
		for alive && time.Since(denial) < 5*time.Second {
			round("new-connections-denied")
			time.Sleep(time.Second)
		}
		if alive {
			t.Fatal("held connection of the revoked user survived the revocation")
		}
		if peers && summary["failureTimedOut"] == true {
			t.Fatal("held connection of the revoked user stalled; the agent did not close it")
		}
		probeDenied(variant + "-denied")
		for range 2 {
			round("after-revocation")
			time.Sleep(time.Second)
		}
		probeAllowed(variant+"-allowed-after", x.peer.Name)
		return summary
	}
	// A time-bound TailnetGrant: at expiresAt the operator withdraws it; no object is touched.
	expiry := func(variant string, peers bool) map[string]any {
		t.Helper()
		grant := newGrant("fixture-denied-l4-"+variant, 8443, 120*time.Second)
		return revocationPhase(variant, peers, grant.Spec.ExpiresAt.Time, func(round func(string)) {
			eventuallyWithin(t, 150*time.Second, "time-bound grant expired", func() bool { round("admitted"); return grantIs(grant, "Expired") })
			if time.Now().Before(grant.Spec.ExpiresAt.Time) {
				t.Fatal("grant reported Expired before expiresAt")
			}
		})
	}
	// The other revocations happen when the test says so: a few exchanges first, then the change,
	// then the wait until the operator has applied a policy without the access.
	immediate := func(variant string, change func()) map[string]any {
		t.Helper()
		ref := time.Now().Add(15 * time.Second)
		return revocationPhase(variant, true, ref, func(round func(string)) {
			for time.Now().Before(ref) {
				round("admitted")
				time.Sleep(time.Second)
			}
			if !policyReady() {
				t.Fatal("current L4 policy unavailable")
			}
			oldHash := tn.Status.Policy.AppliedHash
			change()
			eventually(t, "revocation applied", func() bool { return policyReady() && tn.Status.Policy.AppliedHash != oldHash })
		})
	}
	// Without another rule the two nodes stop being peers at expiresAt.
	revocations := map[string]any{"isolated": expiry("isolated", false)}
	// With a permanent grant to a port the ingress does not expose, the two nodes stay peers after
	// every later revocation. That grant alone must not open the exposed port.
	newGrant("fixture-denied-l4-peer", 9, 0)
	probeDenied("peered-before-grant")
	revocations["peered"] = expiry("peered", true)
	// Deleting a grant is the documented way to revoke it early.
	permanent := newGrant("fixture-denied-l4-deleted", 8443, 0)
	revocations["deleted"] = immediate("deleted", func() {
		if f.kube.Delete(t.Context(), permanent) != nil {
			t.Fatal("grant deletion rejected")
		}
	})
	// The allowFrom group of the ingress loses the user in the base policy.
	setAllowed(true)
	revocations["group"] = immediate("group", func() { setAllowed(false) })
	if !ready() || !policyReady() || f.kube.Get(t.Context(), client.ObjectKeyFromObject(&deployment), &deployment) != nil || deployment.Generation != generation {
		t.Fatal("L4 fixture health or agent template changed")
	}
	for i, pod := range identities {
		if f.kube.Get(t.Context(), client.ObjectKeyFromObject(pod), pod) != nil || pod.UID != initial[i].UID || len(pod.Status.ContainerStatuses) != 1 || pod.Status.ContainerStatuses[0].ContainerID != initial[i].Status.ContainerStatuses[0].ContainerID || pod.Status.ContainerStatuses[0].RestartCount != initial[i].Status.ContainerStatuses[0].RestartCount {
			t.Fatal("ACL sequence replaced or restarted a participant")
		}
	}
	x.save("result.json", map[string]any{"realChartAndReconciler": true, "generatedAgentStartupGate": true, "l4ByteExchange": true, "separateUserACLNegative": true, "denyAllowDenyRecovery": true, "sameParticipants": true, "probes": results, "egressSubnetRoutingTested": false, "httpCoexistenceTested": false, "aclNegativeAddress": "tailnet-ipv4", "negativeSamplesPerPhase": l4NegativeSamples, "dnsACLNegativeTested": false, "immediateRevocationTested": false, "timeBoundGrant": true, "establishedConnectionsAtExpiryTested": true, "establishedConnectionsCutOnRevocation": true, "revocations": revocations})
	t.Log("gate: generated L4 ingress, IPv4/MagicDNS byte exchange, independent user IPv4 deny/allow/deny with fixed timeout/no-route samples and positive controls; unchanged participants; revocation convergence recorded separately; the denied user is admitted and revoked by a time-bound TailnetGrant (without and with another rule that keeps the nodes peers), by a deleted grant and by the allowFrom group; each time new connections are denied and a connection opened before fails within 5 s of that denial, closed by the agent where the nodes stay peers")
}
