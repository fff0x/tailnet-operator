//go:build e2e_kind

package e2ekind

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"reflect"
	"strings"
	"testing"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"

	tnv1 "tsunaro.io/tailnet-operator/api/v1alpha1"
	"tsunaro.io/tailnet-operator/internal/certificates"
	"tsunaro.io/tailnet-operator/test/internal/kindfixture"
)

// The inert documentation-address ACL passes the empty-policy guard without
// granting access to the agent. Only the CR-derived group grant allows that.
func ingressHTTPBasePolicy(includeDenied bool) string {
	members := []string{httpFixtureUser + "@"}
	if includeDenied {
		members = append(members, "fixture-denied@")
	}
	b, _ := json.Marshal(map[string]any{
		"groups": map[string][]string{"group:http-allowed": members}, "tagOwners": map[string]any{},
		"acls": []map[string]any{{"action": "accept", "src": []string{"autogroup:member"}, "dst": []string{"192.0.2.1:443"}}},
	})
	return string(b)
}

type httpACLObservation struct {
	OK           bool   `json:"ok"`
	Status       int    `json:"status"`
	Major        int    `json:"httpMajor"`
	ALPN         string `json:"alpn"`
	Leaf         string `json:"leafSHA256"`
	Backend      bool   `json:"backendVerified"`
	Connected    bool   `json:"connected"`
	DialTimedOut bool   `json:"dialTimedOut"`
	DialError    string `json:"dialError"`
}

func decodeHTTPACLObservation(data []byte) (httpACLObservation, error) {
	var got httpACLObservation
	if len(data) > 4096 {
		return got, errors.New("HTTP ACL probe oversized")
	}
	fields := map[string]json.RawMessage{}
	dec := json.NewDecoder(bytes.NewReader(data))
	if token, err := dec.Token(); err != nil || token != json.Delim('{') {
		return got, errors.New("HTTP ACL probe malformed")
	}
	for dec.More() {
		token, err := dec.Token()
		name, ok := token.(string)
		if err != nil || !ok || fields[name] != nil {
			return got, errors.New("HTTP ACL probe duplicate or invalid field")
		}
		var value json.RawMessage
		if dec.Decode(&value) != nil {
			return got, errors.New("HTTP ACL probe invalid value")
		}
		fields[name] = value
	}
	if token, err := dec.Token(); err != nil || token != json.Delim('}') || len(fields) != 9 {
		return got, errors.New("HTTP ACL probe malformed")
	}
	if _, err := dec.Token(); err != io.EOF {
		return got, errors.New("HTTP ACL probe trailing data")
	}
	for _, name := range []string{"ok", "status", "httpMajor", "alpn", "leafSHA256", "backendVerified", "connected", "dialTimedOut", "dialError"} {
		if v, ok := fields[name]; !ok || string(v) == "null" {
			return got, errors.New("HTTP ACL probe missing field")
		}
	}
	if json.Unmarshal(data, &got) != nil {
		return httpACLObservation{}, errors.New("HTTP ACL probe invalid field")
	}
	switch got.DialError {
	case "", "timeout", "noRoute", "unreachable", "refused", "reset", "canceled", "other":
	default:
		return httpACLObservation{}, errors.New("HTTP ACL probe unknown dial category")
	}
	if got.DialTimedOut != (got.DialError == "timeout") {
		return httpACLObservation{}, errors.New("HTTP ACL probe contradictory dial category")
	}
	return got, nil
}

func httpACLDenied(got httpACLObservation) bool {
	switch got.DialError {
	case "timeout":
		return got == (httpACLObservation{DialError: "timeout", DialTimedOut: true})
	case "noRoute", "unreachable":
		return got == (httpACLObservation{DialError: got.DialError})
	default:
		return false
	}
}

const httpACLNegativeSamples = 3

func requireHTTPACLDenials(probe func() (httpACLObservation, error)) error {
	for range httpACLNegativeSamples {
		got, err := probe()
		if err != nil || !httpACLDenied(got) {
			return errors.New("HTTP ACL negative probe connected or lacked classified TCP denial evidence")
		}
	}
	return nil
}

// Use the proven admin virtual host: its verified HTTPS backend returns 404 for
// the fixed probe path for either user. The strict primary backend intentionally
// accepts forwarding headers only from the original peer and stays unchanged.
func testIngressHTTPACL(t *testing.T, x *httpPeerFixture, tn *tnv1.Tailnet, ingress *tnv1.TailnetIngress, agent *corev1.Pod) {
	f := x.f
	var deployment appsv1.Deployment
	if f.kube.Get(t.Context(), ingressAgentKey(ingress), &deployment) != nil || !metav1.IsControlledBy(&deployment, ingress) || deployment.Spec.Template.Annotations["tsunaro.io/agent-config-protocol"] != "http-v3" {
		t.Fatal("HTTP ACL v3 agent missing")
	}
	initialDeployment := deployment.DeepCopy()
	ingressUID, ingressGeneration := ingress.UID, ingress.Generation
	ready := func() bool {
		return f.kube.Get(t.Context(), client.ObjectKeyFromObject(ingress), ingress) == nil && ingress.UID == ingressUID && ingress.Generation == ingressGeneration && ingress.Status.ObservedGeneration == ingress.Generation && meta.IsStatusConditionTrue(ingress.Status.Conditions, "Ready") && meta.IsStatusConditionTrue(ingress.Status.Conditions, "TLSReady")
	}
	policyReady := func() bool {
		return f.kube.Get(t.Context(), client.ObjectKeyFromObject(tn), tn) == nil && meta.IsStatusConditionTrue(tn.Status.Conditions, "HeadscaleCompatible") && meta.IsStatusConditionTrue(tn.Status.Conditions, "PolicyApplied") && tn.Status.Policy != nil && tn.Status.Policy.AppliedHash != "" && tn.Status.Policy.AppliedHash == tn.Status.Policy.RenderedHash
	}
	eventually(t, "HTTP ACL initial ingress and policy ready", func() bool { return ready() && policyReady() })
	var target string
	for _, raw := range ingress.Status.TailnetIPs {
		ip, err := netip.ParseAddr(raw)
		if err == nil && ip.Is4() && netip.MustParsePrefix("100.64.0.0/10").Contains(ip) {
			target = raw
		}
	}
	if target == "" {
		t.Fatal("HTTP ACL tailnet IPv4 missing")
	}
	var secret corev1.Secret
	if f.kube.Get(t.Context(), client.ObjectKey{Namespace: namespace, Name: ingress.Status.TLSSecretName}, &secret) != nil {
		t.Fatal("HTTP ACL serving certificate missing")
	}
	pair, err := certificates.ParseServingPair(secret.Data["tls.crt"], secret.Data["tls.key"], "admin.fixture.test")
	if err != nil {
		t.Fatal("HTTP ACL serving certificate invalid")
	}
	sum := sha256.Sum256(pair.Leaf.Raw)
	leaf := hex.EncodeToString(sum[:])
	var deniedUser struct {
		ID uint64 `json:"id"`
	}
	if json.Unmarshal(x.cli("users", "create", "fixture-denied", "--output", "json"), &deniedUser) != nil || deniedUser.ID == 0 {
		t.Fatal("HTTP ACL denied user missing")
	}
	var deniedKey struct {
		Key string `json:"key"`
	}
	if json.Unmarshal(x.cli("preauthkeys", "create", "--user", fmt.Sprint(deniedUser.ID), "--expiration", "1h", "--output", "json"), &deniedKey) != nil || deniedKey.Key == "" {
		t.Fatal("HTTP ACL denied credential unavailable")
	}
	x.create(&corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: "denied-peer-auth", Namespace: namespace}, StringData: map[string]string{"key": deniedKey.Key}})
	denied := httpFixturePod("denied-peer", x.image)
	denied.Spec.Containers[0].Command = []string{"/httppeer"}
	denied.Spec.Containers[0].Args = []string{"--fixture=p1.8-http", "--identity=denied", "--serving-ca=cert-manager"}
	denied.Spec.Containers[0].Env = []corev1.EnvVar{x.keyEnv("denied-peer-auth")}
	denied.Spec.Containers[0].VolumeMounts = []corev1.VolumeMount{{Name: "ca", MountPath: "/control-ca", ReadOnly: true}, {Name: "serving-ca", MountPath: "/serving-ca", ReadOnly: true}, {Name: "state", MountPath: "/state"}}
	denied.Spec.Volumes = []corev1.Volume{fixtureConfigVolume("ca", "fixture-control-ca"), fixtureConfigVolume("serving-ca", "fixture-serving-ca"), fixtureStateVolume("state", "32Mi")}
	if kindfixture.AddNetworkGate(denied, x.image) != nil {
		t.Fatal("HTTP ACL denied startup gate failed")
	}
	x.create(denied)
	releaseFixturePod(t, f, denied)
	eventually(t, "HTTP ACL denied peer registered", func() bool { _, err := x.proxy(denied.Name, 9081, "readyz", ""); return err == nil })
	participants := []*corev1.Pod{agent, x.peer, denied}
	initial := make([]corev1.Pod, len(participants))
	for i, p := range participants {
		if f.kube.Get(t.Context(), client.ObjectKeyFromObject(p), p) != nil || len(p.Status.ContainerStatuses) != 1 || !p.Status.ContainerStatuses[0].Ready {
			t.Fatal("HTTP ACL participant missing")
		}
		initial[i] = *p.DeepCopy()
	}
	type record struct {
		Phase string `json:"phase"`
		HTTP2 bool   `json:"http2"`
		Valid bool   `json:"valid"`
		httpACLObservation
	}
	var observations []record
	t.Cleanup(func() { x.save("http-acl-observations.json", observations) })
	probeOnce := func(phase, pod string, h2 bool) (httpACLObservation, error) {
		raw, _ := json.Marshal(map[string]any{"target": target, "http2": h2, "sni": "admin.fixture.test", "host": "admin.fixture.test"})
		b, err := x.proxy(pod, 9081, "probe-http-acl", string(raw))
		got, decodeErr := decodeHTTPACLObservation(b)
		valid := err == nil && decodeErr == nil
		observations = append(observations, record{Phase: phase, HTTP2: h2, Valid: valid, httpACLObservation: got})
		if !valid {
			return got, errors.New("HTTP ACL probe unavailable or malformed")
		}
		return got, nil
	}
	allowed := func(phase, pod string) {
		t.Helper()
		for _, h2 := range []bool{false, true} {
			eventually(t, "HTTP ACL allowed peer receives verified upstream response", func() bool {
				got, err := probeOnce(phase, pod, h2)
				return err == nil && got.Connected && !got.DialTimedOut && got.DialError == "" && !got.OK && !got.Backend && got.Status == 404 && got.Leaf == leaf && ((!h2 && got.Major == 1 && got.ALPN == "http/1.1") || (h2 && got.Major == 2 && got.ALPN == "h2"))
			})
		}
	}
	denials := func(phase string) {
		t.Helper()
		for _, h2 := range []bool{false, true} {
			// Registration and policy changes both precede netmap convergence.
			// Retain bounded convergence separately for BOTH denial phases. Only
			// the agreed TCP failure categories count; control errors stay fatal.
			eventually(t, "HTTP ACL "+phase+" converges", func() bool {
				got, err := probeOnce(phase+"-convergence", denied.Name, h2)
				if err != nil {
					t.Fatal("HTTP ACL convergence probe unavailable or malformed")
				}
				return httpACLDenied(got)
			})
			// Fixed fresh samples never retry a contradictory observation.
			if err := requireHTTPACLDenials(func() (httpACLObservation, error) { return probeOnce(phase, denied.Name, h2) }); err != nil {
				t.Fatal(err)
			}
		}
	}
	setAllowed := func(allow bool) {
		t.Helper()
		var base corev1.ConfigMap
		if !policyReady() || f.kube.Get(t.Context(), client.ObjectKey{Namespace: namespace, Name: "headscale-policy"}, &base) != nil {
			t.Fatal("HTTP ACL policy unavailable")
		}
		oldHash := tn.Status.Policy.AppliedHash
		before := base.DeepCopy()
		base.Data["policy"] = ingressHTTPBasePolicy(allow)
		if f.kube.Patch(t.Context(), &base, client.MergeFromWithOptions(before, client.MergeFromWithOptimisticLock{})) != nil {
			t.Fatal("HTTP ACL group update failed")
		}
		eventually(t, "HTTP ACL updated membership applied", func() bool { return policyReady() && tn.Status.Policy.AppliedHash != oldHash })
	}
	allowed("allowed-before", x.peer.Name)
	denials("denied-before")
	allowed("allowed-during-denial", x.peer.Name)
	setAllowed(true)
	allowed("denied-user-now-allowed", denied.Name)
	allowed("original-user-still-allowed", x.peer.Name)
	setAllowed(false)
	denials("denied-again")
	allowed("allowed-after", x.peer.Name)
	if !ready() || !policyReady() || f.kube.Get(t.Context(), client.ObjectKeyFromObject(&deployment), &deployment) != nil || deployment.UID != initialDeployment.UID || deployment.Generation != initialDeployment.Generation {
		t.Fatal("HTTP ACL health or template changed")
	}
	for i, p := range participants {
		if f.kube.Get(t.Context(), client.ObjectKeyFromObject(p), p) != nil || p.UID != initial[i].UID || len(p.Status.ContainerStatuses) != 1 || !p.Status.ContainerStatuses[0].Ready || p.Status.ContainerStatuses[0].ContainerID != initial[i].Status.ContainerStatuses[0].ContainerID || p.Status.ContainerStatuses[0].RestartCount != initial[i].Status.ContainerStatuses[0].RestartCount {
			t.Fatal("HTTP ACL replaced or restarted a participant")
		}
	}
	x.save("http-acl-result.json", map[string]any{"aclNegativeTested": true, "separateUser": true, "denyAllowDeny": true, "http1AndHTTP2PositiveControls": true, "verifiedUpstreamStatus": 404, "negativeAddressKind": "tailnet-ipv4", "negativeSamplesPerProtocolPerPhase": httpACLNegativeSamples, "denialCategories": []string{"timeout", "noRoute", "unreachable"}, "convergenceBeforeEachSampleSet": true, "sameParticipants": true, "dnsDenialTested": false, "immediateRevocationTested": false, "establishedConnectionRevocationTested": false})
	t.Log("gate: separate-user HTTP ACL deny/allow/deny; fresh classified IPv4 TCP denials, verified HTTP1+HTTP2 recovery and positive controls; unchanged participants")
}

func TestHTTPACLPolicyFixture(t *testing.T) {
	for _, allowed := range []bool{false, true} {
		var p struct {
			Groups map[string][]string `json:"groups"`
			ACLs   []struct {
				Dst []string `json:"dst"`
			} `json:"acls"`
		}
		if json.Unmarshal([]byte(ingressHTTPBasePolicy(allowed)), &p) != nil || len(p.ACLs) != 1 || !reflect.DeepEqual(p.ACLs[0].Dst, []string{"192.0.2.1:443"}) {
			t.Fatal("base policy grants real fixture access")
		}
		want := []string{httpFixtureUser + "@"}
		if allowed {
			want = append(want, "fixture-denied@")
		}
		if len(p.Groups) != 1 || !reflect.DeepEqual(p.Groups["group:http-allowed"], want) {
			t.Fatal("HTTP ACL group differs")
		}
	}
}

func TestHTTPACLNegativeAssertions(t *testing.T) {
	timeout := httpACLObservation{DialTimedOut: true, DialError: "timeout"}
	noRoute := httpACLObservation{DialError: "noRoute"}
	unreachable := httpACLObservation{DialError: "unreachable"}
	for _, tc := range []struct {
		name       string
		got        []httpACLObservation
		probeError bool
		wantCalls  int
		pass       bool
	}{
		{"three TCP timeouts", []httpACLObservation{timeout, timeout, timeout}, false, 3, true},
		{"mixed allowed denials", []httpACLObservation{noRoute, timeout, unreachable}, false, 3, true},
		{"refused", []httpACLObservation{{DialError: "refused"}}, false, 1, false},
		{"reset", []httpACLObservation{{DialError: "reset"}}, false, 1, false},
		{"canceled", []httpACLObservation{{DialError: "canceled"}}, false, 1, false},
		{"other", []httpACLObservation{{DialError: "other"}}, false, 1, false},
		{"unknown category", []httpACLObservation{{DialError: "dns"}}, false, 1, false},
		{"no route after connect", []httpACLObservation{{Connected: true, DialError: "noRoute"}}, false, 1, false},
		{"unreachable with response", []httpACLObservation{{Status: 404, DialError: "unreachable"}}, false, 1, false},
		{"missing timeout flag", []httpACLObservation{{DialError: "timeout"}}, false, 1, false},
		{"contradictory timeout flag", []httpACLObservation{{DialError: "noRoute", DialTimedOut: true}}, false, 1, false},
		{"connect then timeout cannot pass", []httpACLObservation{{Connected: true}, timeout, timeout}, false, 1, false},
		{"timeout then connect cannot pass", []httpACLObservation{timeout, {Connected: true}}, false, 2, false},
		{"TLS timeout", []httpACLObservation{{Connected: true, DialTimedOut: true, DialError: "timeout"}}, false, 1, false},
		{"TLS error", []httpACLObservation{{Connected: true}}, false, 1, false},
		{"unclassified error", []httpACLObservation{{}}, false, 1, false},
		{"HTTP error", []httpACLObservation{{Status: 502, Connected: true}}, false, 1, false},
		{"contradictory response", []httpACLObservation{{Status: 200, DialTimedOut: true}}, false, 1, false},
		{"probe unavailable", nil, true, 1, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			calls := 0
			err := requireHTTPACLDenials(func() (httpACLObservation, error) {
				calls++
				if tc.probeError {
					return httpACLObservation{}, errors.New("unavailable")
				}
				if calls > len(tc.got) {
					t.Fatal("negative assertion retried contradiction")
				}
				return tc.got[calls-1], nil
			})
			if (err == nil) != tc.pass || calls != tc.wantCalls {
				t.Fatal("negative assertion misclassified evidence")
			}
		})
	}
	for _, category := range []string{"", "timeout", "noRoute", "unreachable", "refused", "reset", "canceled", "other"} {
		want := httpACLObservation{DialError: category, DialTimedOut: category == "timeout"}
		data, _ := json.Marshal(want)
		got, err := decodeHTTPACLObservation(data)
		if err != nil || got != want || httpACLDenied(got) != (category == "timeout" || category == "noRoute" || category == "unreachable") {
			t.Fatalf("category round-trip or denial rule differs: %q", category)
		}
	}
	valid := `{"ok":false,"status":0,"httpMajor":0,"alpn":"","leafSHA256":"","backendVerified":false,"connected":false,"dialTimedOut":true,"dialError":"timeout"}`
	if got, err := decodeHTTPACLObservation([]byte(valid)); err != nil || !httpACLDenied(got) {
		t.Fatal("valid denial rejected")
	}
	for _, raw := range []string{
		`null`, `{}`, `{"dialTimedOut":true}`, valid + `{}`,
		`{"connected":true,` + valid[1:], // Duplicate must not hide a connection.
		`{"conne\u0063ted":true,` + valid[1:],
		`{"extra":false,` + valid[1:],
		strings.Replace(valid, `,"dialError":"timeout"`, "", 1),
		strings.Replace(valid, `"dialError":"timeout"`, `"dialError":null`, 1),
		strings.Replace(valid, `"dialError":"timeout"`, `"dialError":true`, 1),
		strings.Replace(valid, `"dialError":"timeout"`, `"dialError":"private unknown error"`, 1),
		strings.Replace(valid, `"dialError":"timeout"`, `"dialError":"noRoute"`, 1),
		`{"dialError":"reset",` + valid[1:],
		`{"dial\u0045rror":"reset",` + valid[1:],
		strings.Repeat(" ", 4097),
	} {
		if _, err := decodeHTTPACLObservation([]byte(raw)); err == nil {
			t.Fatal("malformed evidence accepted")
		}
	}
}
