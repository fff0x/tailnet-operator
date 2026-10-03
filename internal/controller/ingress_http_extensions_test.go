package controller

import (
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"math/big"
	"reflect"
	"strings"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"

	tnv1 "tsunaro.io/tailnet-operator/api/v1alpha1"
	"tsunaro.io/tailnet-operator/internal/certificates"
)

func extensionString(s string) *string { return &s }

func backendTLSFixture() *tnv1.BackendTLS {
	return &tnv1.BackendTLS{ServerName: "app.backend-only.svc.cluster.local",
		CAConfigMapRef: tnv1.CAConfigMapRef{Name: "public-ca", Key: "root.pem"}}
}

func TestIngressHTTPExtensionResources(t *testing.T) {
	in := tlsResourceIngress()
	in.Spec.Exposes[0].Backend.TLS = backendTLSFixture()
	in.Spec.Exposes[0].Timeouts = &tnv1.HTTPTimeouts{Request: extensionString("600s"), BackendRequest: extensionString("0s")}
	before := in.DeepCopy()
	plan := tlsTestPlan(in, "frontend")
	target := renderedIngressTargets(t, in, in.Namespace, plan)[0]
	if target.BackendServerName != in.Spec.Exposes[0].Backend.TLS.ServerName || target.BackendCAFile != "/backend-tls/ca.crt" ||
		target.RequestTimeout != "600s" || target.BackendRequestTimeout != "0s" || target.Address != "app.backend-only.svc.cluster.local" {
		t.Fatalf("incorrect extension target: %+v", target)
	}
	for _, image := range []string{"operator:old", "tailnet:override", "ingress:override"} {
		dep := ingressAgentDeploymentTLS(in, &tnv1.Tailnet{}, in.Namespace, image, nil, corev1.ResourceRequirements{}, plan)
		if dep.Spec.Strategy.Type != "Recreate" || dep.Spec.Template.Annotations["tsunaro.io/agent-config-protocol"] != "http-v2" ||
			dep.Spec.Template.Spec.Containers[0].Image != image {
			t.Fatal("image overrides must never bypass protocol transition and process retirement")
		}
		var source *corev1.ConfigMapVolumeSource
		for _, v := range dep.Spec.Template.Spec.Volumes {
			if v.Name == "backend-tls" {
				source = v.ConfigMap
			}
		}
		if source == nil || source.Name != "public-ca" || source.Optional == nil || !*source.Optional ||
			!reflect.DeepEqual(source.Items, []corev1.KeyToPath{{Key: "root.pem", Path: "ca.crt"}}) {
			t.Fatal("backend CA must project only the selected namespace-local key")
		}
		found := false
		for _, mount := range dep.Spec.Template.Spec.Containers[0].VolumeMounts {
			if mount.Name == "backend-tls" {
				found = mount.MountPath == "/backend-tls" && mount.ReadOnly && mount.SubPath == "" && mount.SubPathExpr == ""
			}
		}
		if !found {
			t.Fatal("backend CA projection must support rotation and remain read-only")
		}
	}
	wrongNS := ingressAgentDeploymentTLS(in, &tnv1.Tailnet{}, "backend-only", "old", nil, corev1.ResourceRequirements{}, plan)
	for _, v := range wrongNS.Spec.Template.Spec.Volumes {
		if v.Name == "backend-tls" {
			t.Fatal("CA reference escaped ingress namespace")
		}
	}
	if !reflect.DeepEqual(before, in) {
		t.Fatal("render mutated input")
	}
	for _, change := range []func(*tnv1.Expose){
		func(e *tnv1.Expose) { e.Backend.TLS.ServerName = "different.example" },
		func(e *tnv1.Expose) { e.Backend.TLS.CAConfigMapRef.Name = "new-ca" },
		func(e *tnv1.Expose) { e.Backend.TLS.CAConfigMapRef.Key = "new.pem" },
		func(e *tnv1.Expose) { e.Timeouts.Request = extensionString("0s") },
		func(e *tnv1.Expose) { e.Timeouts.BackendRequest = nil },
	} {
		copy := in.DeepCopy()
		change(&copy.Spec.Exposes[0])
		if got := renderedIngressTargets(t, copy, copy.Namespace, plan)[0].ConfigID; got == target.ConfigID {
			t.Fatal("extension change reused a previous observation identity")
		}
	}
}

func TestIngressHTTPExtensionProtocolSkew(t *testing.T) {
	for _, tc := range []struct {
		name   string
		change func(*tnv1.Expose)
		valid  bool
	}{
		{"tls", func(e *tnv1.Expose) { e.Backend.TLS = backendTLSFixture() }, true},
		{"empty-timeouts", func(e *tnv1.Expose) { e.Timeouts = &tnv1.HTTPTimeouts{} }, true},
		{"zero", func(e *tnv1.Expose) { e.Timeouts = &tnv1.HTTPTimeouts{Request: extensionString("0s")} }, true},
		{"beyond-24h", func(e *tnv1.Expose) { e.Timeouts = &tnv1.HTTPTimeouts{BackendRequest: extensionString("99999h")} }, true},
		{"empty-tls", func(e *tnv1.Expose) { e.Backend.TLS = &tnv1.BackendTLS{} }, false},
		{"l4-tls", func(e *tnv1.Expose) { e.Mode = "l4"; e.Backend.TLS = backendTLSFixture() }, false},
		{"omitted-mode-timeouts", func(e *tnv1.Expose) { e.Mode = ""; e.Timeouts = &tnv1.HTTPTimeouts{} }, false},
		{"empty-duration", func(e *tnv1.Expose) { e.Timeouts = &tnv1.HTTPTimeouts{Request: extensionString("")} }, false},
		{"fraction", func(e *tnv1.Expose) { e.Timeouts = &tnv1.HTTPTimeouts{Request: extensionString("1.5s")} }, false},
		{"negative", func(e *tnv1.Expose) { e.Timeouts = &tnv1.HTTPTimeouts{Request: extensionString("-1s")} }, false},
		{"too-many-digits", func(e *tnv1.Expose) { e.Timeouts = &tnv1.HTTPTimeouts{Request: extensionString("100000s")} }, false},
		{"ip-name", func(e *tnv1.Expose) { e.Backend.TLS = backendTLSFixture(); e.Backend.TLS.ServerName = "10.0.0.1" }, false},
		{"invalid-key", func(e *tnv1.Expose) {
			e.Backend.TLS = backendTLSFixture()
			e.Backend.TLS.CAConfigMapRef.Key = "../root"
		}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			in := tlsResourceIngress()
			tc.change(&in.Spec.Exposes[0])
			plan := tlsTestPlan(in, "frontend")
			cm, err := ingressExposesConfigMap(in, in.Namespace, plan)
			if err != nil {
				t.Fatal(err)
			}
			var envelope struct {
				Version int
				Targets []agentTarget
			}
			if json.Unmarshal([]byte(cm.Data[targetsFile]), &envelope) != nil || envelope.Version != 2 || envelope.Targets == nil {
				t.Fatal("new feature presence did not select fail-closed v2 envelope")
			}
			if (len(envelope.Targets) == 2) != tc.valid || (!tc.valid && len(envelope.Targets) != 0) {
				t.Fatalf("invalid request retained a listener: %+v", envelope.Targets)
			}
			if ingressProtocolAnnotations(in)["tsunaro.io/agent-config-protocol"] != "http-v2" {
				t.Fatal("missing rollout boundary")
			}
		})
	}
}

func backendCAFixture(t *testing.T, namespace string, now time.Time) *corev1.ConfigMap {
	t.Helper()
	secret, _ := ingressTestCertificate(t, &x509.Certificate{SerialNumber: big.NewInt(2),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign,
		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour)})
	return &corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Name: "public-ca", Namespace: namespace},
		Data: map[string]string{"root.pem": string(secret.Data[corev1.TLSCertKey])}}
}

func TestIngressBackendCASource(t *testing.T) {
	ctx := context.Background()
	in := tlsResourceIngress()
	in.Spec.Exposes[0].Backend.TLS = backendTLSFixture()
	original := backendCAFixture(t, in.Namespace, time.Now())
	for _, tc := range []struct {
		name   string
		mutate func(*corev1.ConfigMap)
		reason string
	}{
		{"valid", func(*corev1.ConfigMap) {}, ""},
		{"foreign-namespace", func(cm *corev1.ConfigMap) { cm.Namespace = "backend-only" }, "BackendCAMissing"},
		{"missing-key", func(cm *corev1.ConfigMap) { cm.Data = nil }, "BackendCAMissing"},
		{"empty", func(cm *corev1.ConfigMap) { cm.Data["root.pem"] = "" }, "BackendCAInvalid"},
		{"malformed", func(cm *corev1.ConfigMap) { cm.Data["root.pem"] = "secret-sentinel" }, "BackendCAInvalid"},
		{"oversized", func(cm *corev1.ConfigMap) { cm.Data["root.pem"] = strings.Repeat("a", certificates.MaxCABundleSize+1) }, "BackendCAInvalid"},
		{"mixed-private-key", func(cm *corev1.ConfigMap) {
			cm.Data["root.pem"] += "-----BEGIN PRIVATE KEY-----\nc2VjcmV0\n-----END PRIVATE KEY-----\n"
		}, "BackendCAInvalid"},
		{"binary", func(cm *corev1.ConfigMap) {
			cm.BinaryData = map[string][]byte{"root.pem": []byte(cm.Data["root.pem"])}
			cm.Data = nil
		}, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cm := original.DeepCopy()
			tc.mutate(cm)
			r := &TailnetIngressReconciler{Client: ingressTLSFakeClient(t, cm)}
			state := r.prepareIngressBackendTLS(ctx, in)["web"]
			if state.reason != tc.reason {
				t.Fatalf("reason %q, want %q", state.reason, tc.reason)
			}
			if state.reason == "" {
				digest := sha256.Sum256([]byte(original.Data["root.pem"]))
				if state.sha256 != hex.EncodeToString(digest[:]) {
					t.Fatal("digest is not over raw source bytes")
				}
				if err := r.Delete(ctx, cm); err != nil {
					t.Fatal(err)
				}
				if got := r.prepareIngressBackendTLS(ctx, in)["web"]; got.reason != "BackendCAMissing" || got.sha256 != "" {
					t.Fatal("source deletion retained successful trust inspection")
				}
			}
		})
	}
}

func TestIngressBackendTLSStatusProof(t *testing.T) {
	for _, tc := range []struct {
		name   string
		change func(*ingressBackendTLSState, *ingressProbe)
		reason string
	}{
		{"valid", func(*ingressBackendTLSState, *ingressProbe) {}, ""},
		{"digest", func(_ *ingressBackendTLSState, p *ingressProbe) { p.BackendCAHash = "old" }, "BackendCAMismatch"},
		{"missing-source", func(s *ingressBackendTLSState, _ *ingressProbe) { s.reason = "BackendCAMissing" }, "BackendCAMissing"},
		{"invalid-source", func(s *ingressBackendTLSState, _ *ingressProbe) { s.reason = "BackendCAInvalid" }, "BackendCAInvalid"},
		{"no-source-proof", func(s *ingressBackendTLSState, _ *ingressProbe) { s.sha256 = "" }, "BackendCAMismatch"},
		{"tcp-only", func(_ *ingressBackendTLSState, p *ingressProbe) { p.BackendTLSNotAfter = nil }, "BackendTLSCertificateExpired"},
		{"stale", func(_ *ingressBackendTLSState, p *ingressProbe) { p.LastProbe = p.LastProbe.Add(-3 * time.Minute) }, "BackendTLSProbeStale"},
		{"future", func(_ *ingressBackendTLSState, p *ingressProbe) { p.LastProbe = p.LastProbe.Add(time.Minute) }, "BackendTLSProbeStale"},
		{"expired", func(_ *ingressBackendTLSState, p *ingressProbe) { v := p.LastProbe; p.BackendTLSNotAfter = &v }, "BackendTLSCertificateExpired"},
		{"wrong-owner", func(_ *ingressBackendTLSState, p *ingressProbe) { p.ConfigID = "other" }, "BackendTLSConfigMismatch"},
		{"failed-handshake", func(_ *ingressBackendTLSState, p *ingressProbe) {
			v := false
			p.BackendReachable = &v
			p.BackendCAHash, p.BackendTLSNotAfter = "", nil
		}, "BackendTLSVerificationFailed"},
		{"failed-handshake-diagnostic", func(_ *ingressBackendTLSState, p *ingressProbe) {
			v := false
			p.BackendReachable = &v
			p.BackendCAHash, p.BackendTLSNotAfter = "", nil
			p.BackendTLSReason = "BackendTLSVerificationFailed"
		}, "BackendTLSVerificationFailed"},
		{"unsafe-diagnostic", func(_ *ingressBackendTLSState, p *ingressProbe) {
			p.BackendCAHash, p.BackendTLSNotAfter = "", nil
			p.BackendTLSReason = "secret-sentinel"
		}, "BackendTLSVerificationFailed"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r, in, state, probes, now := ingressTLSStatusFixture(t)
			in.Spec.Exposes[0].Backend.TLS = backendTLSFixture()
			cm := backendCAFixture(t, in.Namespace, now)
			if err := r.Create(context.Background(), cm); err != nil {
				t.Fatal(err)
			}
			state.backends = r.prepareIngressBackendTLS(context.Background(), in)
			p := probes["web"]
			p.ConfigID = renderedIngressTargets(t, in, in.Namespace, state.plan)[0].ConfigID
			p.BackendCAHash = state.backends["web"].sha256
			expiry := now.Add(time.Hour)
			p.BackendTLSNotAfter = &expiry
			backend := state.backends["web"]
			tc.change(&backend, &p)
			state.backends["web"] = backend
			probes["web"] = p
			r.computeIngressStatus(in, state, probes, nil, now)
			want := tc.reason == ""
			if (condStatus(in.Status.Conditions, "BackendsReachable") == metav1.ConditionTrue) != want || in.Status.Exposes[0].Reachable != want ||
				(condStatus(in.Status.Conditions, "Ready") == metav1.ConditionTrue) != want {
				t.Fatal("backend verdict did not govern aggregate readiness")
			}
			if tc.reason != "" && meta.FindStatusCondition(in.Status.Conditions, "BackendsReachable").Reason != tc.reason {
				t.Fatalf("wrong bounded reason: %+v", in.Status.Conditions)
			}
			if tc.name != "wrong-owner" && tc.name != "stale" && tc.name != "future" && condStatus(in.Status.Conditions, "TLSReady") != metav1.ConditionTrue {
				t.Fatal("backend failure changed frontend TLS readiness")
			}
			encoded, _ := json.Marshal(in.Status)
			if strings.Contains(string(encoded), "secret-sentinel") {
				t.Fatal("unsafe backend diagnostic leaked")
			}
			invalidateIngressTLSObservation(in)
			if condStatus(in.Status.Conditions, "BackendsReachable") != metav1.ConditionFalse || in.Status.Exposes[0].Reachable {
				t.Fatal("early failure retained stale green backend")
			}
		})
	}
}

func TestIngressBackendCAWatch(t *testing.T) {
	a := tlsResourceIngress()
	a.Spec.Exposes[0].Backend.TLS = backendTLSFixture()
	b := a.DeepCopy()
	b.Name = "second"
	b.UID = "second"
	c := a.DeepCopy()
	c.Namespace = "backend-only"
	c.UID = "foreign"
	r := &TailnetIngressReconciler{Client: ingressTLSFakeClient(t, a, b, c)}
	keys := r.ingressesForBackendCA(context.Background(), &corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Name: "public-ca", Namespace: a.Namespace}})
	if !reflect.DeepEqual(keys, []types.NamespacedName{{Namespace: a.Namespace, Name: a.Name}, {Namespace: b.Namespace, Name: b.Name}}) {
		t.Fatalf("namespace-local CA watch: %+v", keys)
	}
}

func TestIngressBackendCARotationAndDeletionInvalidateProof(t *testing.T) {
	ctx := context.Background()
	r, in, state, probes, now := ingressTLSStatusFixture(t)
	in.Spec.Exposes[0].Backend.TLS = backendTLSFixture()
	cm := backendCAFixture(t, in.Namespace, now)
	if err := r.Create(ctx, cm); err != nil {
		t.Fatal(err)
	}
	beforeTargets := renderedIngressTargets(t, in, in.Namespace, state.plan)
	beforeDeployment := ingressAgentDeploymentTLS(in, &tnv1.Tailnet{}, in.Namespace, "override:old", nil, corev1.ResourceRequirements{}, state.plan)
	state.backends = r.prepareIngressBackendTLS(ctx, in)
	p := probes["web"]
	p.ConfigID = beforeTargets[0].ConfigID
	p.BackendCAHash = state.backends["web"].sha256
	expiry := now.Add(time.Hour)
	p.BackendTLSNotAfter = &expiry
	probes["web"] = p
	check := func(reason string) {
		t.Helper()
		state.backends = r.prepareIngressBackendTLS(ctx, in)
		r.computeIngressStatus(in, state, probes, nil, now)
		if got := condReason(in.Status.Conditions, "BackendsReachable"); got != reason {
			t.Fatalf("backend reason = %s, want %s", got, reason)
		}
		if condStatus(in.Status.Conditions, "TLSReady") != metav1.ConditionTrue {
			t.Fatal("backend trust source changed the independent frontend proof")
		}
		if (condStatus(in.Status.Conditions, "Ready") == metav1.ConditionTrue) != (reason == "AllReachable") {
			t.Fatal("source change left incorrect aggregate readiness")
		}
	}
	check("AllReachable")
	// Raw-byte changes, even whitespace, require the current projected digest, but
	// never restart the Pod or change the static listener/config identity.
	cm.Data["root.pem"] += "\n"
	if err := r.Update(ctx, cm); err != nil {
		t.Fatal(err)
	}
	check("BackendCAMismatch")
	if !reflect.DeepEqual(beforeTargets, renderedIngressTargets(t, in, in.Namespace, state.plan)) ||
		!reflect.DeepEqual(beforeDeployment, ingressAgentDeploymentTLS(in, &tnv1.Tailnet{}, in.Namespace, "override:old", nil, corev1.ResourceRequirements{}, state.plan)) {
		t.Fatal("CA rotation changed static configuration or Pod template")
	}
	p.BackendCAHash = state.backends["web"].sha256
	probes["web"] = p
	check("AllReachable")
	if err := r.Delete(ctx, cm); err != nil {
		t.Fatal(err)
	}
	check("BackendCAMissing")
	cm.ResourceVersion = ""
	cm.Data["root.pem"] = "malformed-new-source"
	if err := r.Create(ctx, cm); err != nil {
		t.Fatal(err)
	}
	check("BackendCAInvalid")
}
