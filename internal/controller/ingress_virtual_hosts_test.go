package controller

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"math/big"
	"reflect"
	"strings"
	"testing"
	"time"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/util/validation"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"

	tnv1 "tsunaro.io/tailnet-operator/api/v1alpha1"
)

func virtualIngress() (*tnv1.TailnetIngress, *tnv1.Tailnet) {
	in := tlsResourceIngress()
	in.Spec.TLS = &tnv1.IngressTLS{SecretName: "frontend"}
	in.Spec.Exposes[0].DNSLabel = "zeta"
	other := *in.Spec.Exposes[0].DeepCopy()
	other.Name, other.DNSLabel, other.Backend.Service = "second", "alpha", "second"
	in.Spec.Exposes = append(in.Spec.Exposes, other)
	return in, tlsTestTailnet()
}

func virtualSecret(t *testing.T, names []string, now time.Time) *corev1.Secret {
	t.Helper()
	secret, _ := ingressTestCertificate(t, &x509.Certificate{SerialNumber: big.NewInt(3), DNSNames: names,
		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}})
	secret.Name = "frontend"
	return secret
}

func TestIngressVirtualNamesWireAndCertificate(t *testing.T) {
	in, tn := virtualIngress()
	in.Status.DNSName = "stale.invalid"
	plan, reason := resolveIngressTLS(in, tn)
	if reason != "" {
		t.Fatal(reason)
	}
	want := []string{"app.tenant.tailnet.invalid", "alpha.tenant.tailnet.invalid", "zeta.tenant.tailnet.invalid"}
	if !reflect.DeepEqual(plan.names.certificateNames, want) {
		t.Fatal(plan.names)
	}
	cm, err := ingressExposesConfigMap(in, in.Namespace, plan)
	if err != nil {
		t.Fatal(err)
	}
	var wire struct {
		Version             int           `json:"version"`
		CertificateDNSNames []string      `json:"certificateDNSNames"`
		Targets             []agentTarget `json:"targets"`
	}
	if err := json.Unmarshal([]byte(cm.Data[targetsFile]), &wire); err != nil {
		t.Fatal(err)
	}
	if wire.Version != 3 || !reflect.DeepEqual(wire.CertificateDNSNames, want) || len(wire.Targets) != 3 {
		t.Fatal(wire)
	}
	for _, target := range wire.Targets {
		if target.Name == "ssh" {
			if target.Mode != "" || target.DNSName != "" {
				t.Fatal(target)
			}
			continue
		}
		if target.DNSName != plan.names.exposeNames[target.Name] || target.DNSName == want[0] || target.CertFile != "/tls/tls.crt" || target.KeyFile != "/tls/tls.key" || len(target.ConfigID) != 64 {
			t.Fatal(target)
		}
	}
	plan.issuer = &tnv1.TLSIssuerReference{Name: "ca", Kind: "Issuer", Group: "cert-manager.io"}
	cert := desiredIngressCertificate(in, plan)
	names, _, err := unstructured.NestedStringSlice(cert.Object, "spec", "dnsNames")
	if err != nil || !reflect.DeepEqual(names, want) {
		t.Fatalf("SAN union: %v %v", names, err)
	}
	if cert.GetNamespace() != in.Namespace || !metav1.IsControlledBy(cert, in) {
		t.Fatal("certificate ownership changed")
	}
	// Effective names must be distinct even when labels themselves are valid.
	tn.Spec.DNS.IngressNameTemplate = "fixed.example"
	if _, reason := resolveIngressTLS(in, tn); reason != "TLSInvalidDNSName" {
		t.Fatal(reason)
	}
}

func TestIngressVirtualCertificateCoverage(t *testing.T) {
	now := time.Unix(1800000000, 0)
	in, tn := virtualIngress()
	plan, _ := resolveIngressTLS(in, tn)
	names := plan.names.certificateNames
	for _, tc := range []struct {
		name    string
		sans    []string
		missing string
	}{
		{"all", names, ""},
		{"wildcard", []string{"*.tenant.tailnet.invalid"}, ""},
		{"missing-base", names[1:], names[0]},
		{"missing-extra", names[:2], names[2]},
		{"only-base", names[:1], names[1]},
		{"wrong-wildcard", []string{"*.tailnet.invalid", "secret-sentinel.invalid"}, names[0]},
	} {
		t.Run(tc.name, func(t *testing.T) {
			secret := virtualSecret(t, tc.sans, now)
			r := &TailnetIngressReconciler{Client: ingressTLSFakeClient(t, secret)}
			copy := in.DeepCopy()
			state := r.prepareIngressTLS(context.Background(), copy, tn, now)
			if tc.missing == "" {
				if state.reason != "" || state.leaf.sha256 == "" {
					t.Fatal(state.reason)
				}
			} else {
				if state.reason != "TLSNameMismatch" || state.uncoveredName != tc.missing || state.leaf.sha256 != "" {
					t.Fatal(state)
				}
				r.computeIngressStatus(copy, state, nil, nil, now)
				condition := meta.FindStatusCondition(copy.Status.Conditions, "TLSReady")
				if condition == nil || !strings.Contains(condition.Message, tc.missing) || strings.Contains(condition.Message, "secret-sentinel") {
					t.Fatal(condition)
				}
			}
		})
	}
}

func TestIngressVirtualVersionIntentAndWithdrawal(t *testing.T) {
	for _, mutate := range []func(*tnv1.TailnetIngress){
		func(in *tnv1.TailnetIngress) { in.Spec.Exposes[0].DNSLabel = "../invalid" },
		func(in *tnv1.TailnetIngress) { in.Spec.Exposes[1].DNSLabel = "l4-intent" },
		func(in *tnv1.TailnetIngress) { in.Spec.Exposes = append(in.Spec.Exposes, in.Spec.Exposes[0]) },
	} {
		in := tlsResourceIngress()
		mutate(in)
		if ingressConfigVersion(in) != 3 || ingressProtocolAnnotations(in)[ingressProtocolAnnotation] != "http-v3" {
			t.Fatal("invalid v3 intent downgraded")
		}
	}
	for _, l4 := range []bool{false, true} {
		in, tn := virtualIngress()
		if !l4 {
			in.Spec.Exposes = append(in.Spec.Exposes[:1], in.Spec.Exposes[2:]...)
		}
		plan, _ := resolveIngressTLS(in, tn)
		for _, sourceFailure := range []string{"TLSSecretMissing", "TLSNameMismatch", "TLSCertificateExpired"} {
			c := transitionClient(t)
			var config string
			c = interceptor.NewClient(c.(client.WithWatch), interceptor.Funcs{Create: func(ctx context.Context, c client.WithWatch, obj client.Object, opts ...client.CreateOption) error {
				if cm, ok := obj.(*corev1.ConfigMap); ok {
					config = cm.Data[targetsFile]
				}
				return c.Create(ctx, obj, opts...)
			}})
			r := &TailnetIngressReconciler{Client: c, Scheme: c.Scheme()}
			if err := r.applyChildren(context.Background(), in, tn, in.Namespace, "agent", ingressTLSState{plan: plan, reason: sourceFailure}); err != nil {
				t.Fatal(err)
			}
			var wire struct {
				Version             int
				CertificateDNSNames []string
				Targets             []agentTarget
			}
			if err := json.Unmarshal([]byte(config), &wire); err != nil {
				t.Fatal(err)
			}
			wantTargets := 0
			if l4 {
				wantTargets = 1
			}
			if wire.Version != 3 || wire.CertificateDNSNames == nil || len(wire.CertificateDNSNames) != 0 || wire.Targets == nil || len(wire.Targets) != wantTargets {
				t.Fatalf("invalid withdrawal: %s", config)
			}
		}
	}
}

func TestIngressVirtualBackendProjectionAndConfigIdentity(t *testing.T) {
	in, tn := virtualIngress()
	for _, i := range []int{0, 2} {
		in.Spec.Exposes[i].Backend.TLS = backendTLSFixture()
	}
	in.Spec.Exposes[2].Backend.TLS.CAConfigMapRef.Key = "second.pem"
	plan, _ := resolveIngressTLS(in, tn)
	dep := ingressAgentDeploymentTLS(in, tn, in.Namespace, "agent", nil, corev1.ResourceRequirements{}, plan)
	targets := renderedIngressTargets(t, in, in.Namespace, plan)
	volumes, mounts := map[string]corev1.Volume{}, map[string]corev1.VolumeMount{}
	for _, volume := range dep.Spec.Template.Spec.Volumes {
		if _, duplicate := volumes[volume.Name]; duplicate {
			t.Fatal("duplicate volume")
		}
		volumes[volume.Name] = volume
		if len(validation.IsDNS1123Label(volume.Name)) != 0 {
			t.Fatal(volume.Name)
		}
	}
	for _, mount := range dep.Spec.Template.Spec.Containers[0].VolumeMounts {
		if _, duplicate := mounts[mount.MountPath]; duplicate {
			t.Fatal("duplicate mount")
		}
		mounts[mount.MountPath] = mount
	}
	for _, i := range []int{0, 2} {
		e := in.Spec.Exposes[i]
		name, path := ingressBackendTLSProjection(in, e)
		volume, mount := volumes[name], mounts[path]
		if volume.ConfigMap == nil || volume.ConfigMap.Name != e.Backend.TLS.CAConfigMapRef.Name || volume.ConfigMap.Items[0].Key != e.Backend.TLS.CAConfigMapRef.Key || !*volume.ConfigMap.Optional || *volume.ConfigMap.DefaultMode != 0440 {
			t.Fatal(volume)
		}
		if !mount.ReadOnly || mount.SubPath != "" || mount.SubPathExpr != "" || targets[i].BackendCAFile != path+"/ca.crt" {
			t.Fatal(mount, targets[i])
		}
	}
	if targets[0].BackendCAFile == targets[2].BackendCAFile {
		t.Fatal("distinct references alias")
	}
	copy := in.DeepCopy()
	copy.Spec.Exposes[0], copy.Spec.Exposes[2] = copy.Spec.Exposes[2], copy.Spec.Exposes[0]
	reordered := renderedIngressTargets(t, copy, copy.Namespace, plan)
	if !reflect.DeepEqual(targets[0], reordered[2]) || !reflect.DeepEqual(targets[2], reordered[0]) {
		t.Fatal("reorder changed projection or target identity")
	}
	for _, mutate := range []func(*tnv1.TailnetIngress, *tnv1.Tailnet){
		func(in *tnv1.TailnetIngress, _ *tnv1.Tailnet) { in.Spec.Exposes[2].DNSLabel = "new-sibling" },
		func(_ *tnv1.TailnetIngress, tn *tnv1.Tailnet) { tn.Spec.DNS.IngressNameTemplate = "{name}.new.example" },
		func(in *tnv1.TailnetIngress, _ *tnv1.Tailnet) { in.Spec.TLS.SecretName = "new-secret" },
		func(in *tnv1.TailnetIngress, _ *tnv1.Tailnet) {
			in.Spec.Exposes[0].Backend.TLS.CAConfigMapRef.Name = "new-ca"
		},
	} {
		copy, net := in.DeepCopy(), tn.DeepCopy()
		mutate(copy, net)
		newPlan, reason := resolveIngressTLS(copy, net)
		if reason != "" {
			t.Fatal(reason)
		}
		if renderedIngressTargets(t, copy, copy.Namespace, newPlan)[0].ConfigID == targets[0].ConfigID {
			t.Fatal("resolved names/reference not bound to configID")
		}
	}
}

func TestIngressVirtualSiblingStatusAndRotations(t *testing.T) {
	ctx := context.Background()
	now := time.Unix(1800000000, 0)
	in, tn := virtualIngress()
	in.Status.NodeID = "node"
	in.Spec.Exposes[0].Backend.TLS = backendTLSFixture()
	plan, _ := resolveIngressTLS(in, tn)
	secret := virtualSecret(t, plan.names.certificateNames, now)
	r := &TailnetIngressReconciler{Client: ingressTLSFakeClient(t, secret)}
	state := r.prepareIngressTLS(ctx, in, tn, now)
	if state.reason != "" || state.backends["web"].reason != "BackendCAMissing" || ingressTransitionSourceReason(in, state) != "" {
		t.Fatal("backend material blocked bundle")
	}
	yes := true
	expiry := state.leaf.notAfter.Time
	probes := map[string]ingressProbe{"ssh": {Name: "ssh", Reachable: true, LastProbe: now}}
	for _, target := range renderedIngressTargets(t, in, in.Namespace, state.plan) {
		if target.Mode == "http" {
			probes[target.Name] = ingressProbe{Name: target.Name, ConfigID: target.ConfigID, BackendReachable: &yes, TLSReady: &yes, TLSCertSHA256: state.leaf.sha256, TLSNotAfter: &expiry, LastProbe: now}
		}
	}
	check := func() {
		t.Helper()
		r.computeIngressStatus(in, state, probes, nil, now)
		if condStatus(in.Status.Conditions, "Ready") != metav1.ConditionFalse || condStatus(in.Status.Conditions, "TLSReady") != metav1.ConditionTrue || in.Status.Exposes[0].Reachable || !in.Status.Exposes[2].Reachable {
			t.Fatal(in.Status)
		}
		for i, e := range in.Spec.Exposes {
			want := ""
			if e.Mode == "http" {
				want = plan.names.exposeNames[e.Name]
			}
			if in.Status.Exposes[i].DNSName != want {
				t.Fatal("per-expose DNS status", in.Status.Exposes)
			}
		}
	}
	check()
	bad := &corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Name: "public-ca", Namespace: in.Namespace}, Data: map[string]string{"root.pem": "not PEM"}}
	if err := r.Create(ctx, bad); err != nil {
		t.Fatal(err)
	}
	state = r.prepareIngressTLS(ctx, in, tn, now)
	check()
	if state.backends["web"].reason != "BackendCAInvalid" || ingressTransitionSourceReason(in, state) != "" {
		t.Fatal(state)
	}
	before := renderedIngressTargets(t, in, in.Namespace, state.plan)
	rotated := virtualSecret(t, []string{"*.tenant.tailnet.invalid"}, now)
	rotated.ResourceVersion = secret.ResourceVersion
	if err := r.Update(ctx, rotated); err != nil {
		t.Fatal(err)
	}
	state = r.prepareIngressTLS(ctx, in, tn, now)
	if !reflect.DeepEqual(before, renderedIngressTargets(t, in, in.Namespace, state.plan)) {
		t.Fatal("leaf bytes changed config")
	}
	r.computeIngressStatus(in, state, probes, nil, now)
	if condReason(in.Status.Conditions, "TLSReady") != "TLSCertificateMismatch" {
		t.Fatal("old leaf proof survived rotation")
	}
	for name, p := range probes {
		if p.TLSReady != nil {
			p.TLSCertSHA256 = state.leaf.sha256
			probes[name] = p
		}
	}
	check()
}

// The fake client exercises ordering/ownership, not API-server SSA or real Pod shutdown.
func TestIngressVirtualFreshAndTransitionBadCASibling(t *testing.T) {
	for _, scenario := range []struct {
		transition bool
		material   string
	}{
		{false, "missing"}, {false, "invalid"}, {false, "deleted"},
		{true, "missing"}, {true, "invalid"}, {true, "deleted"},
	} {
		transition := scenario.transition
		t.Run(map[bool]string{false: "fresh", true: "transition"}[transition]+"/"+scenario.material, func(t *testing.T) {
			ctx := context.Background()
			in, tn := virtualIngress()
			in.Spec.Exposes[0].Backend.TLS = backendTLSFixture()
			plan, _ := resolveIngressTLS(in, tn)
			var objects []client.Object
			c := transitionClient(t)
			if transition {
				old := in.DeepCopy()
				old.Spec.Exposes = old.Spec.Exposes[:2]
				old.Spec.Exposes[0].DNSLabel = ""
				dep := ingressAgentDeploymentTLS(old, tn, in.Namespace, "old", nil, corev1.ResourceRequirements{}, tlsTestPlan(old, "frontend"))
				zero := int32(0)
				dep.Spec.Replicas = &zero
				dep.Generation = 4
				dep.Status.ObservedGeneration = 4
				if err := controllerutil.SetControllerReference(in, dep, c.Scheme()); err != nil {
					t.Fatal(err)
				}
				objects = append(objects, dep)
			}
			objects = append(objects, virtualSecret(t, plan.names.certificateNames, time.Now()))
			ca := backendCAFixture(t, in.Namespace, time.Now())
			if scenario.material == "invalid" {
				ca.Data["root.pem"] = "invalid"
			}
			if scenario.material != "missing" {
				objects = append(objects, ca)
			}
			c = transitionClient(t, objects...)
			if scenario.material == "deleted" {
				if err := c.Delete(ctx, ca); err != nil {
					t.Fatal(err)
				}
			}
			var published string
			c = interceptor.NewClient(c.(client.WithWatch), interceptor.Funcs{
				Patch: func(ctx context.Context, c client.WithWatch, obj client.Object, patch client.Patch, opts ...client.PatchOption) error {
					if cm, ok := obj.(*corev1.ConfigMap); ok {
						published = cm.Data[targetsFile]
						return nil
					}
					if _, ok := obj.(*appsv1.Deployment); ok {
						if published == "" {
							t.Fatal("replicas restored before config")
						}
						return c.Patch(ctx, obj, patch, opts...)
					}
					return nil
				},
				Create: func(ctx context.Context, c client.WithWatch, obj client.Object, opts ...client.CreateOption) error {
					if cm, ok := obj.(*corev1.ConfigMap); ok {
						published = cm.Data[targetsFile]
					}
					if _, ok := obj.(*appsv1.Deployment); ok && published == "" {
						t.Fatal("created before config")
					}
					return c.Create(ctx, obj, opts...)
				},
			})
			r := &TailnetIngressReconciler{Client: c, Scheme: c.Scheme()}
			state := r.prepareIngressTLS(ctx, in, tn, time.Now())
			wantReason := "BackendCAMissing"
			if scenario.material == "invalid" {
				wantReason = "BackendCAInvalid"
			}
			if state.backends["web"].reason != wantReason || ingressTransitionSourceReason(in, state) != "" {
				t.Fatal("bad CA blocked siblings or was not inspected", state.backends)
			}
			if err := r.applyChildren(ctx, in, tn, in.Namespace, "agent", state); err != nil {
				t.Fatal(err)
			}
			var dep appsv1.Deployment
			if err := r.Get(ctx, client.ObjectKeyFromObject(in), &dep); err != nil {
				t.Fatal(err)
			}
			var wire struct{ Targets []agentTarget }
			if err := json.Unmarshal([]byte(published), &wire); err != nil {
				t.Fatal(err)
			}
			if *dep.Spec.Replicas != 1 || len(wire.Targets) != 3 || wire.Targets[0].BackendCAFile == "" || wire.Targets[2].DNSName == "" {
				t.Fatal("bundle suppressed", wire)
			}
		})
	}
}
