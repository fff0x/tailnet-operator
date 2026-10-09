package controller

import (
	"encoding/json"
	"reflect"
	"testing"

	corev1 "k8s.io/api/core/v1"

	tnv1 "tsunaro.io/tailnet-operator/api/v1alpha1"
)

func tlsTestTailnet() *tnv1.Tailnet {
	tn := &tnv1.Tailnet{}
	tn.Spec.DNS.IngressNameTemplate = "{name}.{namespace}.tailnet.invalid"
	return tn
}

func tlsTestPlan(in *tnv1.TailnetIngress, secret string) ingressTLSPlan {
	names, _ := resolveIngressDNSNames(in, tlsTestTailnet())
	return ingressTLSPlan{http: true, secretName: secret, names: names}
}

func tlsResourceIngress() *tnv1.TailnetIngress {
	in := tlsIngress()
	in.UID, in.Generation = "ingress-uid", 3
	in.Spec.Exposes[0].Backend.Namespace = "backend-only"
	in.Spec.Exposes = append(in.Spec.Exposes, tnv1.Expose{Name: "ssh", Port: 22,
		Backend: tnv1.Backend{Service: "ssh", Port: 2222}})
	return in
}

func renderedIngressTargets(t *testing.T, in *tnv1.TailnetIngress, ns string, plan ingressTLSPlan) []agentTarget {
	t.Helper()
	cm, err := ingressExposesConfigMap(in, ns, plan)
	if err != nil {
		t.Fatal(err)
	}
	var targets []agentTarget
	if ingressConfigVersion(in) > 0 {
		var envelope struct {
			Version int           `json:"version"`
			Targets []agentTarget `json:"targets"`
		}
		if err := json.Unmarshal([]byte(cm.Data[targetsFile]), &envelope); err != nil || envelope.Version != ingressConfigVersion(in) || envelope.Targets == nil {
			t.Fatal("invalid HTTP config envelope")
		}
		return envelope.Targets
	}
	if err := json.Unmarshal([]byte(cm.Data[targetsFile]), &targets); err != nil {
		t.Fatal(err)
	}
	return targets
}

func TestIngressTLSResources(t *testing.T) {
	in, tn := tlsResourceIngress(), &tnv1.Tailnet{}
	before := in.DeepCopy()
	plan := tlsTestPlan(in, "external-tls")
	targets := renderedIngressTargets(t, in, in.Namespace, plan)
	if len(targets) != 2 || targets[0].Mode != "http" || targets[0].ListenPort != 443 ||
		targets[0].Address != "app.backend-only.svc.cluster.local" || targets[0].Port != 8080 ||
		targets[0].DNSName != in.Status.DNSName || targets[0].CertFile != "/tls/tls.crt" ||
		targets[0].KeyFile != "/tls/tls.key" || len(targets[0].ConfigID) != 64 {
		t.Fatalf("incorrect HTTP projection: %+v", targets)
	}
	if targets[1].Mode != "" || targets[1].CertFile != "" || targets[1].ConfigID != "" {
		t.Fatal("L4 inherited TLS configuration")
	}
	dep := ingressAgentDeploymentTLS(in, tn, in.Namespace, "operator:test", nil, corev1.ResourceRequirements{}, plan)
	pod := dep.Spec.Template.Spec
	if dep.Spec.Template.Annotations["tsunaro.io/agent-config-protocol"] != "http-v1" || dep.Spec.Strategy.Type != "Recreate" {
		t.Fatal("HTTP protocol transition must retire legacy listeners")
	}
	plain := in.DeepCopy()
	plain.Spec.Exposes[0].Mode = "l4"
	if ann := ingressAgentDeployment(plain, tn, plain.Namespace, "operator:test", nil, corev1.ResourceRequirements{}).Spec.Template.Annotations; ann[ingressProtocolAnnotation] != "" || len(ann) != 1 {
		t.Fatal("L4-only configuration must carry no protocol marker, only the tag binding")
	}
	if dep.Namespace != in.Namespace || pod.SecurityContext.FSGroup == nil || *pod.SecurityContext.FSGroup != 65532 {
		t.Fatal("TLS Secret must remain in the ingress namespace and readable by the nonroot agent")
	}
	var tlsVolume *corev1.SecretVolumeSource
	for _, v := range pod.Volumes {
		if v.Name == "tls" {
			tlsVolume = v.Secret
		}
	}
	if tlsVolume == nil || tlsVolume.SecretName != plan.secretName || tlsVolume.Optional == nil || !*tlsVolume.Optional ||
		tlsVolume.DefaultMode == nil || *tlsVolume.DefaultMode != 0440 || len(tlsVolume.Items) != 2 {
		t.Fatal("incorrect TLS Secret projection")
	}
	if !reflect.DeepEqual(tlsVolume.Items, []corev1.KeyToPath{{Key: "tls.crt", Path: "tls.crt"}, {Key: "tls.key", Path: "tls.key"}}) {
		t.Fatal("projection includes unrelated Secret keys")
	}
	found := false
	for _, mount := range pod.Containers[0].VolumeMounts {
		if mount.Name == "tls" {
			found = mount.ReadOnly && mount.MountPath == "/tls" && mount.SubPath == "" && mount.SubPathExpr == ""
		}
	}
	if !found || !reflect.DeepEqual(in, before) {
		t.Fatal("missing read-only rotatable projection, or input mutated")
	}

	// Observed Secret metadata and certificate rotations must not restart the Pod or listener.
	rotated := in.DeepCopy()
	rotated.ResourceVersion = "next"
	rotated.Status.TLSSecretName = "changed-observation"
	if got := ingressAgentDeploymentTLS(rotated, tn, in.Namespace, "operator:test", nil, corev1.ResourceRequirements{}, plan); !reflect.DeepEqual(dep, got) {
		t.Fatal("observed certificate status changed the Pod template")
	}
	if got := renderedIngressTargets(t, rotated, in.Namespace, plan); !reflect.DeepEqual(targets, got) {
		t.Fatal("observed certificate status changed targets")
	}
}

func TestIngressHTTPNeverFallsBackToL4(t *testing.T) {
	for _, tc := range []struct {
		name   string
		change func(*tnv1.TailnetIngress, *ingressTLSPlan, *string)
	}{
		{"no-plan", func(_ *tnv1.TailnetIngress, p *ingressTLSPlan, _ *string) { *p = ingressTLSPlan{} }},
		{"missing-secret", func(_ *tnv1.TailnetIngress, p *ingressTLSPlan, _ *string) { p.secretName = "" }},
		{"invalid-secret", func(_ *tnv1.TailnetIngress, p *ingressTLSPlan, _ *string) { p.secretName = "../secret" }},
		{"no-uid", func(in *tnv1.TailnetIngress, _ *ingressTLSPlan, _ *string) { in.UID = "" }},
		{"unresolved-names", func(_ *tnv1.TailnetIngress, p *ingressTLSPlan, _ *string) { p.names = ingressDNSPlan{} }},
		{"wrong-namespace", func(_ *tnv1.TailnetIngress, _ *ingressTLSPlan, ns *string) { *ns = "foreign" }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			in := tlsResourceIngress()
			plan, ns := tlsTestPlan(in, "external-tls"), in.Namespace
			tc.change(in, &plan, &ns)
			got := renderedIngressTargets(t, in, ns, plan)
			if len(got) != 1 || got[0].Name != "ssh" || got[0].Mode != "" {
				t.Fatalf("HTTP not withdrawn independently of L4: %+v", got)
			}
			dep := ingressAgentDeploymentTLS(in, &tnv1.Tailnet{}, ns, "operator:test", nil, corev1.ResourceRequirements{}, plan)
			for _, v := range dep.Spec.Template.Spec.Volumes {
				if v.Name == "tls" {
					t.Fatal("invalid configuration projected a Secret")
				}
			}
		})
	}
	in := tlsResourceIngress()
	cm, err := exposesConfigMap(in, in.Namespace)
	if err != nil {
		t.Fatal(err)
	}
	var got []agentTarget
	if json.Unmarshal([]byte(cm.Data[targetsFile]), &got) == nil {
		t.Fatal("old agent could consume HTTP configuration as plaintext targets")
	}
	got = renderedIngressTargets(t, in, in.Namespace, ingressTLSPlan{})
	if len(got) != 1 || got[0].Name != "ssh" {
		t.Fatal("unresolved HTTP source affected the L4 target")
	}
}

func TestIngressAmbiguousExposesWithdrawAllListeners(t *testing.T) {
	for _, change := range []func(*tnv1.TailnetIngress){
		func(in *tnv1.TailnetIngress) { in.Spec.Exposes[1].Port = 443 },
		func(in *tnv1.TailnetIngress) { in.Spec.Exposes[1].Name = "web" },
		func(in *tnv1.TailnetIngress) { in.Spec.Exposes[0].Mode = "unknown" },
		func(in *tnv1.TailnetIngress) { in.Spec.Exposes[0].Port = 8443 },
		func(in *tnv1.TailnetIngress) { in.Spec.Exposes[0].Backend.Service = "bad/service" },
	} {
		in := tlsResourceIngress()
		change(in)
		plan := tlsTestPlan(in, "external-tls")
		if got := renderedIngressTargets(t, in, in.Namespace, plan); len(got) != 0 {
			t.Fatalf("ambiguous listeners retained: %+v", got)
		}
	}
}

func TestIngressHTTPConfigIdentity(t *testing.T) {
	in := tlsResourceIngress()
	plan := tlsTestPlan(in, "external-tls")
	base := renderedIngressTargets(t, in, in.Namespace, plan)[0].ConfigID
	for _, change := range []func(*tnv1.TailnetIngress, *ingressTLSPlan){
		func(in *tnv1.TailnetIngress, _ *ingressTLSPlan) { in.UID = "recreated" },
		func(in *tnv1.TailnetIngress, _ *ingressTLSPlan) { in.Generation++ },
		func(_ *tnv1.TailnetIngress, p *ingressTLSPlan) {
			p.names = ingressDNSPlan{baseName: "new.tailnet.invalid", exposeNames: map[string]string{"web": "new.tailnet.invalid"}, certificateNames: []string{"new.tailnet.invalid"}}
		},
		func(in *tnv1.TailnetIngress, _ *ingressTLSPlan) { in.Spec.Exposes[0].Backend.Port++ },
		func(_ *tnv1.TailnetIngress, p *ingressTLSPlan) { p.secretName = "new-secret" },
		func(_ *tnv1.TailnetIngress, p *ingressTLSPlan) {
			p.issuer = &tnv1.TLSIssuerReference{Name: "new-issuer"}
		},
	} {
		copy, p := in.DeepCopy(), plan
		change(copy, &p)
		if got := renderedIngressTargets(t, copy, copy.Namespace, p)[0].ConfigID; got == base {
			t.Fatal("changed configuration retained an old probe identity")
		}
	}
}
