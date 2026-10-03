package controller

import (
	"context"
	"encoding/json"
	"reflect"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"

	tnv1 "tsunaro.io/tailnet-operator/api/v1alpha1"
)

func TestIngressVirtualResolvedRetirementBeforeMissingKey(t *testing.T) {
	for _, tc := range []struct {
		name   string
		mutate func(*tnv1.TailnetIngress, *tnv1.Tailnet)
		retire bool
	}{
		{"name-template", func(_ *tnv1.TailnetIngress, tn *tnv1.Tailnet) { tn.Spec.DNS.IngressNameTemplate = "{name}.new.example" }, true},
		{"invalid-template", func(_ *tnv1.TailnetIngress, tn *tnv1.Tailnet) { tn.Spec.DNS.IngressNameTemplate = "*.invalid" }, true},
		{"removed-template", func(_ *tnv1.TailnetIngress, tn *tnv1.Tailnet) { tn.Spec.DNS.IngressNameTemplate = "" }, true},
		{"issuer-default", func(in *tnv1.TailnetIngress, tn *tnv1.Tailnet) {
			in.Spec.TLS = nil
			tn.Spec.Defaults.TLS.IssuerRef.Name = "new-ca"
		}, true},
		{"invalid-default", func(in *tnv1.TailnetIngress, tn *tnv1.Tailnet) {
			in.Spec.TLS = nil
			tn.Spec.Defaults.TLS.IssuerRef.Group = "unsupported"
		}, true},
		{"missing-default", func(in *tnv1.TailnetIngress, tn *tnv1.Tailnet) { in.Spec.TLS = nil; tn.Spec.Defaults.TLS = nil }, true},
		{"control-server", func(_ *tnv1.TailnetIngress, tn *tnv1.Tailnet) { tn.Spec.Server = "https://new.example" }, true},
		{"tailnet-recreated", func(_ *tnv1.TailnetIngress, tn *tnv1.Tailnet) { tn.UID = "new-tailnet" }, true},
		{"hostname-template", func(in *tnv1.TailnetIngress, tn *tnv1.Tailnet) {
			in.Spec.Hostname = ""
			tn.Spec.IngressHostnameTemplate = "new-{name}"
		}, true},
		{"tag-template", func(in *tnv1.TailnetIngress, tn *tnv1.Tailnet) {
			in.Spec.Tag = ""
			tn.Spec.IngressTagTemplate = "tag:new-{name}"
		}, true},
		{"overridden-default", func(_ *tnv1.TailnetIngress, tn *tnv1.Tailnet) { tn.Spec.Defaults.TLS.IssuerRef.Name = "irrelevant" }, false},
		{"overridden-hostname", func(_ *tnv1.TailnetIngress, tn *tnv1.Tailnet) { tn.Spec.IngressHostnameTemplate = "irrelevant-{name}" }, false},
		{"unrelated-image", func(_ *tnv1.TailnetIngress, tn *tnv1.Tailnet) { tn.Spec.Proxy.Image = "another-image" }, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()
			in, tn := virtualIngress()
			in.Spec.TailnetRef.Name, in.Spec.Tag, in.Spec.Hostname = "corp", "tag:app", "app"
			tn.Name, tn.UID = "corp", "original-tailnet"
			tn.Spec.Server = "https://old.example"
			tn.Spec.IngressTagTemplate, tn.Spec.IngressHostnameTemplate = "tag:{name}", "{name}"
			tn.Spec.Defaults.TLS = &tnv1.TLSDefaults{IssuerRef: &tnv1.TLSIssuerReference{Name: "ca"}}
			// Set explicit overrides before capturing the predecessor. The mutation
			// below then changes only the effective Tailnet source, not the CR spec.
			if tc.name == "issuer-default" || tc.name == "invalid-default" || tc.name == "missing-default" {
				in.Spec.TLS = nil
			}
			if tc.name == "hostname-template" {
				in.Spec.Hostname = ""
			}
			if tc.name == "tag-template" {
				in.Spec.Tag = ""
			}
			plan, reason := resolveIngressTLS(in, tn)
			if reason != "" {
				t.Fatal(reason)
			}
			dep := ingressAgentDeploymentTLS(in, tn, in.Namespace, "agent", nil, corev1.ResourceRequirements{}, plan)
			dep.UID, dep.Generation = "deployment", 4
			dep.Status.ObservedGeneration, dep.Status.Replicas = 4, 1
			c := transitionClient(t)
			if err := controllerutil.SetControllerReference(in, dep, c.Scheme()); err != nil {
				t.Fatal(err)
			}
			pod := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "old", Namespace: in.Namespace, Labels: ingressSelectorLabels(in.Name)}, Status: corev1.PodStatus{Phase: corev1.PodSucceeded}}
			tc.mutate(in, tn)
			c = transitionClient(t, in, tn, dep, pod)
			r := &TailnetIngressReconciler{Client: c, Scheme: c.Scheme(), OperatorNamespace: "operator"}
			before := transitionDeployment(t, r, in)
			if _, reason := transitionReconcile(t, r, in); tc.retire {
				if reason != "HTTPTransitionPending" {
					t.Fatal(reason)
				}
				got := transitionDeployment(t, r, in)
				if *got.Spec.Replicas != 0 || !reflect.DeepEqual(got.Spec.Template, before.Spec.Template) {
					t.Fatal("changed marker before retirement")
				}
				transitionAcknowledgeScale(t, r, in)
				if _, reason := transitionReconcile(t, r, in); reason != "HTTPTransitionPending" {
					t.Fatal("terminal/colliding Pod skipped", reason)
				}
				if err := r.Delete(ctx, pod); err != nil {
					t.Fatal(err)
				}
				if _, reason := transitionReconcile(t, r, in); reason != "NoAPIKey" {
					t.Fatal(reason)
				}
				if *transitionDeployment(t, r, in).Spec.Replicas != 0 {
					t.Fatal("missing dependency restarted predecessor")
				}
			} else {
				if reason != "NoAPIKey" || !reflect.DeepEqual(transitionDeployment(t, r, in).Spec.Template, before.Spec.Template) || *transitionDeployment(t, r, in).Spec.Replicas != 1 {
					t.Fatal("irrelevant source retired process", reason)
				}
			}
		})
	}
}

func TestIngressVirtualResolvedGuardIgnoresMaterial(t *testing.T) {
	ctx := context.Background()
	in, tn := virtualIngress()
	in.Spec.TailnetRef.Name = "corp"
	tn.Name = "corp"
	in.Spec.Exposes[0].Backend.TLS = backendTLSFixture()
	plan, _ := resolveIngressTLS(in, tn)
	dep := ingressAgentDeploymentTLS(in, tn, in.Namespace, "agent", nil, corev1.ResourceRequirements{}, plan)
	c := transitionClient(t)
	if err := controllerutil.SetControllerReference(in, dep, c.Scheme()); err != nil {
		t.Fatal(err)
	}
	ca := backendCAFixture(t, in.Namespace, time.Now())
	c = transitionClient(t, in, tn, dep, ca)
	r := &TailnetIngressReconciler{Client: c, Scheme: c.Scheme(), OperatorNamespace: "operator"}
	for _, action := range []string{"initial", "rotated", "invalid", "deleted"} {
		switch action {
		case "rotated":
			ca.Data["root.pem"] += "\n"
			if err := r.Update(ctx, ca); err != nil {
				t.Fatal(err)
			}
		case "invalid":
			ca.Data["root.pem"] = "invalid"
			if err := r.Update(ctx, ca); err != nil {
				t.Fatal(err)
			}
		case "deleted":
			if err := r.Delete(ctx, ca); err != nil {
				t.Fatal(err)
			}
		}
		if _, reason := transitionReconcile(t, r, in); reason != "NoAPIKey" || *transitionDeployment(t, r, in).Spec.Replicas != 1 {
			t.Fatal("CA bytes retired listener", action, reason)
		}
	}
}

func TestIngressVirtualEntryUpdateAndExits(t *testing.T) {
	for _, next := range []string{"v3-entry", "v3-update", "v1", "l4"} {
		t.Run(next, func(t *testing.T) {
			ctx := context.Background()
			in, tn := virtualIngress()
			old := in.DeepCopy()
			if next == "v3-entry" {
				old.Spec.Exposes = old.Spec.Exposes[:2]
				old.Spec.Exposes[0].DNSLabel = ""
			}
			plan, _ := resolveIngressTLS(old, tn)
			dep := ingressAgentDeploymentTLS(old, tn, old.Namespace, "agent", nil, corev1.ResourceRequirements{}, plan)
			dep.UID, dep.Generation = "old-deployment", 3
			dep.Status.ObservedGeneration, dep.Status.Replicas = 3, 1
			c := transitionClient(t)
			if err := controllerutil.SetControllerReference(in, dep, c.Scheme()); err != nil {
				t.Fatal(err)
			}
			switch next {
			case "v3-update":
				in.Spec.Exposes[2].Backend.Service = "updated"
			case "v1":
				in.Spec.Exposes = in.Spec.Exposes[:2]
				in.Spec.Exposes[0].DNSLabel = ""
			case "l4":
				in.Spec.Exposes = in.Spec.Exposes[1:2]
				in.Spec.TLS = nil
			}
			pod := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "old", Namespace: in.Namespace, Labels: ingressSelectorLabels(in.Name)}}
			c = transitionClient(t, in, dep, pod)
			r := &TailnetIngressReconciler{Client: c, Scheme: c.Scheme()}
			before := transitionDeployment(t, r, in)
			if _, reason := transitionReconcile(t, r, in); reason != "HTTPTransitionPending" {
				t.Fatal(reason)
			}
			if !reflect.DeepEqual(before.Spec.Template, transitionDeployment(t, r, in).Spec.Template) {
				t.Fatal("premature marker change")
			}
			transitionAcknowledgeScale(t, r, in)
			if _, reason := transitionReconcile(t, r, in); reason != "HTTPTransitionPending" {
				t.Fatal("surviving Pod bypassed", reason)
			}
			if err := r.Delete(ctx, pod); err != nil {
				t.Fatal(err)
			}
			if _, reason := transitionReconcile(t, r, in); reason != "NoTailnet" {
				t.Fatal(reason)
			}
			plan, reason := resolveIngressTLS(in, tn)
			if reason != "" {
				t.Fatal(reason)
			}
			if err := r.applyChildren(ctx, in, tn, in.Namespace, "new-agent", ingressTLSState{plan: plan}, true); err != nil {
				t.Fatal(err)
			}
			got := transitionDeployment(t, r, in)
			if *got.Spec.Replicas != 1 || !ingressHTTPMarkersMatch(got.Spec.Template.Annotations, ingressProtocolAnnotations(in), false) {
				t.Fatal("failed recovery", got.Spec.Template.Annotations)
			}
			if ingressConfigVersion(in) == 0 && got.Spec.Template.Annotations[ingressHTTPSourceAnnotation] != "" {
				t.Fatal("exit retained old source marker")
			}
		})
	}
}

func TestIngressDeploymentSnapshotFencesMatchingReplacement(t *testing.T) {
	ctx := context.Background()
	for _, change := range []string{"replace", "update", "disappear"} {
		t.Run(change, func(t *testing.T) {
			in, tn := virtualIngress()
			plan, _ := resolveIngressTLS(in, tn)
			dep := ingressAgentDeploymentTLS(in, tn, in.Namespace, "agent", nil, corev1.ResourceRequirements{}, plan)
			dep.UID = "original"
			c := transitionClient(t)
			if err := controllerutil.SetControllerReference(in, dep, c.Scheme()); err != nil {
				t.Fatal(err)
			}
			c = transitionClient(t, dep)
			r := &TailnetIngressReconciler{Client: c, Scheme: c.Scheme()}
			observed, err := r.ingressHTTPDeploymentSnapshot(ctx, in, false)
			if err != nil {
				t.Fatal(err)
			}
			current := observed.DeepCopy()
			if change == "update" {
				current.Labels["test.example/concurrent"] = "changed"
				if err := r.Update(ctx, current); err != nil {
					t.Fatal(err)
				}
			} else {
				if err := r.Delete(ctx, current); err != nil {
					t.Fatal(err)
				}
				if change == "replace" {
					current.ResourceVersion, current.UID = "", "replacement"
					if err := r.Create(ctx, current); err != nil {
						t.Fatal(err)
					}
				}
			}
			if err := r.applyExtendedIngressDeployment(ctx, in, dep.DeepCopy(), observed); err != errIngressTransitionChanged {
				t.Fatalf("matching markers bypassed snapshot: %v", err)
			}
		})
	}
}

func TestIngressHTTPCompanionOwnership(t *testing.T) {
	ctx := context.Background()
	in, _ := virtualIngress()
	for _, race := range []string{"foreign", "replace", "create"} {
		t.Run(race, func(t *testing.T) {
			cm, err := ingressExposesConfigMap(in, in.Namespace, tlsTestPlan(in, "frontend"))
			if err != nil {
				t.Fatal(err)
			}
			c := transitionClient(t)
			if err := controllerutil.SetControllerReference(in, cm, c.Scheme()); err != nil {
				t.Fatal(err)
			}
			current := cm.DeepCopy()
			current.UID = "old-uid"
			if race == "foreign" {
				current.OwnerReferences[0].UID = "foreign"
			}
			if race != "create" {
				if err := c.Create(ctx, current); err != nil {
					t.Fatal(err)
				}
			}
			c = interceptor.NewClient(c.(client.WithWatch), interceptor.Funcs{
				Patch: func(ctx context.Context, c client.WithWatch, obj client.Object, patch client.Patch, opts ...client.PatchOption) error {
					if obj.GetUID() != current.UID || obj.GetResourceVersion() == "" {
						t.Fatal("unfenced companion write")
					}
					if err := c.Delete(ctx, current); err != nil {
						t.Fatal(err)
					}
					current.UID, current.ResourceVersion, current.OwnerReferences[0].UID = "new-uid", "", "foreign"
					if err := c.Create(ctx, current); err != nil {
						t.Fatal(err)
					}
					// Unlike the API server, the fake resets RV to 1 on recreation
					// and does not enforce immutable ConfigMap UIDs. Advance its RV;
					// above we separately assert that both preconditions were sent.
					if err := c.Update(ctx, current); err != nil {
						t.Fatal(err)
					}
					return c.Patch(ctx, obj, patch, opts...)
				},
				Create: func(ctx context.Context, c client.WithWatch, obj client.Object, opts ...client.CreateOption) error {
					current.ResourceVersion, current.OwnerReferences[0].UID = "", "foreign"
					if err := c.Create(ctx, current); err != nil {
						t.Fatal(err)
					}
					return c.Create(ctx, obj, opts...)
				},
			})
			r := &TailnetIngressReconciler{Client: c, Scheme: c.Scheme()}
			if err := r.applyIngressHTTPChild(ctx, in, cm); err == nil {
				t.Fatal("adopted companion collision", race)
			}
		})
	}
}

func TestIngressV1ResolvedNameChangeRetiresBeforeKey(t *testing.T) {
	in := tlsResourceIngress()
	in.Spec.TLS = &tnv1.IngressTLS{SecretName: "frontend"}
	in.Spec.TailnetRef.Name = "corp"
	tn := tlsTestTailnet()
	tn.Name = "corp"
	plan, reason := resolveIngressTLS(in, tn)
	if reason != "" {
		t.Fatal(reason)
	}
	dep := ingressAgentDeploymentTLS(in, tn, in.Namespace, "agent", nil, corev1.ResourceRequirements{}, plan)
	c := transitionClient(t)
	if err := controllerutil.SetControllerReference(in, dep, c.Scheme()); err != nil {
		t.Fatal(err)
	}
	tn.Spec.DNS.IngressNameTemplate = "{name}.new.example"
	c = transitionClient(t, in, tn, dep)
	r := &TailnetIngressReconciler{Client: c, Scheme: c.Scheme()}
	if _, reason := transitionReconcile(t, r, in); reason != "HTTPTransitionPending" || *transitionDeployment(t, r, in).Spec.Replicas != 0 {
		t.Fatal(reason)
	}
	if ingressConfigVersion(in) != 1 {
		t.Fatal("ordinary HTTP wire compatibility changed")
	}
}

func TestIngressVirtualExitWriteRaces(t *testing.T) {
	for _, race := range []string{"foreign-before-apply", "owned-running-replacement", "uid-rv-at-patch"} {
		t.Run(race, func(t *testing.T) {
			ctx := context.Background()
			in, tn := virtualIngress()
			plan, _ := resolveIngressTLS(in, tn)
			dep := ingressAgentDeploymentTLS(in, tn, in.Namespace, "old", nil, corev1.ResourceRequirements{}, plan)
			zero := int32(0)
			dep.Spec.Replicas = &zero
			dep.UID, dep.Generation, dep.Status.ObservedGeneration = "old-uid", 4, 4
			c := transitionClient(t)
			if err := controllerutil.SetControllerReference(in, dep, c.Scheme()); err != nil {
				t.Fatal(err)
			}
			c = transitionClient(t, dep)
			r := &TailnetIngressReconciler{Client: c, Scheme: c.Scheme()}
			in.Spec.Exposes = in.Spec.Exposes[1:2]
			in.Spec.TLS = nil
			if transition, waiting, err := r.retireIngressHTTPPredecessor(ctx, in); err != nil || !transition || waiting {
				t.Fatal(transition, waiting, err)
			}
			desired := ingressAgentDeploymentTLS(in, tn, in.Namespace, "new", nil, corev1.ResourceRequirements{}, ingressTLSPlan{})
			if err := controllerutil.SetControllerReference(in, desired, c.Scheme()); err != nil {
				t.Fatal(err)
			}
			current := transitionDeployment(t, r, in)
			if race == "foreign-before-apply" {
				current.OwnerReferences[0].UID = "foreign"
				if err := r.Update(ctx, current); err != nil {
					t.Fatal(err)
				}
			} else if race == "owned-running-replacement" {
				if err := r.Delete(ctx, current); err != nil {
					t.Fatal(err)
				}
				replacement := desired.DeepCopy()
				replacement.UID = "new-uid"
				if err := r.Create(ctx, replacement); err != nil {
					t.Fatal(err)
				}
			} else {
				r.Client = interceptor.NewClient(c.(client.WithWatch), interceptor.Funcs{Patch: func(ctx context.Context, c client.WithWatch, obj client.Object, patch client.Patch, opts ...client.PatchOption) error {
					data, err := patch.Data(obj)
					if err != nil {
						t.Fatal(err)
					}
					var body struct {
						Metadata struct{ UID, ResourceVersion string }
					}
					if err := json.Unmarshal(data, &body); err != nil || body.Metadata.UID != "old-uid" || body.Metadata.ResourceVersion == "" {
						t.Fatal("missing exit UID/RV fence", string(data))
					}
					if err := c.Delete(ctx, current); err != nil {
						t.Fatal(err)
					}
					replacement := current.DeepCopy()
					replacement.UID, replacement.ResourceVersion = "new-uid", ""
					replacement.OwnerReferences[0].UID = "foreign"
					if err := c.Create(ctx, replacement); err != nil {
						t.Fatal(err)
					}
					return c.Patch(ctx, obj, patch, opts...)
				}})
			}
			if err := r.applyExtendedIngressDeployment(ctx, in, desired); err == nil {
				t.Fatal("exit adopted/restarted a replacement")
			}
		})
	}
}
