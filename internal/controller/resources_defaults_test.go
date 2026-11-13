package controller

import (
	"context"
	"encoding/json"
	"reflect"
	"testing"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"

	tnv1 "tsunaro.io/tailnet-operator/api/v1alpha1"
)

func resourceBlock(t *testing.T, raw string) corev1.ResourceRequirements {
	t.Helper()
	var result corev1.ResourceRequirements
	if err := json.Unmarshal([]byte(raw), &result); err != nil {
		t.Fatal(err)
	}
	return result
}

func TestAgentDeploymentResources(t *testing.T) {
	defaults := `{"requests":{"cpu":"10m","memory":"32Mi"},"limits":{"memory":"128Mi"}}`
	for _, tc := range []struct{ name, cr, tailnet, defaults, want string }{
		{"binary zero", `{}`, `{}`, `{}`, `{}`},
		{"chart defaults", `{}`, `{}`, defaults, defaults},
		{"null maps fall through", `{"requests":null,"limits":null}`, `{}`, defaults, defaults},
		{"tailnet whole block", `{}`, `{"requests":{"cpu":"20m"}}`, defaults, `{"requests":{"cpu":"20m"}}`},
		{"CR whole block", `{"limits":{"cpu":"1"}}`, `{"requests":{"memory":"64Mi"}}`, defaults, `{"limits":{"cpu":"1"}}`},
		{"CR requests only", `{"requests":{"cpu":"30m"}}`, `{"limits":{"memory":"256Mi"}}`, defaults, `{"requests":{"cpu":"30m"}}`},
		{"tailnet limits only", `{}`, `{"limits":{"cpu":"1"}}`, defaults, `{"limits":{"cpu":"1"}}`},
		{"CR empty requests selects", `{"requests":{}}`, `{"limits":{"cpu":"1"}}`, defaults, `{"requests":{}}`},
		{"CR empty limits selects", `{"limits":{}}`, `{"limits":{"cpu":"1"}}`, defaults, `{"limits":{}}`},
		{"tailnet empty requests selects", `{}`, `{"requests":{}}`, defaults, `{"requests":{}}`},
		{"tailnet empty limits selects", `{}`, `{"limits":{}}`, defaults, `{"limits":{}}`},
		{"explicit zero selects", `{"requests":{"cpu":"0"}}`, `{}`, defaults, `{"requests":{"cpu":"0"}}`},
	} {
		for _, builder := range []string{"egress", "ingress", "ingress TLS"} {
			t.Run(builder+"/"+tc.name, func(t *testing.T) {
				cr, tn, def := resourceBlock(t, tc.cr), &tnv1.Tailnet{}, resourceBlock(t, tc.defaults)
				tn.Spec.Proxy.Resources = resourceBlock(t, tc.tailnet)
				beforeCR, beforeTN, beforeDef := cr.DeepCopy(), tn.DeepCopy(), def.DeepCopy()
				build := func() *appsv1.Deployment {
					switch builder {
					case "egress":
						return agentDeployment(&tnv1.TailnetEgress{Spec: tnv1.TailnetEgressSpec{Resources: cr}}, tn, "agents", "image", nil, def)
					case "ingress":
						return ingressAgentDeployment(&tnv1.TailnetIngress{Spec: tnv1.TailnetIngressSpec{Resources: cr}}, tn, "agents", "image", nil, def)
					default:
						in := tlsResourceIngress()
						in.Spec.Resources = cr
						return ingressAgentDeploymentTLS(in, tn, in.Namespace, "image", nil, def, ingressTLSPlan{http: true, secretName: "frontend"})
					}
				}
				first, second := build(), build()
				got := &first.Spec.Template.Spec.Containers[0].Resources
				want := resourceBlock(t, tc.want)
				if !reflect.DeepEqual(*got, want) {
					t.Fatalf("got %#v, want %#v", *got, want)
				}
				for _, list := range []corev1.ResourceList{got.Requests, got.Limits} {
					if list != nil {
						list[corev1.ResourceCPU] = resource.MustParse("999")
					}
				}
				if !reflect.DeepEqual(cr, *beforeCR) || !reflect.DeepEqual(tn, beforeTN) || !reflect.DeepEqual(def, *beforeDef) ||
					!reflect.DeepEqual(second.Spec.Template.Spec.Containers[0].Resources, want) {
					t.Fatal("deployment resources alias an input or another deployment")
				}
			})
		}
	}
}

// Exercise the production child-application methods of both reconcilers. The
// interceptor captures SSA intent; this is not an API-server admission test.
func TestReconcilersApplyAgentResources(t *testing.T) {
	for _, kind := range []string{"egress", "ingress", "ingress TLS"} {
		for _, tier := range []string{"default", "Tailnet", "CR"} {
			t.Run(kind+"/"+tier, func(t *testing.T) {
				defaults := resourceBlock(t, `{"requests":{"cpu":"10m","memory":"32Mi"},"limits":{"memory":"128Mi"}}`)
				tn := &tnv1.Tailnet{}
				var cr corev1.ResourceRequirements
				want := defaults
				if tier == "Tailnet" || tier == "CR" {
					tn.Spec.Proxy.Resources = resourceBlock(t, `{"requests":{"cpu":"20m"}}`)
					want = tn.Spec.Proxy.Resources
				}
				if tier == "CR" {
					cr = resourceBlock(t, `{"limits":{"memory":"256Mi"}}`)
					want = cr
				}
				var applied *appsv1.Deployment
				base := transitionClient(t)
				c := interceptor.NewClient(base.(client.WithWatch), interceptor.Funcs{
					Patch: func(_ context.Context, _ client.WithWatch, obj client.Object, _ client.Patch, _ ...client.PatchOption) error {
						if dep, ok := obj.(*appsv1.Deployment); ok {
							applied = dep.DeepCopy()
						}
						return nil
					},
				})
				var err error
				if kind == "egress" {
					eg := &tnv1.TailnetEgress{ObjectMeta: metav1.ObjectMeta{Name: "out", Namespace: "agents", UID: "egress-uid"}}
					eg.Spec.Resources = cr
					r := &TailnetEgressReconciler{Client: c, Scheme: c.Scheme(), OperatorNamespace: "agents", AgentResources: defaults}
					err = r.applyChildren(context.Background(), eg, tn, eg.Namespace, "image", nil, nil)
				} else {
					in := tlsResourceIngress()
					in.Spec.Resources = cr
					state := ingressTLSState{}
					if kind == "ingress TLS" {
						state.plan = ingressTLSPlan{http: true, secretName: "frontend"}
					} else {
						in.Spec.Exposes = nil
					}
					r := &TailnetIngressReconciler{Client: c, Scheme: c.Scheme(), OperatorNamespace: "agents", AgentResources: defaults}
					err = r.applyChildren(context.Background(), in, tn, in.Namespace, "image", state)
				}
				if err != nil {
					t.Fatal(err)
				}
				if applied == nil || !reflect.DeepEqual(applied.Spec.Template.Spec.Containers[0].Resources, want) {
					t.Fatalf("reconciler did not pass the selected resource block: %#v", applied)
				}
			})
		}
	}
}

func TestAgentResourcesCopiesDecimalQuantities(t *testing.T) {
	// AsDec forces the pointer-backed Quantity representation; copying only the
	// ResourceList map would still alias these quantities.
	q := resource.MustParse("10m")
	q.AsDec()
	input := corev1.ResourceRequirements{Requests: corev1.ResourceList{corev1.ResourceCPU: q}}
	for _, tier := range []string{"CR", "Tailnet", "default"} {
		t.Run(tier, func(t *testing.T) {
			var cr, tn, defaults corev1.ResourceRequirements
			switch tier {
			case "CR":
				cr = input
			case "Tailnet":
				tn = input
			default:
				defaults = input
			}
			got := agentResources(cr, tn, defaults)
			quantity := got.Requests[corev1.ResourceCPU]
			quantity.AsDec().SetUnscaled(999)
			original := input.Requests[corev1.ResourceCPU]
			if original.Cmp(resource.MustParse("10m")) != 0 {
				t.Fatal("quantity aliases selected input")
			}
		})
	}
}
