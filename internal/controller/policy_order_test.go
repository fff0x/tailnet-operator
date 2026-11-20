package controller

import (
	"context"
	"slices"
	"testing"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"

	tnv1 "tsunaro.io/tailnet-operator/api/v1alpha1"
	"tsunaro.io/tailnet-operator/internal/policy"
)

// Two ingresses that resolve to the SAME tag but carry different allowFrom render two distinct
// grants under one dst. Their order in the grants array must follow the CRs' namespace/name, not
// the List order — otherwise the fragment hash flips between reconciles and the hub reports a
// perpetual ApprovalPending with an all-zero delta when two ingresses share a source tag.
func TestCollectOrderIndependentOfListOrder(t *testing.T) {
	s := exportScheme(t)
	tn := &tnv1.Tailnet{ObjectMeta: metav1.ObjectMeta{Name: "corp"},
		Spec: tnv1.TailnetSpec{TagTemplate: "tag:egress-{name}", IngressTagTemplate: "tag:ingress-{name}",
			Policy: tnv1.PolicySpec{Mode: "Export", TagOwners: []string{"group:operator"},
				IngressSourceAllowlist: []string{"group:*"}}}}
	mk := func(name, group string) *tnv1.TailnetIngress {
		return &tnv1.TailnetIngress{ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: "apps"},
			Spec: tnv1.TailnetIngressSpec{TailnetRef: tnv1.TailnetRef{Name: "corp"}, Tag: "tag:ingress-shared",
				AllowFrom: []string{group}, Exposes: []tnv1.Expose{{Name: "https", Port: 443}}}}
	}
	a, b := mk("alpha", "group:a"), mk("bravo", "group:b")

	render := func(reverse bool) []byte {
		base := fake.NewClientBuilder().WithScheme(s).WithObjects(tn, a, b).Build()
		c := interceptor.NewClient(base.(client.WithWatch), interceptor.Funcs{
			List: func(ctx context.Context, w client.WithWatch, list client.ObjectList, opts ...client.ListOption) error {
				if err := w.List(ctx, list, opts...); err != nil {
					return err
				}
				if reverse {
					if il, ok := list.(*tnv1.TailnetIngressList); ok {
						slices.Reverse(il.Items)
					}
				}
				return nil
			},
		})
		r := TailnetPolicyReconciler{Client: c, Scheme: s, OperatorNamespace: "operator"}
		in, _, _, err := r.collect(context.Background(), tn)
		if err != nil {
			t.Fatal(err)
		}
		doc, _, err := policy.RenderFragment(in)
		if err != nil {
			t.Fatal(err)
		}
		canon, err := policy.Normalize(doc)
		if err != nil {
			t.Fatal(err)
		}
		return []byte(canon)
	}

	forward, reversed := render(false), render(true)
	if string(forward) != string(reversed) {
		t.Fatalf("fragment depends on List order:\n forward=%s\nreversed=%s", forward, reversed)
	}
	if policy.Hash(string(forward)) != policy.Hash(string(reversed)) {
		t.Fatal("fragment hash depends on List order")
	}
}
