package gateway

import (
	"context"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	policyv1 "k8s.io/api/policy/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"

	tnv1 "tsunaro.io/tailnet-operator/api/v1alpha1"
)

// InspectFreshFromReader captures the necessary Kubernetes snapshots with an
// explicitly supplied reader. It never uses a default kubeconfig, does not call
// Headscale, and is not wired to the suspension controller. A reader error is
// UNKNOWN, never an absent name. Even a completely clean inventory remains
// blocked by InspectFreshSnapshots' provenance error. The caller must bind
// nodeNames to a separately verified Headscale server; an empty slice is not
// proof that no node exists.
func InspectFreshFromReader(ctx context.Context, r client.Reader, gatewayName, namespace string, serial uint32, nodeNames []string) (FreshInspection, error) {
	if r == nil || gatewayName == "" || namespace == "" || serial == 0 {
		return FreshInspection{}, ErrFreshSnapshot
	}
	g := &tnv1.TailnetGateway{}
	if err := r.Get(ctx, types.NamespacedName{Name: gatewayName}, g); err != nil {
		return FreshInspection{}, ErrFreshSnapshot
	}
	tn := &tnv1.Tailnet{}
	if err := r.Get(ctx, types.NamespacedName{Name: string(g.Spec.TailnetRef.Name)}, tn); err != nil {
		return FreshInspection{}, ErrFreshSnapshot
	}
	state := &corev1.Secret{}
	if err := r.Get(ctx, types.NamespacedName{Namespace: namespace, Name: string(g.Spec.StateSecretRef.Name)}, state); err != nil {
		return FreshInspection{}, ErrFreshSnapshot
	}
	hosts := &corev1.ConfigMap{}
	if tn.Spec.DNS.HostsConfigMap == "" || r.Get(ctx, types.NamespacedName{Namespace: namespace, Name: tn.Spec.DNS.HostsConfigMap}, hosts) != nil {
		return FreshInspection{}, ErrFreshSnapshot
	}
	egresses := &tnv1.TailnetEgressList{}
	peers := &tnv1.TailnetGatewayList{}
	if r.List(ctx, egresses, client.InNamespace(namespace)) != nil || r.List(ctx, peers) != nil {
		return FreshInspection{}, ErrFreshSnapshot
	}
	in := FreshInspectionInputs{Fresh: FreshInputs{Gateway: g, Tailnet: tn, Namespace: namespace, Egresses: egresses.Items, Hosts: hosts.Data["hosts"], DNSSerial: serial},
		State: state, Hosts: hosts, PeerGateways: peers.Items, NodeNames: nodeNames}
	plan, err := RenderFresh(in.Fresh)
	if err != nil {
		return FreshInspection{}, ErrFreshSnapshot
	}
	for _, desired := range plan.Objects {
		current := emptyFreshObject(desired)
		if current == nil {
			return FreshInspection{}, ErrFreshSnapshot
		}
		key := types.NamespacedName{Namespace: desired.GetNamespace(), Name: desired.GetName()}
		err := r.Get(ctx, key, current)
		switch {
		case apierrors.IsNotFound(err):
			in.Absent = append(in.Absent, FreshObjectKey{Kind: freshObjectKind(desired), Namespace: key.Namespace, Name: key.Name})
		case err == nil:
			in.Occupied = append(in.Occupied, current)
		default:
			return FreshInspection{}, ErrFreshSnapshot
		}
	}
	return InspectFreshSnapshots(in)
}

func emptyFreshObject(obj client.Object) client.Object {
	switch obj.(type) {
	case *corev1.ServiceAccount:
		return &corev1.ServiceAccount{}
	case *rbacv1.Role:
		return &rbacv1.Role{}
	case *rbacv1.RoleBinding:
		return &rbacv1.RoleBinding{}
	case *corev1.ConfigMap:
		return &corev1.ConfigMap{}
	case *corev1.Service:
		return &corev1.Service{}
	case *policyv1.PodDisruptionBudget:
		return &policyv1.PodDisruptionBudget{}
	case *appsv1.StatefulSet:
		return &appsv1.StatefulSet{}
	default:
		return nil
	}
}
