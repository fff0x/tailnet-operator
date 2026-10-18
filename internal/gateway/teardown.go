package gateway

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"strings"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	policyv1 "k8s.io/api/policy/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	apimeta "k8s.io/apimachinery/pkg/api/meta"
	"sigs.k8s.io/controller-runtime/pkg/client"

	tnv1 "tsunaro.io/tailnet-operator/api/v1alpha1"
	"tsunaro.io/tailnet-operator/internal/headscale"
)

// TeardownFinalizer records the user's deletionPolicy=Delete consent on the CR.
const TeardownFinalizer = "tsunaro.io/gateway-teardown"

// ErrTeardownBlocked means an object or node could not be attributed to this
// gateway, or Headscale refused; nothing further is deleted and the finalizer stays.
var ErrTeardownBlocked = errors.New("gateway teardown: blocked")

// GatewayTeardownHeadscale adds the two mutations the teardown needs.
type GatewayTeardownHeadscale interface {
	GatewayHeadscale
	DeleteNode(context.Context, string) error
	ExpirePreAuthKey(context.Context, string) error
}

// TeardownProgress names the step the teardown is waiting on; Done means every
// attributable resource, the Headscale node and the bootstrap key are gone.
type TeardownProgress struct {
	Step string
	Done bool
}

// TeardownFresh deletes, fail-closed and in a fixed order, only what this gateway
// provably created: receipt children by recorded UID, provenance objects — and,
// without a completion receipt, the partial bootstrap's children — by the
// operator's own gateway-uid label, the Headscale node bound to the state Secret
// and the minted bootstrap key. Every Kubernetes delete carries a UID precondition.
// It is idempotent: each call re-reads the inventory and resumes.
//
// ponytail: the Headscale node is attributed through VerifyGatewayState or the
// controller's own status.nodeId; a gateway that never registered leaves no node.
func TeardownFresh(ctx context.Context, c client.Client, ns string, g *tnv1.TailnetGateway, tn *tnv1.Tailnet, hs GatewayTeardownHeadscale) (TeardownProgress, error) {
	if c == nil || hs == nil || g == nil || g.UID == "" || ns == "" {
		return TeardownProgress{}, ErrTeardownBlocked
	}
	receipt, err := teardownReceipt(ctx, c, ns, g)
	if err != nil {
		return TeardownProgress{Step: "receipt"}, err
	}

	// 1. Workload first: delete the StatefulSet, then wait until its Pods are gone
	// (explicitly, not via propagation policy, so a restart resumes correctly).
	for _, ref := range receipt.Objects {
		if ref.Kind != "StatefulSet" {
			continue
		}
		if err := teardownDelete(ctx, c, ns, ref); err != nil {
			return TeardownProgress{Step: "statefulset"}, err
		}
	}
	if len(receipt.Objects) == 0 {
		// Partial bootstrap: the StatefulSet, if it got as far, carries only the label.
		sts, owned, err := teardownOwned(ctx, c, ns, g.Name, g, &appsv1.StatefulSet{})
		if err != nil {
			return TeardownProgress{Step: "statefulset"}, err
		}
		if owned {
			if err := teardownDeleteObject(ctx, c, sts); err != nil {
				return TeardownProgress{Step: "statefulset"}, err
			}
		}
	}
	pods := &corev1.PodList{}
	if c.List(ctx, pods, client.InNamespace(ns), client.MatchingLabels{gatewayUIDLabel: string(g.UID)}) != nil {
		return TeardownProgress{Step: "pods"}, ErrTeardownBlocked
	}
	if len(pods.Items) != 0 || !apierrors.IsNotFound(c.Get(ctx, client.ObjectKey{Namespace: ns, Name: g.Name}, &appsv1.StatefulSet{})) {
		return TeardownProgress{Step: "workload-stopping"}, nil
	}

	// 2. Headscale: node (removes its route approvals), then the bootstrap key.
	// Both read the Secrets that step 4 deletes, so they must run before it.
	state, stateOwned, err := teardownOwned(ctx, c, ns, string(g.Spec.StateSecretRef.Name), g, &corev1.Secret{})
	if err != nil {
		return TeardownProgress{Step: "state"}, err
	}
	nodeID := g.Status.NodeID
	if stateOwned && tn != nil {
		nodes, err := hs.ListNodes(ctx)
		if err != nil {
			return TeardownProgress{Step: "node-list"}, ErrTeardownBlocked
		}
		if binding, err := VerifyGatewayState(g, tn, state.(*corev1.Secret), ns, receipt.StateUID, nodes, receipt.Auth.KeyID); err == nil {
			nodeID = binding.NodeID
		}
	}
	if nodeID != "" {
		if err := hs.DeleteNode(ctx, nodeID); err != nil && !headscaleNotFound(err) {
			return TeardownProgress{Step: "node-delete"}, ErrTeardownBlocked
		}
	}
	auth, authOwned, err := teardownOwned(ctx, c, ns, g.Name+"-auth", g, &corev1.Secret{})
	if err != nil {
		return TeardownProgress{Step: "auth"}, err
	}
	if authOwned {
		if id := auth.GetAnnotations()["tsunaro.io/auth-key-id"]; validGatewayKeyID(id) {
			if err := hs.ExpirePreAuthKey(ctx, id); err != nil && !headscaleNotFound(err) {
				return TeardownProgress{Step: "key-expire"}, ErrTeardownBlocked
			}
		}
	}

	// 3. Remaining receipt children, by recorded UID.
	for _, ref := range receipt.Objects {
		if ref.Kind == "StatefulSet" {
			continue
		}
		if err := teardownDelete(ctx, c, ns, ref); err != nil {
			return TeardownProgress{Step: strings.ToLower(ref.Kind)}, err
		}
	}
	// 3b. No receipt means a bootstrap that stopped between the first Create and
	// the completion record: the children it wrote are known only by the label.
	if len(receipt.Objects) == 0 {
		if err := teardownSweepLabelled(ctx, c, ns, g); err != nil {
			return TeardownProgress{Step: "partial-children"}, err
		}
	}

	// 4. Provenance last, completion receipt very last: it is the inventory.
	for _, step := range []struct {
		name  string
		owned bool
		obj   client.Object
	}{{"auth", authOwned, auth}, {"state", stateOwned, state}} {
		if !step.owned {
			continue
		}
		if step.name == "state" && receipt.StateUID != "" && step.obj.GetUID() != receipt.StateUID {
			return TeardownProgress{Step: "state"}, ErrTeardownBlocked
		}
		if err := teardownDeleteObject(ctx, c, step.obj); err != nil {
			return TeardownProgress{Step: step.name}, err
		}
	}
	for _, name := range []string{g.Name + "-auth-receipt", g.Name + "-fresh", g.Name + "-fresh-next"} {
		obj, owned, err := teardownOwned(ctx, c, ns, name, g, &corev1.ConfigMap{})
		if err != nil {
			return TeardownProgress{Step: "receipts"}, err
		}
		if owned {
			if err := teardownDeleteObject(ctx, c, obj); err != nil {
				return TeardownProgress{Step: "receipts"}, err
			}
		}
	}
	return TeardownProgress{Step: "done", Done: true}, nil
}

// teardownReceipt returns the completion receipt if this gateway owns one. A
// missing receipt (partial creation) yields an empty inventory; a foreign one blocks.
func teardownReceipt(ctx context.Context, c client.Client, ns string, g *tnv1.TailnetGateway) (freshReceipt, error) {
	record := &corev1.ConfigMap{}
	err := c.Get(ctx, client.ObjectKey{Namespace: ns, Name: g.Name + "-fresh"}, record)
	if apierrors.IsNotFound(err) {
		return freshReceipt{}, nil
	}
	if err != nil || record.Labels[gatewayUIDLabel] != string(g.UID) {
		return freshReceipt{}, ErrTeardownBlocked
	}
	raw := record.Data["receipt.json"]
	var receipt freshReceipt
	decoder := json.NewDecoder(strings.NewReader(raw))
	decoder.DisallowUnknownFields()
	if len(raw) == 0 || len(raw) > 1<<20 || decoder.Decode(&receipt) != nil || decoder.Decode(&struct{}{}) != io.EOF {
		return freshReceipt{}, ErrTeardownBlocked
	}
	for _, ref := range receipt.Objects {
		if ref.UID == "" || ref.Name == "" || teardownEmpty(ref.Kind) == nil {
			return freshReceipt{}, ErrTeardownBlocked
		}
	}
	return receipt, nil
}

// teardownOwned fetches name and reports whether it carries this gateway's label.
// An existing object without the label is foreign: it is left alone, not deleted.
func teardownOwned(ctx context.Context, c client.Client, ns, name string, g *tnv1.TailnetGateway, obj client.Object) (client.Object, bool, error) {
	err := c.Get(ctx, client.ObjectKey{Namespace: ns, Name: name}, obj)
	if apierrors.IsNotFound(err) {
		return obj, false, nil
	}
	if err != nil {
		return obj, false, ErrTeardownBlocked
	}
	return obj, obj.GetLabels()[gatewayUIDLabel] == string(g.UID), nil
}

// teardownSweepLabelled deletes the plan-kind children that carry this gateway's
// own UID label — the only attribution a bootstrap without a completion receipt
// leaves behind. Unlabelled objects, even under our names, are foreign and stay.
// Provenance Secrets and the receipt ConfigMaps are handled by name in step 4.
func teardownSweepLabelled(ctx context.Context, c client.Client, ns string, g *tnv1.TailnetGateway) error {
	skip := map[string]bool{g.Name + "-auth-receipt": true, g.Name + "-fresh": true, g.Name + "-fresh-next": true}
	for _, list := range []client.ObjectList{&corev1.ServiceAccountList{}, &rbacv1.RoleList{}, &rbacv1.RoleBindingList{}, &corev1.ServiceList{}, &policyv1.PodDisruptionBudgetList{}, &corev1.ConfigMapList{}} {
		if c.List(ctx, list, client.InNamespace(ns), client.MatchingLabels{gatewayUIDLabel: string(g.UID)}) != nil {
			return ErrTeardownBlocked
		}
		items, err := apimeta.ExtractList(list)
		if err != nil {
			return ErrTeardownBlocked
		}
		for _, item := range items {
			obj, ok := item.(client.Object)
			if !ok {
				return ErrTeardownBlocked
			}
			if _, isCM := obj.(*corev1.ConfigMap); isCM && skip[obj.GetName()] {
				continue
			}
			if err := teardownDeleteObject(ctx, c, obj); err != nil {
				return err
			}
		}
	}
	return nil
}

func teardownDelete(ctx context.Context, c client.Client, ns string, ref freshObjectReceipt) error {
	obj := teardownEmpty(ref.Kind)
	err := c.Get(ctx, client.ObjectKey{Namespace: ns, Name: ref.Name}, obj)
	if apierrors.IsNotFound(err) {
		return nil
	}
	if err != nil || obj.GetUID() != ref.UID {
		return ErrTeardownBlocked
	}
	return teardownDeleteObject(ctx, c, obj)
}

func teardownDeleteObject(ctx context.Context, c client.Client, obj client.Object) error {
	uid := obj.GetUID()
	if uid == "" {
		return ErrTeardownBlocked
	}
	if err := c.Delete(ctx, obj, client.Preconditions{UID: &uid}); err != nil && !apierrors.IsNotFound(err) {
		return ErrTeardownBlocked
	}
	return nil
}

func teardownEmpty(kind string) client.Object {
	switch kind {
	case "StatefulSet":
		return &appsv1.StatefulSet{}
	case "Service":
		return &corev1.Service{}
	case "PodDisruptionBudget":
		return &policyv1.PodDisruptionBudget{}
	case "ServiceAccount":
		return &corev1.ServiceAccount{}
	case "Role":
		return &rbacv1.Role{}
	case "RoleBinding":
		return &rbacv1.RoleBinding{}
	case "ConfigMap":
		return &corev1.ConfigMap{}
	case "Secret":
		return &corev1.Secret{}
	}
	return nil
}

func headscaleNotFound(err error) bool {
	var status *headscale.StatusError
	return errors.As(err, &status) && status.Code == 404
}

// The production client satisfies the teardown contract.
var _ GatewayTeardownHeadscale = (*headscale.Client)(nil)
