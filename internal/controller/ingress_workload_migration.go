package controller

import (
	"context"
	"errors"

	appsv1 "k8s.io/api/apps/v1"
	networkingv1 "k8s.io/api/networking/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"

	tnv1 "tsunaro.io/tailnet-operator/api/v1alpha1"
)

var errLegacyWorkload = errors.New("cannot retire the legacy ingress workload")

// retireLegacyIngressWorkload removes the pre-v0.12 Deployment and NetworkPolicy, which were named
// exactly like the CR. It runs before anything else touches the workload: both generations carry
// the same pod labels and the same Headscale host, so the old agent must be gone before the new one
// starts. Only objects controlled by this CR are touched; a same-named user Deployment is left alone.
// waiting reports that the old workload is still draining.
func (r *TailnetIngressReconciler) retireLegacyIngressWorkload(ctx context.Context, in *tnv1.TailnetIngress) (waiting bool, err error) {
	if in.UID == "" {
		return false, nil
	}
	key := types.NamespacedName{Namespace: in.Namespace, Name: in.Name}
	var dep appsv1.Deployment
	switch err := r.Get(ctx, key, &dep); {
	case apierrors.IsNotFound(err):
	case err != nil:
		return false, errLegacyWorkload
	case metav1.IsControlledBy(&dep, in):
		if dep.Spec.Replicas == nil || *dep.Spec.Replicas != 0 {
			base := dep.DeepCopy()
			zero := int32(0)
			dep.Spec.Replicas = &zero
			if err := r.Patch(ctx, &dep, client.MergeFromWithOptions(base, client.MergeFromWithOptimisticLock{})); err != nil {
				return false, errLegacyWorkload
			}
			return true, nil
		}
		if dep.Status.ObservedGeneration < dep.Generation || dep.Status.Replicas != 0 {
			return true, nil
		}
		remain, err := r.ingressHTTPPodsRemain(ctx, in)
		if err != nil {
			return false, errLegacyWorkload
		}
		if remain {
			return true, nil
		}
		if err := r.Delete(ctx, &dep, client.Preconditions{UID: &dep.UID}); client.IgnoreNotFound(err) != nil {
			return false, errLegacyWorkload
		}
		waiting = true
	}
	var np networkingv1.NetworkPolicy
	if err := r.Get(ctx, key, &np); err == nil && metav1.IsControlledBy(&np, in) {
		if err := r.Delete(ctx, &np, client.Preconditions{UID: &np.UID}); client.IgnoreNotFound(err) != nil {
			return false, errLegacyWorkload
		}
	} else if err != nil && !apierrors.IsNotFound(err) {
		return false, errLegacyWorkload
	}
	return waiting, nil
}
