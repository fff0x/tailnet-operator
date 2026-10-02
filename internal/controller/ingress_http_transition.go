package controller

import (
	"context"
	"errors"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"

	tnv1 "tsunaro.io/tailnet-operator/api/v1alpha1"
)

var (
	errIngressTransitionOwnership = errors.New("ingress Deployment is not controlled by this TailnetIngress")
	errIngressTransitionRead      = errors.New("cannot inspect ingress Deployment for HTTP configuration transition")
	errIngressTransitionScale     = errors.New("cannot pause ingress Deployment for HTTP configuration transition")
	errIngressTransitionPods      = errors.New("cannot inspect ingress Pods for HTTP configuration transition")
)

// retireIngressHTTPPredecessor runs before Tailnet, key and Headscale lookups.
// A running predecessor may retain last-good plaintext listeners on reload errors;
// changing status or the ConfigMap is not a security boundary. Keep its template
// marker unchanged until it is gone AND ordinary reconciliation can install the
// new config. The returned transition flag also keeps missing TLS sources paused.
func (r *TailnetIngressReconciler) retireIngressHTTPPredecessor(ctx context.Context, in *tnv1.TailnetIngress) (transition, waiting bool, err error) {
	if ingressConfigVersion(in) != 2 {
		return false, false, nil
	}
	var dep appsv1.Deployment
	if err := r.Get(ctx, client.ObjectKeyFromObject(in), &dep); err != nil {
		if apierrors.IsNotFound(err) {
			// A deleted Deployment can still have terminating/orphaned Pods.
			// Only a creation with no predecessor may skip retirement.
			waiting, err := r.ingressHTTPPodsRemain(ctx, in)
			return waiting, waiting, err
		}
		return false, false, errIngressTransitionRead
	}
	if in.UID == "" || !metav1.IsControlledBy(&dep, in) {
		return false, false, errIngressTransitionOwnership
	}
	desired := ingressProtocolAnnotations(in)
	if dep.Spec.Template.Annotations[ingressProtocolAnnotation] == desired[ingressProtocolAnnotation] &&
		dep.Spec.Template.Annotations[ingressHTTPConfigAnnotation] == desired[ingressHTTPConfigAnnotation] {
		return false, false, nil
	}
	if dep.Spec.Replicas == nil || *dep.Spec.Replicas != 0 {
		base := dep.DeepCopy()
		zero := int32(0)
		dep.Spec.Replicas = &zero
		// Do not overwrite an ownership/template/scale change made since the read.
		if err := r.Patch(ctx, &dep, client.MergeFromWithOptions(base, client.MergeFromWithOptimisticLock{})); err != nil {
			return true, false, errIngressTransitionScale
		}
		return true, true, nil
	}
	// Wait for the Deployment controller to observe the scale-down as well as
	// checking Pods; an empty list alone can race the old desired replica count.
	if dep.Status.ObservedGeneration < dep.Generation || dep.Status.Replicas != 0 {
		return true, true, nil
	}
	waiting, err = r.ingressHTTPPodsRemain(ctx, in)
	return true, waiting, err
}

func (r *TailnetIngressReconciler) ingressHTTPPodsRemain(ctx context.Context, in *tnv1.TailnetIngress) (bool, error) {
	var pods corev1.PodList
	if err := r.List(ctx, &pods, client.InNamespace(in.Namespace), client.MatchingLabels(ingressSelectorLabels(in.Name))); err != nil {
		return false, errIngressTransitionPods
	}
	// Include terminating and terminal Pods. Never force-delete, change their
	// metadata, or bypass termination. Selector collisions delay recovery safely;
	// traversing ReplicaSets would require new RBAC and is unnecessary here.
	return len(pods.Items) != 0, nil
}

// applyExtendedIngressDeployment also fences the write side: dependency lookups
// can take long enough for the Deployment to be replaced after the barrier read.
// Create must not adopt an object that appeared in the meantime; updating an
// existing object carries its identity/version through SSA.
func (r *TailnetIngressReconciler) applyExtendedIngressDeployment(ctx context.Context, in *tnv1.TailnetIngress, desired *appsv1.Deployment) error {
	var current appsv1.Deployment
	if err := r.Get(ctx, client.ObjectKeyFromObject(desired), &current); err != nil {
		if apierrors.IsNotFound(err) {
			return r.Create(ctx, desired, client.FieldOwner(fieldOwner))
		}
		return errIngressTransitionRead
	}
	if in.UID == "" || !metav1.IsControlledBy(&current, in) {
		return errIngressTransitionOwnership
	}
	desired.UID, desired.ResourceVersion = current.UID, current.ResourceVersion
	return ssaApply(ctx, r.Client, desired)
}

func ingressTransitionSourceReason(in *tnv1.TailnetIngress, state ingressTLSState) string {
	if !safeIngressExposes(in.Spec.Exposes) {
		return "TLSConfigurationInvalid"
	}
	if state.reason != "" {
		return state.reason
	}
	for _, expose := range in.Spec.Exposes {
		if backend := state.backends[expose.Name]; backend.reason != "" {
			return backend.reason
		}
	}
	return ""
}
