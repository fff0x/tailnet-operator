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
	errIngressTransitionPending   = errors.New("ingress predecessor has not completed HTTP configuration retirement")
	errIngressTransitionChanged   = errors.New("ingress Deployment changed during HTTP configuration application")
)

// retireIngressHTTPPredecessor runs before Tailnet, key and Headscale lookups.
// A running predecessor may retain last-good plaintext listeners on reload errors;
// changing status or the ConfigMap is not a security boundary. Keep its template
// marker unchanged until it is gone AND ordinary reconciliation can install the
// new config. The returned transition flag also keeps missing TLS sources paused.
func (r *TailnetIngressReconciler) retireIngressHTTPPredecessor(ctx context.Context, in *tnv1.TailnetIngress) (transition, waiting bool, err error) {
	return r.retireIngressHTTPConfiguration(ctx, in, nil)
}

// A nil Tailnet checks spec intent only. The resolved check additionally fences effective
// external sources, even if subsequent working-key or Headscale reads fail.
func (r *TailnetIngressReconciler) retireIngressHTTPConfiguration(ctx context.Context, in *tnv1.TailnetIngress, tn *tnv1.Tailnet) (transition, waiting bool, err error) {
	var dep appsv1.Deployment
	if err := r.Get(ctx, ingressWorkloadKey(in), &dep); err != nil {
		if apierrors.IsNotFound(err) {
			// A deleted Deployment can still have terminating/orphaned Pods.
			// Only a creation with no predecessor may skip retirement.
			waiting, err := r.ingressHTTPPodsRemain(ctx, in)
			return waiting, waiting, err
		}
		return false, false, errIngressTransitionRead
	}
	if !ingressExtendedTransition(in, &dep) && !(tn != nil && ingressHTTPProtocol(in)) {
		return false, false, nil
	}
	if in.UID == "" || !metav1.IsControlledBy(&dep, in) {
		return false, false, errIngressTransitionOwnership
	}
	desired := ingressProtocolAnnotations(in)
	if tn != nil && ingressConfigVersion(in) > 0 {
		desired[ingressHTTPSourceAnnotation] = ingressResolvedSourceDigest(in, tn)
	}
	if ingressHTTPMarkersMatch(dep.Spec.Template.Annotations, desired, tn != nil) {
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

func ingressExtendedTransition(in *tnv1.TailnetIngress, dep *appsv1.Deployment) bool {
	protocol := dep.Spec.Template.Annotations[ingressProtocolAnnotation]
	return ingressConfigVersion(in) >= 2 || protocol == "http-v2" || protocol == "http-v3"
}

func ingressHTTPMarkersMatch(current, desired map[string]string, resolved bool) bool {
	return current[ingressProtocolAnnotation] == desired[ingressProtocolAnnotation] &&
		current[ingressHTTPConfigAnnotation] == desired[ingressHTTPConfigAnnotation] &&
		(!resolved || current[ingressHTTPSourceAnnotation] == desired[ingressHTTPSourceAnnotation])
}

func (r *TailnetIngressReconciler) ingressDeploymentDrained(ctx context.Context, in *tnv1.TailnetIngress, dep *appsv1.Deployment) error {
	if dep.Spec.Replicas == nil || *dep.Spec.Replicas != 0 || dep.Status.ObservedGeneration < dep.Generation || dep.Status.Replicas != 0 {
		return errIngressTransitionPending
	}
	waiting, err := r.ingressHTTPPodsRemain(ctx, in)
	if err != nil {
		return err
	}
	if waiting {
		return errIngressTransitionPending
	}
	return nil
}

// Capture identity before installing the ConfigMap. A source/spec transition must
// still be drained even if another writer installed matching markers meanwhile.
func (r *TailnetIngressReconciler) ingressHTTPDeploymentSnapshot(ctx context.Context, in *tnv1.TailnetIngress, transition bool) (*appsv1.Deployment, error) {
	var dep appsv1.Deployment
	if err := r.Get(ctx, ingressWorkloadKey(in), &dep); err != nil {
		if apierrors.IsNotFound(err) {
			return nil, nil
		}
		return nil, errIngressTransitionRead
	}
	if in.UID == "" || !metav1.IsControlledBy(&dep, in) {
		return nil, errIngressTransitionOwnership
	}
	if transition {
		if err := r.ingressDeploymentDrained(ctx, in, &dep); err != nil {
			return nil, err
		}
	}
	return &dep, nil
}

// applyExtendedIngressDeployment also fences the write side: dependency lookups
// can take long enough for the Deployment to be replaced after the barrier read.
// Create must not adopt an object that appeared in the meantime; updating an
// existing object carries its identity/version through SSA.
func (r *TailnetIngressReconciler) applyExtendedIngressDeployment(ctx context.Context, in *tnv1.TailnetIngress, desired *appsv1.Deployment, observed ...*appsv1.Deployment) error {
	var current appsv1.Deployment
	if err := r.Get(ctx, client.ObjectKeyFromObject(desired), &current); err != nil {
		if apierrors.IsNotFound(err) {
			if len(observed) != 0 && observed[0] != nil {
				return errIngressTransitionChanged
			}
			waiting, err := r.ingressHTTPPodsRemain(ctx, in)
			if err != nil {
				return err
			}
			if waiting {
				return errIngressTransitionPending
			}
			return r.Create(ctx, desired, client.FieldOwner(fieldOwner))
		}
		return errIngressTransitionRead
	}
	if len(observed) != 0 && (observed[0] == nil || observed[0].UID != current.UID || observed[0].ResourceVersion != current.ResourceVersion) {
		return errIngressTransitionChanged
	}
	if in.UID == "" || !metav1.IsControlledBy(&current, in) {
		return errIngressTransitionOwnership
	}
	if ingressConfigVersion(in) < 2 || (ingressExtendedTransition(in, &current) && !ingressHTTPMarkersMatch(current.Spec.Template.Annotations, desired.Spec.Template.Annotations, true)) {
		if err := r.ingressDeploymentDrained(ctx, in, &current); err != nil {
			return err
		}
	}
	// Explicitly clear retired markers, including ones written by older managers.
	// SSA omission alone does not remove a marker owned by another field manager.
	for _, key := range []string{ingressProtocolAnnotation, ingressHTTPConfigAnnotation, ingressHTTPSourceAnnotation} {
		if current.Spec.Template.Annotations[key] != "" && desired.Spec.Template.Annotations[key] == "" {
			if desired.Spec.Template.Annotations == nil {
				desired.Spec.Template.Annotations = make(map[string]string)
			}
			desired.Spec.Template.Annotations[key] = ""
		}
	}
	desired.UID, desired.ResourceVersion = current.UID, current.ResourceVersion
	return ssaApply(ctx, r.Client, desired)
}

// Fence companion objects too: installing targets must not adopt a namespace-local
// name collision, and a replacement between read and apply must fail its UID/RV check.
func (r *TailnetIngressReconciler) applyIngressHTTPChild(ctx context.Context, in *tnv1.TailnetIngress, desired client.Object) error {
	current := desired.DeepCopyObject().(client.Object)
	if err := r.Get(ctx, client.ObjectKeyFromObject(desired), current); err != nil {
		if apierrors.IsNotFound(err) {
			return r.Create(ctx, desired, client.FieldOwner(fieldOwner))
		}
		return errors.New("cannot inspect ingress HTTP child")
	}
	if in.UID == "" || !metav1.IsControlledBy(current, in) {
		return errors.New("ingress HTTP child is not controlled by this TailnetIngress")
	}
	desired.SetUID(current.GetUID())
	desired.SetResourceVersion(current.GetResourceVersion())
	return ssaApply(ctx, r.Client, desired)
}

func ingressTransitionSourceReason(in *tnv1.TailnetIngress, state ingressTLSState) string {
	if !safeIngressExposes(in.Spec.Exposes) {
		return "TLSConfigurationInvalid"
	}
	if state.reason != "" {
		return state.reason
	}
	// Backend CA material is per-target. Optional projections and agent transport
	// validation isolate it; an unavailable CA must not suppress healthy siblings.
	return ""
}
