package controller

import (
	"context"

	"k8s.io/apimachinery/pkg/api/equality"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"

	tnv1 "tsunaro.io/tailnet-operator/api/v1alpha1"
)

// TailnetGatewayReconciler reports suspension only. Admission currently requires
// suspend=true; even a bypassed/older CR cannot activate a workload writer. No
// child, Secret, Tailnet or Headscale reads are necessary to honor suspension.
// Persistent gateway identity must never use the ephemeral agent lifecycle.
type TailnetGatewayReconciler struct {
	client.Client
}

// gatewayAPIError retains classification without exposing API response bodies,
// object payloads or credentials through controller-runtime's error logger.
type gatewayAPIError struct {
	operation string
	cause     error
}

func (e *gatewayAPIError) Error() string { return "gateway " + e.operation + " failed" }
func (e *gatewayAPIError) Unwrap() error { return e.cause }

func (r *TailnetGatewayReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	var gw tnv1.TailnetGateway
	if err := r.Get(ctx, req.NamespacedName, &gw); err != nil {
		if client.IgnoreNotFound(err) == nil {
			return ctrl.Result{}, nil
		}
		return ctrl.Result{}, &gatewayAPIError{operation: "resource read", cause: err}
	}
	if !gw.DeletionTimestamp.IsZero() {
		// Retain: no finalizer, garbage-collection ownership, or cleanup of state,
		// workloads or nodes. This controller never created any of those.
		return ctrl.Result{}, nil
	}
	before := gw.DeepCopy()
	reason := "Suspended"
	message := "Gateway reconciliation is suspended; runtime has not been observed."
	if gw.Spec.Suspend != nil && !*gw.Spec.Suspend {
		reason = "RuntimeUnavailable"
		message = "Gateway runtime is not available; no resources have been changed."
	}
	gw.Status.ObservedGeneration = gw.Generation
	for _, condition := range []string{"Registered", "RoutesInSync", "DNSReady", "StaleNodes", "ClusterDNSForward", "Ready"} {
		status := metav1.ConditionUnknown
		if condition == "Ready" {
			status = metav1.ConditionFalse
		}
		meta.SetStatusCondition(&gw.Status.Conditions, metav1.Condition{
			Type: condition, Status: status, ObservedGeneration: gw.Generation,
			Reason: reason, Message: message,
		})
	}
	// Keep last-known identity/routes and the unacknowledged debounce state.
	// Unknown conditions make clear that these are not fresh observations.
	if equality.Semantic.DeepEqual(before.Status, gw.Status) {
		return ctrl.Result{}, nil
	}
	patch := client.MergeFromWithOptions(before, client.MergeFromWithOptimisticLock{})
	if err := r.Status().Patch(ctx, &gw, patch); err != nil {
		return ctrl.Result{}, &gatewayAPIError{operation: "status write", cause: err}
	}
	return ctrl.Result{}, nil
}

func (r *TailnetGatewayReconciler) SetupWithManager(mgr ctrl.Manager) error {
	// Observe status updates too: repair stale Ready=True, then the equality
	// guard stops our own status event. No child informer or periodic polling.
	return ctrl.NewControllerManagedBy(mgr).
		Named("tailnetgateway").
		For(&tnv1.TailnetGateway{}).
		Complete(r)
}
