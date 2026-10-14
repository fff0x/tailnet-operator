package controller

import (
	"context"

	"k8s.io/apimachinery/pkg/api/equality"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/tools/record"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"

	tnv1 "tsunaro.io/tailnet-operator/api/v1alpha1"
	"tsunaro.io/tailnet-operator/internal/gateway"
	operatormetrics "tsunaro.io/tailnet-operator/internal/metrics"
)

// TailnetGatewayReconciler keeps suspension read-only and explicitly opts fresh
// gateways into a create-only retained lifecycle, never the ephemeral agent path.
type TailnetGatewayReconciler struct {
	client.Client
	// RuntimeClient bypasses the cache for all provenance and exclusivity checks.
	RuntimeClient     client.Client
	OperatorNamespace string
	Recorder          record.EventRecorder
	Metrics           *operatormetrics.Metrics
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
			r.Metrics.Delete("TailnetGateway", "", req.Name)
			return ctrl.Result{}, nil
		}
		return ctrl.Result{}, &gatewayAPIError{operation: "resource read", cause: err}
	}
	runtime := r.RuntimeClient != nil && r.OperatorNamespace != ""
	if !gw.DeletionTimestamp.IsZero() {
		// Retain: no finalizer, garbage-collection ownership, or cleanup of state,
		// workloads or nodes, including resources created by the fresh writer.
		// Only a finalizer recorded under deletionPolicy=Delete authorizes teardown.
		if !runtime || !controllerutil.ContainsFinalizer(&gw, gateway.TeardownFinalizer) {
			return ctrl.Result{}, nil
		}
		return r.reconcileTeardown(ctx, req)
	}
	// The finalizer mirrors deletionPolicy=Delete; it is the only CR metadata write.
	if want := runtime && gw.Spec.DeletionPolicy == tnv1.GatewayDeletionPolicyDelete; want != controllerutil.ContainsFinalizer(&gw, gateway.TeardownFinalizer) {
		before := gw.DeepCopy()
		if want {
			controllerutil.AddFinalizer(&gw, gateway.TeardownFinalizer)
		} else {
			controllerutil.RemoveFinalizer(&gw, gateway.TeardownFinalizer)
		}
		if err := r.Patch(ctx, &gw, client.MergeFromWithOptions(before, client.MergeFromWithOptimisticLock{})); err != nil {
			return ctrl.Result{}, &gatewayAPIError{operation: "finalizer write", cause: err}
		}
	}
	if gw.Spec.Suspend != nil && !*gw.Spec.Suspend && runtime {
		return r.reconcileFresh(ctx, req)
	}
	before := gw.DeepCopy()
	reason := "Suspended"
	message := "Gateway reconciliation is suspended; runtime has not been observed."
	if gw.Spec.Suspend != nil && !*gw.Spec.Suspend {
		reason = "RuntimeUnavailable"
		message = "Gateway runtime is not available; no resources have been changed."
	}
	gw.Status.ObservedGeneration = gw.Generation
	meta.RemoveStatusCondition(&gw.Status.Conditions, "ServiceReady")
	for _, condition := range []string{"Registered", "RoutesInSync", "DNSReady", "StaleNodes", "ClusterDNSForward", "WorkloadCurrent", "Ready"} {
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
	// Observe even when the status is unchanged: Metrics is a process-local
	// Prometheus registry, so after an operator restart the gauges start empty
	// and would stay absent until the next real status change. Observe is
	// idempotent (DeletePartialMatch + rebuild under the Metrics mutex; a
	// suspended gateway deletes its series instead of exporting them).
	if equality.Semantic.DeepEqual(before.Status, gw.Status) {
		r.Metrics.Observe(&gw)
		return ctrl.Result{}, nil
	}
	patch := client.MergeFromWithOptions(before, client.MergeFromWithOptimisticLock{})
	if err := r.Status().Patch(ctx, &gw, patch); err != nil {
		return ctrl.Result{}, &gatewayAPIError{operation: "status write", cause: err}
	}
	r.Metrics.Observe(&gw)
	return ctrl.Result{}, nil
}

func (r *TailnetGatewayReconciler) SetupWithManager(mgr ctrl.Manager) error {
	// Observe status updates too: repair stale Ready=True, then the equality
	// guard stops our own status event. Active gateways also poll uncached children.
	return ctrl.NewControllerManagedBy(mgr).
		Named("tailnetgateway").
		For(&tnv1.TailnetGateway{}).
		Complete(r)
}
