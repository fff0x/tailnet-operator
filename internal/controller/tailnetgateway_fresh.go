package controller

import (
	"context"
	"time"

	"k8s.io/apimachinery/pkg/api/equality"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"

	tnv1 "tsunaro.io/tailnet-operator/api/v1alpha1"
	"tsunaro.io/tailnet-operator/internal/gateway"
	"tsunaro.io/tailnet-operator/internal/headscale"
)

func (r *TailnetGatewayReconciler) reconcileFresh(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	g := &tnv1.TailnetGateway{}
	if err := r.RuntimeClient.Get(ctx, req.NamespacedName, g); err != nil {
		return ctrl.Result{}, &gatewayAPIError{operation: "fresh resource read", cause: err}
	}
	if g.DeletionTimestamp != nil || g.Spec.Suspend == nil || *g.Spec.Suspend {
		return ctrl.Result{}, nil
	}
	before := g.DeepCopy()
	observation, reason := r.observeFreshRuntime(ctx, g)
	message := "Fresh prerequisites or retained provenance are unverified; no adoption or automatic retry of partial creation."
	ready := metav1.ConditionFalse
	if reason == "Provisioning" {
		message = "Fresh resources are retained; waiting for a running Pod and verified persistent identity."
	}
	if observation.Ready {
		reason = "FreshRuntimeReady"
		ready = metav1.ConditionTrue
		message = "Fresh Pod is running with verified persistent identity and advertised routes; route approval and cluster DNS forwarding remain external."
	}
	g.Status.ObservedGeneration = g.Generation
	for _, name := range []string{"Registered", "DNSReady", "Ready"} {
		status := ready
		meta.SetStatusCondition(&g.Status.Conditions, metav1.Condition{Type: name, Status: status, Reason: reason, Message: message, ObservedGeneration: g.Generation})
	}
	for _, name := range []string{"RoutesInSync", "StaleNodes", "ClusterDNSForward"} {
		meta.SetStatusCondition(&g.Status.Conditions, metav1.Condition{Type: name, Status: metav1.ConditionUnknown, Reason: "ExternallyManaged", Message: "Fresh bootstrap does not manage route approvals, stale nodes or cluster DNS forwarding.", ObservedGeneration: g.Generation})
	}
	if observation.Ready {
		g.Status.NodeID, g.Status.IPv4 = observation.Binding.NodeID, observation.Binding.IPv4
		g.Status.RoutesAdvertised, g.Status.RoutesApproved = observation.Routes, observation.Approved
	}
	if !equality.Semantic.DeepEqual(before.Status, g.Status) {
		if err := r.RuntimeClient.Status().Patch(ctx, g, client.MergeFromWithOptions(before, client.MergeFromWithOptimisticLock{})); err != nil {
			return ctrl.Result{}, &gatewayAPIError{operation: "fresh status write", cause: err}
		}
	}
	return ctrl.Result{RequeueAfter: 5 * time.Second}, nil
}

func (r *TailnetGatewayReconciler) observeFreshRuntime(ctx context.Context, g *tnv1.TailnetGateway) (gateway.FreshObservation, string) {
	tn := &tnv1.Tailnet{}
	if r.RuntimeClient.Get(ctx, client.ObjectKey{Name: string(g.Spec.TailnetRef.Name)}, tn) != nil {
		return gateway.FreshObservation{}, "NoTailnet"
	}
	token, err := readWorkingKey(ctx, r.RuntimeClient, r.OperatorNamespace, tn.Name)
	if err != nil {
		return gateway.FreshObservation{}, "NoAPIKey"
	}
	endpoint := tn.Spec.APIURL
	if endpoint == "" {
		endpoint = tn.Spec.Server
	}
	// This is the same working-key and API-endpoint selection used by egress.
	// Neither credential values nor arbitrary server/API errors enter status/logs.
	hs := headscale.New(endpoint, token)
	observation, err := gateway.ReconcileFresh(ctx, r.RuntimeClient, r.OperatorNamespace, g, tn, hs, time.Now)
	if err != nil {
		return gateway.FreshObservation{}, "FreshBlocked"
	}
	return observation, "Provisioning"
}
