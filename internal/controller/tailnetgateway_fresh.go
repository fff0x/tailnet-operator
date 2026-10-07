package controller

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/equality"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	"sigs.k8s.io/controller-runtime/pkg/log"

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
	observation, tn, reason := r.observeFreshRuntime(ctx, g)
	message := "Fresh prerequisites or retained provenance are unverified; no adoption or automatic retry of partial creation."
	ready := metav1.ConditionFalse
	if reason == "Provisioning" {
		message = "Fresh resources are retained; waiting for a running Pod and verified persistent identity."
	}
	if reason == "IdentityChanged" {
		message = "Identity fields pinned at creation (tailnetRef, hostname, stateSecretRef, tags, replicas, service.loadBalancerIP/loadBalancerClass, dns zone/service/extraZones, forwards; Tailnet server and dns.hostsConfigMap) differ from the completion receipt, or the receipt predates format 3. Nothing is written: revert the change, or delete with deletionPolicy=Delete and recreate."
	}
	if observation.Ready {
		reason = "FreshRuntimeReady"
		ready = metav1.ConditionTrue
		message = "Fresh Pod is running with verified persistent identity and advertised routes; route approval and cluster DNS forwarding remain external."
	}
	g.Status.ObservedGeneration = g.Generation
	meta.SetStatusCondition(&g.Status.Conditions, metav1.Condition{Type: "Registered", Status: ready, Reason: reason, Message: message, ObservedGeneration: g.Generation})
	meta.SetStatusCondition(&g.Status.Conditions, metav1.Condition{Type: "Ready", Status: ready, Reason: reason, Message: message, ObservedGeneration: g.Generation})
	// Live DNS runs only once the writer confirms a verified completion receipt;
	// before that, the derived zone has no persisted state to reconcile.
	dnsStatus, dnsReason, dnsMessage := metav1.ConditionFalse, reason, message
	if observation.Completed {
		switch err := gateway.UpdateDNSRevision(ctx, r.RuntimeClient, g.Name, r.OperatorNamespace); {
		case err == nil:
			dnsStatus, dnsReason, dnsMessage = metav1.ConditionTrue, "DNSInSync", "Derived zone matches the Tailnet hosts source at the recorded serial."
		case errors.Is(err, gateway.ErrDNSWriteConflict):
			dnsStatus, dnsReason, dnsMessage = metav1.ConditionFalse, "DNSUpdateConflict", "Concurrent change on the derived zone; a later reconcile will retry."
		default:
			dnsStatus, dnsReason, dnsMessage = metav1.ConditionFalse, "DNSUpdateBlocked", "Derived zone source, target or revision annotations are not verified; no update is attempted."
		}
	}
	meta.SetStatusCondition(&g.Status.Conditions, metav1.Condition{Type: "DNSReady", Status: dnsStatus, Reason: dnsReason, Message: dnsMessage, ObservedGeneration: g.Generation})
	// Images, routes (TS_ROUTES) and LB pool labels follow the spec. The running Pod is never
	// restarted by the operator (StatefulSet OnDelete): staleness is reported.
	if observation.Completed {
		status, wReason, wMessage := r.reconcileWorkload(ctx, g, tn, observation)
		meta.SetStatusCondition(&g.Status.Conditions, metav1.Condition{Type: "WorkloadCurrent", Status: status, Reason: wReason, Message: wMessage, ObservedGeneration: g.Generation})
	} else {
		meta.RemoveStatusCondition(&g.Status.Conditions, "WorkloadCurrent")
	}
	if observation.Completed {
		meta.SetStatusCondition(&g.Status.Conditions, serviceReady(g, observation))
	} else {
		meta.RemoveStatusCondition(&g.Status.Conditions, "ServiceReady")
	}
	meta.SetStatusCondition(&g.Status.Conditions, routesInSync(g, observation, tn, reason))
	for _, name := range []string{"StaleNodes", "ClusterDNSForward"} {
		meta.SetStatusCondition(&g.Status.Conditions, metav1.Condition{Type: name, Status: metav1.ConditionUnknown, Reason: "ExternallyManaged", Message: "Fresh bootstrap does not manage stale nodes or cluster DNS forwarding.", ObservedGeneration: g.Generation})
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

// reconcileWorkload brings the Service pool labels and the StatefulSet template (images, routes,
// env, container ports) in line with the spec and reports whether the running Pod already matches.
func (r *TailnetGatewayReconciler) reconcileWorkload(ctx context.Context, g *tnv1.TailnetGateway, tn *tnv1.Tailnet, o gateway.FreshObservation) (metav1.ConditionStatus, string, string) {
	plan, err := gateway.PlanSpecRoutes(ctx, r.RuntimeClient, r.OperatorNamespace, g)
	if err != nil {
		return metav1.ConditionFalse, "WorkloadUpdateBlocked", "Spec routes do not plan (invalid prefix, tailnetLBCIDR without loadBalancerIP, or a non-IPv4 route); nothing is written."
	}
	// Both writes are attempted independently: a blocked Service never stalls the template.
	svcErr := gateway.UpdateServiceRevision(ctx, r.RuntimeClient, r.OperatorNamespace, g, o)
	switch err := gateway.UpdateWorkloadRevision(ctx, r.RuntimeClient, r.OperatorNamespace, g, tn, o, plan.Routes); {
	case errors.Is(err, gateway.ErrWorkloadConflict):
		return metav1.ConditionFalse, "WorkloadUpdateConflict", "Concurrent change on the StatefulSet; a later reconcile will retry."
	case err != nil:
		return metav1.ConditionFalse, "WorkloadUpdateBlocked", "StatefulSet or completion receipt is not verified; the Pod template is not updated."
	}
	switch {
	case errors.Is(svcErr, gateway.ErrServiceConflict):
		return metav1.ConditionFalse, "ServiceUpdateConflict", "Concurrent change on the LoadBalancer Service; a later reconcile will retry."
	case svcErr != nil:
		return metav1.ConditionFalse, "ServiceUpdateBlocked", "LoadBalancer Service or completion receipt is not verified, or a pool label key already exists on the Service; the Service is not updated."
	}
	if !o.PodPresent {
		return metav1.ConditionUnknown, "Provisioning", "No verified Pod yet."
	}
	var pending []string
	for _, route := range plan.Routes {
		if !slices.Contains(o.PodRoutes, route) {
			pending = append(pending, route)
		}
	}
	if o.PodCurrent && slices.Equal(o.PodRoutes, plan.Routes) {
		return metav1.ConditionTrue, "PodCurrent", "Running Pod matches the template wanted by the spec."
	}
	message := "StatefulSet follows the spec; delete Pod " + g.Name + "-0 to apply it (OnDelete). The running Pod keeps serving."
	if len(pending) > 0 {
		message += " Routes not yet advertised: " + strings.Join(pending, ", ") + "."
	}
	if len(o.PodRoutes) > len(plan.Routes)-len(pending) {
		message += " Routes the Pod advertises beyond the spec stay until it restarts."
	}
	return metav1.ConditionFalse, "PodTemplateStale", message
}

// routesInSync reports whether Headscale approved every route the completion receipt advertises.
// It only reads: approvals come from the policy controller (autoApprovers replay), never from here.
func routesInSync(g *tnv1.TailnetGateway, o gateway.FreshObservation, tn *tnv1.Tailnet, reason string) metav1.Condition {
	c := metav1.Condition{Type: "RoutesInSync", Status: metav1.ConditionUnknown, Reason: reason, Message: "Routes are judged once the gateway is Ready.", ObservedGeneration: g.Generation}
	if !o.Ready {
		return c
	}
	var missing []string
	for _, route := range o.Routes {
		if !slices.Contains(o.Approved, route) {
			missing = append(missing, route)
		}
	}
	if len(missing) == 0 {
		c.Status, c.Reason, c.Message = metav1.ConditionTrue, "Approved", "Every advertised route is approved."
		return c
	}
	c.Status, c.Reason = metav1.ConditionFalse, "NotApproved"
	c.Message = "Advertised but not approved: " + strings.Join(missing, ", ") + ". "
	if tn != nil && policyOwned(tn) {
		c.Message += "The policy controller approves them from autoApprovers within 5 minutes; if this persists, check the Tailnet's PolicyRendered condition."
	} else {
		c.Message += "The Tailnet does not own its policy (needs policy.baseConfigMap and mode Apply): approve them in Headscale (headscale nodes approve-routes) or via your own autoApprovers."
	}
	return c
}

func (r *TailnetGatewayReconciler) observeFreshRuntime(ctx context.Context, g *tnv1.TailnetGateway) (gateway.FreshObservation, *tnv1.Tailnet, string) {
	tn, hs, reason := r.freshHeadscale(ctx, g)
	if hs == nil {
		return gateway.FreshObservation{}, tn, reason
	}
	observation, err := gateway.ReconcileFresh(ctx, r.RuntimeClient, r.OperatorNamespace, g, tn, hs, time.Now)
	if errors.Is(err, gateway.ErrFreshIdentity) {
		return gateway.FreshObservation{}, tn, "IdentityChanged"
	}
	if err != nil {
		return gateway.FreshObservation{}, tn, "FreshBlocked"
	}
	return observation, tn, "Provisioning"
}

// freshHeadscale resolves the Tailnet and an authenticated client, or a reason.
func (r *TailnetGatewayReconciler) freshHeadscale(ctx context.Context, g *tnv1.TailnetGateway) (*tnv1.Tailnet, *headscale.Client, string) {
	tn := &tnv1.Tailnet{}
	if r.RuntimeClient.Get(ctx, client.ObjectKey{Name: string(g.Spec.TailnetRef.Name)}, tn) != nil {
		return nil, nil, "NoTailnet"
	}
	token, err := readWorkingKey(ctx, r.RuntimeClient, r.OperatorNamespace, tn.Name)
	if err != nil {
		return nil, nil, "NoAPIKey"
	}
	endpoint := tn.Spec.APIURL
	if endpoint == "" {
		endpoint = tn.Spec.Server
	}
	// This is the same working-key and API-endpoint selection used by egress.
	// Neither credential values nor arbitrary server/API errors enter status/logs.
	return tn, headscale.New(endpoint, token), ""
}

// reconcileTeardown runs only for a terminating CR that carries the teardown
// finalizer. Switching deletionPolicy back to Retain while terminating drops the
// finalizer and retains everything; Headscale or attribution failures block.
func (r *TailnetGatewayReconciler) reconcileTeardown(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	g := &tnv1.TailnetGateway{}
	if err := r.RuntimeClient.Get(ctx, req.NamespacedName, g); err != nil {
		if client.IgnoreNotFound(err) == nil {
			return ctrl.Result{}, nil
		}
		return ctrl.Result{}, &gatewayAPIError{operation: "teardown resource read", cause: err}
	}
	if g.DeletionTimestamp == nil || !controllerutil.ContainsFinalizer(g, gateway.TeardownFinalizer) {
		return ctrl.Result{}, nil
	}
	progress, reason := gateway.TeardownProgress{}, "Deleting"
	if g.Spec.DeletionPolicy != tnv1.GatewayDeletionPolicyDelete {
		progress, reason = gateway.TeardownProgress{Step: "retained", Done: true}, "Retained"
	} else if tn, hs, why := r.freshHeadscale(ctx, g); hs == nil {
		progress, reason = gateway.TeardownProgress{Step: why}, "TeardownBlocked"
	} else if p, err := gateway.TeardownFresh(ctx, r.RuntimeClient, r.OperatorNamespace, g, tn, hs); err != nil {
		progress, reason = p, "TeardownBlocked"
	} else {
		progress = p
	}
	if progress.Done {
		before := g.DeepCopy()
		controllerutil.RemoveFinalizer(g, gateway.TeardownFinalizer)
		if err := r.RuntimeClient.Patch(ctx, g, client.MergeFromWithOptions(before, client.MergeFromWithOptimisticLock{})); err != nil {
			return ctrl.Result{}, &gatewayAPIError{operation: "finalizer removal", cause: err}
		}
		// Bounded fields only; the receipt inventory and Headscale IDs stay out of logs.
		log.FromContext(ctx).Info("gateway teardown finished; finalizer released", "gateway", g.Name, "outcome", reason)
		if r.Recorder != nil {
			r.Recorder.Eventf(g, corev1.EventTypeNormal, "GatewayTeardownFinished", "teardown finished (%s); finalizer released", reason)
		}
		return ctrl.Result{}, nil
	}
	before := g.DeepCopy()
	g.Status.ObservedGeneration = g.Generation
	message := "Teardown in progress; step: " + progress.Step + "."
	if reason == "TeardownBlocked" {
		message = "Teardown blocked at step " + progress.Step + "; nothing further is deleted. Set deletionPolicy=Retain to release the finalizer and keep all resources."
	}
	meta.RemoveStatusCondition(&g.Status.Conditions, "WorkloadCurrent")
	meta.RemoveStatusCondition(&g.Status.Conditions, "ServiceReady")
	for _, name := range []string{"Registered", "RoutesInSync", "DNSReady", "StaleNodes", "ClusterDNSForward", "Ready"} {
		status := metav1.ConditionUnknown
		if name == "Ready" {
			status = metav1.ConditionFalse
		}
		meta.SetStatusCondition(&g.Status.Conditions, metav1.Condition{Type: name, Status: status, Reason: reason, Message: message, ObservedGeneration: g.Generation})
	}
	if !equality.Semantic.DeepEqual(before.Status, g.Status) {
		if err := r.RuntimeClient.Status().Patch(ctx, g, client.MergeFromWithOptions(before, client.MergeFromWithOptimisticLock{})); err != nil {
			return ctrl.Result{}, &gatewayAPIError{operation: "teardown status write", cause: err}
		}
	}
	return ctrl.Result{RequeueAfter: 5 * time.Second}, nil
}

// serviceReady reports the platform's LoadBalancer allocation, which Ready deliberately ignores:
// a gateway can be registered and serving routes while its Service address is still being assigned.
func serviceReady(g *tnv1.TailnetGateway, o gateway.FreshObservation) metav1.Condition {
	c := metav1.Condition{Type: "ServiceReady", ObservedGeneration: g.Generation}
	if len(o.LoadBalancerIPs) == 0 {
		c.Status, c.Reason, c.Message = metav1.ConditionFalse, "LBPending",
			"the LoadBalancer Service has no assigned address yet; check the load balancer controller and its address pool"
		return c
	}
	c.Status, c.Reason, c.Message = metav1.ConditionTrue, "LoadBalancerAssigned",
		fmt.Sprintf("the LoadBalancer Service is assigned %s", strings.Join(o.LoadBalancerIPs, ", "))
	return c
}
