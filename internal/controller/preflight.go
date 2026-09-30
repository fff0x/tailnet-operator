package controller

import (
	"context"
	"fmt"

	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	tnv1 "this-is-fine.io/tailnet-operator/api/v1alpha1"
	"this-is-fine.io/tailnet-operator/internal/headscale"
	"this-is-fine.io/tailnet-operator/internal/naming"
)

func preflightConditions(ctx context.Context, hs *headscale.Client, tn *tnv1.Tailnet) bool {
	caps, err := hs.Probe(ctx)
	setPreflightConditions(tn, caps, err)
	if caps.DBHealth != nil && !*caps.DBHealth {
		setCond(&tn.Status.Conditions, tn.Generation, "ApiReachable", metav1.ConditionFalse, "Unhealthy",
			"authenticated health check reports no database connectivity")
		return false
	}
	return err == nil
}

func setPreflightConditions(tn *tnv1.Tailnet, caps headscale.Capabilities, probeErr error) {
	modeStatus, modeReason := metav1.ConditionUnknown, "CannotVerify"
	modeMsg := "policy response has no mode evidence; expected an explicit updatedAt timestamp (database) or null (file)"
	if caps.PolicyDatabaseMode != nil {
		if *caps.PolicyDatabaseMode {
			modeStatus, modeReason, modeMsg = metav1.ConditionTrue, "Database", "policy response identifies database mode"
		} else {
			modeStatus, modeReason, modeMsg = metav1.ConditionFalse, "File", "operator cannot write policy; set policy.mode: database"
		}
	} else if probeErr != nil {
		modeReason, modeMsg = "ProbeFailed", "could not determine policy mode; check API reachability, key validity and Headscale logs"
	}
	setCond(&tn.Status.Conditions, tn.Generation, "PolicyMode", modeStatus, modeReason, modeMsg)

	status, reason := metav1.ConditionUnknown, "CannotVerify"
	msg := "cannot verify required Headscale capabilities from the API response"
	switch {
	case probeErr != nil:
		reason, msg = "ProbeFailed", "capability probe failed; check API reachability, key validity and Headscale logs"
	case caps.PolicyDatabaseMode != nil && !*caps.PolicyDatabaseMode:
		status, reason, msg = metav1.ConditionFalse, "Incompatible", "database policy mode is required; set policy.mode: database"
	case caps.PolicyCheck != nil && !*caps.PolicyCheck:
		status, reason, msg = metav1.ConditionFalse, "Incompatible", "policy/check endpoint missing; Headscale 0.29 or later is required"
	case caps.PolicyDatabaseMode != nil && caps.PolicyCheck != nil && *caps.PolicyDatabaseMode && *caps.PolicyCheck:
		status, reason, msg = metav1.ConditionTrue, "Compatible", "database policy mode and policy/check are available"
	}
	if tn.Spec.Headscale.Version != "" {
		msg += fmt.Sprintf(" (configured version hint %q; not detected)", truncate(tn.Spec.Headscale.Version, 64))
	}
	// Do not copy upstream response bodies into status: gateways can echo bearer tokens or policies.
	setCond(&tn.Status.Conditions, tn.Generation, "HeadscaleCompatible", status, reason, msg)
	setSplitDNSCondition(tn)
}

func setSplitDNSCondition(tn *tnv1.Tailnet) {
	zone := naming.ZoneOf(tn.Spec.DNS.IngressNameTemplate)
	if zone == "" {
		meta.RemoveStatusCondition(&tn.Status.Conditions, "SplitDNS")
		return
	}
	setCond(&tn.Status.Conditions, tn.Generation, "SplitDNS", metav1.ConditionUnknown, "CannotVerify",
		fmt.Sprintf("Headscale has no DNS API; expected dns.nameservers.split.%s to point to your gateway DNS Service IP", zone))
}
