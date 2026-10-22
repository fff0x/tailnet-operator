package controller

import (
	"context"
	"fmt"
	"sort"
	"strconv"
	"strings"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	tnv1 "tsunaro.io/tailnet-operator/api/v1alpha1"
	"tsunaro.io/tailnet-operator/internal/headscale"
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
}

// userConditions lists Headscale users and reports names shared by more than one user as
// UsersUnique=False/Duplicate. Headscale refuses every policy write while such a collision exists
// ("multiple users found"), so without this check the operator only notices at the next policy
// change. The message carries counts and user IDs, never a name: user names are e-mail addresses.
func userConditions(ctx context.Context, hs *headscale.Client, tn *tnv1.Tailnet) {
	users, err := hs.ListUsers(ctx)
	if err != nil {
		tn.Status.UserConflicts = 0
		setCond(&tn.Status.Conditions, tn.Generation, "UsersUnique", metav1.ConditionUnknown, "CannotVerify",
			"could not list Headscale users; check API reachability, key validity and Headscale logs")
		return
	}
	names, ids := duplicateUsers(users)
	tn.Status.UserConflicts = int32(len(names))
	if len(names) == 0 {
		setCond(&tn.Status.Conditions, tn.Generation, "UsersUnique", metav1.ConditionTrue, "Unique",
			fmt.Sprintf("%d Headscale user(s), no shared names", len(users)))
		return
	}
	setCond(&tn.Status.Conditions, tn.Generation, "UsersUnique", metav1.ConditionFalse, "Duplicate",
		fmt.Sprintf("%d user name(s) shared by Headscale user IDs %s; policy writes are rejected until the duplicates are removed (headscale users destroy)",
			len(names), strings.Join(ids, ",")))
}

// duplicateUsers returns the shared names (count only matters to callers) and the sorted IDs of
// every user involved in a collision. Comparison is exact: Headscale matches tokens literally.
func duplicateUsers(users []headscale.User) (names []string, ids []string) {
	byName := map[string][]string{}
	for _, u := range users {
		byName[u.Name] = append(byName[u.Name], u.ID)
	}
	for name, list := range byName {
		if len(list) > 1 {
			names = append(names, name)
			ids = append(ids, list...)
		}
	}
	sort.Strings(names)
	sort.Slice(ids, func(i, j int) bool {
		a, errA := strconv.Atoi(ids[i])
		b, errB := strconv.Atoi(ids[j])
		if errA != nil || errB != nil {
			return ids[i] < ids[j]
		}
		return a < b
	})
	return names, ids
}
