// Package controller holds the reconcilers (Tailnet, TailnetEgress, TailnetIngress, TailnetDNS,
// TailnetPolicy) and the resources they write. The operator only ever writes Kubernetes objects and
// talks to the Headscale REST API (nodes, keys and — when enabled — the policy document); it never
// speaks tailscale itself — the agent does that, and reports back over HTTP, mirroring the
// tor-operator's split.
package controller

import (
	"context"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

// ssaApply server-side-applies obj as the operator's field manager, taking ownership of the fields
// it sets. Every child object goes through here so a hand-edit to a managed field is corrected on the
// next reconcile.
func ssaApply(ctx context.Context, c client.Client, obj client.Object) error {
	return c.Patch(ctx, obj, client.Apply, client.FieldOwner(fieldOwner), client.ForceOwnership)
}

// workloadBlocked returns the reason an agent Deployment cannot create its pods — a LimitRange or
// ResourceQuota rejecting the request, PodSecurity, a missing pull Secret — read from the Deployment
// condition ReplicaFailure the apps controller sets from the ReplicaSet's FailedCreate. Empty when
// the Deployment is absent or its pods create fine, so an agent that simply has not registered yet
// keeps its NotRegistered reason. The message is the admission text (no secrets), capped like policy
// rejections.
func workloadBlocked(ctx context.Context, c client.Client, key types.NamespacedName) string {
	var dep appsv1.Deployment
	if err := c.Get(ctx, key, &dep); err != nil {
		return "" // absent or unreadable: nothing to report
	}
	for _, cond := range dep.Status.Conditions {
		if cond.Type == appsv1.DeploymentReplicaFailure && cond.Status == corev1.ConditionTrue {
			msg := cond.Message
			if len(msg) > 1024 {
				msg = msg[:1024] + "…"
			}
			return msg
		}
	}
	return ""
}
