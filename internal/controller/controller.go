// Package controller holds the reconcilers (Tailnet, TailnetEgress, TailnetIngress, TailnetDNS,
// TailnetPolicy) and the resources they write. The operator only ever writes Kubernetes objects and
// talks to the Headscale REST API (nodes, keys and — when enabled — the policy document); it never
// speaks tailscale itself — the agent does that, and reports back over HTTP, mirroring the
// tor-operator's split.
package controller

import (
	"context"

	"sigs.k8s.io/controller-runtime/pkg/client"
)

// ssaApply server-side-applies obj as the operator's field manager, taking ownership of the fields
// it sets. Every child object goes through here so a hand-edit to a managed field is corrected on the
// next reconcile.
func ssaApply(ctx context.Context, c client.Client, obj client.Object) error {
	return c.Patch(ctx, obj, client.Apply, client.FieldOwner(fieldOwner), client.ForceOwnership)
}
