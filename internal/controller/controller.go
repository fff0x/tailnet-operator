// Package controller holds the reconcilers (Tailnet, TailnetEgress, TailnetIngress, TailnetDNS) and the resources they write. The operator only ever
// writes Kubernetes objects and talks to the Headscale REST API; it never speaks tailscale itself —
// the agent does that, and reports back over HTTP, mirroring the tor-operator's split.
package controller

import (
	"context"

	"github.com/prometheus/client_golang/prometheus"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/metrics"
)

var (
	// apiKeyExpiresSeconds tracks the working API key's remaining life; alert when it stops rising
	// after a rotation should have happened.
	apiKeyExpiresSeconds = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "tailnet_apikey_expires_seconds",
		Help: "Seconds until the operator's working Headscale API key expires.",
	}, []string{"tailnet"})

	// authKeyExpiresSeconds tracks each CR's pre-auth key.
	authKeyExpiresSeconds = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "tailnetegress_authkey_expires_seconds",
		Help: "Seconds until a TailnetEgress pre-auth key expires.",
	}, []string{"namespace", "name"})

	// routesMissing is the count of target routes not present in a CR's netmap — the headline
	// symptom, broken down by reason only in the CR status.
	routesMissing = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "tailnetegress_routes_missing",
		Help: "Number of target routes missing from a TailnetEgress netmap.",
	}, []string{"namespace", "name"})

	// ingressAuthKeyExpiresSeconds tracks each TailnetIngress's pre-auth key.
	ingressAuthKeyExpiresSeconds = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "tailnetingress_authkey_expires_seconds",
		Help: "Seconds until a TailnetIngress pre-auth key expires.",
	}, []string{"namespace", "name"})

	// ingressBackendsUnreachable is the count of a TailnetIngress's backends the agent could not
	// reach on its last probe.
	ingressBackendsUnreachable = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "tailnetingress_backends_unreachable",
		Help: "Number of in-cluster backends a TailnetIngress agent could not reach.",
	}, []string{"namespace", "name"})
)

func init() {
	metrics.Registry.MustRegister(apiKeyExpiresSeconds, authKeyExpiresSeconds, routesMissing,
		ingressAuthKeyExpiresSeconds, ingressBackendsUnreachable)
}

// ssaApply server-side-applies obj as the operator's field manager, taking ownership of the fields
// it sets. Every child object goes through here so a hand-edit to a managed field is corrected on the
// next reconcile.
func ssaApply(ctx context.Context, c client.Client, obj client.Object) error {
	return c.Patch(ctx, obj, client.Apply, client.FieldOwner(fieldOwner), client.ForceOwnership)
}
