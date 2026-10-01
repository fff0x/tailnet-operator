// Package v1alpha1 holds the tailnet-operator API types.
//
// Two kinds, one per scope:
//   - Tailnet        (cluster-scoped): a Headscale/Tailscale control server the cluster talks to.
//   - TailnetEgress  (namespaced):     a per-CR egress identity into that tailnet.
//
// Nothing here is organisation-specific: tag and hostname schemes are templates on Tailnet, and the
// control server, its API and image all come from the CR. That is the whole point — the operator is
// meant to run against any Headscale.
// +kubebuilder:object:generate=true
// +groupName=tsunaro.io
package v1alpha1

import (
	"k8s.io/apimachinery/pkg/runtime/schema"
	"sigs.k8s.io/controller-runtime/pkg/scheme"
)

// GroupVersion is the API group/version for all kinds in this package.
var GroupVersion = schema.GroupVersion{Group: "tsunaro.io", Version: "v1alpha1"}

// SchemeBuilder registers the kinds into a runtime.Scheme.
var SchemeBuilder = &scheme.Builder{GroupVersion: GroupVersion}

// AddToScheme adds the kinds in this package to a scheme.
var AddToScheme = SchemeBuilder.AddToScheme
