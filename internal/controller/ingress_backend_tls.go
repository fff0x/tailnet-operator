package controller

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"net"
	"time"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/validation"
	"sigs.k8s.io/controller-runtime/pkg/client"

	tnv1 "tsunaro.io/tailnet-operator/api/v1alpha1"
	"tsunaro.io/tailnet-operator/internal/certificates"
	"tsunaro.io/tailnet-operator/internal/httpconfig"
	"tsunaro.io/tailnet-operator/internal/naming"
)

func safeIngressHTTPExtensions(e tnv1.Expose) bool {
	if (e.Backend.TLS != nil || e.Timeouts != nil) && e.Mode != "http" {
		return false
	}
	if tls := e.Backend.TLS; tls != nil {
		if naming.ValidateDNSName(tls.ServerName) != nil || net.ParseIP(tls.ServerName) != nil ||
			len(validation.IsDNS1123Subdomain(tls.CAConfigMapRef.Name)) != 0 ||
			tls.CAConfigMapRef.Key == "" || len(validation.IsConfigMapKey(tls.CAConfigMapRef.Key)) != 0 {
			return false
		}
	}
	if e.Timeouts != nil {
		for _, timeout := range []*string{e.Timeouts.Request, e.Timeouts.BackendRequest} {
			if timeout != nil {
				if _, err := httpconfig.ParseDuration(*timeout); err != nil {
					return false
				}
			}
		}
	}
	return true
}

// Public trust source inspection is distinct from a verified handshake by the agent.
// Raw source bytes are hashed so a delayed or stale kubelet projection cannot report green.
type ingressBackendTLSState struct {
	sha256 string
	reason string
}

func (r *TailnetIngressReconciler) prepareIngressBackendTLS(ctx context.Context, in *tnv1.TailnetIngress) map[string]ingressBackendTLSState {
	states := make(map[string]ingressBackendTLSState)
	for _, e := range in.Spec.Exposes {
		if e.Backend.TLS == nil {
			continue
		}
		state := ingressBackendTLSState{}
		switch {
		case !safeIngressHTTPExtensions(e):
			state.reason = "BackendTLSConfigurationInvalid"
		case r.Client == nil:
			state.reason = "BackendCAUnavailable"
		default:
			ref := e.Backend.TLS.CAConfigMapRef
			var cm corev1.ConfigMap
			// Deliberately use the cached Client, not the frontend Secret reader, and
			// never the backend Service namespace.
			err := r.Get(ctx, types.NamespacedName{Namespace: in.Namespace, Name: ref.Name}, &cm)
			switch {
			case apierrors.IsNotFound(err):
				state.reason = "BackendCAMissing"
			case apierrors.IsForbidden(err):
				state.reason = "BackendCAForbidden"
			case err != nil:
				state.reason = "BackendCAUnavailable"
			case cm.DeletionTimestamp != nil:
				state.reason = "BackendCAMissing"
			default:
				data, found := cm.BinaryData[ref.Key]
				if text, ok := cm.Data[ref.Key]; ok {
					if found { // Kubernetes rejects overlap; remain fail-closed if admission was bypassed.
						state.reason = "BackendCAInvalid"
						break
					}
					data, found = []byte(text), true
				}
				if !found {
					state.reason = "BackendCAMissing"
				} else if _, err := certificates.ParseCABundle(data); err != nil {
					state.reason = "BackendCAInvalid"
				} else {
					digest := sha256.Sum256(data)
					state.sha256 = hex.EncodeToString(digest[:])
				}
			}
		}
		states[e.Name] = state
	}
	return states
}

func ingressBackendTLSReason(state ingressBackendTLSState, probe ingressProbe, expected string, probeErr error, now time.Time) string {
	switch {
	case state.reason != "":
		return state.reason
	case probeErr != nil:
		return "BackendTLSProbeFailed"
	case expected == "" || probe.ConfigID != expected:
		return "BackendTLSConfigMismatch"
	case !ingressProbeFresh(probe, now):
		return "BackendTLSProbeStale"
	case probe.BackendReachable == nil || !*probe.BackendReachable || probe.BackendTLSReason != "":
		// Failed handshakes intentionally omit their digest. Do not misclassify
		// those as successful handshakes against a delayed CA projection, and
		// never copy agent-provided diagnostics into Kubernetes status.
		return "BackendTLSVerificationFailed"
	case state.sha256 == "" || probe.BackendCAHash != state.sha256:
		return "BackendCAMismatch"
	case probe.BackendTLSNotAfter == nil || !now.Before(*probe.BackendTLSNotAfter):
		return "BackendTLSCertificateExpired"
	default:
		return ""
	}
}

// ConfigMaps are public, namespace-local references, not owned children. Include deletes
// and empty/invalid HTTP intent so an old successful backend observation is invalidated.
func (r *TailnetIngressReconciler) ingressesForBackendCA(ctx context.Context, obj client.Object) []types.NamespacedName {
	var list tnv1.TailnetIngressList
	if err := r.List(ctx, &list, client.InNamespace(obj.GetNamespace())); err != nil {
		return nil
	}
	var out []types.NamespacedName
	for _, in := range list.Items {
		for _, e := range in.Spec.Exposes {
			if e.Backend.TLS != nil && e.Backend.TLS.CAConfigMapRef.Name == obj.GetName() {
				out = append(out, client.ObjectKeyFromObject(&in))
				break
			}
		}
	}
	return out
}
