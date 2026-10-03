package controller

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"

	tnv1 "tsunaro.io/tailnet-operator/api/v1alpha1"
)

// Source inspection, projected material and a live local TLS observation are separate facts.
// None of these proves that a remote tailnet peer can reach the listener.
type ingressTLSState struct {
	plan          ingressTLSPlan
	leaf          servingCertificate
	reason        string
	uncoveredName string
	required      bool
	backends      map[string]ingressBackendTLSState
}

func (r *TailnetIngressReconciler) prepareIngressTLS(ctx context.Context, in *tnv1.TailnetIngress, tn *tnv1.Tailnet, now time.Time) ingressTLSState {
	intentBase := in.DeepCopy()
	previousSecret := in.Status.TLSSecretName
	oldManaged := previousSecret == in.Name+"-tls" || meta.FindStatusCondition(in.Status.Conditions, "TLSCleanup") != nil
	plan, reason := resolveIngressTLS(in, tn)
	state := ingressTLSState{plan: plan, reason: reason, required: ingressHTTPProtocol(in),
		backends: r.prepareIngressBackendTLS(ctx, in)}
	in.Status.TLSSecretName, in.Status.TLSNotAfter = "", nil
	if reason != "" {
		// The old generated name is no longer the selected source, but a rejected
		// selection must not lose the cleanup obligation for a later valid transition.
		if oldManaged {
			setCond(&in.Status.Conditions, in.Generation, "TLSCleanup", metav1.ConditionFalse, reason,
				"previous owned Certificate remains tracked until TLS source selection is resolved")
		}
		// Do not project references from a rejected source selection.
		state.plan = ingressTLSPlan{names: plan.names}
		return state
	}
	if oldManaged && plan.issuer == nil {
		if cleanupReason := removeIngressCertificate(ctx, r.Certificates, in, plan.secretName); cleanupReason != "" {
			// Retain a retry marker even after status switches to the new Secret. Cleanup
			// of unused material must not prevent L4 or a valid external Secret from working.
			setCond(&in.Status.Conditions, in.Generation, "TLSCleanup", metav1.ConditionFalse, cleanupReason,
				"previous owned Certificate cleanup is pending; no external Secret is deleted")
		} else {
			meta.RemoveStatusCondition(&in.Status.Conditions, "TLSCleanup")
		}
	} else if plan.issuer != nil {
		meta.RemoveStatusCondition(&in.Status.Conditions, "TLSCleanup")
	}
	if !plan.http {
		return state
	}
	in.Status.TLSSecretName = plan.secretName
	if plan.issuer != nil && previousSecret != plan.secretName {
		// Record the cleanup obligation before creating a child. A crash or failed final
		// status write must not leave an owned Certificate invisible to later source changes.
		setCond(&in.Status.Conditions, in.Generation, "TLSReady", metav1.ConditionFalse, "TLSCertificatePending",
			"managed Certificate source is pending")
		setCond(&in.Status.Conditions, in.Generation, "Ready", metav1.ConditionFalse, "TLSCertificatePending",
			"HTTP requires a current local TLS observation and reachable backend")
		if r.Client == nil {
			state.reason = "TLSCertificateUnavailable"
			return state
		}
		// Patch only this function's status changes. DNS/node observations already being
		// computed by Reconcile must not be published before their own validation.
		intent := in.DeepCopy()
		patch := client.MergeFromWithOptions(intentBase, client.MergeFromWithOptimisticLock{})
		if err := patchObservedStatus(ctx, r.Client, r.Metrics, intent, patch); err != nil {
			state.reason = "TLSCertificateUnavailable"
			if apierrors.IsConflict(err) {
				state.reason = "TLSCertificatePending"
			}
			return state
		}
		in.ResourceVersion = intent.ResourceVersion
	}
	reader := r.SecretReader
	if reader == nil {
		reader = r.Client
	}
	if state.reason == "" {
		state.reason = ensureIngressCertificate(ctx, r.Certificates, reader, in, plan)
	}
	var secret corev1.Secret
	if reader == nil {
		if state.reason == "" {
			state.reason = "TLSSecretUnavailable"
		}
		return state
	}
	if err := reader.Get(ctx, types.NamespacedName{Namespace: in.Namespace, Name: plan.secretName}, &secret); err != nil {
		if state.reason == "" {
			switch {
			case apierrors.IsNotFound(err):
				state.reason = "TLSSecretMissing"
			case apierrors.IsForbidden(err):
				state.reason = "TLSSecretForbidden"
			default:
				state.reason = "TLSSecretUnavailable"
			}
		}
		return state
	}
	leaf, secretReason, uncoveredName := inspectIngressCertificateNames(&secret, plan.names.certificateNames, now)
	state.uncoveredName = uncoveredName
	state.leaf = leaf
	if !leaf.notAfter.IsZero() {
		in.Status.TLSNotAfter = leaf.notAfter.DeepCopy()
	}
	if state.reason == "" {
		state.reason = secretReason
	}
	return state
}

type ingressProbe struct {
	Name               string     `json:"name"`
	Reachable          bool       `json:"reachable"`
	BackendReachable   *bool      `json:"backendReachable,omitempty"`
	TLSReady           *bool      `json:"tlsReady,omitempty"`
	ConfigID           string     `json:"configID,omitempty"`
	TLSCertSHA256      string     `json:"tlsCertSHA256,omitempty"`
	TLSNotAfter        *time.Time `json:"tlsNotAfter,omitempty"`
	BackendCAHash      string     `json:"backendCAHash,omitempty"`
	BackendTLSNotAfter *time.Time `json:"backendTLSNotAfter,omitempty"`
	BackendTLSReason   string     `json:"backendTLSReason,omitempty"`
	LastProbe          time.Time  `json:"lastProbe"`
}

var errIngressProbe = errors.New("agent probe unavailable or invalid")

func (r *TailnetIngressReconciler) scrapeIngressProbes(ctx context.Context, ns, name string) (map[string]ingressProbe, error) {
	ip := r.agentPodIP(ctx, ns, name)
	if ip == "" {
		return nil, errNoAgentPod
	}
	var results []ingressProbe
	if err := scrapeJSON(ctx, ip, "targets", &results); err != nil {
		// Timestamp/JSON decoder errors can echo arbitrary response content.
		return nil, errIngressProbe
	}
	out := make(map[string]ingressProbe, len(results))
	if len(results) > 50 {
		return nil, errIngressProbe
	}
	for _, result := range results {
		if _, exists := out[result.Name]; exists || result.Name == "" {
			return nil, errIngressProbe
		}
		out[result.Name] = result
	}
	return out, nil
}

// computeIngressStatus keeps legacy backend status, then adds the stricter HTTP local TLS proof.
// HTTP observations are bound to both the static config revision and the selected public leaf.
func (r *TailnetIngressReconciler) computeIngressStatus(in *tnv1.TailnetIngress, state ingressTLSState, probes map[string]ingressProbe, probeErr error, now time.Time) {
	// Derive the identity through the same renderer used for the ConfigMap.
	expected := make(map[string]string)
	if state.required {
		cm, err := ingressExposesConfigMap(in, in.Namespace, state.plan)
		if err == nil {
			var envelope struct {
				Targets []agentTarget `json:"targets"`
			}
			if json.Unmarshal([]byte(cm.Data[targetsFile]), &envelope) == nil {
				for _, target := range envelope.Targets {
					expected[target.Name] = target.ConfigID
				}
			}
		}
	}
	backends := make(map[string]bool, len(probes))
	backendReasons := make(map[string]string)
	validExposes := safeIngressExposes(in.Spec.Exposes)
	for _, expose := range in.Spec.Exposes {
		probe := probes[expose.Name]
		if !validExposes {
			backendReasons[expose.Name] = "BackendConfigurationInvalid"
		} else if expose.Backend.TLS != nil {
			reason := ingressBackendTLSReason(state.backends[expose.Name], probe, expected[expose.Name], probeErr, now)
			backendReasons[expose.Name] = reason
			backends[expose.Name] = reason == ""
		} else if expose.Mode == "http" {
			backends[expose.Name] = probe.BackendReachable != nil && *probe.BackendReachable &&
				expected[expose.Name] != "" && probe.ConfigID == expected[expose.Name] && ingressProbeFresh(probe, now)
		} else {
			backends[expose.Name] = probe.Reachable
		}
	}
	if probeErr != nil {
		backends = nil
		probeErr = errIngressProbe
	}
	r.computeExposeStatus(in, backends, probeErr)
	backendReason := ""
	for i, expose := range in.Spec.Exposes {
		if expose.Mode == "http" {
			in.Status.Exposes[i].DNSName = state.plan.names.exposeNames[expose.Name]
			if alias := state.plan.names.aliasNames[expose.Name]; alias != "" {
				in.Status.Exposes[i].DNSAliases = []string{alias}
			}
		}
		if reason := backendReasons[expose.Name]; reason != "" {
			in.Status.Exposes[i].Reason = reason
			if backendReason == "" {
				backendReason = reason
			}
		}
	}
	if backendReason != "" {
		setCond(&in.Status.Conditions, in.Generation, "BackendsReachable", metav1.ConditionFalse, backendReason,
			"backend configuration, trust source or verified agent observation is not ready")
		setCond(&in.Status.Conditions, in.Generation, "Ready", metav1.ConditionFalse, backendReason,
			"all backends require current verified observations")
	}
	if !state.required && state.reason == "" {
		meta.RemoveStatusCondition(&in.Status.Conditions, "TLSReady")
		return
	}
	reason := state.reason
	for i, expose := range in.Spec.Exposes {
		if expose.Mode != "http" {
			continue
		}
		probe, exists := probes[expose.Name]
		localReason := state.reason
		if localReason == "" {
			switch {
			case probeErr != nil:
				localReason = "TLSProbeFailed"
			case !exists || probe.TLSReady == nil || !*probe.TLSReady:
				localReason = "TLSProbePending"
			case expected[expose.Name] == "" || probe.ConfigID != expected[expose.Name]:
				localReason = "TLSConfigMismatch"
			case !ingressProbeFresh(probe, now):
				localReason = "TLSProbeStale"
			case state.leaf.sha256 == "" || probe.TLSCertSHA256 != state.leaf.sha256 || probe.TLSNotAfter == nil ||
				!probe.TLSNotAfter.Equal(state.leaf.notAfter.Time) || !now.Before(state.leaf.notAfter.Time):
				localReason = "TLSCertificateMismatch"
			}
		}
		ready := localReason == ""
		in.Status.Exposes[i].TLSReady = &ready
		if !ready {
			in.Status.Exposes[i].Reason = localReason
			if reason == "" {
				reason = localReason
			}
		}
	}
	if reason != "" {
		message := "local TLS source or agent observation is not ready; this condition does not test a remote tailnet path"
		if reason == "TLSNameMismatch" && state.uncoveredName != "" {
			message = fmt.Sprintf("certificate does not cover configured DNS name %q", state.uncoveredName)
		}
		setCond(&in.Status.Conditions, in.Generation, "TLSReady", metav1.ConditionFalse, reason, message)
		setCond(&in.Status.Conditions, in.Generation, "Ready", metav1.ConditionFalse, reason,
			"HTTP requires a current local TLS observation and reachable backend")
		return
	}
	setCond(&in.Status.Conditions, in.Generation, "TLSReady", metav1.ConditionTrue, "TLSReady",
		"selected certificate and local agent TLS handshake verified; remote tailnet reachability requires separate peer tests")
}

// Early control-plane failures must not preserve a green TLS verdict indefinitely.
// Keep the selected Secret name for cleanup tracking and the last observed public expiry.
func invalidateIngressTLSObservation(in *tnv1.TailnetIngress) {
	if ingressConfigVersion(in) > 0 {
		setCond(&in.Status.Conditions, in.Generation, "BackendsReachable", metav1.ConditionFalse, "BackendProbePending",
			"a current backend observation is unavailable")
		for i := range in.Status.Exposes {
			in.Status.Exposes[i].Reachable = false
			in.Status.Exposes[i].Reason = "BackendProbePending"
		}
	}
	if !ingressHTTPProtocol(in) {
		meta.RemoveStatusCondition(&in.Status.Conditions, "TLSReady")
		for i := range in.Status.Exposes {
			in.Status.Exposes[i].TLSReady = nil
		}
		return
	}
	setCond(&in.Status.Conditions, in.Generation, "TLSReady", metav1.ConditionFalse, "TLSProbePending",
		"a current local TLS observation is unavailable")
	for i := range in.Status.Exposes {
		if in.Status.Exposes[i].TLSReady != nil {
			ready := false
			in.Status.Exposes[i].TLSReady = &ready
		}
	}
}

func ingressProbeFresh(probe ingressProbe, now time.Time) bool {
	return !probe.LastProbe.IsZero() && !probe.LastProbe.Before(now.Add(-2*time.Minute)) && !probe.LastProbe.After(now.Add(5*time.Second))
}

// External TLS Secrets have no ingress owner reference. Watch them by namespace-local reference;
// generated names are included so issuance/rotation is noticed before status is first persisted.
func (r *TailnetIngressReconciler) ingressesForTLSSecret(ctx context.Context, obj client.Object) []types.NamespacedName {
	var list tnv1.TailnetIngressList
	if err := r.List(ctx, &list, client.InNamespace(obj.GetNamespace())); err != nil {
		return nil
	}
	var out []types.NamespacedName
	for _, in := range list.Items {
		if !ingressHTTPProtocol(&in) {
			continue
		}
		name := in.Name + "-tls"
		if in.Spec.TLS != nil && in.Spec.TLS.SecretName != "" {
			name = in.Spec.TLS.SecretName
		}
		if name == obj.GetName() {
			out = append(out, types.NamespacedName{Namespace: in.Namespace, Name: in.Name})
		}
	}
	return out
}
