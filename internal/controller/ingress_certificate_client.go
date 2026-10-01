package controller

import (
	"context"
	"encoding/json"
	"errors"
	"reflect"

	jsonpatch "github.com/evanphx/json-patch/v5"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/dynamic"
	"sigs.k8s.io/controller-runtime/pkg/client"

	tnv1 "tsunaro.io/tailnet-operator/api/v1alpha1"
)

var ingressCertificateResource = schema.GroupVersionResource{Group: "cert-manager.io", Version: "v1", Resource: "certificates"}

// ensureIngressCertificate uses only namespace-local requests to the optional API. It needs
// neither discovery nor an informer. Success here is NOT TLSReady: the caller must separately
// inspect the selected Secret and observe the agent's serving certificate.
func ensureIngressCertificate(ctx context.Context, certificates dynamic.Interface, secrets client.Reader, in *tnv1.TailnetIngress, plan ingressTLSPlan) string {
	if !plan.http || plan.issuer == nil {
		return ""
	}
	if in == nil || in.UID == "" || in.Namespace == "" || in.Name == "" || certificates == nil {
		return "TLSCertificateUnavailable"
	}
	desired := desiredIngressCertificate(in, plan)
	resource := certificates.Resource(ingressCertificateResource).Namespace(in.Namespace)
	cert, err := resource.Get(ctx, desired.GetName(), metav1.GetOptions{})
	if apierrors.IsNotFound(err) {
		if secrets == nil {
			return "TLSCertificateUnavailable"
		}
		// This check is deliberately not a cross-object CAS: a Secret can appear after this
		// read (or a cached reader can lag). Use a direct reader in production. Create below
		// protects the Certificate name, not the Secret name; cert-manager's Secret writes
		// cannot be made transactional with this check.
		var secret corev1.Secret
		err = secrets.Get(ctx, client.ObjectKey{Namespace: in.Namespace, Name: plan.secretName}, &secret)
		if err == nil {
			return "TLSSecretConflict"
		}
		if !apierrors.IsNotFound(err) {
			return ingressCertificateFailure(err)
		}
		_, err = resource.Create(ctx, desired, metav1.CreateOptions{})
		if ingressCertificateRouteMissing(err) {
			return "CertManagerMissing"
		}
		if err != nil {
			return ingressCertificateFailure(err)
		}
		return "TLSCertificatePending"
	}
	if err != nil {
		return ingressCertificateFailure(err)
	}
	if !ingressOwnsCertificate(in, cert) {
		return "TLSCertificateConflict"
	}
	if cert.GetDeletionTimestamp() != nil {
		return "TLSCertificatePending"
	}
	patch, err := ingressCertificateSpecPatch(cert, desired)
	if err != nil {
		return "TLSCertificateUnavailable"
	}
	if patch != nil {
		// A merge patch includes both identity and revision preconditions. Never apply/upsert
		// or force ownership over a concurrently replaced Certificate.
		if cert.GetUID() == "" || cert.GetResourceVersion() == "" {
			return "TLSCertificateUnavailable"
		}
		if _, err = resource.Patch(ctx, cert.GetName(), types.MergePatchType, patch, metav1.PatchOptions{}); err != nil {
			return ingressCertificateFailure(err)
		}
		// Even a response carrying the previous Ready=True is not evidence for the new spec.
		return "TLSCertificatePending"
	}
	return ingressCertificateReadiness(cert)
}

// removeIngressCertificate never deletes Secrets or adopts foreign Certificates. Retaining the
// generated Secret name allows an explicit Secret source to keep using managed material.
func removeIngressCertificate(ctx context.Context, certificates dynamic.Interface, in *tnv1.TailnetIngress, retainSecretName string) string {
	if in != nil && retainSecretName == in.Name+"-tls" {
		return ""
	}
	if in == nil || in.UID == "" || in.Namespace == "" || in.Name == "" || certificates == nil {
		return "TLSCertificateUnavailable"
	}
	resource := certificates.Resource(ingressCertificateResource).Namespace(in.Namespace)
	cert, err := resource.Get(ctx, in.Name+"-tls", metav1.GetOptions{})
	if apierrors.IsNotFound(err) {
		return ""
	}
	if err != nil {
		return ingressCertificateFailure(err)
	}
	if !ingressOwnsCertificate(in, cert) {
		return ""
	}
	if cert.GetDeletionTimestamp() != nil {
		return "TLSCertificatePending"
	}
	uid, version := cert.GetUID(), cert.GetResourceVersion()
	if uid == "" || version == "" {
		return "TLSCertificateUnavailable"
	}
	err = resource.Delete(ctx, cert.GetName(), metav1.DeleteOptions{Preconditions: &metav1.Preconditions{UID: &uid, ResourceVersion: &version}})
	if err == nil {
		// Accepted deletion is not completed deletion; retain a retry marker until GET
		// confirms absence, including when cert-manager finalizers delay removal.
		return "TLSCertificatePending"
	}
	if apierrors.IsNotFound(err) {
		return ""
	}
	return ingressCertificateFailure(err)
}

func ingressOwnsCertificate(in *tnv1.TailnetIngress, cert *unstructured.Unstructured) bool {
	if cert == nil {
		return false
	}
	refs, _, err := unstructured.NestedSlice(cert.Object, "metadata", "ownerReferences")
	if err != nil {
		return false
	}
	owned := false
	for _, raw := range refs {
		ref, ok := raw.(map[string]any)
		if !ok {
			return false
		}
		if ref["controller"] != true {
			continue
		}
		if owned || ref["uid"] != string(in.UID) || ref["name"] != in.Name ||
			ref["kind"] != "TailnetIngress" || ref["apiVersion"] != tnv1.GroupVersion.String() {
			return false
		}
		owned = true
	}
	return owned
}

// Only these three spec fields are managed; merge-patch nulls remove obsolete issuerRef keys,
// while unrelated spec (duration, renewBefore, etc.) and metadata stay untouched.
func ingressCertificateSpecPatch(cert, desired *unstructured.Unstructured) ([]byte, error) {
	oldSpec := make(map[string]any)
	for _, key := range []string{"secretName", "dnsNames", "issuerRef"} {
		value, found, err := unstructured.NestedFieldNoCopy(cert.Object, "spec", key)
		if err != nil {
			return nil, err
		}
		if found {
			oldSpec[key] = value
		}
	}
	newSpec, _, err := unstructured.NestedMap(desired.Object, "spec")
	if err != nil || reflect.DeepEqual(oldSpec, newSpec) {
		return nil, err
	}
	oldJSON, err := json.Marshal(oldSpec)
	if err != nil {
		return nil, err
	}
	newJSON, err := json.Marshal(newSpec)
	if err != nil {
		return nil, err
	}
	specPatch, err := jsonpatch.CreateMergePatch(oldJSON, newJSON)
	if err != nil {
		return nil, err
	}
	return json.Marshal(map[string]any{
		"metadata": map[string]any{"uid": cert.GetUID(), "resourceVersion": cert.GetResourceVersion()},
		"spec":     json.RawMessage(specPatch),
	})
}

func ingressCertificateReadiness(cert *unstructured.Unstructured) string {
	generation, _, err := unstructured.NestedInt64(cert.Object, "metadata", "generation")
	if err != nil {
		return "TLSCertificateUnavailable"
	}
	conditions, _, err := unstructured.NestedSlice(cert.Object, "status", "conditions")
	if err != nil {
		return "TLSCertificateUnavailable"
	}
	ready, seen := false, false
	for _, raw := range conditions {
		condition, ok := raw.(map[string]any)
		if !ok {
			return "TLSCertificateUnavailable"
		}
		kind, _, err := unstructured.NestedString(condition, "type")
		if err != nil {
			return "TLSCertificateUnavailable"
		}
		if kind != "Ready" {
			continue
		}
		if seen { // An ambiguous/duplicate Ready condition is not evidence of readiness.
			return "TLSCertificateUnavailable"
		}
		seen = true
		status, _, statusErr := unstructured.NestedString(condition, "status")
		observed, _, observedErr := unstructured.NestedInt64(condition, "observedGeneration")
		if statusErr != nil || observedErr != nil {
			return "TLSCertificateUnavailable"
		}
		ready = status == "True" && generation > 0 && observed == generation
	}
	if ready {
		return ""
	}
	return "TLSCertificatePending"
}

// Only a collection-route 404 on Create establishes missing cert-manager. A named GET 404
// cannot distinguish an absent object from an absent API. Namespace/other resource failures
// must not masquerade as missing cert-manager; response messages are never inspected or logged.
func ingressCertificateRouteMissing(err error) bool {
	if !apierrors.IsNotFound(err) {
		return false
	}
	var status apierrors.APIStatus
	if !errors.As(err, &status) {
		return false
	}
	details := status.Status().Details
	return details == nil || (details.Name == "" &&
		(details.Group == "" || details.Group == ingressCertificateResource.Group) &&
		(details.Kind == "" || details.Kind == ingressCertificateResource.Resource))
}

func ingressCertificateFailure(err error) string {
	switch {
	case apierrors.IsForbidden(err):
		return "TLSCertificateForbidden"
	case apierrors.IsConflict(err), apierrors.IsAlreadyExists(err):
		return "TLSCertificatePending"
	default:
		return "TLSCertificateUnavailable"
	}
}
