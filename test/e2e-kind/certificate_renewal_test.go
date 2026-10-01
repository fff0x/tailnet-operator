//go:build e2e_kind

package e2ekind

import (
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"

	tnv1 "this-is-fine.io/tailnet-operator/api/v1alpha1"
)

// Keep identity separately: Get and Patch may overwrite their destination.
type certificateRenewalIdentity struct {
	certificateKey client.ObjectKey
	certificateUID types.UID
	ingressKey     client.ObjectKey
	ingressUID     types.UID
}

func captureCertificateRenewalIdentity(certificate *unstructured.Unstructured, ingress *tnv1.TailnetIngress) (certificateRenewalIdentity, error) {
	if certificate == nil || ingress == nil {
		return certificateRenewalIdentity{}, errors.New("renewal inputs missing")
	}
	id := certificateRenewalIdentity{
		certificateKey: client.ObjectKeyFromObject(certificate), certificateUID: certificate.GetUID(),
		ingressKey: client.ObjectKeyFromObject(ingress), ingressUID: ingress.UID,
	}
	if err := id.validate(certificate, ingress); err != nil {
		return certificateRenewalIdentity{}, err
	}
	return id, nil
}

func (id certificateRenewalIdentity) validate(certificate *unstructured.Unstructured, ingress *tnv1.TailnetIngress) error {
	if certificate == nil || ingress == nil || id.certificateUID == "" || id.ingressUID == "" ||
		id.ingressKey.Namespace != namespace || id.ingressKey.Name == "" ||
		id.certificateKey.Namespace != id.ingressKey.Namespace || id.certificateKey.Name != id.ingressKey.Name+"-tls" ||
		client.ObjectKeyFromObject(certificate) != id.certificateKey || certificate.GetUID() != id.certificateUID ||
		client.ObjectKeyFromObject(ingress) != id.ingressKey || ingress.UID != id.ingressUID ||
		certificate.GetAPIVersion() != "cert-manager.io/v1" || certificate.GetKind() != "Certificate" ||
		certificate.GetDeletionTimestamp() != nil || ingress.DeletionTimestamp != nil ||
		certificate.GetGeneration() <= 0 || certificate.GetResourceVersion() == "" {
		return errors.New("renewal identity differs")
	}
	owners := certificate.GetOwnerReferences()
	controllers := 0
	for _, owner := range owners {
		if owner.Controller == nil || !*owner.Controller {
			continue
		}
		controllers++
		if owner.APIVersion != tnv1.GroupVersion.String() || owner.Kind != "TailnetIngress" || owner.Name != id.ingressKey.Name || owner.UID != id.ingressUID {
			return errors.New("renewal controller owner differs")
		}
	}
	if controllers != 1 {
		return errors.New("renewal controller owner ambiguous")
	}
	for field, want := range map[string]time.Duration{"duration": time.Hour, "renewBefore": 20 * time.Minute} {
		value, found, err := unstructured.NestedString(certificate.Object, "spec", field)
		parsed, parseErr := time.ParseDuration(value)
		if err != nil || !found || parseErr != nil || parsed != want {
			return errors.New("renewal duration differs")
		}
	}
	return nil
}

// buildCertificateRenewalPatch requests the same Issuing intent as cmctl renew.
// It never manufactures Ready, a revision, dates, or Secret contents. A Ready
// observation from the previous generation is valid after the duration patch.
// nil patch + !done means an older issuance is still running; do not retrigger.
func buildCertificateRenewalPatch(id certificateRenewalIdentity, certificate *unstructured.Unstructured, ingress *tnv1.TailnetIngress, previousRevision int64, now time.Time) (raw []byte, done bool, err error) {
	if err := id.validate(certificate, ingress); err != nil {
		return nil, false, err
	}
	revision, found, err := unstructured.NestedInt64(certificate.Object, "status", "revision")
	if previousRevision <= 0 || err != nil || !found || revision < previousRevision {
		return nil, false, errors.New("renewal revision invalid")
	}
	if revision > previousRevision {
		return nil, true, nil // Automatic issuance already fulfilled this intent.
	}
	conditions, found, err := unstructured.NestedSlice(certificate.Object, "status", "conditions")
	if err != nil || !found || len(conditions) == 0 {
		return nil, false, errors.New("renewal conditions missing")
	}
	seen := map[string]bool{}
	ready, issuingIndex := false, -1
	for i, item := range conditions {
		condition, ok := item.(map[string]any)
		if !ok {
			return nil, false, errors.New("renewal condition malformed")
		}
		kind, kindOK := condition["type"].(string)
		status, statusOK := condition["status"].(string)
		if !kindOK || kind == "" || seen[kind] || !statusOK || (status != "True" && status != "False" && status != "Unknown") {
			return nil, false, errors.New("renewal condition ambiguous")
		}
		seen[kind] = true
		for _, key := range []string{"reason", "message", "lastTransitionTime"} {
			if value, exists := condition[key]; exists {
				s, ok := value.(string)
				if !ok {
					return nil, false, errors.New("renewal condition malformed")
				}
				if key == "lastTransitionTime" {
					if _, err := time.Parse(time.RFC3339, s); err != nil {
						return nil, false, errors.New("renewal condition time malformed")
					}
				}
			}
		}
		generation, genOK := condition["observedGeneration"].(int64)
		if _, exists := condition["observedGeneration"]; exists && (!genOK || generation < 0 || generation > certificate.GetGeneration()) {
			return nil, false, errors.New("renewal condition generation malformed")
		}
		switch kind {
		case "Ready":
			ready = status == "True" && genOK && generation > 0
		case "Issuing":
			if !genOK || generation <= 0 {
				return nil, false, errors.New("renewal issuing generation missing")
			}
			issuingIndex = i
		}
	}
	issuing := map[string]any{"type": "Issuing"}
	if issuingIndex >= 0 {
		issuing = conditions[issuingIndex].(map[string]any)
		if issuing["status"] == "True" {
			return nil, issuing["observedGeneration"] == certificate.GetGeneration(), nil
		}
	} else {
		conditions = append(conditions, issuing)
	}
	if !ready {
		return nil, false, errors.New("renewal requires an actually issued Ready certificate")
	}
	// NestedSlice returned a deep copy, including unknown condition fields.
	issuing["status"] = "True"
	issuing["reason"] = "ManuallyTriggered"
	issuing["message"] = "Certificate re-issuance manually triggered"
	issuing["observedGeneration"] = certificate.GetGeneration()
	issuing["lastTransitionTime"] = now.UTC().Format(time.RFC3339)
	patch := []map[string]any{
		{"op": "test", "path": "/metadata/uid", "value": string(id.certificateUID)},
		{"op": "test", "path": "/metadata/resourceVersion", "value": certificate.GetResourceVersion()},
		{"op": "replace", "path": "/status/conditions", "value": conditions},
	}
	raw, err = json.Marshal(patch)
	if err != nil {
		return nil, false, errors.New("renewal intent encoding failed")
	}
	return raw, false, nil
}

func requestFixtureCertificateRenewal(t *testing.T, f *fixture, certificate *unstructured.Unstructured, ingress *tnv1.TailnetIngress, previousRevision int64) {
	t.Helper()
	if f == nil || f.kube == nil {
		t.Fatal("renewal client missing")
	}
	id, err := captureCertificateRenewalIdentity(certificate, ingress)
	if err != nil {
		t.Fatal("renewal initial identity rejected")
	}
	if _, _, err := buildCertificateRenewalPatch(id, certificate, ingress, previousRevision, time.Now()); err != nil {
		t.Fatal("renewal initial certificate rejected")
	}
	ctx, cancel := context.WithTimeout(t.Context(), 90*time.Second)
	defer cancel()
	eventually(t, "cert-manager manual renewal intent", func() bool {
		current := cmObject("Certificate", id.certificateKey.Namespace, id.certificateKey.Name, nil)
		var currentIngress tnv1.TailnetIngress
		if f.kube.Get(ctx, id.certificateKey, current) != nil || f.kube.Get(ctx, id.ingressKey, &currentIngress) != nil {
			t.Fatal("renewal fresh identity read failed")
		}
		raw, done, err := buildCertificateRenewalPatch(id, current, &currentIngress, previousRevision, time.Now())
		if err != nil {
			t.Fatal("renewal fresh certificate rejected")
		}
		if done || raw == nil {
			return done
		}
		version := current.GetResourceVersion()
		err = f.kube.Status().Patch(ctx, current, client.RawPatch(types.JSONPatchType, raw))
		if err == nil {
			return true
		}
		if apierrors.IsConflict(err) {
			return false
		}
		// The API server can report failed JSON Patch tests as a generic 422.
		// Retry only after proving that this snapshot actually became stale.
		if apierrors.IsInvalid(err) || apierrors.IsBadRequest(err) {
			fresh := cmObject("Certificate", id.certificateKey.Namespace, id.certificateKey.Name, nil)
			if f.kube.Get(ctx, id.certificateKey, fresh) == nil && (fresh.GetUID() != id.certificateUID || fresh.GetResourceVersion() != version) {
				return false
			}
		}
		t.Fatal("renewal status intent patch failed")
		return false
	})
}
