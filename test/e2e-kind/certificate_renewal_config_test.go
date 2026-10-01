//go:build e2e_kind

package e2ekind

import (
	"encoding/json"
	"reflect"
	"testing"
	"time"

	jsonpatch "github.com/evanphx/json-patch/v5"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"

	tnv1 "this-is-fine.io/tailnet-operator/api/v1alpha1"
)

func renewalConfigFixture(t *testing.T) (*unstructured.Unstructured, *tnv1.TailnetIngress, certificateRenewalIdentity) {
	t.Helper()
	ingress := &tnv1.TailnetIngress{ObjectMeta: metav1.ObjectMeta{Name: "http-agent", Namespace: namespace, UID: "ingress-original"}}
	certificate := cmObject("Certificate", namespace, ingress.Name+"-tls", map[string]any{"duration": "1h0m0s", "renewBefore": "1200s", "secretName": "untouched"})
	certificate.SetUID("certificate-original")
	certificate.SetResourceVersion("123")
	certificate.SetGeneration(2)
	certificate.SetOwnerReferences([]metav1.OwnerReference{*metav1.NewControllerRef(ingress, tnv1.GroupVersion.WithKind("TailnetIngress"))})
	certificate.Object["status"] = map[string]any{
		"revision": int64(1), "notBefore": "2026-01-01T00:00:00Z", "notAfter": "2026-04-01T00:00:00Z",
		"renewalTime": "2026-03-01T00:00:00Z", "nextPrivateKeySecretName": "untouched-key",
		"unknown": map[string]any{"nested": []any{"keep", int64(9)}},
		"conditions": []any{
			map[string]any{"type": "Ready", "status": "True", "observedGeneration": int64(1), "reason": "Ready", "message": "Certificate is up to date and has not expired", "lastTransitionTime": "2026-01-01T00:00:00Z", "unknown": "preserved"},
			map[string]any{"type": "FutureCondition", "status": "Unknown", "unknown": map[string]any{"keep": true}},
		},
	}
	id, err := captureCertificateRenewalIdentity(certificate, ingress)
	if err != nil {
		t.Fatal(err)
	}
	return certificate, ingress, id
}

func renewalConfigConditions(c *unstructured.Unstructured) []any {
	return c.Object["status"].(map[string]any)["conditions"].([]any)
}

func renewalConfigAddIssuing(c *unstructured.Unstructured, status string, generation int64) {
	c.Object["status"].(map[string]any)["conditions"] = append(renewalConfigConditions(c), map[string]any{
		"type": "Issuing", "status": status, "observedGeneration": generation, "reason": "Old", "message": "Old message",
		"lastTransitionTime": "2026-01-01T00:00:00Z", "unknown": map[string]any{"keep": true},
	})
}

func TestCertificateRenewalPatchPreservesStatus(t *testing.T) {
	for _, existing := range []bool{false, true} {
		t.Run(map[bool]string{false: "append", true: "replace-issuing"}[existing], func(t *testing.T) {
			c, ingress, id := renewalConfigFixture(t)
			if existing {
				renewalConfigAddIssuing(c, "False", 1)
			}
			before := c.DeepCopy()
			now := time.Date(2026, 2, 3, 4, 5, 6, 0, time.FixedZone("offset", 3600))
			raw, done, err := buildCertificateRenewalPatch(id, c, ingress, 1, now)
			if err != nil || done || len(raw) == 0 {
				t.Fatalf("expected intent patch: done=%t err=%v", done, err)
			}
			if !reflect.DeepEqual(c, before) {
				t.Fatal("pure builder changed input")
			}
			var operations []struct {
				Op    string          `json:"op"`
				Path  string          `json:"path"`
				Value json.RawMessage `json:"value"`
			}
			if json.Unmarshal(raw, &operations) != nil || len(operations) != 3 {
				t.Fatal("unexpected patch shape")
			}
			if operations[0].Op != "test" || operations[0].Path != "/metadata/uid" || string(operations[0].Value) != `"certificate-original"` ||
				operations[1].Op != "test" || operations[1].Path != "/metadata/resourceVersion" || string(operations[1].Value) != `"123"` ||
				operations[2].Op != "replace" || operations[2].Path != "/status/conditions" {
				t.Fatal("patch must only test identity/version and replace conditions")
			}
			patch, err := jsonpatch.DecodePatch(raw)
			if err != nil {
				t.Fatal(err)
			}
			original, _ := json.Marshal(before.Object)
			updated, err := patch.Apply(original)
			if err != nil {
				t.Fatal(err)
			}
			var got unstructured.Unstructured
			if got.UnmarshalJSON(updated) != nil {
				t.Fatal("patched object decode failed")
			}
			expected := before.DeepCopy()
			if !existing {
				expected.Object["status"].(map[string]any)["conditions"] = append(renewalConfigConditions(expected), map[string]any{"type": "Issuing"})
			}
			issuing := renewalConfigConditions(expected)[2].(map[string]any)
			issuing["status"] = "True"
			issuing["reason"] = "ManuallyTriggered"
			issuing["message"] = "Certificate re-issuance manually triggered"
			issuing["observedGeneration"] = int64(2)
			issuing["lastTransitionTime"] = "2026-02-03T03:05:06Z"
			if !reflect.DeepEqual(got.Object, expected.Object) {
				t.Fatal("patch did not preserve every unrelated field and condition")
			}
			for _, field := range []string{"uid", "resourceVersion"} {
				stale := before.DeepCopy()
				stale.Object["metadata"].(map[string]any)[field] = "changed"
				data, _ := json.Marshal(stale.Object)
				if _, err := patch.Apply(data); err == nil {
					t.Fatalf("patch accepted stale %s", field)
				}
			}
		})
	}
}

func TestCertificateRenewalPatchRejectsUnsafeInputs(t *testing.T) {
	tests := map[string]func(*unstructured.Unstructured, *tnv1.TailnetIngress){
		"certificate-uid":       func(c *unstructured.Unstructured, _ *tnv1.TailnetIngress) { c.SetUID("replacement") },
		"certificate-name":      func(c *unstructured.Unstructured, _ *tnv1.TailnetIngress) { c.SetName("other-tls") },
		"certificate-namespace": func(c *unstructured.Unstructured, _ *tnv1.TailnetIngress) { c.SetNamespace("other") },
		"certificate-version":   func(c *unstructured.Unstructured, _ *tnv1.TailnetIngress) { c.SetAPIVersion("cert-manager.io/v1beta1") },
		"certificate-kind":      func(c *unstructured.Unstructured, _ *tnv1.TailnetIngress) { c.SetKind("CertificateRequest") },
		"certificate-deletion": func(c *unstructured.Unstructured, _ *tnv1.TailnetIngress) {
			now := metav1.Now()
			c.SetDeletionTimestamp(&now)
		},
		"ingress-uid":       func(_ *unstructured.Unstructured, i *tnv1.TailnetIngress) { i.UID = "replacement" },
		"ingress-name":      func(_ *unstructured.Unstructured, i *tnv1.TailnetIngress) { i.Name = "other" },
		"ingress-namespace": func(_ *unstructured.Unstructured, i *tnv1.TailnetIngress) { i.Namespace = "other" },
		"ingress-deletion": func(_ *unstructured.Unstructured, i *tnv1.TailnetIngress) {
			now := metav1.Now()
			i.DeletionTimestamp = &now
		},
		"resource-version": func(c *unstructured.Unstructured, _ *tnv1.TailnetIngress) { c.SetResourceVersion("") },
		"generation":       func(c *unstructured.Unstructured, _ *tnv1.TailnetIngress) { c.SetGeneration(0) },
		"duration": func(c *unstructured.Unstructured, _ *tnv1.TailnetIngress) {
			c.Object["spec"].(map[string]any)["duration"] = "2h"
		},
		"renew-before": func(c *unstructured.Unstructured, _ *tnv1.TailnetIngress) {
			c.Object["spec"].(map[string]any)["renewBefore"] = "10m"
		},
		"duration-malformed": func(c *unstructured.Unstructured, _ *tnv1.TailnetIngress) {
			c.Object["spec"].(map[string]any)["duration"] = int64(3600)
		},
		"status-missing": func(c *unstructured.Unstructured, _ *tnv1.TailnetIngress) { delete(c.Object, "status") },
		"conditions-missing": func(c *unstructured.Unstructured, _ *tnv1.TailnetIngress) {
			delete(c.Object["status"].(map[string]any), "conditions")
		},
		"conditions-not-array": func(c *unstructured.Unstructured, _ *tnv1.TailnetIngress) {
			c.Object["status"].(map[string]any)["conditions"] = "bad"
		},
		"ready-false": func(c *unstructured.Unstructured, _ *tnv1.TailnetIngress) {
			renewalConfigConditions(c)[0].(map[string]any)["status"] = "False"
		},
		"ready-missing": func(c *unstructured.Unstructured, _ *tnv1.TailnetIngress) {
			renewalConfigConditions(c)[0].(map[string]any)["type"] = "NotReady"
		},
		"ready-generation": func(c *unstructured.Unstructured, _ *tnv1.TailnetIngress) {
			delete(renewalConfigConditions(c)[0].(map[string]any), "observedGeneration")
		},
		"duplicate-ready": func(c *unstructured.Unstructured, _ *tnv1.TailnetIngress) {
			c.Object["status"].(map[string]any)["conditions"] = append(renewalConfigConditions(c), renewalConfigConditions(c)[0])
		},
		"duplicate-issuing": func(c *unstructured.Unstructured, _ *tnv1.TailnetIngress) {
			renewalConfigAddIssuing(c, "True", 2)
			renewalConfigAddIssuing(c, "True", 2)
		},
		"condition-not-object": func(c *unstructured.Unstructured, _ *tnv1.TailnetIngress) { renewalConfigConditions(c)[1] = "bad" },
		"condition-type": func(c *unstructured.Unstructured, _ *tnv1.TailnetIngress) {
			renewalConfigConditions(c)[1].(map[string]any)["type"] = ""
		},
		"condition-status": func(c *unstructured.Unstructured, _ *tnv1.TailnetIngress) {
			renewalConfigConditions(c)[1].(map[string]any)["status"] = true
		},
		"condition-time": func(c *unstructured.Unstructured, _ *tnv1.TailnetIngress) {
			renewalConfigConditions(c)[0].(map[string]any)["lastTransitionTime"] = "bad"
		},
		"condition-message": func(c *unstructured.Unstructured, _ *tnv1.TailnetIngress) {
			renewalConfigConditions(c)[0].(map[string]any)["message"] = int64(1)
		},
		"issuing-future":     func(c *unstructured.Unstructured, _ *tnv1.TailnetIngress) { renewalConfigAddIssuing(c, "True", 3) },
		"issuing-generation": func(c *unstructured.Unstructured, _ *tnv1.TailnetIngress) { renewalConfigAddIssuing(c, "True", 0) },
		"revision-lower": func(c *unstructured.Unstructured, _ *tnv1.TailnetIngress) {
			c.Object["status"].(map[string]any)["revision"] = int64(0)
		},
		"revision-malformed": func(c *unstructured.Unstructured, _ *tnv1.TailnetIngress) {
			c.Object["status"].(map[string]any)["revision"] = "1"
		},
		"revision-missing": func(c *unstructured.Unstructured, _ *tnv1.TailnetIngress) {
			delete(c.Object["status"].(map[string]any), "revision")
		},
	}
	for _, field := range []string{"uid", "name", "kind", "apiVersion", "controller", "missing", "duplicate"} {
		tests["owner-"+field] = func(c *unstructured.Unstructured, _ *tnv1.TailnetIngress) {
			owners := c.GetOwnerReferences()
			switch field {
			case "uid":
				owners[0].UID = "stale"
			case "name":
				owners[0].Name = "other"
			case "kind":
				owners[0].Kind = "TailnetEgress"
			case "apiVersion":
				owners[0].APIVersion = "wrong/v1"
			case "controller":
				owners[0].Controller = nil
			case "missing":
				owners = nil
			case "duplicate":
				owners = append(owners, owners[0])
			}
			c.SetOwnerReferences(owners)
		}
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			c, i, id := renewalConfigFixture(t)
			mutate(c, i)
			raw, done, err := buildCertificateRenewalPatch(id, c, i, 1, time.Now())
			if err == nil || raw != nil || done {
				t.Fatal("unsafe input accepted")
			}
		})
	}
}

func TestCertificateRenewalPatchNoDuplicateIntent(t *testing.T) {
	for _, test := range []struct {
		name                        string
		revision, issuingGeneration int64
		readyFalse, done            bool
	}{
		{name: "current-issuing", revision: 1, issuingGeneration: 2, done: true},
		{name: "current-issuing-not-ready", revision: 1, issuingGeneration: 2, readyFalse: true, done: true},
		{name: "older-issuing", revision: 1, issuingGeneration: 1},
		{name: "older-issuing-not-ready", revision: 1, issuingGeneration: 1, readyFalse: true},
		{name: "automatic-renewal-complete", revision: 2, done: true},
		{name: "advanced-revision-not-ready", revision: 2, readyFalse: true, done: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			c, i, id := renewalConfigFixture(t)
			c.Object["status"].(map[string]any)["revision"] = test.revision
			if test.issuingGeneration > 0 {
				renewalConfigAddIssuing(c, "True", test.issuingGeneration)
			}
			if test.readyFalse {
				renewalConfigConditions(c)[0].(map[string]any)["status"] = "False"
			}
			before := c.DeepCopy()
			raw, done, err := buildCertificateRenewalPatch(id, c, i, 1, time.Now())
			if err != nil || raw != nil || done != test.done || !reflect.DeepEqual(before, c) {
				t.Fatalf("unexpected renewal decision: done=%t err=%v", done, err)
			}
			// Advanced revisions never bypass identity/spec safety checks.
			c.SetUID("replacement")
			if _, _, err := buildCertificateRenewalPatch(id, c, i, 1, time.Now()); err == nil {
				t.Fatal("identity bypassed")
			}
		})
	}
}

func TestCertificateRenewalPatchNilInputs(t *testing.T) {
	c, i, id := renewalConfigFixture(t)
	if _, err := captureCertificateRenewalIdentity(nil, i); err == nil {
		t.Fatal("nil certificate accepted")
	}
	if _, err := captureCertificateRenewalIdentity(c, nil); err == nil {
		t.Fatal("nil ingress accepted")
	}
	for _, test := range []struct {
		c        *unstructured.Unstructured
		i        *tnv1.TailnetIngress
		id       certificateRenewalIdentity
		previous int64
	}{
		{nil, i, id, 1}, {c, nil, id, 1}, {c, i, certificateRenewalIdentity{}, 1}, {c, i, id, 0}, {c, i, id, -1},
	} {
		if raw, done, err := buildCertificateRenewalPatch(test.id, test.c, test.i, test.previous, time.Now()); err == nil || raw != nil || done {
			t.Fatal("invalid input accepted")
		}
	}
}
