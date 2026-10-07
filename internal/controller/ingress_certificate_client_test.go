package controller

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"reflect"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	dynamicfake "k8s.io/client-go/dynamic/fake"
	ktesting "k8s.io/client-go/testing"
	"sigs.k8s.io/controller-runtime/pkg/client"

	tnv1 "tsunaro.io/tailnet-operator/api/v1alpha1"
)

func certificateClientFixture() (*tnv1.TailnetIngress, ingressTLSPlan, *unstructured.Unstructured) {
	in := &tnv1.TailnetIngress{
		ObjectMeta: metav1.ObjectMeta{Name: "web", Namespace: "tenant", UID: "ingress-uid"},
		Spec: tnv1.TailnetIngressSpec{Exposes: []tnv1.Expose{{Name: "http", Mode: "http", Port: 443,
			Backend: tnv1.Backend{Namespace: "foreign-backend", Service: "web", Port: 8080}}}},
		Status: tnv1.TailnetIngressStatus{DNSName: "web.tenant.invalid"},
	}
	plan := tlsTestPlan(in, "web-tls")
	plan.issuer = &tnv1.TLSIssuerReference{Name: "tenant-ca", Kind: "Issuer", Group: "cert-manager.io"}
	cert := desiredIngressCertificate(in, plan)
	cert.SetUID("certificate-uid")
	cert.SetResourceVersion("7")
	cert.SetGeneration(3)
	cert.Object["status"] = map[string]any{"conditions": []any{map[string]any{
		"type": "Ready", "status": "True", "observedGeneration": int64(3),
	}}}
	return in, plan, cert
}

// Deliberately implements only reads: any list is a test failure. No test touches a cluster.
type certificateSecretReader struct {
	t      *testing.T
	calls  int
	exists bool
	secret *corev1.Secret
	err    error
}

func (r *certificateSecretReader) Get(_ context.Context, key client.ObjectKey, obj client.Object, _ ...client.GetOption) error {
	r.t.Helper()
	r.calls++
	if key != (client.ObjectKey{Namespace: "tenant", Name: "web-tls"}) {
		r.t.Fatalf("nonlocal/unexpected Secret query: %v", key)
	}
	if _, ok := obj.(*corev1.Secret); !ok {
		r.t.Fatalf("read %T instead of Secret", obj)
	}
	if r.err != nil {
		return r.err
	}
	if r.exists {
		if r.secret != nil {
			r.secret.DeepCopyInto(obj.(*corev1.Secret))
		}
		return nil
	}
	return apierrors.NewNotFound(schema.GroupResource{Resource: "secrets"}, key.Name)
}

func (r *certificateSecretReader) List(context.Context, client.ObjectList, ...client.ListOption) error {
	r.t.Fatal("unexpected list")
	return nil
}

func checkCertificateActions(t *testing.T, c *dynamicfake.FakeDynamicClient, verbs ...string) {
	t.Helper()
	actions := c.Actions()
	if len(actions) != len(verbs) {
		t.Fatalf("got %d API calls, want %v: %#v", len(actions), verbs, actions)
	}
	for i, action := range actions {
		if action.GetVerb() != verbs[i] || action.GetResource() != ingressCertificateResource ||
			action.GetNamespace() != "tenant" || action.GetSubresource() != "" {
			t.Fatalf("unexpected action %d: %#v", i, action)
		}
		switch a := action.(type) {
		case ktesting.GetAction:
			if a.GetName() != "web-tls" {
				t.Fatal("wrong Certificate GET name")
			}
		case ktesting.PatchAction:
			if a.GetName() != "web-tls" {
				t.Fatal("wrong Certificate PATCH name")
			}
		case ktesting.DeleteAction:
			if a.GetName() != "web-tls" {
				t.Fatal("wrong Certificate DELETE name")
			}
		}
	}
}

func TestEnsureIngressCertificateNoWorkflow(t *testing.T) {
	for _, plan := range []ingressTLSPlan{{}, {http: true, secretName: "external"},
		{issuer: &tnv1.TLSIssuerReference{Name: "unused-for-l4"}}} {
		in, _, _ := certificateClientFixture()
		if got := ensureIngressCertificate(context.Background(), nil, nil, in, plan); got != "" {
			t.Fatalf("nil optional client changed non-issuer workflow: %q", got)
		}
		c := dynamicfake.NewSimpleDynamicClient(runtime.NewScheme())
		r := &certificateSecretReader{t: t}
		if got := ensureIngressCertificate(context.Background(), c, r, in, plan); got != "" || r.calls != 0 {
			t.Fatalf("non-issuer workflow: %q, Secret calls=%d", got, r.calls)
		}
		checkCertificateActions(t, c)
	}
}

func TestIngressCertificateClientMissingIdentity(t *testing.T) {
	for _, field := range []string{"uid", "namespace", "name", "nil-ingress", "nil-client"} {
		t.Run(field, func(t *testing.T) {
			in, plan, _ := certificateClientFixture()
			c := dynamicfake.NewSimpleDynamicClient(runtime.NewScheme())
			r := &certificateSecretReader{t: t}
			switch field {
			case "uid":
				in.UID = ""
			case "namespace":
				in.Namespace = ""
			case "name":
				in.Name = ""
			case "nil-ingress":
				in = nil
			case "nil-client":
				if got := ensureIngressCertificate(context.Background(), nil, r, in, plan); got != "TLSCertificateUnavailable" {
					t.Fatalf("ensure: %q", got)
				}
				if got := removeIngressCertificate(context.Background(), nil, in, ""); got != "TLSCertificateUnavailable" {
					t.Fatalf("remove: %q", got)
				}
				return
			}
			if got := ensureIngressCertificate(context.Background(), c, r, in, plan); got != "TLSCertificateUnavailable" {
				t.Fatalf("ensure: %q", got)
			}
			if got := removeIngressCertificate(context.Background(), c, in, ""); got != "TLSCertificateUnavailable" {
				t.Fatalf("remove: %q", got)
			}
			checkCertificateActions(t, c)
			if r.calls != 0 {
				t.Fatal("Secret read without ingress identity")
			}
		})
	}
}

func TestEnsureIngressCertificateCreate(t *testing.T) {
	gr := ingressCertificateResource.GroupResource()
	privateError := errors.New("sensitive-upstream-diagnostic")
	for _, tt := range []struct {
		name                       string
		getErr, createErr, readErr error
		secretExists, nilReader    bool
		reason                     string
		verbs                      []string
		reads                      int
	}{
		{name: "absent-object-create", reason: "TLSCertificatePending", verbs: []string{"get", "create"}, reads: 1},
		{name: "missing-route", getErr: apierrors.NewNotFound(gr, "web-tls"),
			createErr: apierrors.NewGenericServerResponse(http.StatusNotFound, "POST", gr, "", "private-response", 0, false),
			reason:    "CertManagerMissing", verbs: []string{"get", "create"}, reads: 1},
		{name: "missing-route-no-details", createErr: &apierrors.StatusError{ErrStatus: metav1.Status{Code: 404, Reason: metav1.StatusReasonNotFound}},
			reason: "CertManagerMissing", verbs: []string{"get", "create"}, reads: 1},
		{name: "namespace-not-found-is-not-missing-api", createErr: apierrors.NewNotFound(schema.GroupResource{Resource: "namespaces"}, "tenant"),
			reason: "TLSCertificateUnavailable", verbs: []string{"get", "create"}, reads: 1},
		{name: "named-create-404-is-not-route-evidence", createErr: apierrors.NewNotFound(gr, "web-tls"),
			reason: "TLSCertificateUnavailable", verbs: []string{"get", "create"}, reads: 1},
		{name: "get-forbidden", getErr: apierrors.NewForbidden(gr, "web-tls", privateError), reason: "TLSCertificateForbidden", verbs: []string{"get"}},
		{name: "get-transport", getErr: privateError, reason: "TLSCertificateUnavailable", verbs: []string{"get"}},
		{name: "get-server-error", getErr: apierrors.NewServiceUnavailable("private-response"), reason: "TLSCertificateUnavailable", verbs: []string{"get"}},
		{name: "create-forbidden", createErr: apierrors.NewForbidden(gr, "", privateError), reason: "TLSCertificateForbidden", verbs: []string{"get", "create"}, reads: 1},
		{name: "create-transport", createErr: privateError, reason: "TLSCertificateUnavailable", verbs: []string{"get", "create"}, reads: 1},
		{name: "create-race", createErr: apierrors.NewAlreadyExists(gr, "web-tls"), reason: "TLSCertificatePending", verbs: []string{"get", "create"}, reads: 1},
		{name: "create-conflict", createErr: apierrors.NewConflict(gr, "web-tls", privateError), reason: "TLSCertificatePending", verbs: []string{"get", "create"}, reads: 1},
		{name: "generated-secret-collision", secretExists: true, reason: "TLSSecretConflict", verbs: []string{"get"}, reads: 1},
		{name: "read-forbidden", readErr: apierrors.NewForbidden(schema.GroupResource{Resource: "secrets"}, "web-tls", privateError), reason: "TLSCertificateForbidden", verbs: []string{"get"}, reads: 1},
		{name: "read-transport", readErr: privateError, reason: "TLSCertificateUnavailable", verbs: []string{"get"}, reads: 1},
		{name: "no-reader", nilReader: true, reason: "TLSCertificateUnavailable", verbs: []string{"get"}},
	} {
		t.Run(tt.name, func(t *testing.T) {
			in, plan, otherNamespace := certificateClientFixture()
			otherNamespace.SetNamespace("foreign-backend")
			c := dynamicfake.NewSimpleDynamicClient(runtime.NewScheme(), otherNamespace)
			if tt.getErr != nil {
				c.PrependReactor("get", "certificates", func(ktesting.Action) (bool, runtime.Object, error) { return true, nil, tt.getErr })
			}
			c.PrependReactor("create", "certificates", func(action ktesting.Action) (bool, runtime.Object, error) {
				obj := action.(ktesting.CreateAction).GetObject().(*unstructured.Unstructured)
				if !reflect.DeepEqual(obj, desiredIngressCertificate(in, plan)) {
					t.Fatal("create was not exact desired Certificate with controller owner and no status")
				}
				return tt.createErr != nil, nil, tt.createErr
			})
			r := &certificateSecretReader{t: t, exists: tt.secretExists, err: tt.readErr}
			var reader client.Reader = r
			if tt.nilReader {
				reader = nil
			}
			if got := ensureIngressCertificate(context.Background(), c, reader, in, plan); got != tt.reason {
				t.Fatalf("reason=%q, want %q", got, tt.reason)
			}
			checkCertificateActions(t, c, tt.verbs...)
			if r.calls != tt.reads {
				t.Fatalf("Secret reads=%d, want %d", r.calls, tt.reads)
			}
		})
	}
}

func TestEnsureIngressCertificateOrphanedSecret(t *testing.T) {
	for _, tt := range []struct {
		name   string
		mutate func(*corev1.Secret)
		reason string
	}{
		{"orphan-of-same-certificate", func(*corev1.Secret) {}, "TLSCertificatePending"},
		{"wrong-certificate", func(s *corev1.Secret) { s.Annotations["cert-manager.io/certificate-name"] = "other" }, "TLSSecretConflict"},
		{"not-tls", func(s *corev1.Secret) { s.Type = corev1.SecretTypeOpaque }, "TLSSecretConflict"},
		{"owned", func(s *corev1.Secret) { s.OwnerReferences = []metav1.OwnerReference{{Name: "x", UID: "u"}} }, "TLSSecretConflict"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			in, plan, other := certificateClientFixture()
			other.SetNamespace("foreign-backend")
			c := dynamicfake.NewSimpleDynamicClient(runtime.NewScheme(), other)
			secret := &corev1.Secret{Type: corev1.SecretTypeTLS,
				ObjectMeta: metav1.ObjectMeta{Annotations: map[string]string{"cert-manager.io/certificate-name": desiredIngressCertificate(in, plan).GetName()}}}
			tt.mutate(secret)
			r := &certificateSecretReader{t: t, exists: true, secret: secret}
			if got := ensureIngressCertificate(context.Background(), c, r, in, plan); got != tt.reason {
				t.Fatalf("reason=%q, want %q", got, tt.reason)
			}
		})
	}
}

func TestEnsureIngressCertificateCreateRace(t *testing.T) {
	in, plan, winner := certificateClientFixture()
	winner.SetUID("other-certificate-uid")
	winner.SetOwnerReferences(nil)
	c := dynamicfake.NewSimpleDynamicClient(runtime.NewScheme())
	c.PrependReactor("create", "certificates", func(ktesting.Action) (bool, runtime.Object, error) {
		// Another writer wins between GET and Create. The failed create must not become
		// an update/apply, even if this competing object has the same requested spec.
		if err := c.Tracker().Create(ingressCertificateResource, winner, in.Namespace); err != nil {
			t.Fatal(err)
		}
		return true, nil, apierrors.NewAlreadyExists(ingressCertificateResource.GroupResource(), winner.GetName())
	})
	r := &certificateSecretReader{t: t}
	if got := ensureIngressCertificate(context.Background(), c, r, in, plan); got != "TLSCertificatePending" {
		t.Fatalf("create race: %q", got)
	}
	if got := ensureIngressCertificate(context.Background(), c, r, in, plan); got != "TLSCertificateConflict" {
		t.Fatalf("next reconcile adopted race winner: %q", got)
	}
	checkCertificateActions(t, c, "get", "create", "get")
	stored, err := c.Tracker().Get(ingressCertificateResource, in.Namespace, winner.GetName())
	if err != nil || !reflect.DeepEqual(stored, winner) || r.calls != 1 {
		t.Fatal("create race mutated foreign Certificate or re-read Secret")
	}
}

func TestIngressCertificateClientForeignOwnership(t *testing.T) {
	for _, field := range []string{"absent", "uid", "name", "kind", "apiVersion", "controller", "duplicate", "malformed"} {
		t.Run(field, func(t *testing.T) {
			in, plan, cert := certificateClientFixture()
			refs := cert.GetOwnerReferences()
			switch field {
			case "absent":
				refs = nil
			case "uid":
				refs[0].UID = "previous-ingress-uid"
			case "name":
				refs[0].Name = "other"
			case "kind":
				refs[0].Kind = "TailnetEgress"
			case "apiVersion":
				refs[0].APIVersion = "foreign.invalid/v1"
			case "controller":
				refs[0].Controller = nil
			case "duplicate":
				refs = append(refs, refs[0])
			}
			cert.SetOwnerReferences(refs)
			if field == "malformed" {
				cert.Object["metadata"].(map[string]any)["ownerReferences"] = "not-a-list"
			}
			c := dynamicfake.NewSimpleDynamicClient(runtime.NewScheme(), cert)
			r := &certificateSecretReader{t: t, exists: true}
			if got := ensureIngressCertificate(context.Background(), c, r, in, plan); got != "TLSCertificateConflict" {
				t.Fatalf("ensure reason=%q", got)
			}
			if got := removeIngressCertificate(context.Background(), c, in, "other-secret"); got != "" {
				t.Fatalf("remove reason=%q", got)
			}
			checkCertificateActions(t, c, "get", "get")
			if r.calls != 0 {
				t.Fatal("foreign Certificate queried Secret")
			}
		})
	}
}

func TestEnsureIngressCertificateReadiness(t *testing.T) {
	for _, tt := range []struct {
		name   string
		mutate func(*unstructured.Unstructured)
		reason string
	}{
		{name: "ready"},
		{name: "missing-status", mutate: func(c *unstructured.Unstructured) { delete(c.Object, "status") }, reason: "TLSCertificatePending"},
		{name: "malformed-status", mutate: func(c *unstructured.Unstructured) { c.Object["status"] = "private-diagnostic" }, reason: "TLSCertificateUnavailable"},
		{name: "malformed-conditions", mutate: func(c *unstructured.Unstructured) {
			c.Object["status"].(map[string]any)["conditions"] = "private-diagnostic"
		}, reason: "TLSCertificateUnavailable"},
		{name: "malformed-condition", mutate: func(c *unstructured.Unstructured) {
			c.Object["status"].(map[string]any)["conditions"] = []any{"private-diagnostic"}
		}, reason: "TLSCertificateUnavailable"},
		{name: "zero-generation", mutate: func(c *unstructured.Unstructured) { c.SetGeneration(0) }, reason: "TLSCertificatePending"},
		{name: "stale-ready", mutate: func(c *unstructured.Unstructured) { c.SetGeneration(4) }, reason: "TLSCertificatePending"},
		{name: "future-ready", mutate: func(c *unstructured.Unstructured) { c.SetGeneration(2) }, reason: "TLSCertificatePending"},
		{name: "malformed-generation", mutate: func(c *unstructured.Unstructured) { c.Object["metadata"].(map[string]any)["generation"] = "3" }, reason: "TLSCertificateUnavailable"},
		{name: "deleting", mutate: func(c *unstructured.Unstructured) { now := metav1.NewTime(time.Now()); c.SetDeletionTimestamp(&now) }, reason: "TLSCertificatePending"},
		{name: "duplicate-ready", mutate: func(c *unstructured.Unstructured) {
			status := c.Object["status"].(map[string]any)
			status["conditions"] = append(status["conditions"].([]any), map[string]any{"type": "Ready", "status": "False"})
		}, reason: "TLSCertificateUnavailable"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			in, plan, cert := certificateClientFixture()
			if tt.mutate != nil {
				tt.mutate(cert)
			}
			c := dynamicfake.NewSimpleDynamicClient(runtime.NewScheme(), cert)
			if got := ensureIngressCertificate(context.Background(), c, nil, in, plan); got != tt.reason {
				t.Fatalf("reason=%q, want %q", got, tt.reason)
			}
			checkCertificateActions(t, c, "get")
		})
	}
	for _, tt := range []struct {
		name, field string
		value       any
		reason      string
	}{
		{"false", "status", "False", "TLSCertificatePending"},
		{"unknown", "status", "Unknown", "TLSCertificatePending"},
		{"lowercase", "status", "true", "TLSCertificatePending"},
		{"malformed-status", "status", true, "TLSCertificateUnavailable"},
		{"other-condition", "type", "Issuing", "TLSCertificatePending"},
		{"malformed-type", "type", true, "TLSCertificateUnavailable"},
		{"missing-observed", "observedGeneration", nil, "TLSCertificatePending"},
		{"malformed-observed", "observedGeneration", "3", "TLSCertificateUnavailable"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			in, plan, cert := certificateClientFixture()
			condition := cert.Object["status"].(map[string]any)["conditions"].([]any)[0].(map[string]any)
			if tt.value == nil {
				delete(condition, tt.field)
			} else {
				condition[tt.field] = tt.value
			}
			c := dynamicfake.NewSimpleDynamicClient(runtime.NewScheme(), cert)
			if got := ensureIngressCertificate(context.Background(), c, nil, in, plan); got != tt.reason {
				t.Fatalf("reason=%q, want %q", got, tt.reason)
			}
			checkCertificateActions(t, c, "get")
		})
	}
}

func TestEnsureIngressCertificateUnrelatedSpec(t *testing.T) {
	in, plan, cert := certificateClientFixture()
	spec := cert.Object["spec"].(map[string]any)
	spec["duration"], spec["renewBefore"] = "2160h", "360h"
	cert.SetAnnotations(map[string]string{"unrelated": "preserve"})
	cert.SetOwnerReferences(append(cert.GetOwnerReferences(), metav1.OwnerReference{
		APIVersion: "v1", Kind: "ConfigMap", Name: "non-controller", UID: "unrelated-owner",
	}))
	c := dynamicfake.NewSimpleDynamicClient(runtime.NewScheme(), cert)
	r := &certificateSecretReader{t: t, exists: true}
	if got := ensureIngressCertificate(context.Background(), c, r, in, plan); got != "" {
		t.Fatalf("unrelated spec changed readiness: %q", got)
	}
	checkCertificateActions(t, c, "get")
	if r.calls != 0 {
		t.Fatal("existing owned Certificate must not run creation-time Secret collision check")
	}
}

func TestEnsureIngressCertificatePatch(t *testing.T) {
	for _, field := range []string{"secretName", "dnsNames", "issuerRef", "issuerRef-extra"} {
		t.Run(field, func(t *testing.T) {
			in, plan, cert := certificateClientFixture()
			spec := cert.Object["spec"].(map[string]any)
			spec["duration"], spec["renewBefore"] = "2160h", "360h"
			spec["privateKey"] = map[string]any{"algorithm": "ECDSA"}
			cert.SetAnnotations(map[string]string{"unrelated": "preserve"})
			switch field {
			case "secretName":
				spec[field] = "previous-secret"
			case "dnsNames":
				spec[field] = []any{"previous.invalid", "extra.invalid"}
			case "issuerRef":
				spec[field] = map[string]any{"name": "old", "kind": "ClusterIssuer", "group": "old.invalid"}
			case "issuerRef-extra":
				spec["issuerRef"].(map[string]any)["unmanaged-extension"] = "remove"
			}
			before := cert.DeepCopy()
			c := dynamicfake.NewSimpleDynamicClient(runtime.NewScheme(), cert)
			c.PrependReactor("patch", "certificates", func(action ktesting.Action) (bool, runtime.Object, error) {
				a := action.(ktesting.PatchAction)
				var patch map[string]any
				if a.GetPatchType() != types.MergePatchType || json.Unmarshal(a.GetPatch(), &patch) != nil {
					t.Fatal("not a merge patch")
				}
				wantMeta := map[string]any{"uid": string(cert.GetUID()), "resourceVersion": cert.GetResourceVersion()}
				if len(patch) != 2 || !reflect.DeepEqual(patch["metadata"], wantMeta) || patch["spec"] == nil {
					t.Fatalf("patch lacks preconditions or rewrites metadata/status: %s", a.GetPatch())
				}
				for _, field := range []string{"duration", "renewBefore", "privateKey"} {
					if _, exists := patch["spec"].(map[string]any)[field]; exists {
						t.Fatalf("patch changes unrelated spec.%s", field)
					}
				}
				return false, nil, nil
			})
			if got := ensureIngressCertificate(context.Background(), c, nil, in, plan); got != "TLSCertificatePending" {
				t.Fatalf("old Ready condition accepted after patch: %q", got)
			}
			checkCertificateActions(t, c, "get", "patch")
			stored, err := c.Tracker().Get(ingressCertificateResource, "tenant", "web-tls")
			if err != nil {
				t.Fatal(err)
			}
			got := stored.(*unstructured.Unstructured)
			want := before.DeepCopy()
			for field, value := range desiredIngressCertificate(in, plan).Object["spec"].(map[string]any) {
				want.Object["spec"].(map[string]any)[field] = value
			}
			if !reflect.DeepEqual(got, want) || !reflect.DeepEqual(before, cert) {
				t.Fatal("managed fields differ, unrelated fields changed, or input mutated")
			}
		})
	}
}

func TestIngressCertificateClientMutationErrors(t *testing.T) {
	gr := ingressCertificateResource.GroupResource()
	for _, verb := range []string{"patch", "delete"} {
		for _, tt := range []struct {
			name, reason string
			err          error
		}{
			{"conflict", "TLSCertificatePending", apierrors.NewConflict(gr, "web-tls", errors.New("private-error"))},
			{"forbidden", "TLSCertificateForbidden", apierrors.NewForbidden(gr, "web-tls", errors.New("private-error"))},
			{"transport", "TLSCertificateUnavailable", errors.New("private-error")},
			{"not-found", "TLSCertificateUnavailable", apierrors.NewNotFound(gr, "web-tls")},
		} {
			t.Run(verb+"/"+tt.name, func(t *testing.T) {
				in, plan, cert := certificateClientFixture()
				cert.Object["spec"].(map[string]any)["secretName"] = "old"
				c := dynamicfake.NewSimpleDynamicClient(runtime.NewScheme(), cert)
				c.PrependReactor(verb, "certificates", func(ktesting.Action) (bool, runtime.Object, error) { return true, nil, tt.err })
				var got string
				want := tt.reason
				if verb == "patch" {
					got = ensureIngressCertificate(context.Background(), c, nil, in, plan)
				} else {
					got = removeIngressCertificate(context.Background(), c, in, "external")
					if apierrors.IsNotFound(tt.err) {
						want = ""
					}
				}
				if got != want {
					t.Fatalf("reason=%q, want %q", got, want)
				}
				checkCertificateActions(t, c, "get", verb)
			})
		}
		for _, field := range []string{"uid", "resourceVersion"} {
			t.Run(verb+"/missing-"+field, func(t *testing.T) {
				in, plan, cert := certificateClientFixture()
				delete(cert.Object["metadata"].(map[string]any), field)
				cert.Object["spec"].(map[string]any)["secretName"] = "old"
				c := dynamicfake.NewSimpleDynamicClient(runtime.NewScheme(), cert)
				var got string
				if verb == "patch" {
					got = ensureIngressCertificate(context.Background(), c, nil, in, plan)
				} else {
					got = removeIngressCertificate(context.Background(), c, in, "")
				}
				if got != "TLSCertificateUnavailable" {
					t.Fatalf("mutation without precondition: %q", got)
				}
				checkCertificateActions(t, c, "get")
			})
		}
	}
}

func TestRemoveIngressCertificate(t *testing.T) {
	for _, retain := range []string{"", "external"} {
		t.Run("delete/"+retain, func(t *testing.T) {
			in, _, cert := certificateClientFixture()
			foreign := cert.DeepCopy()
			foreign.SetNamespace("foreign-backend")
			c := dynamicfake.NewSimpleDynamicClient(runtime.NewScheme(), cert, foreign)
			c.PrependReactor("delete", "certificates", func(action ktesting.Action) (bool, runtime.Object, error) {
				opts := action.(ktesting.DeleteAction).GetDeleteOptions()
				if opts.Preconditions == nil || opts.Preconditions.UID == nil || opts.Preconditions.ResourceVersion == nil ||
					*opts.Preconditions.UID != cert.GetUID() || *opts.Preconditions.ResourceVersion != cert.GetResourceVersion() {
					t.Fatal("delete missing UID and resourceVersion preconditions")
				}
				return false, nil, nil
			})
			if got := removeIngressCertificate(context.Background(), c, in, retain); got != "TLSCertificatePending" {
				t.Fatalf("accepted deletion must remain pending, got reason=%q", got)
			}
			checkCertificateActions(t, c, "get", "delete")
			if got := removeIngressCertificate(context.Background(), c, in, retain); got != "" {
				t.Fatalf("confirmed absence should complete cleanup, got %q", got)
			}
			if _, err := c.Tracker().Get(ingressCertificateResource, "tenant", "web-tls"); !apierrors.IsNotFound(err) {
				t.Fatal("owned Certificate was not deleted")
			}
			stored, err := c.Tracker().Get(ingressCertificateResource, "foreign-backend", "web-tls")
			if err != nil || !reflect.DeepEqual(stored, foreign) {
				t.Fatal("cleanup touched same-name Certificate in backend namespace")
			}
		})
	}
	t.Run("retain-generated-secret", func(t *testing.T) {
		in, _, cert := certificateClientFixture()
		c := dynamicfake.NewSimpleDynamicClient(runtime.NewScheme(), cert)
		if got := removeIngressCertificate(context.Background(), nil, in, "web-tls"); got != "" {
			t.Fatalf("nil client retaining selected generated Secret: %q", got)
		}
		if got := removeIngressCertificate(context.Background(), c, in, "web-tls"); got != "" {
			t.Fatalf("reason=%q", got)
		}
		checkCertificateActions(t, c)
	})
	gr := ingressCertificateResource.GroupResource()
	for _, tt := range []struct {
		name, reason string
		err          error
	}{
		{"absent", "", apierrors.NewNotFound(gr, "web-tls")},
		{"missing-api", "", apierrors.NewGenericServerResponse(404, "GET", gr, "", "private", 0, false)},
		{"forbidden", "TLSCertificateForbidden", apierrors.NewForbidden(gr, "web-tls", errors.New("private"))},
		{"unavailable", "TLSCertificateUnavailable", errors.New("private")},
		{"conflict", "TLSCertificatePending", apierrors.NewConflict(gr, "web-tls", errors.New("private"))},
	} {
		t.Run(tt.name, func(t *testing.T) {
			in, _, _ := certificateClientFixture()
			c := dynamicfake.NewSimpleDynamicClient(runtime.NewScheme())
			c.PrependReactor("get", "certificates", func(ktesting.Action) (bool, runtime.Object, error) { return true, nil, tt.err })
			if got := removeIngressCertificate(context.Background(), c, in, ""); got != tt.reason {
				t.Fatalf("reason=%q, want %q", got, tt.reason)
			}
			checkCertificateActions(t, c, "get")
		})
	}
}
