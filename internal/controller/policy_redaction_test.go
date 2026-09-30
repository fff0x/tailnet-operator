package controller

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	tnv1 "this-is-fine.io/tailnet-operator/api/v1alpha1"
)

func TestPolicyStatusRedactsDecoderInputs(t *testing.T) {
	const credential = "synthetic-private-input-do-not-emit"
	const valid = `{"tagOwners":{},"acls":[{"action":"accept","src":["*"],"dst":["192.0.2.1:443"]}]}`
	for _, tc := range []struct{ name, base, condition, reason string }{
		{"local-literal", `{"secret":"` + credential + `\q"}`, "PolicyRendered", "BaseInvalid"},
		{"upstream-timestamp", valid, "PolicyApplied", "ApplyFailed"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Method == http.MethodGet && r.URL.Path == "/api/v1/policy" {
					_ = json.NewEncoder(w).Encode(map[string]any{"policy": "{}", "updatedAt": credential})
					return
				}
				w.WriteHeader(http.StatusBadRequest)
				_, _ = w.Write([]byte(credential))
			}))
			defer srv.Close()
			scheme := runtime.NewScheme()
			if err := clientgoscheme.AddToScheme(scheme); err != nil {
				t.Fatal(err)
			}
			if err := tnv1.AddToScheme(scheme); err != nil {
				t.Fatal(err)
			}
			tn := &tnv1.Tailnet{
				ObjectMeta: metav1.ObjectMeta{Name: tc.name, UID: "redaction-fixture", Generation: 1},
				Spec: tnv1.TailnetSpec{Server: srv.URL, Policy: tnv1.PolicySpec{
					BaseConfigMap: "base", Mode: "Apply", TagOwners: []string{"autogroup:member"}, RouteApprovers: []string{"tag:fabric"},
				}},
			}
			cm := &corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Name: "base", Namespace: "operator"}, Data: map[string]string{policyKey: tc.base}}
			key := &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: workingSecretName(tn.Name), Namespace: "operator"}, Data: map[string][]byte{apiKeyData: []byte(credential)}}
			c := fake.NewClientBuilder().WithScheme(scheme).WithObjects(tn, cm, key).WithStatusSubresource(tn).Build()
			r := TailnetPolicyReconciler{Client: c, Scheme: scheme, OperatorNamespace: "operator"}
			ctx := context.Background()
			if _, err := r.Reconcile(ctx, ctrl.Request{NamespacedName: types.NamespacedName{Name: tn.Name}}); err != nil {
				t.Fatal("reconciliation failed (details withheld)")
			}
			if err := c.Get(ctx, types.NamespacedName{Name: tn.Name}, tn); err != nil {
				t.Fatal(err)
			}
			if condReason(tn.Status.Conditions, tc.condition) != tc.reason {
				t.Fatal("fixture did not reach its expected failure condition")
			}
			data, err := json.Marshal(tn.Status)
			if err != nil {
				t.Fatal(err)
			}
			if strings.Contains(string(data), credential) {
				t.Fatal("decoder input leaked into persisted status (output withheld)")
			}
		})
	}
}
