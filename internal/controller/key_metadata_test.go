package controller

import (
	"context"
	"reflect"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	tnv1 "this-is-fine.io/tailnet-operator/api/v1alpha1"
)

func TestRepairWorkingKeyPrefixWithoutRotation(t *testing.T) {
	const key = "hskey-api-ab-cd_12EFgh-synthetic-secret"
	const prefix = "ab-cd_12EFgh"
	for _, oldPrefix := range []string{key, "", "wrong", prefix} {
		t.Run(map[bool]string{true: "already-canonical", false: "repair"}[oldPrefix == prefix], func(t *testing.T) {
			scheme := runtime.NewScheme()
			if err := corev1.AddToScheme(scheme); err != nil {
				t.Fatal(err)
			}
			expires := time.Now().Add(time.Hour).UTC().Truncate(time.Second)
			secret := &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{Name: "test-apikey", Namespace: "operator", Annotations: map[string]string{
					annPrefix: oldPrefix, annExpiresAt: expires.Format(time.RFC3339), "keep": "yes",
				}},
				Data: map[string][]byte{apiKeyData: []byte(key)},
			}
			c := fake.NewClientBuilder().WithScheme(scheme).WithObjects(secret).Build()
			r := &TailnetReconciler{Client: c, Scheme: scheme, OperatorNamespace: "operator"}
			tn := &tnv1.Tailnet{ObjectMeta: metav1.ObjectMeta{Name: "test"}}
			tn.Spec.APIKeyLifetime = metav1.Duration{Duration: time.Hour}
			ctx := context.Background()
			gotKey, gotExpiry, err := r.apiKeyFor(ctx, tn)
			if err != nil || gotKey != key || !gotExpiry.Equal(expires) {
				t.Fatal("prefix repair changed key lifecycle or required bootstrap")
			}
			var updated corev1.Secret
			namespaced := types.NamespacedName{Namespace: secret.Namespace, Name: secret.Name}
			if err := c.Get(ctx, namespaced, &updated); err != nil {
				t.Fatal(err)
			}
			if updated.Annotations[annPrefix] != prefix || updated.Annotations[annExpiresAt] != secret.Annotations[annExpiresAt] ||
				updated.Annotations["keep"] != "yes" || !reflect.DeepEqual(updated.Data, secret.Data) {
				t.Fatal("metadata repair did not preserve the credential and other metadata")
			}
			resourceVersion := updated.ResourceVersion
			if _, _, err := r.apiKeyFor(ctx, tn); err != nil {
				t.Fatal(err)
			}
			if err := c.Get(ctx, namespaced, &updated); err != nil {
				t.Fatal(err)
			}
			if updated.ResourceVersion != resourceVersion {
				t.Fatal("canonical prefix caused repeated Secret writes")
			}
		})
	}
}
