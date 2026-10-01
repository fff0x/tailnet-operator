package controller

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"reflect"
	"sync/atomic"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	tnv1 "tsunaro.io/tailnet-operator/api/v1alpha1"
	"tsunaro.io/tailnet-operator/internal/headscale"
	"tsunaro.io/tailnet-operator/internal/migration"
)

// These controller regressions demonstrate the legacy failure first, then use the explicit
// metadata transfer. Real API-server JSONPatch/CAS behavior has separate admission tests.
func TestTransferredKeysReuseCredentials(t *testing.T) {
	for _, kind := range []string{"Tailnet", "TailnetEgress", "TailnetIngress"} {
		for _, migrated := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/migrated=%t", kind, migrated), func(t *testing.T) {
				ctx := context.Background()
				var requests atomic.Int32
				server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					requests.Add(1)
					w.WriteHeader(http.StatusUnauthorized) // Bootstrap is expired; no replacement can be minted.
				}))
				defer server.Close()
				scheme := runtime.NewScheme()
				if err := corev1.AddToScheme(scheme); err != nil {
					t.Fatal(err)
				}
				if err := tnv1.AddToScheme(scheme); err != nil {
					t.Fatal(err)
				}
				tn := &tnv1.Tailnet{
					TypeMeta:   metav1.TypeMeta{APIVersion: migration.APIVersion, Kind: "Tailnet"},
					ObjectMeta: metav1.ObjectMeta{Name: "corp", UID: "new-tailnet", ResourceVersion: "1"},
					Spec: tnv1.TailnetSpec{Server: server.URL, APISecretRef: tnv1.SecretKeyRef{Name: "bootstrap"},
						APIKeyLifetime: metav1.Duration{Duration: time.Hour}, AuthKeyLifetime: metav1.Duration{Duration: time.Hour}},
				}
				eg := &tnv1.TailnetEgress{TypeMeta: metav1.TypeMeta{APIVersion: migration.APIVersion, Kind: "TailnetEgress"},
					ObjectMeta: metav1.ObjectMeta{Name: "app", Namespace: "operator", UID: "new-egress", ResourceVersion: "1"},
					Spec:       tnv1.TailnetEgressSpec{TailnetRef: tnv1.TailnetRef{Name: tn.Name}}}
				in := &tnv1.TailnetIngress{TypeMeta: metav1.TypeMeta{APIVersion: migration.APIVersion, Kind: "TailnetIngress"},
					ObjectMeta: metav1.ObjectMeta{Name: "app", Namespace: "operator", UID: "new-ingress", ResourceVersion: "1"},
					Spec:       tnv1.TailnetIngressSpec{TailnetRef: tnv1.TailnetRef{Name: tn.Name}}}
				var parent client.Object = tn
				if kind == "TailnetEgress" {
					parent = eg
				} else if kind == "TailnetIngress" {
					parent = in
				}
				parentMap, err := runtime.DefaultUnstructuredConverter.ToUnstructured(parent)
				if err != nil {
					t.Fatal(err)
				}
				old := &unstructured.Unstructured{Object: parentMap}
				old.SetAPIVersion(migration.LegacyAPIVersion)
				old.SetUID("old-parent")
				expires := time.Now().Add(time.Hour).UTC().Truncate(time.Second)
				secretName, dataKey, key := authKeySecretName(parent.GetName()), authKeySecretKey, "synthetic-preauth"
				if kind == "Tailnet" {
					secretName, dataKey, key = workingSecretName(parent.GetName()), apiKeyData, "hskey-api-ab-cd_12EFgh-synthetic-secret"
				}
				yes := true
				secret := &corev1.Secret{ObjectMeta: metav1.ObjectMeta{
					Name: secretName, Namespace: "operator", UID: "preserved-secret", ResourceVersion: "1",
					Annotations:     map[string]string{"tailnet.this-is-fine.io/expires-at": expires.Format(time.RFC3339)},
					OwnerReferences: []metav1.OwnerReference{{APIVersion: migration.LegacyAPIVersion, Kind: kind, Name: parent.GetName(), UID: old.GetUID(), Controller: &yes}},
				}, Data: map[string][]byte{dataKey: []byte(key)}}
				if kind == "Tailnet" {
					secret.Annotations["tailnet.this-is-fine.io/prefix"] = key // Historical unsafe metadata; never copy it.
				}
				bootstrap := &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: "bootstrap", Namespace: "operator"}, Data: map[string][]byte{"apiKey": []byte("expired-bootstrap")}}
				objects := []client.Object{tn, secret, bootstrap, old}
				if kind != "Tailnet" {
					objects = append(objects, parent)
				}
				c := fake.NewClientBuilder().WithScheme(scheme).WithObjects(objects...).Build()
				if migrated {
					fetch := func(version, kind, ns, name string) *unstructured.Unstructured {
						t.Helper()
						obj := &unstructured.Unstructured{}
						obj.SetAPIVersion(version)
						obj.SetKind(kind)
						if err := c.Get(ctx, types.NamespacedName{Namespace: ns, Name: name}, obj); err != nil {
							t.Fatal(err)
						}
						return obj
					}
					old = fetch(migration.LegacyAPIVersion, kind, parent.GetNamespace(), parent.GetName())
					next := fetch(migration.APIVersion, kind, parent.GetNamespace(), parent.GetName())
					dest := fetch(migration.APIVersion, "Tailnet", "", tn.Name)
					child := fetch("v1", "Secret", secret.Namespace, secret.Name)
					plan, err := migration.PlanTransfer(child, old, next, dest)
					if err != nil {
						t.Fatal(err)
					}
					if err := migration.ApplyTransfer(ctx, c, plan, false); err != nil {
						t.Fatal(err)
					}
				}
				var gotExpiry *time.Time
				var lifecycleErr error
				switch kind {
				case "Tailnet":
					r := &TailnetReconciler{Client: c, Scheme: scheme, OperatorNamespace: "operator"}
					gotKey, exp, err := r.apiKeyFor(ctx, tn)
					gotExpiry, lifecycleErr = &exp, err
					if migrated && gotKey != key {
						t.Fatal("working credential changed")
					}
				case "TailnetEgress":
					r := &TailnetEgressReconciler{Client: c, Scheme: scheme, OperatorNamespace: "operator"}
					gotExpiry, lifecycleErr = r.ensureAuthKey(ctx, eg, tn, headscale.New(server.URL, "working"), "tag:app")
				case "TailnetIngress":
					r := &TailnetIngressReconciler{Client: c, Scheme: scheme, OperatorNamespace: "operator"}
					gotExpiry, lifecycleErr = r.ensureAuthKey(ctx, in, tn, headscale.New(server.URL, "working"), "tag:app")
				}
				if !migrated {
					if lifecycleErr == nil || requests.Load() == 0 {
						t.Fatal("legacy metadata no longer reproduces failed key mint")
					}
					return
				}
				if lifecycleErr != nil || gotExpiry == nil || !gotExpiry.Equal(expires) || requests.Load() != 0 {
					t.Fatal("transferred key required bootstrap/rotation or changed lifetime")
				}
				var updated corev1.Secret
				if err := c.Get(ctx, client.ObjectKeyFromObject(secret), &updated); err != nil {
					t.Fatal(err)
				}
				if updated.UID != secret.UID || !reflect.DeepEqual(updated.Data, secret.Data) || !ownedBy(&updated, parent.GetUID()) {
					t.Fatal("Secret identity, contents or transferred ownership changed")
				}
				if kind == "Tailnet" && updated.Annotations[annPrefix] != headscale.PrefixOf(key) {
					t.Fatal("canonical working-key prefix was not rebuilt")
				}
			})
		}
	}
}
