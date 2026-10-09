package controller

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"reflect"
	"sync/atomic"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"

	tnv1 "tsunaro.io/tailnet-operator/api/v1alpha1"
	"tsunaro.io/tailnet-operator/internal/headscale"
)

// The rule: a working authkey is reused while it is neither expired nor due and its stored
// server+tag binding matches the CR's effective identity. Unbound (legacy/transferred) Secrets
// count as matching and are labelled in place; a changed server or tag mints a new key; a changed
// Tailnet UID is recorded only.
func TestAuthKeyBoundToEffectiveIdentity(t *testing.T) {
	const server = "https://hs.example"
	cases := []struct {
		name       string
		ann        map[string]string // stored binding (nil = legacy Secret with expiry only)
		wantMint   bool
		wantServer string // expected server annotation afterwards
	}{
		{"bound-match", map[string]string{annServer: server, annTag: "tag:app", annTailnetUID: "tn-uid"}, false, server},
		{"tag-changed", map[string]string{annServer: server, annTag: "tag:old", annTailnetUID: "tn-uid"}, true, server},
		{"server-changed", map[string]string{annServer: "https://old.example", annTag: "tag:app", annTailnetUID: "tn-uid"}, true, server},
		{"tailnet-uid-changed", map[string]string{annServer: server, annTag: "tag:app", annTailnetUID: "old-uid"}, false, server},
		{"unbound-legacy", nil, false, server},
	}
	for _, kind := range []string{"TailnetEgress", "TailnetIngress"} {
		for _, tc := range cases {
			t.Run(kind+"/"+tc.name, func(t *testing.T) {
				ctx := context.Background()
				var mints atomic.Int32
				hsrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					mints.Add(1)
					_ = json.NewEncoder(w).Encode(map[string]any{"preAuthKey": map[string]any{"key": "minted", "expiration": time.Now().Add(time.Hour).UTC().Format(time.RFC3339)}})
				}))
				defer hsrv.Close()
				scheme := runtime.NewScheme()
				if err := corev1.AddToScheme(scheme); err != nil {
					t.Fatal(err)
				}
				if err := tnv1.AddToScheme(scheme); err != nil {
					t.Fatal(err)
				}
				tn := &tnv1.Tailnet{ObjectMeta: metav1.ObjectMeta{Name: "corp", UID: "tn-uid"},
					Spec: tnv1.TailnetSpec{Server: server, AuthKeyLifetime: metav1.Duration{Duration: time.Hour}}}
				expires := time.Now().Add(time.Hour).UTC().Truncate(time.Second)
				ann := map[string]string{annExpiresAt: expires.Format(time.RFC3339)}
				for k, v := range tc.ann {
					ann[k] = v
				}
				eg := &tnv1.TailnetEgress{ObjectMeta: metav1.ObjectMeta{Name: "app", Namespace: "ns", UID: "eg-uid"}}
				in := &tnv1.TailnetIngress{ObjectMeta: metav1.ObjectMeta{Name: "app", Namespace: "ns", UID: "in-uid"}}
				var parent client.Object = eg
				if kind == "TailnetIngress" {
					parent = in
				}
				secret := &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: authKeySecretName("app"), Namespace: "ns", UID: "sec-uid", Annotations: ann},
					Data: map[string][]byte{authKeySecretKey: []byte("current")}}
				if err := controllerutil.SetControllerReference(parent, secret, scheme); err != nil {
					t.Fatal(err)
				}
				c := fake.NewClientBuilder().WithScheme(scheme).WithObjects(tn, parent, secret).Build()
				hs := headscale.New(hsrv.URL, "working")
				var exp *time.Time
				var err error
				if kind == "TailnetEgress" {
					exp, err = (&TailnetEgressReconciler{Client: c, Scheme: scheme}).ensureAuthKey(ctx, eg, tn, hs, "tag:app")
				} else {
					exp, err = (&TailnetIngressReconciler{Client: c, Scheme: scheme}).ensureAuthKey(ctx, in, tn, hs, "tag:app")
				}
				if err != nil || exp == nil {
					t.Fatalf("ensureAuthKey: exp=%v err=%v", exp, err)
				}
				var got corev1.Secret
				if err := c.Get(ctx, client.ObjectKeyFromObject(secret), &got); err != nil {
					t.Fatal(err)
				}
				if minted := mints.Load() == 1; minted != tc.wantMint || mints.Load() > 1 {
					t.Fatalf("mints=%d want mint=%t", mints.Load(), tc.wantMint)
				}
				if !tc.wantMint && (!exp.Equal(expires) || !reflect.DeepEqual(got.Data, secret.Data) || got.UID != secret.UID) {
					t.Fatal("reuse changed key, expiry or Secret identity")
				}
				// The fake client does not fold StringData into Data like the API server does.
				if tc.wantMint && (exp.Equal(expires) || got.StringData[authKeySecretKey] != "minted") {
					t.Fatal("re-mint did not replace key and expiry")
				}
				if got.Annotations[annServer] != tc.wantServer || got.Annotations[annTag] != "tag:app" || got.Annotations[annTailnetUID] != "tn-uid" {
					t.Fatalf("binding not written: %v", got.Annotations)
				}
			})
		}
	}
}
