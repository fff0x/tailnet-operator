package controller

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"

	tnv1 "tsunaro.io/tailnet-operator/api/v1alpha1"
	"tsunaro.io/tailnet-operator/internal/headscale"
)

// fakeHeadscale mints key id "42" and records every expired id.
func fakeHeadscale(t *testing.T) (*httptest.Server, func() []string) {
	t.Helper()
	var mu sync.Mutex
	var expired []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/v1/preauthkey":
			_ = json.NewEncoder(w).Encode(map[string]any{"preAuthKey": map[string]any{"id": "42", "key": "minted",
				"expiration": time.Now().Add(time.Hour).UTC().Format(time.RFC3339)}})
		case "/api/v1/preauthkey/expire":
			var body map[string]string
			_ = json.NewDecoder(r.Body).Decode(&body)
			mu.Lock()
			expired = append(expired, body["id"])
			mu.Unlock()
			_, _ = w.Write([]byte(`{}`))
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(srv.Close)
	return srv, func() []string { mu.Lock(); defer mu.Unlock(); return append([]string(nil), expired...) }
}

func authKeyScheme(t *testing.T) *runtime.Scheme {
	t.Helper()
	s := runtime.NewScheme()
	if err := corev1.AddToScheme(s); err != nil {
		t.Fatal(err)
	}
	if err := tnv1.AddToScheme(s); err != nil {
		t.Fatal(err)
	}
	return s
}

// The rule: a minted key's Headscale ID is recorded on the Secret; when a key is replaced, the
// recorded predecessor is expired; a Secret without ID (older operator) is replaced silently.
func TestAuthKeyRotationExpiresPredecessor(t *testing.T) {
	for _, tc := range []struct {
		name    string
		oldID   string
		wantExp []string
	}{
		{"recorded", "7", []string{"7"}},
		{"legacy-without-id", "", nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()
			srv, expired := fakeHeadscale(t)
			s := authKeyScheme(t)
			tn := &tnv1.Tailnet{ObjectMeta: metav1.ObjectMeta{Name: "corp", UID: "tn-uid"},
				Spec: tnv1.TailnetSpec{Server: srv.URL, AuthKeyLifetime: metav1.Duration{Duration: time.Hour}}}
			eg := &tnv1.TailnetEgress{ObjectMeta: metav1.ObjectMeta{Name: "app", Namespace: "ns", UID: "eg-uid"}}
			ann := map[string]string{annExpiresAt: time.Now().Add(-time.Minute).UTC().Format(time.RFC3339)} // expired → rotate
			if tc.oldID != "" {
				ann[annAuthKeyID] = tc.oldID
			}
			sec := &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: authKeySecretName("app"), Namespace: "ns", Annotations: ann},
				Data: map[string][]byte{authKeySecretKey: []byte("old")}}
			c := fake.NewClientBuilder().WithScheme(s).WithObjects(tn, eg, sec).Build()
			r := &TailnetEgressReconciler{Client: c, Scheme: s}
			if _, err := r.ensureAuthKey(ctx, eg, tn, headscale.New(srv.URL, "working"), "tag:app"); err != nil {
				t.Fatal(err)
			}
			var got corev1.Secret
			if err := c.Get(ctx, client.ObjectKeyFromObject(sec), &got); err != nil {
				t.Fatal(err)
			}
			if got.Annotations[annAuthKeyID] != "42" {
				t.Fatalf("new key id not recorded: %v", got.Annotations)
			}
			if e := expired(); len(e) != len(tc.wantExp) || (len(e) == 1 && e[0] != tc.wantExp[0]) {
				t.Fatalf("expired = %v, want %v", e, tc.wantExp)
			}
		})
	}
}

// The rule: a reconcile adds the authkey finalizer; a delete expires the recorded key and removes
// the finalizer; a Headscale that is unreachable, a missing Secret or a missing Tailnet never block
// the delete. Checked for both CR kinds.
func TestAuthKeyFinalizerReleasesKey(t *testing.T) {
	for _, kind := range []string{"TailnetEgress", "TailnetIngress"} {
		for _, tc := range []struct {
			name              string
			headscaleUp       bool
			withSecret        bool
			withTailnet       bool
			wantExpired       bool
			wantFinalizerLeft bool
		}{
			{"expires", true, true, true, true, false},
			{"headscale-down", false, true, true, false, false},
			{"secret-gone", true, false, true, false, false},
			{"tailnet-gone", true, true, false, false, false},
		} {
			t.Run(kind+"/"+tc.name, func(t *testing.T) {
				ctx := context.Background()
				srv, expired := fakeHeadscale(t)
				server := srv.URL
				if !tc.headscaleUp {
					server = "http://127.0.0.1:1" // nothing listens
				}
				s := authKeyScheme(t)
				tn := &tnv1.Tailnet{ObjectMeta: metav1.ObjectMeta{Name: "corp", UID: "tn-uid"}, Spec: tnv1.TailnetSpec{Server: server}}
				working := &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: workingSecretName("corp"), Namespace: "operator"},
					Data: map[string][]byte{apiKeyData: []byte("working")}}
				now := metav1.Now()
				meta := metav1.ObjectMeta{Name: "app", Namespace: "ns", UID: "cr-uid", DeletionTimestamp: &now, Finalizers: []string{authKeyFinalizer}}
				ref := tnv1.TailnetRef{Name: "corp"}
				var cr client.Object
				if kind == "TailnetEgress" {
					cr = &tnv1.TailnetEgress{ObjectMeta: meta, Spec: tnv1.TailnetEgressSpec{TailnetRef: ref}}
				} else {
					cr = &tnv1.TailnetIngress{ObjectMeta: meta, Spec: tnv1.TailnetIngressSpec{TailnetRef: ref}}
				}
				objs := []client.Object{cr, working}
				if tc.withTailnet {
					objs = append(objs, tn)
				}
				if tc.withSecret {
					objs = append(objs, &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: authKeySecretName("app"), Namespace: "ns",
						Annotations: map[string]string{annAuthKeyID: "7"}}, Data: map[string][]byte{authKeySecretKey: []byte("k")}})
				}
				c := fake.NewClientBuilder().WithScheme(s).WithObjects(objs...).WithStatusSubresource(cr).Build()
				req := ctrl.Request{NamespacedName: client.ObjectKeyFromObject(cr)}
				start := time.Now()
				var err error
				if kind == "TailnetEgress" {
					_, err = (&TailnetEgressReconciler{Client: c, Scheme: s, OperatorNamespace: "operator"}).Reconcile(ctx, req)
				} else {
					_, err = (&TailnetIngressReconciler{Client: c, Scheme: s, OperatorNamespace: "operator"}).Reconcile(ctx, req)
				}
				if err != nil {
					t.Fatalf("delete reconcile must not fail: %v", err)
				}
				if d := time.Since(start); d > authKeyExpireTimeout {
					t.Fatalf("delete blocked for %s", d)
				}
				// The fake client removes an object once its last finalizer is gone.
				if err := c.Get(ctx, req.NamespacedName, cr); !apierrors.IsNotFound(err) {
					t.Fatalf("finalizer still present or Get failed: %v (finalizers %v)", err, cr.GetFinalizers())
				}
				if got := len(expired()) == 1; got != tc.wantExpired {
					t.Fatalf("expired = %v, want expired=%t", expired(), tc.wantExpired)
				}
			})
		}
	}

	// A live CR gets the finalizer on its first reconcile, before anything else can fail.
	t.Run("added-on-reconcile", func(t *testing.T) {
		ctx := context.Background()
		s := authKeyScheme(t)
		eg := &tnv1.TailnetEgress{ObjectMeta: metav1.ObjectMeta{Name: "app", Namespace: "ns"},
			Spec: tnv1.TailnetEgressSpec{TailnetRef: tnv1.TailnetRef{Name: "absent"}}}
		c := fake.NewClientBuilder().WithScheme(s).WithObjects(eg).WithStatusSubresource(eg).Build()
		if _, err := (&TailnetEgressReconciler{Client: c, Scheme: s}).Reconcile(ctx, ctrl.Request{NamespacedName: client.ObjectKeyFromObject(eg)}); err != nil {
			t.Fatal(err)
		}
		if err := c.Get(ctx, types.NamespacedName{Namespace: "ns", Name: "app"}, eg); err != nil || !controllerutil.ContainsFinalizer(eg, authKeyFinalizer) {
			t.Fatalf("finalizer missing: %v %v", eg.Finalizers, err)
		}
	})
}
