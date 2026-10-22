package controller

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	tnv1 "tsunaro.io/tailnet-operator/api/v1alpha1"
	"tsunaro.io/tailnet-operator/internal/headscale"
)

func TestPreflightConditions(t *testing.T) {
	yes, no := true, false
	for _, tc := range []struct {
		name             string
		mode, check      *bool
		err              error
		modeReason       string
		compatibleReason string
		compatibleStatus metav1.ConditionStatus
	}{
		{"compatible", &yes, &yes, nil, "Database", "Compatible", metav1.ConditionTrue},
		{"old server", &yes, &no, nil, "Database", "Incompatible", metav1.ConditionFalse},
		{"file", &no, &yes, nil, "File", "Incompatible", metav1.ConditionFalse},
		{"mode omitted", nil, &yes, nil, "CannotVerify", "CannotVerify", metav1.ConditionUnknown},
		{"probe failed", nil, nil, errors.New("secret-token echoed by proxy"), "ProbeFailed", "ProbeFailed", metav1.ConditionUnknown},
		{"partial failure", &yes, nil, errors.New("server offline"), "Database", "ProbeFailed", metav1.ConditionUnknown},
	} {
		t.Run(tc.name, func(t *testing.T) {
			tn := &tnv1.Tailnet{ObjectMeta: metav1.ObjectMeta{Generation: 7}, Spec: tnv1.TailnetSpec{
				Headscale: tnv1.HeadscaleSpec{Version: "99.0.0"},
				DNS:       tnv1.DNSSpec{IngressNameTemplate: "{name}-{namespace}.prod-1.tailnet.example.com"},
			}}
			setPreflightConditions(tn, headscale.Capabilities{PolicyDatabaseMode: tc.mode, PolicyCheck: tc.check}, tc.err)
			if got := condReason(tn.Status.Conditions, "PolicyMode"); got != tc.modeReason {
				t.Fatalf("PolicyMode=%s, want %s", got, tc.modeReason)
			}
			c := meta.FindStatusCondition(tn.Status.Conditions, "HeadscaleCompatible")
			if c == nil || c.Reason != tc.compatibleReason || c.Status != tc.compatibleStatus || c.ObservedGeneration != 7 {
				t.Fatalf("HeadscaleCompatible=%+v", c)
			}
			if !strings.Contains(c.Message, "99.0.0") || strings.Contains(c.Message, "secret-token") {
				t.Fatalf("version hint missing or upstream secret leaked: %s", c.Message)
			}
			for _, cond := range tn.Status.Conditions {
				if strings.Contains(cond.Message, "secret-token") {
					t.Fatal("upstream body leaked into preflight status")
				}
			}
		})
	}
}

func TestTailnetReconcilePreflight(t *testing.T) {
	for _, tc := range []struct {
		name, policy, dbHealth, modeReason, compatibility, reachable string
		checkCode                                                    int
	}{
		{"database", `{"policy":"{}","updatedAt":"2026-09-30T00:00:00Z"}`, `true`, "Database", "Compatible", "Reachable", 200},
		{"file", `{"policy":"{}","updatedAt":null}`, `true`, "File", "Incompatible", "Reachable", 200},
		{"old", `{"policy":"{}","updatedAt":"2026-09-30T00:00:00Z"}`, `true`, "Database", "Incompatible", "Reachable", 404},
		{"database health false", `{"policy":"{}","updatedAt":"2026-09-30T00:00:00Z"}`, `false`, "Database", "Compatible", "Unhealthy", 200},
	} {
		t.Run(tc.name, func(t *testing.T) {
			calls := map[string]int{}
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
				calls[req.URL.Path]++
				switch req.URL.Path {
				case "/health":
					_, _ = w.Write([]byte(`{"status":"pass"}`))
				case "/api/v1/apikey":
					_, _ = w.Write([]byte(`{"apiKeys":[]}`))
				case "/api/v1/policy":
					if req.Method != http.MethodGet {
						t.Error("preflight wrote policy")
					}
					_, _ = w.Write([]byte(tc.policy))
				case "/api/v1/policy/check":
					w.WriteHeader(tc.checkCode)
					_, _ = w.Write([]byte(`{}`))
				case "/api/v1/health":
					_, _ = w.Write([]byte(`{"databaseConnectivity":` + tc.dbHealth + `}`))
				case "/api/v1/user":
					_, _ = w.Write([]byte(`{"users":[{"id":"1","name":"ops@example.test"}]}`))
				default:
					t.Errorf("unexpected endpoint %s", req.URL.Path)
					http.NotFound(w, req)
				}
			}))
			defer srv.Close()
			s := runtime.NewScheme()
			_ = clientgoscheme.AddToScheme(s)
			_ = tnv1.AddToScheme(s)
			tn := &tnv1.Tailnet{ObjectMeta: metav1.ObjectMeta{Name: "test", Generation: 1}, Spec: tnv1.TailnetSpec{
				Server: srv.URL, DNS: tnv1.DNSSpec{IngressNameTemplate: "{name}.cluster.example"},
			}}
			secret := &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: workingSecretName(tn.Name), Namespace: "operator",
				Annotations: map[string]string{annExpiresAt: time.Now().Add(25 * 24 * time.Hour).Format(time.RFC3339)}},
				Data: map[string][]byte{apiKeyData: []byte("working-key")}}
			c := fake.NewClientBuilder().WithScheme(s).WithObjects(tn, secret).WithStatusSubresource(tn).Build()
			r := TailnetReconciler{Client: c, Scheme: s, OperatorNamespace: "operator"}
			if _, err := r.Reconcile(context.Background(), ctrl.Request{NamespacedName: types.NamespacedName{Name: tn.Name}}); err != nil {
				t.Fatal(err)
			}
			if err := c.Get(context.Background(), types.NamespacedName{Name: tn.Name}, tn); err != nil {
				t.Fatal(err)
			}
			for typ, want := range map[string]string{"PolicyMode": tc.modeReason, "HeadscaleCompatible": tc.compatibility,
				"ApiKeyValid": "Valid", "ApiReachable": tc.reachable, "SplitDNS": "CannotVerify", "UsersUnique": "Unique"} {
				if got := condReason(tn.Status.Conditions, typ); got != want {
					t.Errorf("%s=%s, want %s", typ, got, want)
				}
			}
			for path, n := range calls {
				if n != 1 {
					t.Errorf("%s called %d times", path, n)
				}
			}
			if len(calls) != 6 {
				t.Fatalf("expected health + key validity + three probes + user list; got %v", calls)
			}
		})
	}
}

func TestPreflightClearsStaleVerdictOnKeyFailure(t *testing.T) {
	s := runtime.NewScheme()
	_ = clientgoscheme.AddToScheme(s)
	_ = tnv1.AddToScheme(s)
	tn := &tnv1.Tailnet{ObjectMeta: metav1.ObjectMeta{Name: "test"}, Spec: tnv1.TailnetSpec{
		APISecretRef: tnv1.SecretKeyRef{Name: "missing"},
	}}
	setCond(&tn.Status.Conditions, 1, "PolicyMode", metav1.ConditionFalse, "File", "old evidence")
	setCond(&tn.Status.Conditions, 1, "HeadscaleCompatible", metav1.ConditionTrue, "Compatible", "old evidence")
	c := fake.NewClientBuilder().WithScheme(s).WithObjects(tn).WithStatusSubresource(tn).Build()
	r := TailnetReconciler{Client: c, Scheme: s, OperatorNamespace: "operator"}
	if _, err := r.Reconcile(context.Background(), ctrl.Request{NamespacedName: types.NamespacedName{Name: tn.Name}}); err != nil {
		t.Fatal(err)
	}
	if err := c.Get(context.Background(), types.NamespacedName{Name: tn.Name}, tn); err != nil {
		t.Fatal(err)
	}
	for _, typ := range []string{"PolicyMode", "HeadscaleCompatible"} {
		if condStatus(tn.Status.Conditions, typ) != metav1.ConditionUnknown || condReason(tn.Status.Conditions, typ) != "ProbeFailed" {
			t.Errorf("stale %s verdict survived key failure: %+v", typ, tn.Status.Conditions)
		}
	}
}
