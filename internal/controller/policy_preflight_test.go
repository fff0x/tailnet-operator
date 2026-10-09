package controller

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/event"

	tnv1 "tsunaro.io/tailnet-operator/api/v1alpha1"
)

func TestPolicyFileModeGuard(t *testing.T) {
	const base = `{"tagOwners":{"tag:base":["group:admins"]},"groups":{"group:admins":["admin@"]},"grants":[{"src":["group:admins"],"dst":["tag:base"],"ip":["*"]}]}`
	for _, tc := range []struct {
		name, mode, reason         string
		knownFile, stale, database bool
		wantReads, wantWrites      int
	}{
		{"preflight file", "Apply", "PolicyModeFile", true, false, false, 0, 0},
		{"file discovered before preflight", "Apply", "PolicyModeFile", false, false, false, 1, 0},
		{"database writes", "Apply", "Applied", false, false, true, 1, 1},
		{"stale verdict ignored", "Apply", "Applied", true, true, true, 1, 1},
		{"dry run still renders", "DryRun", "DryRun", true, false, false, 0, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			reads, writes, nodes := 0, 0, 0
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
				switch {
				case req.URL.Path == "/api/v1/policy" && req.Method == http.MethodGet:
					reads++
					var timestamp any
					if tc.database {
						timestamp = "2026-09-30T00:00:00Z"
					}
					_ = json.NewEncoder(w).Encode(map[string]any{"policy": "{}", "updatedAt": timestamp})
				case req.URL.Path == "/api/v1/policy" && req.Method == http.MethodPut:
					writes++
					_, _ = w.Write([]byte(`{}`))
				case req.URL.Path == "/api/v1/node":
					nodes++
					_, _ = w.Write([]byte(`{"nodes":[]}`))
				default:
					t.Errorf("unexpected API call: %s %s", req.Method, req.URL.Path)
					http.NotFound(w, req)
				}
			}))
			defer srv.Close()
			s := runtime.NewScheme()
			_ = clientgoscheme.AddToScheme(s)
			_ = tnv1.AddToScheme(s)
			tn := &tnv1.Tailnet{ObjectMeta: metav1.ObjectMeta{Name: "corp", UID: "test-uid", Generation: 2},
				Spec: tnv1.TailnetSpec{Server: srv.URL, Policy: tnv1.PolicySpec{BaseConfigMap: "base", Mode: tc.mode,
					TagOwners: []string{"group:admins"}, RouteApprovers: []string{"tag:fabric"}}}}
			if tc.knownFile {
				gen := tn.Generation
				if tc.stale {
					gen--
				}
				setCond(&tn.Status.Conditions, gen, "PolicyMode", metav1.ConditionFalse, "File", "file mode")
			}
			cm := &corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Name: "base", Namespace: "operator"}, Data: map[string]string{policyKey: base}}
			secret := &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: workingSecretName(tn.Name), Namespace: "operator"}, Data: map[string][]byte{apiKeyData: []byte("key")}}
			c := fake.NewClientBuilder().WithScheme(s).WithObjects(tn, cm, secret).WithStatusSubresource(tn).Build()
			r := TailnetPolicyReconciler{Client: c, Scheme: s, OperatorNamespace: "operator"}
			r.retryAfter(tn.Name, policyRequeue)
			result, err := r.Reconcile(context.Background(), ctrl.Request{NamespacedName: types.NamespacedName{Name: tn.Name}})
			if err != nil {
				t.Fatal(err)
			}
			if err := c.Get(context.Background(), types.NamespacedName{Name: tn.Name}, tn); err != nil {
				t.Fatal(err)
			}
			if reads != tc.wantReads || writes != tc.wantWrites || (tc.wantWrites == 0 && nodes != 0) {
				t.Fatalf("read=%d write=%d nodes=%d, expected read=%d write=%d", reads, writes, nodes, tc.wantReads, tc.wantWrites)
			}
			if got := condReason(tn.Status.Conditions, "PolicyApplied"); got != tc.reason {
				t.Fatalf("PolicyApplied=%s want %s", got, tc.reason)
			}
			if condReason(tn.Status.Conditions, "PolicyRendered") != "Rendered" || tn.Status.Policy == nil || tn.Status.Policy.RenderedHash == "" {
				t.Fatal("file mode/DryRun must still render for review")
			}
			if result.RequeueAfter != policyRequeue {
				t.Fatalf("unexpected retry cadence: %s", result.RequeueAfter)
			}
			if tc.reason == "PolicyModeFile" && r.failures[tn.Name] != 0 {
				t.Fatal("file-mode guard must clear write-error backoff")
			}
			var rendered corev1.ConfigMap
			if err := c.Get(context.Background(), types.NamespacedName{Namespace: "operator", Name: "base-rendered"}, &rendered); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestPolicyModeChanged(t *testing.T) {
	old := &tnv1.Tailnet{}
	setCond(&old.Status.Conditions, 1, "PolicyMode", metav1.ConditionFalse, "File", "file mode")
	current := old.DeepCopy()
	setCond(&current.Status.Conditions, 1, "PolicyMode", metav1.ConditionTrue, "Database", "database mode")
	if !policyModeChanged(event.UpdateEvent{ObjectOld: old, ObjectNew: current}) {
		t.Fatal("file -> database must wake the policy controller")
	}
	old = current.DeepCopy()
	setCond(&current.Status.Conditions, 1, "PolicyApplied", metav1.ConditionTrue, "InSync", "same policy")
	if policyModeChanged(event.UpdateEvent{ObjectOld: old, ObjectNew: current}) {
		t.Fatal("own status write must not trigger another reconcile")
	}
}
