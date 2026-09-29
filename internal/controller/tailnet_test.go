package controller

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	tnv1 "this-is-fine.io/tailnet-operator/api/v1alpha1"
	"this-is-fine.io/tailnet-operator/internal/headscale"
)

// TestHealthConditions: a dead database must surface as ApiReachable=Unhealthy, a bad key as
// ApiKeyValid=Rejected — not as the blanket 401 Headscale reports for both.
func TestHealthConditions(t *testing.T) {
	cases := []struct {
		name, health, policy string
		ok                   bool
		reachable, keyValid  string // expected reasons; "" = untouched
	}{
		{"healthy", "pass", "ok", true, "Reachable", "Valid"},
		{"db down", "fail", "401", false, "Unhealthy", ""},
		{"bad key", "pass", "401", false, "Reachable", "Rejected"},
		{"server error", "pass", "500", false, "Reachable", "Error"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				switch r.URL.Path {
				case "/health":
					if c.health == "fail" {
						w.WriteHeader(500)
					}
					_, _ = w.Write([]byte(`{"status":"` + c.health + `"}`))
				case "/api/v1/policy":
					switch c.policy {
					case "401":
						http.Error(w, "Unauthorized", 401)
					case "500":
						http.Error(w, "boom", 500)
					default:
						_, _ = w.Write([]byte(`{"policy":"{}"}`))
					}
				default:
					http.NotFound(w, r)
				}
			}))
			defer srv.Close()
			tn := &tnv1.Tailnet{}
			ok := healthConditions(context.Background(), headscale.New(srv.URL, "k"), tn, time.Now().Add(time.Hour))
			if ok != c.ok {
				t.Fatalf("ok=%v want %v", ok, c.ok)
			}
			if got := condReason(tn.Status.Conditions, "ApiReachable"); got != c.reachable {
				t.Fatalf("ApiReachable=%q want %q", got, c.reachable)
			}
			if got := condReason(tn.Status.Conditions, "ApiKeyValid"); got != c.keyValid {
				t.Fatalf("ApiKeyValid=%q want %q", got, c.keyValid)
			}
			if c.ok && condStatus(tn.Status.Conditions, "ApiKeyValid") != metav1.ConditionTrue {
				t.Fatal("ApiKeyValid should be True when healthy")
			}
		})
	}
}
