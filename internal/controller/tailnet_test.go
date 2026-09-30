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

func TestMintAndVerifyWithoutPolicy(t *testing.T) {
	var creates, verifies int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodPost && r.URL.Path == "/api/v1/apikey":
			creates++
			_, _ = w.Write([]byte(`{"apiKey":"new.key"}`))
		case r.Method == http.MethodGet && r.URL.Path == "/api/v1/apikey":
			verifies++
			if r.Header.Get("Authorization") != "Bearer new.key" {
				t.Error("verification must use the newly minted key")
			}
			_, _ = w.Write([]byte(`{"apiKeys":[]}`))
		default:
			t.Errorf("unexpected call %s %s; key verification must not require a policy", r.Method, r.URL.Path)
			http.Error(w, "policy unavailable", http.StatusInternalServerError)
		}
	}))
	defer srv.Close()
	now := time.Now()
	r := &TailnetReconciler{}
	key, exp, err := r.mintAndVerify(context.Background(), srv.URL, "bootstrap", time.Hour, now)
	if err != nil || key != "new.key" || !exp.Equal(now.Add(time.Hour)) || creates != 1 || verifies != 1 {
		t.Fatalf("key=%q expiry=%s creates=%d verifies=%d err=%v", key, exp, creates, verifies, err)
	}
}

// TestHealthConditions: a dead database must surface as ApiReachable=Unhealthy, a bad key as
// ApiKeyValid=Rejected — not as the blanket 401 Headscale reports for both.
func TestHealthConditions(t *testing.T) {
	cases := []struct {
		name, health, keys  string
		ok                  bool
		reachable, keyValid string // expected reasons; "" = untouched
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
				case "/api/v1/apikey":
					switch c.keys {
					case "401":
						http.Error(w, "Unauthorized", 401)
					case "500":
						http.Error(w, "boom", 500)
					default:
						_, _ = w.Write([]byte(`{"apiKeys":[]}`))
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
