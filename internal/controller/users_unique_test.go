package controller

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	tnv1 "tsunaro.io/tailnet-operator/api/v1alpha1"
	"tsunaro.io/tailnet-operator/internal/headscale"
)

// Headscale rejects every policy write while two users share a name. UsersUnique reports the
// collision by ID and count only: user names are e-mail addresses and must not reach the status.
func TestUserConditions(t *testing.T) {
	const alice = "alice@example.test"
	cases := []struct {
		name, body string
		status     int
		cond       metav1.ConditionStatus
		reason     string
		conflicts  int32
		contains   string
	}{
		{"unique", `{"users":[{"id":"1","name":"` + alice + `"},{"id":"2","name":"bob@example.test"}]}`, 200, metav1.ConditionTrue, "Unique", 0, "2 Headscale user(s)"},
		{"duplicate", `{"users":[{"id":"10","name":"` + alice + `"},{"id":"2","name":"` + alice + `"},{"id":"3","name":"bob@example.test"}]}`, 200, metav1.ConditionFalse, "Duplicate", 1, "user IDs 2,10"},
		{"api error", `boom`, 500, metav1.ConditionUnknown, "CannotVerify", 0, "could not list"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path != "/api/v1/user" {
					http.NotFound(w, r)
					return
				}
				w.WriteHeader(c.status)
				_, _ = w.Write([]byte(c.body))
			}))
			defer srv.Close()
			tn := &tnv1.Tailnet{ObjectMeta: metav1.ObjectMeta{Generation: 3}}
			tn.Status.UserConflicts = 7 // stale value from an earlier reconcile must not survive
			userConditions(context.Background(), headscale.New(srv.URL, "k"), tn)
			got := meta.FindStatusCondition(tn.Status.Conditions, "UsersUnique")
			if got == nil || got.Status != c.cond || got.Reason != c.reason || got.ObservedGeneration != 3 {
				t.Fatalf("condition = %+v", got)
			}
			if tn.Status.UserConflicts != c.conflicts {
				t.Fatalf("userConflicts = %d, want %d", tn.Status.UserConflicts, c.conflicts)
			}
			if !strings.Contains(got.Message, c.contains) || strings.Contains(got.Message, alice) {
				t.Fatalf("message %q must mention %q and never a user name", got.Message, c.contains)
			}
		})
	}
}

func TestDuplicateUsersGroupsExactNames(t *testing.T) {
	names, ids := duplicateUsers([]headscale.User{
		{ID: "9", Name: "a"}, {ID: "1", Name: "a"}, {ID: "2", Name: "A"}, // case differs: distinct for Headscale
		{ID: "5", Name: "b"}, {ID: "3", Name: "b"}, {ID: "4", Name: "c"},
	})
	if len(names) != 2 || names[0] != "a" || names[1] != "b" {
		t.Fatalf("names = %v", names)
	}
	if strings.Join(ids, ",") != "1,3,5,9" {
		t.Fatalf("ids = %v (want numeric order)", ids)
	}
}
