package headscale

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestListUsersDecodesOIDCIdentity(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/user" || r.Method != http.MethodGet {
			w.WriteHeader(http.StatusForbidden)
			return
		}
		_, _ = w.Write([]byte(`{"users":[{"id":"3","name":"synthetic","displayName":"Synthetic Person","email":"synthetic@example.test","providerId":"https://id.example.test/1234","provider":"oidc"}]}`))
	}))
	defer server.Close()
	users, err := New(server.URL, "synthetic-token").ListUsers(context.Background())
	want := User{ID: "3", Name: "synthetic", DisplayName: "Synthetic Person", Email: "synthetic@example.test", ProviderID: "https://id.example.test/1234"}
	if err != nil || len(users) != 1 || users[0] != want {
		t.Fatalf("users = %+v, err = %v", users, err)
	}
}
