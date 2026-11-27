//go:build e2e

package e2e

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	authv1 "k8s.io/api/authentication/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"tsunaro.io/tailnet-operator/internal/controller"
)

// serviceAccountToken creates a ServiceAccount and requests a token for the given audiences
// (none = the API server's own audience).
func serviceAccountToken(t *testing.T, ctx context.Context, name string, audiences ...string) string {
	t.Helper()
	sa := &corev1.ServiceAccount{ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: namespace}}
	if err := client.IgnoreAlreadyExists(kube.Create(ctx, sa)); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = client.IgnoreNotFound(kube.Delete(context.Background(), sa)) })
	tr := &authv1.TokenRequest{Spec: authv1.TokenRequestSpec{Audiences: audiences}}
	if err := kube.SubResource("token").Create(ctx, sa, tr); err != nil {
		t.Fatal(err)
	}
	return tr.Status.Token
}

// TestConsoleAPI: the real API server's TokenReview admits only the console's token for the
// console audience, and the answer carries the Headscale users and the live policy.
func TestConsoleAPI(t *testing.T) {
	for _, version := range versions {
		t.Run(version, func(t *testing.T) {
			if version == "v0.28.0" {
				t.Skip("unsupported capability row; the live policy needs the 0.29 policy lifecycle")
			}
			ctx := testContext(t)
			hs := startHeadscale(t, ctx, version, "database", false)
			hs.cli(t, ctx, "users", "create", "fixture", "--output", "json")
			name := createTailnet(t, ctx, hs)
			enablePolicy(t, ctx, name, grantBasePolicy, "Apply")
			waitApplied(t, ctx, name, "192.0.2.1:443", hs)

			api := httptest.NewServer((&controller.ConsoleAPI{
				Client: kube, OperatorNamespace: namespace,
				Subject: "system:serviceaccount:" + namespace + ":console",
			}).Handler())
			defer api.Close()
			call := func(path, token string) (int, string) {
				req, _ := http.NewRequestWithContext(ctx, http.MethodGet, api.URL+path, nil)
				req.Header.Set("Authorization", "Bearer "+token)
				resp, err := http.DefaultClient.Do(req)
				if err != nil {
					t.Fatal(err)
				}
				defer resp.Body.Close()
				b, _ := io.ReadAll(resp.Body)
				return resp.StatusCode, string(b)
			}

			console := serviceAccountToken(t, ctx, "console", controller.ConsoleAPIAudience)
			code, body := call("/v1/tailnets/"+name+"/users", console)
			var users struct {
				Users []struct{ Name string } `json:"users"`
			}
			if code != http.StatusOK || json.Unmarshal([]byte(body), &users) != nil || len(users.Users) != 1 || users.Users[0].Name != "fixture" {
				t.Fatalf("users: %d %s", code, body)
			}
			if code, body = call("/v1/tailnets/"+name+"/policy", console); code != http.StatusOK || !strings.Contains(body, "192.0.2.1:443") {
				t.Fatalf("policy: %d %s", code, body)
			}
			if code, _ = call("/v1/tailnets/"+name+"/users", serviceAccountToken(t, ctx, "console")); code != http.StatusUnauthorized {
				t.Fatalf("API-server token: %d, want 401", code)
			}
			if code, _ = call("/v1/tailnets/"+name+"/users", serviceAccountToken(t, ctx, "intruder", controller.ConsoleAPIAudience)); code != http.StatusForbidden {
				t.Fatalf("other ServiceAccount: %d, want 403", code)
			}
		})
	}
}
