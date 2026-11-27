package controller

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"

	"github.com/go-logr/logr/funcr"
	authv1 "k8s.io/api/authentication/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"
	logf "sigs.k8s.io/controller-runtime/pkg/log"

	tnv1 "tsunaro.io/tailnet-operator/api/v1alpha1"
)

const consoleSubject = "system:serviceaccount:operator:tsunaro-console"

// consoleAPIFixture serves a synthetic Headscale and a fake API server whose TokenReview knows
// three tokens: the console's, another ServiceAccount's, and one issued for the API server only.
func consoleAPIFixture(t *testing.T, headscaleCode int, withKey bool) (http.Handler, *strings.Builder) {
	t.Helper()
	hs := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer working-key" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		if headscaleCode != http.StatusOK {
			w.WriteHeader(headscaleCode)
			_, _ = w.Write([]byte("upstream-secret-detail"))
			return
		}
		switch r.URL.Path {
		case "/api/v1/user":
			_, _ = w.Write([]byte(`{"users":[{"id":"1","name":"person","displayName":"Synthetic Person","email":"person@example.test","providerId":"https://id.example.test/42","createdAt":"2026-01-01T00:00:00Z"}]}`))
		case "/api/v1/node":
			_, _ = w.Write([]byte(`{"nodes":[{"id":"1","givenName":"laptop-of-person","online":true,"ipAddresses":["100.64.0.1"],"user":{"name":"person"}},` +
				`{"id":"2","name":"raw","givenName":"ingress-api","online":false,"lastSeen":"2026-11-27T08:00:00Z","tags":["tag:ingress-api"],"ipAddresses":["100.64.0.2"],"machineKey":"mkey:x"}]}`))
		case "/api/v1/policy":
			_, _ = w.Write([]byte(`{"policy":"{\"grants\":[]}","updatedAt":"2026-11-27T08:00:00Z"}`))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	t.Cleanup(hs.Close)
	objs := []client.Object{&tnv1.Tailnet{ObjectMeta: metav1.ObjectMeta{Name: "corp"}, Spec: tnv1.TailnetSpec{Server: hs.URL}}}
	if withKey {
		objs = append(objs, &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Namespace: "operator", Name: "corp-apikey"},
			Data: map[string][]byte{apiKeyData: []byte("working-key")}})
	}
	c := fake.NewClientBuilder().WithScheme(exportScheme(t)).WithObjects(objs...).WithInterceptorFuncs(interceptor.Funcs{
		Create: func(ctx context.Context, c client.WithWatch, obj client.Object, opts ...client.CreateOption) error {
			tr, ok := obj.(*authv1.TokenReview)
			if !ok {
				return c.Create(ctx, obj, opts...)
			}
			if !slices.Equal(tr.Spec.Audiences, []string{ConsoleAPIAudience}) {
				t.Errorf("audiences = %v", tr.Spec.Audiences)
			}
			switch tr.Spec.Token {
			case "console-token":
				tr.Status = authv1.TokenReviewStatus{Authenticated: true, Audiences: []string{ConsoleAPIAudience}, User: authv1.UserInfo{Username: consoleSubject}}
			case "other-token":
				tr.Status = authv1.TokenReviewStatus{Authenticated: true, Audiences: []string{ConsoleAPIAudience}, User: authv1.UserInfo{Username: "system:serviceaccount:apps:intruder"}}
			case "apiserver-token":
				tr.Status = authv1.TokenReviewStatus{Authenticated: true, Audiences: []string{"https://kubernetes.default.svc"}, User: authv1.UserInfo{Username: consoleSubject}}
			}
			return nil
		},
	}).Build()
	logs := &strings.Builder{}
	logger := funcr.New(func(prefix, args string) { logs.WriteString(prefix + " " + args + "\n") }, funcr.Options{})
	api := (&ConsoleAPI{Client: c, OperatorNamespace: "operator", Subject: consoleSubject}).Handler()
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		api.ServeHTTP(w, r.WithContext(logf.IntoContext(r.Context(), logger)))
	}), logs
}

func consoleCall(h http.Handler, method, path, token string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, path, nil)
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

func TestConsoleAPIAccessAndErrors(t *testing.T) {
	ok, _ := consoleAPIFixture(t, http.StatusOK, true)
	noKey, _ := consoleAPIFixture(t, http.StatusOK, false)
	broken, _ := consoleAPIFixture(t, http.StatusInternalServerError, true)
	for _, tc := range []struct {
		name, method, path, token string
		h                         http.Handler
		code                      int
	}{
		{"no token", http.MethodGet, "/v1/tailnets/corp/users", "", ok, http.StatusUnauthorized},
		{"unknown token", http.MethodGet, "/v1/tailnets/corp/users", "forged", ok, http.StatusUnauthorized},
		{"API server audience", http.MethodGet, "/v1/tailnets/corp/users", "apiserver-token", ok, http.StatusUnauthorized},
		{"other service account", http.MethodGet, "/v1/tailnets/corp/users", "other-token", ok, http.StatusForbidden},
		{"unknown path before auth", http.MethodGet, "/v1/other", "", ok, http.StatusUnauthorized},
		{"unknown path", http.MethodGet, "/v1/tailnets/corp/keys", "console-token", ok, http.StatusNotFound},
		{"write method", http.MethodPost, "/v1/tailnets/corp/policy", "console-token", ok, http.StatusMethodNotAllowed},
		{"unknown tailnet", http.MethodGet, "/v1/tailnets/other/users", "console-token", ok, http.StatusNotFound},
		{"no working key", http.MethodGet, "/v1/tailnets/corp/users", "console-token", noKey, http.StatusServiceUnavailable},
		{"headscale failure", http.MethodGet, "/v1/tailnets/corp/policy", "console-token", broken, http.StatusBadGateway},
		{"users", http.MethodGet, "/v1/tailnets/corp/users", "console-token", ok, http.StatusOK},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rec := consoleCall(tc.h, tc.method, tc.path, tc.token)
			if rec.Code != tc.code {
				t.Fatalf("code = %d, want %d", rec.Code, tc.code)
			}
			if rec.Header().Get("Cache-Control") != "no-store" {
				t.Fatal("response may be cached")
			}
			if tc.code != http.StatusOK && strings.Contains(rec.Body.String(), "upstream") {
				t.Fatal("Headscale error text was forwarded")
			}
		})
	}
}

func TestConsoleAPIResponseFields(t *testing.T) {
	h, logs := consoleAPIFixture(t, http.StatusOK, true)
	fields := func(path, list string) []map[string]any {
		rec := consoleCall(h, http.MethodGet, path, "console-token")
		var body map[string][]map[string]any
		if rec.Code != http.StatusOK || json.Unmarshal(rec.Body.Bytes(), &body) != nil {
			t.Fatalf("%s: %d %s", path, rec.Code, rec.Body)
		}
		return body[list]
	}
	keys := func(m map[string]any) []string {
		var out []string
		for k := range m {
			out = append(out, k)
		}
		slices.Sort(out)
		return out
	}
	users := fields("/v1/tailnets/corp/users", "users")
	if len(users) != 1 || !slices.Equal(keys(users[0]), []string{"displayName", "email", "id", "name", "providerId"}) ||
		users[0]["providerId"] != "https://id.example.test/42" {
		t.Fatalf("users = %v", users)
	}
	nodes := fields("/v1/tailnets/corp/nodes", "nodes")
	if len(nodes) != 1 || !slices.Equal(keys(nodes[0]), []string{"lastSeen", "name", "online", "tags"}) || nodes[0]["name"] != "ingress-api" {
		t.Fatalf("only tagged nodes with four fields may leave the operator: %v", nodes)
	}
	rec := consoleCall(h, http.MethodGet, "/v1/tailnets/corp/policy", "console-token")
	if rec.Code != http.StatusOK || strings.TrimSpace(rec.Body.String()) != `{"policy":"{\"grants\":[]}"}` {
		t.Fatalf("policy = %d %s", rec.Code, rec.Body)
	}
	consoleCall(h, http.MethodGet, "/v1/tailnets/corp/users", "other-token")
	for _, leak := range []string{"console-token", "other-token", "intruder", "person", "Synthetic", "example.test", "working-key"} {
		if strings.Contains(logs.String(), leak) {
			t.Fatalf("log contains %q:\n%s", leak, logs)
		}
	}
	if !strings.Contains(logs.String(), "caller is not the console") {
		t.Fatalf("rejection reason not logged:\n%s", logs)
	}
}
