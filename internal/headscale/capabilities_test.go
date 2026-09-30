package headscale

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"reflect"
	"testing"
)

func testBool(v bool) *bool { return &v }

func TestProbe(t *testing.T) {
	const database = `{"policy":"{}","updatedAt":"2026-09-30T10:00:00Z"}`
	const healthy = `{"databaseConnectivity":true}`
	for _, tc := range []struct {
		name, path, body string
		code             int
		mode, check, db  *bool
		wantErr          bool
	}{
		{"database", "", "", 0, testBool(true), testBool(true), testBool(true), false},
		{"file", "/api/v1/policy", `{"policy":"{}","updatedAt":null}`, 200, testBool(false), testBool(true), testBool(true), false},
		{"omitted mode is unknown", "/api/v1/policy", `{"policy":"{}"}`, 200, nil, testBool(true), testBool(true), false},
		{"missing policy", "/api/v1/policy", `{}`, 200, nil, testBool(true), testBool(true), true},
		{"null policy", "/api/v1/policy", `{"policy":null,"updatedAt":null}`, 200, nil, testBool(true), testBool(true), true},
		{"invalid timestamp", "/api/v1/policy", `{"policy":"{}","updatedAt":"not-a-time"}`, 200, nil, testBool(true), testBool(true), true},
		{"proxy policy HTML", "/api/v1/policy", `<html>login</html>`, 200, nil, testBool(true), testBool(true), true},
		{"policy unauthorized", "/api/v1/policy", `{"message":"Unauthorized"}`, 401, nil, testBool(true), testBool(true), true},
		{"policy forbidden", "/api/v1/policy", `{}`, 403, nil, testBool(true), testBool(true), true},
		{"policy transient failure", "/api/v1/policy", `database down`, 500, nil, testBool(true), testBool(true), true},
		{"empty database is not file", "/api/v1/policy", `{"code":2,"message":"loading ACL from database: acl policy not found","details":[]}`, 500, nil, testBool(true), testBool(true), true},
		{"old server", "/api/v1/policy/check", `{"code":5,"message":"Not Found"}`, 404, testBool(true), testBool(false), testBool(true), false},
		{"check unauthorized", "/api/v1/policy/check", `{}`, 401, testBool(true), nil, testBool(true), true},
		{"check forbidden", "/api/v1/policy/check", `{}`, 403, testBool(true), nil, testBool(true), true},
		{"check bad request", "/api/v1/policy/check", `{"code":3,"message":"bad request"}`, 400, testBool(true), nil, testBool(true), true},
		{"check server failure", "/api/v1/policy/check", `{}`, 500, testBool(true), nil, testBool(true), true},
		{"proxy check HTML", "/api/v1/policy/check", `<html>login</html>`, 200, testBool(true), nil, testBool(true), true},
		{"proxy check JSON", "/api/v1/policy/check", `{"message":"login required"}`, 200, testBool(true), nil, testBool(true), true},
		{"null check response", "/api/v1/policy/check", `null`, 200, testBool(true), nil, testBool(true), true},
		{"health absent", "/api/v1/health", `not found`, 404, testBool(true), testBool(true), nil, false},
		{"health unhealthy", "/api/v1/health", `{"databaseConnectivity":false}`, 200, testBool(true), testBool(true), testBool(false), false},
		{"health error", "/api/v1/health", `pinging database: offline`, 500, testBool(true), testBool(true), nil, true},
		{"health unauthorized", "/api/v1/health", `{}`, 401, testBool(true), testBool(true), nil, true},
		{"health missing field", "/api/v1/health", `{}`, 200, testBool(true), testBool(true), nil, true},
		{"health wrong shape", "/api/v1/health", `{"database_connectivity":true}`, 200, testBool(true), testBool(true), nil, true},
		{"health null", "/api/v1/health", `{"databaseConnectivity":null}`, 200, testBool(true), testBool(true), nil, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			calls := map[string]int{}
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				calls[r.URL.Path]++
				if r.Header.Get("Authorization") != "Bearer test-token" {
					t.Error("probe did not authenticate")
				}
				body := database
				switch r.URL.Path {
				case "/api/v1/policy":
					if r.Method != http.MethodGet {
						t.Errorf("probe must not write policy: %s", r.Method)
					}
				case "/api/v1/policy/check":
					var request map[string]string
					if r.Method != http.MethodPost || json.NewDecoder(r.Body).Decode(&request) != nil || request["policy"] != "{}" {
						t.Error("unexpected policy/check request")
					}
					body = `{}`
				case "/api/v1/health":
					if r.Method != http.MethodGet {
						t.Errorf("health method: %s", r.Method)
					}
					body = healthy
				default:
					t.Errorf("unexpected probe: %s %s", r.Method, r.URL.Path)
				}
				if r.URL.Path == tc.path {
					w.WriteHeader(tc.code)
					body = tc.body
				}
				_, _ = w.Write([]byte(body))
			}))
			defer srv.Close()
			caps, err := New(srv.URL, "test-token").Probe(context.Background())
			want := Capabilities{PolicyDatabaseMode: tc.mode, PolicyCheck: tc.check, DBHealth: tc.db}
			if !reflect.DeepEqual(caps, want) || (err != nil) != tc.wantErr {
				t.Fatalf("caps=%+v want=%+v err=%v wantErr=%v", caps, want, err, tc.wantErr)
			}
			if len(calls) != 3 {
				t.Fatalf("want exactly three endpoints, got %v", calls)
			}
			for path, n := range calls {
				if n != 1 {
					t.Errorf("%s called %d times", path, n)
				}
			}
		})
	}
}

func TestProbeCanceled(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	caps, err := New("http://127.0.0.1:1", "test-token").Probe(ctx)
	if caps != (Capabilities{}) || !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled probe: %+v, %v", caps, err)
	}
}

func TestCheckPolicy(t *testing.T) {
	const policy = `{"tagOwners":{"tag:app":["group:admins"]}}`
	for _, code := range []int{http.StatusOK, http.StatusBadRequest} {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			var body struct{ Policy string }
			if r.URL.Path != "/api/v1/policy/check" || r.Method != http.MethodPost ||
				json.NewDecoder(r.Body).Decode(&body) != nil || body.Policy != policy {
				t.Error("policy was not passed unchanged to the check endpoint")
			}
			w.WriteHeader(code)
			_, _ = w.Write([]byte(`{}`))
		}))
		err := New(srv.URL, "token").CheckPolicy(context.Background(), policy)
		srv.Close()
		if code == http.StatusOK && err != nil {
			t.Fatal(err)
		}
		if code != http.StatusOK && !hasStatus(err, code) {
			t.Fatalf("validation error lost: %v", err)
		}
	}
}
