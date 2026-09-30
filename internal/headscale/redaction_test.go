package headscale

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

const credentialFixture = "hskey-api-AbCdEfGhIjKl-NEVER-EMIT-secret"

type redactionTransport func(*http.Request) (*http.Response, error)

func (f redactionTransport) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

type unsafeJSON struct{}

func (unsafeJSON) MarshalJSON() ([]byte, error) { return nil, errors.New(credentialFixture) }

type unsafeBody struct{}

func (unsafeBody) Read([]byte) (int, error) { return 0, errors.New(credentialFixture) }
func (unsafeBody) Close() error             { return nil }

func assertSafeError(t *testing.T, err error, operation string) {
	t.Helper()
	if err == nil {
		t.Fatal("expected failure")
	}
	for _, text := range []string{err.Error(), fmt.Sprintf("%v", err), fmt.Sprintf("%+v", err), fmt.Sprintf("%s", err), fmt.Errorf("controller: %w", err).Error()} {
		if strings.Contains(text, credentialFixture) || strings.Contains(text, "Bearer") || strings.Contains(text, "https://") || strings.Contains(text, "http://") {
			t.Fatal("credential-bearing upstream data reached formatted error (output withheld)")
		}
		if !strings.Contains(text, operation) || len(text) > 180 {
			t.Fatal("missing or unbounded safe operation metadata")
		}
	}
}

func TestClientDoRedactsHTTPFailures(t *testing.T) {
	for _, code := range []int{400, 401, 403, 422, 500, 503} {
		t.Run(fmt.Sprint(code), func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("X-Upstream-Credential", credentialFixture)
				w.WriteHeader(code)
				_, _ = fmt.Fprintf(w, "Authorization: %s\nsecret response: %s", r.Header.Get("Authorization"), credentialFixture)
			}))
			defer server.Close()
			err := New(server.URL, credentialFixture).SetPolicy(context.Background(), "{}")
			assertSafeError(t, err, "headscale PUT /api/v1/policy: HTTP "+fmt.Sprint(code))
			var status *StatusError
			if !errors.As(err, &status) || status.Code != code || IsUnauthorized(err) != (code == 401) {
				t.Fatal("HTTP classification lost")
			}
		})
	}
}

func TestClientDoRedactsCodecAndTransportFailures(t *testing.T) {
	for _, tt := range []struct {
		name, response, stage string
	}{
		{"syntax", `{"apiKey":"` + credentialFixture + `",`, "decode response failed"},
		// time.ParseError quotes its input; JSON type errors can quote arbitrary object keys.
		{"timestamp", `{"apiKeys":[{"expiration":"` + credentialFixture + `"}]}`, "decode response failed"},
		{"type", `{"apiKeys": "` + credentialFixture + `"}`, "decode response failed"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			c := New("https://user:"+credentialFixture+"@example.invalid", credentialFixture)
			c.http.Transport = redactionTransport(func(*http.Request) (*http.Response, error) {
				return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader(tt.response))}, nil
			})
			_, err := c.ListAPIKeys(context.Background())
			assertSafeError(t, err, "GET /api/v1/apikey: "+tt.stage)
		})
	}
	c := New("https://user:"+credentialFixture+"@example.invalid", credentialFixture)
	cause := errors.New("Authorization: Bearer " + credentialFixture)
	c.http.Transport = redactionTransport(func(*http.Request) (*http.Response, error) { return nil, cause })
	_, err := c.ListNodes(context.Background())
	assertSafeError(t, err, "GET /api/v1/node: transport failed")
	var urlErr *url.Error
	if !errors.Is(err, cause) || !errors.As(err, &urlErr) {
		t.Fatal("transport inspection lost")
	}
	c.http.Transport = redactionTransport(func(*http.Request) (*http.Response, error) { return nil, context.Canceled })
	_, err = c.ListNodes(context.Background())
	if !errors.Is(err, context.Canceled) {
		t.Fatal("context cancellation inspection lost")
	}
	assertSafeError(t, err, "transport failed")

	err = c.do(context.Background(), http.MethodPost, "/api/v1/policy", unsafeJSON{}, nil)
	assertSafeError(t, err, "encode request failed")
	var marshalErr *json.MarshalerError
	if !errors.As(err, &marshalErr) {
		t.Fatal("marshal inspection lost")
	}
	_, err = New("://"+credentialFixture, credentialFixture).ListNodes(context.Background())
	assertSafeError(t, err, "create request failed")
	c.http.Transport = redactionTransport(func(*http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: 200, Body: unsafeBody{}}, nil
	})
	_, err = c.ListNodes(context.Background())
	assertSafeError(t, err, "read response failed")
}

func TestPolicyTimestampRedaction(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/v1/policy":
			_ = json.NewEncoder(w).Encode(map[string]any{"policy": "{}", "updatedAt": credentialFixture})
		case "/api/v1/policy/check":
			_, _ = io.WriteString(w, "{}")
		case "/api/v1/health":
			_, _ = io.WriteString(w, `{"databaseConnectivity":true}`)
		}
	}))
	defer server.Close()
	c := New(server.URL, credentialFixture)
	_, mode, err := c.GetPolicyWithMode(context.Background())
	assertSafeError(t, err, "decode policy updatedAt")
	if mode != nil {
		t.Fatal("malformed timestamp must not produce a mode verdict")
	}
	_, err = c.Probe(context.Background())
	assertSafeError(t, err, "decode policy updatedAt")
}

func TestClientDoRedactsDynamicOperationsAndStatusText(t *testing.T) {
	c := New("https://example.invalid", credentialFixture)
	c.http.Transport = redactionTransport(func(*http.Request) (*http.Response, error) {
		// Error bodies must not even be read, and a nonstandard status phrase is untrusted.
		return &http.Response{StatusCode: 401, Status: "401 " + credentialFixture, Body: unsafeBody{}}, nil
	})
	for _, tt := range []struct{ method, path, want string }{
		{http.MethodDelete, "/api/v1/node/" + credentialFixture, "DELETE /api/v1/node/{id}"},
		{http.MethodPost, "/api/v1/node/" + credentialFixture + "/rename/" + credentialFixture, "POST /api/v1/node/{id}/rename/{name}"},
		{http.MethodPost, "/api/v1/node/" + credentialFixture + "/approve_routes", "POST /api/v1/node/{id}/approve_routes"},
		{http.MethodGet, "/api/v1/policy?token=" + credentialFixture, "GET unknown endpoint"},
		{credentialFixture, "/" + credentialFixture, "request unknown endpoint"},
	} {
		err := c.do(context.Background(), tt.method, tt.path, nil, nil)
		assertSafeError(t, err, tt.want)
		if !IsUnauthorized(err) {
			t.Fatal("untrusted status/body changed HTTP classification")
		}
	}
}
