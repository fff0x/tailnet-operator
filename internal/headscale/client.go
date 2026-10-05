// Package headscale is a minimal REST client for the Headscale API.
//
// Hand-written structs, not github.com/juanfont/headscale/gen/go: the API is REST/JSON and we touch
// a handful of fields, while importing the generated gRPC types drags protobuf + grpc into a module
// graph that already needs careful pinning for tsnet. Field names were verified against a live
// v0.29.3 (camelCase protojson): availableRoutes, approvedRoutes, givenName, aclTags, apiKey.
package headscale

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// Client talks to one Headscale server with one bearer token. The operator builds a fresh Client per
// reconcile with the current working key, so a rotated key is picked up without any shared state.
type Client struct {
	baseURL  string
	token    string
	http     *http.Client
	observer Observer
}

// Observer receives one sanitized observation per operation. Code is zero when no response
// arrived; method and pathTemplate are bounded constants, never request or response data.
type Observer func(method, pathTemplate string, code int, elapsed time.Duration)

// New returns a client for baseURL authenticating with token, optionally observing operations.
// Only the first observer is used; existing two-argument callers need no instrumentation.
func New(baseURL, token string, observers ...Observer) *Client {
	var observer Observer
	if len(observers) > 0 {
		observer = observers[0]
	}
	return &Client{
		observer: observer,
		baseURL:  strings.TrimRight(baseURL, "/"),
		token:    token,
		http:     &http.Client{Timeout: 15 * time.Second},
	}
}

// Node is the subset of a Headscale node the operator reads.
type Node struct {
	ID              string       `json:"id"`
	MachineKey      string       `json:"machineKey"`
	NodeKey         string       `json:"nodeKey"`
	Name            string       `json:"name"`
	GivenName       string       `json:"givenName"`
	Online          bool         `json:"online"`
	LastSeen        *time.Time   `json:"lastSeen"`
	IPAddresses     []string     `json:"ipAddresses"`
	AvailableRoutes []string     `json:"availableRoutes"`
	ApprovedRoutes  []string     `json:"approvedRoutes"`
	SubnetRoutes    []string     `json:"subnetRoutes"`
	Tags            []string     `json:"tags"`
	PreAuthKey      *NodeAuthKey `json:"preAuthKey"`
}

// NodeAuthKey contains only read-only metadata; the API may mask Key.
// Never use a listed key prefix to prove possession of the full credential.
type NodeAuthKey struct {
	ID        string `json:"id"`
	Ephemeral bool   `json:"ephemeral"`
}

// PreAuthKey is a minted pre-auth key. Key carries the secret used to register a node.
type PreAuthKey struct {
	ID         string    `json:"id"`
	Key        string    `json:"key"`
	Reusable   bool      `json:"reusable"`
	Ephemeral  bool      `json:"ephemeral"`
	Used       bool      `json:"used"`
	Expiration time.Time `json:"expiration"`
	ACLTags    []string  `json:"aclTags"`
}

// APIKey is a listed API key. The secret is never returned by list; only the prefix identifies it.
type APIKey struct {
	ID         string    `json:"id"`
	Prefix     string    `json:"prefix"`
	Expiration time.Time `json:"expiration"`
	CreatedAt  time.Time `json:"createdAt"`
	LastSeen   time.Time `json:"lastSeen"`
}

// StatusError is a non-2xx answer. Code lets callers tell "key rejected" (401) from "server broken".
type StatusError struct {
	Code int
	Msg  string
}

func (e *StatusError) Error() string { return e.Msg }

// IsUnauthorized reports whether err is a 401 from Headscale.
func IsUnauthorized(err error) bool {
	var se *StatusError
	return errors.As(err, &se) && se.Code == http.StatusUnauthorized
}

// Health probes GET /health, which needs no key: Headscale pings its database and answers
// 500 {"status":"fail"} when it cannot — the same condition it masks as 401 on every API call.
func (c *Client) Health(ctx context.Context) error {
	return c.do(ctx, http.MethodGet, "/health", nil, nil)
}

// requestError withholds arbitrary transport/codec text from logs, events and status while
// preserving errors.Is/As (including context cancellation). Callers must not log the unwrapped cause.
// In particular, url.Error, JSON type errors and custom transports can contain credentials.
type requestError struct {
	message string
	cause   error
}

func (e *requestError) Error() string { return e.message }
func (e *requestError) Unwrap() error { return e.cause }

// safeOperation uses only bounded constants, never URL, header, body or dynamic path data.
func safeOperation(method, path string) string {
	method, path = safeLabels(method, path)
	return "headscale " + method + " " + path
}

func safeLabels(method, path string) (string, string) {
	switch method {
	case http.MethodGet, http.MethodPost, http.MethodPut, http.MethodDelete:
	default:
		method = "request"
	}
	route := "unknown endpoint"
	switch path {
	case "/health", "/api/v1/health", "/api/v1/policy/check", "/api/v1/node", "/api/v1/preauthkey", "/api/v1/preauthkey/expire",
		"/api/v1/apikey", "/api/v1/apikey/expire", "/api/v1/policy":
		route = path
	default:
		parts := strings.Split(path, "/")
		if len(parts) >= 5 && parts[0] == "" && parts[1] == "api" && parts[2] == "v1" && parts[3] == "node" {
			switch {
			case len(parts) == 5:
				route = "/api/v1/node/{id}"
			case len(parts) == 6 && parts[5] == "approve_routes":
				route = "/api/v1/node/{id}/approve_routes"
			case len(parts) == 7 && parts[5] == "rename":
				route = "/api/v1/node/{id}/rename/{name}"
			}
		}
	}
	return method, route
}

func (c *Client) do(ctx context.Context, method, path string, body, out any) error {
	op := safeOperation(method, path)
	started := time.Now()
	code := 0
	if c.observer != nil {
		defer func() {
			m, p := safeLabels(method, path)
			c.observer(m, p, code, time.Since(started))
		}()
	}
	fail := func(stage string, cause error) error {
		return &requestError{message: op + ": " + stage, cause: cause}
	}
	var rdr io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return fail("encode request failed", err)
		}
		rdr = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, method, c.baseURL+path, rdr)
	if err != nil {
		return fail("create request failed", err)
	}
	req.Header.Set("Authorization", "Bearer "+c.token)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return fail("transport failed", err)
	}
	code = resp.StatusCode
	defer resp.Body.Close()
	if resp.StatusCode/100 != 2 {
		// Neither the status text nor error body is trustworthy. Do not read the error body.
		return &StatusError{Code: resp.StatusCode, Msg: fmt.Sprintf("%s: HTTP %d", op, resp.StatusCode)}
	}
	rb, err := io.ReadAll(resp.Body)
	if err != nil {
		return fail("read response failed", err)
	}
	if out != nil {
		if err := json.Unmarshal(rb, out); err != nil {
			return fail("decode response failed", err)
		}
	}
	return nil
}

// ListNodes returns all nodes.
func (c *Client) ListNodes(ctx context.Context) ([]Node, error) {
	var out struct {
		Nodes []Node `json:"nodes"`
	}
	if err := c.do(ctx, http.MethodGet, "/api/v1/node", nil, &out); err != nil {
		return nil, err
	}
	return out.Nodes, nil
}

// DeleteNode removes a node by its numeric ID.
func (c *Client) DeleteNode(ctx context.Context, id string) error {
	return c.do(ctx, http.MethodDelete, "/api/v1/node/"+id, nil, nil)
}

// RenameNode sets a node's given name (its MagicDNS label). Fails while another node holds the name.
func (c *Client) RenameNode(ctx context.Context, id, name string) error {
	return c.do(ctx, http.MethodPost, "/api/v1/node/"+id+"/rename/"+name, nil, nil)
}

// SetApprovedRoutes replaces a node's approved routes; pass the full list (existing ∪ new).
func (c *Client) SetApprovedRoutes(ctx context.Context, id string, routes []string) error {
	return c.do(ctx, http.MethodPost, "/api/v1/node/"+id+"/approve_routes", map[string]any{"routes": routes}, nil)
}

// CreatePreAuthKeyRequest mints a pre-auth key. Since Headscale 0.28 a tagged key needs no user.
type CreatePreAuthKeyRequest struct {
	Reusable   bool      `json:"reusable"`
	Ephemeral  bool      `json:"ephemeral"`
	Expiration time.Time `json:"expiration"`
	ACLTags    []string  `json:"aclTags"`
}

// CreatePreAuthKey mints a key and returns it.
func (c *Client) CreatePreAuthKey(ctx context.Context, req CreatePreAuthKeyRequest) (*PreAuthKey, error) {
	var out struct {
		PreAuthKey PreAuthKey `json:"preAuthKey"`
	}
	if err := c.do(ctx, http.MethodPost, "/api/v1/preauthkey", req, &out); err != nil {
		return nil, err
	}
	return &out.PreAuthKey, nil
}

// ExpirePreAuthKey stops a pre-auth key from registering further nodes. Headscale
// 0.26+ addresses keys by numeric ID (protojson accepts the uint64 as a string).
func (c *Client) ExpirePreAuthKey(ctx context.Context, id string) error {
	return c.do(ctx, http.MethodPost, "/api/v1/preauthkey/expire", map[string]string{"id": id}, nil)
}

// CreateAPIKey mints an API key and returns the full secret (prefix.secret). It is shown once.
func (c *Client) CreateAPIKey(ctx context.Context, expiration time.Time) (string, error) {
	var out struct {
		APIKey string `json:"apiKey"`
	}
	if err := c.do(ctx, http.MethodPost, "/api/v1/apikey", map[string]any{"expiration": expiration}, &out); err != nil {
		return "", err
	}
	return out.APIKey, nil
}

// ExpireAPIKey expires the API key identified by its prefix.
func (c *Client) ExpireAPIKey(ctx context.Context, prefix string) error {
	return c.do(ctx, http.MethodPost, "/api/v1/apikey/expire", map[string]string{"prefix": prefix}, nil)
}

// ListAPIKeys returns all API keys (secrets omitted by the server).
func (c *Client) ListAPIKeys(ctx context.Context) ([]APIKey, error) {
	var out struct {
		APIKeys []APIKey `json:"apiKeys"`
	}
	if err := c.do(ctx, http.MethodGet, "/api/v1/apikey", nil, &out); err != nil {
		return nil, err
	}
	return out.APIKeys, nil
}

// GetPolicy returns the current policy document (HuJSON) as a string.
func (c *Client) GetPolicy(ctx context.Context) (string, error) {
	var out struct {
		Policy string `json:"policy"`
	}
	if err := c.do(ctx, http.MethodGet, "/api/v1/policy", nil, &out); err != nil {
		return "", err
	}
	return out.Policy, nil
}

// SetPolicy replaces the whole policy document (HuJSON). Only accepted when the control server
// runs policy mode "database"; in file mode Headscale rejects the write. The server validates the
// document (syntax, references, the `tests` block) before storing it, so a rejected write leaves the
// previous policy active.
func (c *Client) SetPolicy(ctx context.Context, policy string) error {
	body := struct {
		Policy string `json:"policy"`
	}{Policy: policy}
	return c.do(ctx, http.MethodPut, "/api/v1/policy", body, nil)
}

// PrefixOf returns the database identifier, never the secret part of a recognized API key.
// Headscale uses legacy prefix.secret and hskey-api-{12-char-prefix}-{secret} formats. The
// URL-safe prefix can itself contain '-', so the modern format requires fixed-width parsing.
// ListAPIKeys returns masked display prefixes; these normalize to the same identifier.
func PrefixOf(key string) string {
	if remainder, ok := strings.CutPrefix(key, "hskey-api-"); ok {
		const size = 12
		if len(remainder) < size || (len(remainder) > size && remainder[size] != '-') {
			return ""
		}
		prefix := remainder[:size]
		for _, ch := range prefix {
			if !((ch >= 'a' && ch <= 'z') || (ch >= 'A' && ch <= 'Z') ||
				(ch >= '0' && ch <= '9') || ch == '_' || ch == '-') {
				return ""
			}
		}
		return prefix
	}
	prefix := strings.TrimSuffix(key, "***")
	if i := strings.IndexByte(key, '.'); i >= 0 {
		prefix = key[:i]
		// Legacy Headscale secrets have a seven-character public identifier.
		// A period alone does not make an arbitrary credential a recognized key.
		if len(prefix) != 7 {
			return ""
		}
	}
	// Bare identifiers are used by the API, but unknown whole-key formats must fail closed.
	if len(prefix) != 7 && len(prefix) != 12 {
		return ""
	}
	for _, ch := range prefix {
		if !((ch >= 'a' && ch <= 'z') || (ch >= 'A' && ch <= 'Z') ||
			(ch >= '0' && ch <= '9') || ch == '_' || ch == '-') {
			return ""
		}
	}
	return prefix
}
