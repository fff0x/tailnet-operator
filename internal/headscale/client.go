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
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// Client talks to one Headscale server with one bearer token. The operator builds a fresh Client per
// reconcile with the current working key, so a rotated key is picked up without any shared state.
type Client struct {
	baseURL string
	token   string
	http    *http.Client
}

// New returns a client for baseURL (e.g. https://ts.example.com) authenticating with token.
func New(baseURL, token string) *Client {
	return &Client{
		baseURL: strings.TrimRight(baseURL, "/"),
		token:   token,
		http:    &http.Client{Timeout: 15 * time.Second},
	}
}

// Node is the subset of a Headscale node the operator reads.
type Node struct {
	ID              string   `json:"id"`
	Name            string   `json:"name"`
	GivenName       string   `json:"givenName"`
	Online          bool     `json:"online"`
	IPAddresses     []string `json:"ipAddresses"`
	AvailableRoutes []string `json:"availableRoutes"`
	ApprovedRoutes  []string `json:"approvedRoutes"`
	SubnetRoutes    []string `json:"subnetRoutes"`
	Tags            []string `json:"tags"`
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

func (c *Client) do(ctx context.Context, method, path string, body, out any) error {
	var rdr io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return err
		}
		rdr = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, method, c.baseURL+path, rdr)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+c.token)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	rb, _ := io.ReadAll(resp.Body)
	if resp.StatusCode/100 != 2 {
		return fmt.Errorf("headscale %s %s: %s: %s", method, path, resp.Status, strings.TrimSpace(string(rb)))
	}
	if out != nil {
		if err := json.Unmarshal(rb, out); err != nil {
			return fmt.Errorf("decode %s %s: %w", method, path, err)
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

// ExpirePreAuthKey stops a pre-auth key from registering further nodes.
func (c *Client) ExpirePreAuthKey(ctx context.Context, key string) error {
	return c.do(ctx, http.MethodPost, "/api/v1/preauthkey/expire", map[string]string{"key": key}, nil)
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

// PrefixOf returns the prefix segment of a full API key secret (everything before the first "."),
// which is what ExpireAPIKey and the list endpoint use to identify a key.
func PrefixOf(fullKey string) string {
	if i := strings.IndexByte(fullKey, '.'); i >= 0 {
		return fullKey[:i]
	}
	return fullKey
}
