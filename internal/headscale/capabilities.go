package headscale

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"time"
)

// Capabilities contains only observed facts. A nil field means no verdict, not false.
// Policy mode inference is verified against Headscale 0.28.0 and 0.29.3: GetPolicy returns an
// updatedAt timestamp in database mode, explicit null in file mode. An omitted field is ambiguous.
type Capabilities struct {
	PolicyDatabaseMode *bool
	PolicyCheck        *bool
	DBHealth           *bool
}

// GetPolicyWithMode reads the policy without changing it. The gateway's explicit updatedAt field
// distinguishes database/file mode on the tested versions; an omitted field gives no mode verdict.
func (c *Client) GetPolicyWithMode(ctx context.Context) (string, *bool, error) {
	var out struct {
		Policy    *string         `json:"policy"`
		UpdatedAt json.RawMessage `json:"updatedAt"`
	}
	if err := c.do(ctx, http.MethodGet, "/api/v1/policy", nil, &out); err != nil {
		return "", nil, err
	}
	if out.Policy == nil {
		return "", nil, fmt.Errorf("policy response is missing policy")
	}
	if len(out.UpdatedAt) == 0 {
		return *out.Policy, nil, nil
	}
	var updatedAt *time.Time
	if err := json.Unmarshal(out.UpdatedAt, &updatedAt); err != nil {
		return "", nil, fmt.Errorf("decode policy updatedAt: %w", err)
	}
	database := updatedAt != nil
	return *out.Policy, &database, nil
}

// CheckPolicy validates a document against the server's live users/nodes without persisting it.
// The upstream response is an empty protobuf message; an arbitrary 200 body is not success.
func (c *Client) CheckPolicy(ctx context.Context, policy string) error {
	var out map[string]json.RawMessage
	if err := c.do(ctx, http.MethodPost, "/api/v1/policy/check", map[string]string{"policy": policy}, &out); err != nil {
		return err
	}
	if out == nil || len(out) != 0 {
		return fmt.Errorf("unexpected policy/check response")
	}
	return nil
}

// Probe performs three non-mutating capability checks. Partial observations survive a failed
// request; errors never imply file mode or endpoint support. A missing health endpoint is optional.
func (c *Client) Probe(ctx context.Context) (Capabilities, error) {
	var caps Capabilities
	_, mode, policyErr := c.GetPolicyWithMode(ctx)
	caps.PolicyDatabaseMode = mode

	checkErr := c.CheckPolicy(ctx, "{}")
	switch {
	case checkErr == nil:
		present := true
		caps.PolicyCheck = &present
	case hasStatus(checkErr, http.StatusNotFound):
		present := false
		caps.PolicyCheck = &present
		checkErr = nil
	}

	var health struct {
		DatabaseConnectivity *bool `json:"databaseConnectivity"`
	}
	healthErr := c.do(ctx, http.MethodGet, "/api/v1/health", nil, &health)
	switch {
	case hasStatus(healthErr, http.StatusNotFound):
		healthErr = nil
	case healthErr == nil && health.DatabaseConnectivity == nil:
		healthErr = fmt.Errorf("health response is missing databaseConnectivity")
	case healthErr == nil:
		caps.DBHealth = health.DatabaseConnectivity
	}
	return caps, errors.Join(policyErr, checkErr, healthErr)
}

func hasStatus(err error, code int) bool {
	var se *StatusError
	return errors.As(err, &se) && se.Code == code
}
