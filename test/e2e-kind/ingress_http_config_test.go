//go:build e2e_kind

package e2ekind

import (
	"testing"

	"this-is-fine.io/tailnet-operator/internal/policy"
)

func TestHTTPFixtureBasePolicyRendersBeforeIngress(t *testing.T) {
	if _, _, err := policy.Render([]byte(ingressHTTPBasePolicy), policy.Inputs{}); err != nil {
		t.Fatal("fixture base must pass the unchanged production empty-policy guard before ingress creation")
	}
}
