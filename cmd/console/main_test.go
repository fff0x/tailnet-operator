package main

import (
	"slices"
	"testing"
)

func TestConfigFromEnv(t *testing.T) {
	env := map[string]string{"CONSOLE_URL": "https://console.example", "OIDC_ISSUER": "https://id.example",
		"OIDC_CLIENT_ID": "c", "OIDC_CLIENT_SECRET": "s", "OIDC_SCOPES": "openid profile,email  groups",
		"CONSOLE_ADMIN_GROUP": "admins", "CONSOLE_OPERATOR_URL": "http://op.operator.svc:8082",
		"CONSOLE_API_TOKEN_FILE": "/var/run/secrets/tsunaro.io/console-api/token"}
	cfg := configFromEnv(func(k string) string { return env[k] })
	if !slices.Equal(cfg.Scopes, []string{"openid", "profile", "email", "groups"}) || cfg.UserGroup != "" ||
		cfg.OperatorURL != env["CONSOLE_OPERATOR_URL"] || cfg.TokenFile != env["CONSOLE_API_TOKEN_FILE"] {
		t.Fatalf("config %+v", cfg)
	}
	if err := cfg.Validate(); err != nil {
		t.Fatal(err)
	}
}
