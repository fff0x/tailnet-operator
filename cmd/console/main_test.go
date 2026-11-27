package main

import (
	"slices"
	"testing"
)

func TestConfigFromEnv(t *testing.T) {
	env := map[string]string{"CONSOLE_URL": "https://console.example", "OIDC_ISSUER": "https://id.example",
		"OIDC_CLIENT_ID": "c", "OIDC_CLIENT_SECRET": "s", "OIDC_SCOPES": "openid profile,email  groups",
		"CONSOLE_ADMIN_GROUP": "admins"}
	cfg := configFromEnv(func(k string) string { return env[k] })
	if !slices.Equal(cfg.Scopes, []string{"openid", "profile", "email", "groups"}) || cfg.UserGroup != "" {
		t.Fatalf("config %+v", cfg)
	}
	if err := cfg.Validate(); err != nil {
		t.Fatal(err)
	}
}
