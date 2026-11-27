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
	if cfg.AuditDir != "" || cfg.FourEyes {
		t.Fatal("access management on without CONSOLE_AUDIT_DIR")
	}
	env["CONSOLE_FOUR_EYES"] = "true"
	if err := configFromEnv(func(k string) string { return env[k] }).Validate(); err == nil {
		t.Fatal("four-eyes accepted without access management")
	}
	env["CONSOLE_AUDIT_DIR"] = "/var/lib/tsunaro-console"
	cfg = configFromEnv(func(k string) string { return env[k] })
	if err := cfg.Validate(); err == nil {
		t.Fatal("audit directory accepted without its anchor")
	}
	env["CONSOLE_AUDIT_ANCHOR"], env["POD_NAMESPACE"] = "tsunaro-console-audit", "tsunaro-system"
	cfg = configFromEnv(func(k string) string { return env[k] })
	if err := cfg.Validate(); err != nil || cfg.AuditDir != "/var/lib/tsunaro-console" || cfg.AuditAnchor != "tsunaro-console-audit" || cfg.Namespace != "tsunaro-system" || !cfg.FourEyes {
		t.Fatalf("config %+v: %v", cfg, err)
	}
}
