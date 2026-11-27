package main

import (
	"flag"
	"io"
	"reflect"
	"strings"
	"testing"
)

func TestLeaderElectionFlag(t *testing.T) {
	for _, tt := range []struct {
		name string
		args []string
		want bool
	}{
		{name: "default", want: true},
		{name: "enabled", args: []string{"--leader-elect=true"}, want: true},
		{name: "disabled", args: []string{"--leader-elect=false"}, want: false},
	} {
		t.Run(tt.name, func(t *testing.T) {
			fs := flag.NewFlagSet("operator", flag.ContinueOnError)
			got := leaderElectionFlag(fs)
			if err := fs.Parse(tt.args); err != nil {
				t.Fatal(err)
			}
			if *got != tt.want {
				t.Fatalf("leader election = %v, want %v", *got, tt.want)
			}
		})
	}
	fs := flag.NewFlagSet("operator", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	leaderElectionFlag(fs)
	if err := fs.Parse([]string{"--leader-elect=invalid"}); err == nil {
		t.Fatal("invalid election flag accepted")
	}
}

func TestParseAgentImagePullSecrets(t *testing.T) {
	for _, tt := range []struct {
		name string
		raw  string
		want []string
	}{
		{name: "unset-or-empty"},
		{name: "empty-array", raw: `[]`, want: []string{}},
		{name: "names", raw: `["registry", "registry.example", "0-registry"]`, want: []string{"registry", "registry.example", "0-registry"}},
		{name: "whitespace", raw: " \n [\"registry\"] \t", want: []string{"registry"}},
		{name: "maximum-length", raw: `["` + strings.Repeat("a", 253) + `"]`, want: []string{strings.Repeat("a", 253)}},
	} {
		t.Run(tt.name, func(t *testing.T) {
			got, err := parseAgentImagePullSecrets(tt.raw)
			if err != nil || !reflect.DeepEqual(got, tt.want) {
				t.Fatalf("got %v, %v; want %v", got, err, tt.want)
			}
		})
	}
}

func TestParseAgentImagePullSecretsRejectsInvalidInput(t *testing.T) {
	for _, raw := range []string{
		`null`, ` null `, `"registry"`, `{}`, `{"name":"registry"}`, `true`, `1`,
		`[1]`, `[true]`, `[null]`, `[["registry"]]`, `[{"name":"registry"}]`,
		`["registry", null]`, `["registry", 1]`,
		`[`, `["registry",]`, `[] []`, `   `,
		`[""]`, `["Registry"]`, `["registry/name"]`, `["registry_name"]`,
		`["registry name"]`, `["-registry"]`, `["registry-"]`,
		`["registry."]`, `[".registry"]`, `["registry..example"]`,
		`["` + strings.Repeat("a", 254) + `"]`,
	} {
		t.Run(raw, func(t *testing.T) {
			got, err := parseAgentImagePullSecrets(raw)
			if err == nil || got != nil {
				t.Fatalf("got %v, %v; want nil and an error", got, err)
			}
		})
	}
}

func TestParseConsoleAPISubject(t *testing.T) {
	for raw, ok := range map[string]bool{
		"": true, "system:serviceaccount:operator:tsunaro-console": true,
		"system:serviceaccount:operator": false, "system:serviceaccounts:operator": false,
		"admin@example.test": false, "system:serviceaccount:Operator:console": false,
		"system:serviceaccount:operator:console:extra": false,
	} {
		got, err := parseConsoleAPISubject(raw)
		if (err == nil) != ok || (ok && got != raw) {
			t.Errorf("%q: got %q, %v", raw, got, err)
		}
	}
}

func TestParseAgentImagePullSecretsErrorsDoNotExposeValues(t *testing.T) {
	for _, raw := range []string{`["SENSITIVE-VALUE"]`, `{"SENSITIVE-VALUE":`, `"SENSITIVE-VALUE"`} {
		_, err := parseAgentImagePullSecrets(raw)
		if err == nil || strings.Contains(err.Error(), "SENSITIVE-VALUE") {
			t.Fatalf("unsafe or missing error: %v", err)
		}
	}
}
