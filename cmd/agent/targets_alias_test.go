package main

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

// v3 HTTP targets may carry dnsAliases: extra SNI/Host names that must be covered by the
// certificate policy, unique across names, and never appear on L4 or pre-v3 configurations.
func TestV3DNSAliases(t *testing.T) {
	a := validHTTPTarget(t)
	a.Name, a.Mode, a.DNSName = "web", "http", "web.ns.hydra.tif.internal"
	alias := "web.hydra.tif.internal"
	path := filepath.Join(t.TempDir(), "targets.json")

	record := func(tgt target, mode string, aliases []string) map[string]any {
		raw, _ := json.Marshal(tgt)
		var rec map[string]any
		_ = json.Unmarshal(raw, &rec)
		rec["mode"] = mode
		if aliases != nil {
			rec["dnsAliases"] = aliases
		}
		return rec
	}
	write := func(version int, certNames []string, recs ...map[string]any) {
		data, _ := json.Marshal(map[string]any{"version": version, "certificateDNSNames": certNames, "targets": recs})
		if err := os.WriteFile(path, data, 0600); err != nil {
			t.Fatal(err)
		}
	}

	// Valid: alias is a certificate SAN and routes to the target.
	write(3, []string{a.DNSName, alias}, record(a, "http", []string{alias}))
	ts, err := loadTargets(path)
	if err != nil || len(ts) != 1 || ts[0].dnsAliases[0] != alias || ts[0].dnsAliases[1] != "" {
		t.Fatalf("valid alias config rejected: %v %+v", err, ts)
	}

	l4 := target{Name: "tcp", Address: "backend.test", Port: 80, ListenPort: 8443}
	for name, mutate := range map[string]func(){
		"alias-not-in-cert":    func() { write(3, []string{a.DNSName}, record(a, "http", []string{alias})) },
		"alias-equals-dnsname": func() { write(3, []string{a.DNSName}, record(a, "http", []string{a.DNSName})) },
		"alias-on-v2":          func() { write(2, nil, record(a, "http", []string{alias})) },
		"alias-on-l4": func() {
			write(3, []string{a.DNSName, alias}, record(a, "http", nil), record(l4, "l4", []string{alias}))
		},
		"alias-overflow": func() {
			many := make([]string, maxAliasesPerTarget+1)
			for i := range many {
				many[i] = alias
			}
			write(3, []string{a.DNSName, alias}, record(a, "http", many))
		},
	} {
		t.Run(name, func(t *testing.T) {
			mutate()
			if _, err := loadTargets(path); !errors.Is(err, errTargetsConfig) {
				t.Fatalf("invalid alias config accepted: %s", name)
			}
		})
	}
}
