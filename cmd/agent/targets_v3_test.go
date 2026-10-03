package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func writeV3Targets(t *testing.T, path string, targets []target, certificateNames []string) {
	t.Helper()
	data, err := json.Marshal(map[string]any{"version": 3, "certificateDNSNames": certificateNames, "targets": targets})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}
}

func TestV3ConfigurationContract(t *testing.T) {
	a := validHTTPTarget(t)
	a.Name, a.DNSName = "a", "a.example.test"
	b := a
	b.Name, b.DNSName = "b", "b.example.test"
	l4 := target{Name: "tcp", Address: "backend.test", Port: 80, ListenPort: 8443}
	path := filepath.Join(t.TempDir(), "targets.json")
	certificateNames := []string{"base.example.test", b.DNSName, a.DNSName}
	writeV3Targets(t, path, []target{a, b, l4}, certificateNames)
	first, err := loadTargets(path)
	if err != nil || len(first) != 3 {
		t.Fatal("valid mixed v3 configuration rejected", err)
	}
	want := [maxAgentTargets + 1]string{"base.example.test", a.DNSName, b.DNSName}
	if first[0].requiredCertificateNames != want || first[1].requiredCertificateNames != want || first[2] != l4 {
		t.Fatal("certificate policy not canonical/comparable or leaked into L4")
	}
	writeV3Targets(t, path, []target{b, l4, a}, []string{"BASE.EXAMPLE.TEST", "A.EXAMPLE.TEST", "B.EXAMPLE.TEST"})
	second, err := loadTargets(path)
	if err != nil {
		t.Fatal(err)
	}
	start, stop := diffTargets(map[string]target{first[0].Name: first[0], first[1].Name: first[1], first[2].Name: first[2]}, second)
	if len(start)+len(stop) != 0 {
		t.Fatal("certificate/target order or certificate-name case caused restart")
	}
	data, _ := json.Marshal(first[0])
	if strings.Contains(string(data), "requiredCertificate") || strings.Contains(string(data), "base.example.test") {
		t.Fatal("private certificate policy changed target wire fields")
	}
	// The base is a distinct policy entry, even if no target routes it.
	writeV3Targets(t, path, []target{a, b}, []string{"other-base.example.test", a.DNSName, b.DNSName})
	third, err := loadTargets(path)
	if err != nil {
		t.Fatal(err)
	}
	start, stop = diffTargets(map[string]target{first[0].Name: first[0], first[1].Name: first[1]}, third)
	if len(start) != 2 || len(stop) != 2 {
		t.Fatal("certificate policy change did not retire group")
	}

	for name, mutate := range map[string]func([]target) []target{
		"duplicate-name":    func(ts []target) []target { ts[1].Name = ts[0].Name; return ts },
		"duplicate-sni":     func(ts []target) []target { ts[1].DNSName = strings.ToUpper(ts[0].DNSName); return ts },
		"different-cert":    func(ts []target) []target { ts[1].CertFile = "/private/other.crt"; return ts },
		"different-key":     func(ts []target) []target { ts[1].KeyFile = "/private/other.key"; return ts },
		"l4-http-port":      func(ts []target) []target { ts[2].ListenPort = 443; return ts },
		"http-other-port":   func(ts []target) []target { ts[1].ListenPort = 8443; return ts },
		"l4-port-high":      func(ts []target) []target { ts[2].Port = 65536; return ts },
		"l4-port-negative":  func(ts []target) []target { ts[2].Port = -1; return ts },
		"listen-high":       func(ts []target) []target { ts[2].ListenPort = 65536; return ts },
		"listen-negative":   func(ts []target) []target { ts[2].ListenPort = -1; return ts },
		"no-http":           func(ts []target) []target { return ts[2:] },
		"empty":             func([]target) []target { return []target{} },
		"duplicate-l4-port": func(ts []target) []target { next := ts[2]; next.Name = "other"; return append(ts, next) },
	} {
		t.Run(name, func(t *testing.T) {
			writeV3Targets(t, path, mutate([]target{a, b, l4}), certificateNames)
			got, err := loadTargets(path)
			if got != nil || !errors.Is(err, errTargetsConfig) || err.Error() != "invalid targets configuration" {
				t.Fatal("invalid whole config not sanitized/rejected", err)
			}
		})
	}
}

func TestV3RequiredNamesAndStrictEnvelope(t *testing.T) {
	a := validHTTPTarget(t)
	path := filepath.Join(t.TempDir(), "targets.json")
	for _, names := range [][]string{nil, {}, {""}, {"base.example.test"}, {a.DNSName, strings.ToUpper(a.DNSName)}, {a.DNSName, "127.0.0.1"}, {a.DNSName, "*.example.test"}, {a.DNSName, "bad..test"}, {a.DNSName, "a.example.test."}, {a.DNSName, "::1"}, {a.DNSName, "K.example.test"}} {
		writeV3Targets(t, path, []target{a}, names)
		if _, err := loadTargets(path); !errors.Is(err, errTargetsConfig) {
			t.Fatalf("invalid required names accepted: %v", names)
		}
	}
	names := []string{a.DNSName}
	for i := 1; i < maxAgentTargets+1; i++ {
		names = append(names, fmt.Sprintf("extra-%d.example.test", i))
	}
	writeV3Targets(t, path, []target{a}, names)
	if _, err := loadTargets(path); err != nil {
		t.Fatal("51 required names rejected", err)
	}
	writeV3Targets(t, path, []target{a}, append(names, "overflow.example.test"))
	if _, err := loadTargets(path); err == nil {
		t.Fatal("52 required names accepted")
	}
	raw, _ := json.Marshal([]target{a})
	for _, source := range []string{
		`{"version":3,"targets":` + string(raw) + `}`,
		`{"version":3,"targets":` + string(raw) + `,"certificateDNSNames":null}`,
		`{"version":3,"targets":` + string(raw) + `,"certificateDNSNames":"app.example.test"}`,
		`{"version":3,"targets":` + string(raw) + `,"CertificateDNSNames":["app.example.test"]}`,
		`{"version":3,"targets":` + string(raw) + `,"certificateDNSNames":["app.example.test"],"certificateDNSNames":["app.example.test"]}`,
		`{"version":3,"targets":` + string(raw) + `,"certificateDNSNames":["app.example.test"],"extra":null}`,
	} {
		if err := os.WriteFile(path, []byte(source), 0600); err != nil {
			t.Fatal(err)
		}
		if _, err := loadTargets(path); !errors.Is(err, errTargetsConfig) {
			t.Fatal("non-exact v3 envelope accepted")
		}
	}
	for _, version := range []int{1, 2} {
		for _, names := range []any{nil, []string{}, []string{a.DNSName}} {
			data, _ := json.Marshal(map[string]any{"version": version, "targets": []target{a}, "certificateDNSNames": names})
			if err := os.WriteFile(path, data, 0600); err != nil {
				t.Fatal(err)
			}
			if _, err := loadTargets(path); err == nil {
				t.Fatal("v1/v2 accepted v3 field")
			}
		}
		b := a
		b.Name, b.DNSName = "b", "b.example.test"
		data, _ := json.Marshal(map[string]any{"version": version, "targets": []target{a, b}})
		if err := os.WriteFile(path, data, 0600); err != nil {
			t.Fatal(err)
		}
		if _, err := loadTargets(path); err == nil {
			t.Fatal("old envelope accepted multi HTTP")
		}
	}
}

func TestV3MaximumRoutesAndWithdrawal(t *testing.T) {
	path := filepath.Join(t.TempDir(), "targets.json")
	prototype := validHTTPTarget(t)
	targets := make([]target, maxAgentTargets)
	names := []string{baseDNS}
	for i := range targets {
		targets[i] = prototype
		targets[i].Name = fmt.Sprintf("route-%d", i)
		targets[i].DNSName = targets[i].Name + ".example.test"
		names = append(names, targets[i].DNSName)
	}
	writeV3Targets(t, path, targets, names)
	if got, err := loadTargets(path); err != nil || len(got) != maxAgentTargets {
		t.Fatal("50 HTTP routes plus base policy rejected", err)
	}
	l4 := target{Name: "l4", Address: "127.0.0.1", Port: 80, ListenPort: 8443}
	for _, remaining := range [][]target{{}, {l4}} {
		writeV3Targets(t, path, remaining, []string{})
		if got, err := loadTargets(path); err != nil || !reflect.DeepEqual(got, remaining) {
			t.Fatal("explicit v3 withdrawal rejected", err)
		}
		for _, invalid := range [][]string{nil, {baseDNS}} {
			writeV3Targets(t, path, remaining, invalid)
			if _, err := loadTargets(path); !errors.Is(err, errTargetsConfig) {
				t.Fatal("withdrawal accepted null or nonempty certificate policy")
			}
		}
	}
}

func TestV3ExtensionPresence(t *testing.T) {
	path := filepath.Join(t.TempDir(), "targets.json")
	for _, mode := range []string{"http", "l4"} {
		for _, field := range []string{"backendServerName", "backendCAFile", "requestTimeout", "backendRequestTimeout", "requeſtTimeout", "bacKendCAFile"} {
			a := validHTTPTarget(t)
			a.Mode = mode
			if mode == "l4" {
				a.Name, a.ListenPort = "l4", 8443
			}
			raw, _ := json.Marshal(a)
			var record map[string]any
			json.Unmarshal(raw, &record)
			record[field] = nil
			records := []any{record}
			if mode == "l4" {
				records = append(records, validHTTPTarget(t))
			}
			data, _ := json.Marshal(map[string]any{"version": 3, "targets": records, "certificateDNSNames": []string{a.DNSName}})
			if err := os.WriteFile(path, data, 0600); err != nil {
				t.Fatal(err)
			}
			_, err := loadTargets(path)
			if (err == nil) != (mode == "http") {
				t.Fatalf("v3 extension presence: mode=%s field=%s err=%v", mode, field, err)
			}
		}
	}
}

func TestInvalidWholeConfigurationNeverChangesListeners(t *testing.T) {
	path := filepath.Join(t.TempDir(), "targets.json")
	fw := &forwarder{mode: "egress", run: map[string]running{}}
	defer fw.stopAll()
	good := target{Name: "good", Address: "127.0.0.1", Port: 80, ListenPort: freePort(t)}
	writeTargets(t, path, []target{good})
	if _, err := fw.reload(context.Background(), path); err != nil {
		t.Fatal(err)
	}
	before := fw.run[good.Name]
	bad := good
	bad.Name = "duplicate-port"
	writeTargets(t, path, []target{good, bad})
	if _, err := fw.reload(context.Background(), path); err == nil || !reflect.DeepEqual(fw.current(), map[string]target{good.Name: good}) || fw.run[good.Name].ln != before.ln || fw.run[good.Name].generation != before.generation {
		t.Fatal("whole config validation permitted partial reload")
	}
}
