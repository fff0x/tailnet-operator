package main

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"testing"
)

func writeVersionedTargets(t *testing.T, path string, ts []target) {
	t.Helper()
	b, err := json.Marshal(struct {
		Version int      `json:"version"`
		Targets []target `json:"targets"`
	}{Version: 1, Targets: ts})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, b, 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestLoadTargetsProtocols(t *testing.T) {
	l4 := target{Name: "tcp", Address: "backend.test", Port: 8080, ListenPort: 10000}
	explicitL4 := l4
	explicitL4.Name, explicitL4.Mode, explicitL4.ListenPort = "explicit", "l4", 10001
	http := validHTTPTarget(t)
	http.ConfigID = "http-source-revision"
	for _, tt := range []struct {
		name      string
		versioned bool
		targets   []target
	}{
		{"legacy-l4", false, []target{l4, explicitL4}},
		{"legacy-empty", false, []target{}},
		{"versioned-mixed", true, []target{http, l4, explicitL4}},
		{"versioned-http", true, []target{http}},
		{"versioned-pending-http-l4-only", true, []target{l4}},
		{"versioned-pending-http-empty", true, []target{}},
	} {
		t.Run(tt.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "targets.json")
			if tt.versioned {
				writeVersionedTargets(t, path, tt.targets)
			} else {
				writeTargets(t, path, tt.targets)
			}
			got, err := loadTargets(path)
			if err != nil || !reflect.DeepEqual(got, tt.targets) {
				t.Fatalf("loaded targets = %+v, error = %v", got, err)
			}
			// Match the published legacy agent: unmarshal a flat slice of the old fields.
			// Unknown HTTP fields in array records were ignored, not validated.
			var legacy []struct {
				Name       string `json:"name"`
				Address    string `json:"address"`
				Port       int    `json:"port"`
				ListenPort int    `json:"listenPort"`
			}
			b, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			err = json.Unmarshal(b, &legacy)
			if tt.versioned {
				var shape *json.UnmarshalTypeError
				if !errors.As(err, &shape) || shape.Value != "object" {
					t.Fatalf("legacy decoder did not reject object protocol: %v", err)
				}
			} else if err != nil || len(legacy) != len(tt.targets) {
				t.Fatalf("legacy L4 compatibility broken: %v", err)
			}
		})
	}
}

func TestLoadTargetsWhitespaceAndEnvelopeOrder(t *testing.T) {
	for _, source := range []string{" \t\r\n[]\n", " \n{\"targets\":[],\"version\":1}\t\r\n"} {
		path := filepath.Join(t.TempDir(), "targets.json")
		if err := os.WriteFile(path, []byte(source), 0o600); err != nil {
			t.Fatal(err)
		}
		if ts, err := loadTargets(path); err != nil || ts == nil || len(ts) != 0 {
			t.Fatalf("valid empty configuration rejected: %v", err)
		}
	}
}

func TestLoadTargetsRejectsFlatHTTP(t *testing.T) {
	path := filepath.Join(t.TempDir(), "targets.json")
	writeTargets(t, path, []target{validHTTPTarget(t)})
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	// This is the old behavior that made a flat HTTP record unsafe for override images.
	var legacy []struct {
		Name       string `json:"name"`
		ListenPort int    `json:"listenPort"`
	}
	if err := json.Unmarshal(b, &legacy); err != nil || len(legacy) != 1 || legacy[0].ListenPort != 443 {
		t.Fatal("reference legacy decoder did not silently accept the HTTP record")
	}
	if ts, err := loadTargets(path); !errors.Is(err, errTargetsConfig) || ts != nil {
		t.Fatal("HTTP in a legacy array was accepted")
	}
}

func TestLoadTargetsRejectsInvalidShapes(t *testing.T) {
	for name, source := range map[string]string{
		"empty": "", "whitespace": " \n\t ", "null": "null", "scalar": "1", "string": `"config"`,
		"non-json-whitespace-array":    "\v[]",
		"non-json-whitespace-envelope": "\u00a0{\"version\":1,\"targets\":[]}",
		"missing-version":              `{"targets":[]}`,
		"null-version":                 `{"version":null,"targets":[]}`,
		"unknown-version":              `{"version":2,"targets":[]}`,
		"zero-version":                 `{"version":0,"targets":[]}`,
		"negative-version":             `{"version":-1,"targets":[]}`,
		"fractional-version":           `{"version":1.1,"targets":[]}`,
		"decimal-version":              `{"version":1.0,"targets":[]}`,
		"exponent-version":             `{"version":1e0,"targets":[]}`,
		"string-version":               `{"version":"1","targets":[]}`,
		"bool-version":                 `{"version":true,"targets":[]}`,
		"object-version":               `{"version":{},"targets":[]}`,
		"array-version":                `{"version":[1],"targets":[]}`,
		"overflow-version":             `{"version":999999999999999999999999999,"targets":[]}`,
		"missing-targets":              `{"version":1}`,
		"null-targets":                 `{"version":1,"targets":null}`,
		"object-targets":               `{"version":1,"targets":{}}`,
		"string-targets":               `{"version":1,"targets":"[]"}`,
		"bool-targets":                 `{"version":1,"targets":false}`,
		"number-targets":               `{"version":1,"targets":1}`,
		"null-target-record":           `{"version":1,"targets":[null]}`,
		"empty-target-record":          `{"version":1,"targets":[{}]}`,
		"scalar-target-record":         `{"version":1,"targets":[1]}`,
		"empty-envelope":               `{}`,
		"unknown-key":                  `{"version":1,"targets":[],"extra":"credential-sentinel"}`,
		"version-case":                 `{"Version":1,"targets":[]}`,
		"targets-case":                 `{"version":1,"Targets":[]}`,
		"duplicate-version":            `{"version":1,"version":1,"targets":[]}`,
		"duplicate-targets":            `{"version":1,"targets":[],"targets":[]}`,
		"malformed-envelope":           `{"version":1,"targets":[`,
		"malformed-array":              `[{`,
		"trailing-envelope":            `{"version":1,"targets":[]} credential-sentinel`,
		"trailing-array":               `[] credential-sentinel`,
		"multiple-envelopes":           `{"version":1,"targets":[]} {"version":1,"targets":[]}`,
		"multiple-arrays":              `[] []`,
		"envelope-then-null":           `{"version":1,"targets":[]} null`,
		"array-then-object":            `[] {}`,
		"invalid-record-field":         `[{"name":"credential-sentinel","address":"backend.test","port":"password-sentinel","listenPort":10000}]`,
		"invalid-mode":                 `{"version":1,"targets":[{"name":"web","address":"backend.test","port":80,"listenPort":443,"mode":"credential-sentinel"}]}`,
		"invalid-http":                 `{"version":1,"targets":[{"name":"web","address":"https://user:credential-sentinel@backend.test","port":80,"listenPort":443,"mode":"http","certFile":"/private/key-sentinel"}]}`,
	} {
		t.Run(name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "private-path-sentinel.json")
			if err := os.WriteFile(path, []byte(source), 0o600); err != nil {
				t.Fatal(err)
			}
			ts, err := loadTargets(path)
			if !errors.Is(err, errTargetsConfig) || err.Error() != "invalid targets configuration" || ts != nil {
				t.Fatalf("invalid configuration did not return the fixed error: %v", err)
			}
			for _, sentinel := range []string{"credential-sentinel", "password-sentinel", "key-sentinel", path} {
				if strings.Contains(err.Error(), sentinel) {
					t.Fatal("configuration error leaked source content or path")
				}
			}
		})
	}
	if _, err := loadTargets(filepath.Join(t.TempDir(), "private-missing-file")); !errors.Is(err, errTargetsConfig) {
		t.Fatal("file read error was not redacted")
	}
}

func names(ts []target) []string {
	out := make([]string, len(ts))
	for i, t := range ts {
		out[i] = t.Name
	}
	sort.Strings(out)
	return out
}

func eq(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func TestDiffFresh(t *testing.T) {
	start, stop := diffTargets(nil, []target{
		{Name: "a", Address: "1.1.1.1", Port: 1, ListenPort: 10000},
		{Name: "b", Address: "2.2.2.2", Port: 2, ListenPort: 10001},
	})
	if !eq(names(start), []string{"a", "b"}) {
		t.Errorf("start=%v want [a b]", names(start))
	}
	if len(stop) != 0 {
		t.Errorf("stop=%v want none", stop)
	}
}

func TestDiffUnchanged(t *testing.T) {
	run := map[string]target{"a": {Name: "a", Address: "1.1.1.1", Port: 1, ListenPort: 10000}}
	start, stop := diffTargets(run, []target{{Name: "a", Address: "1.1.1.1", Port: 1, ListenPort: 10000}})
	if len(start) != 0 || len(stop) != 0 {
		t.Errorf("unchanged should be a no-op: start=%v stop=%v", names(start), stop)
	}
}

func TestDiffRemoved(t *testing.T) {
	run := map[string]target{
		"a": {Name: "a", Address: "1.1.1.1", Port: 1, ListenPort: 10000},
		"b": {Name: "b", Address: "2.2.2.2", Port: 2, ListenPort: 10001},
	}
	start, stop := diffTargets(run, []target{{Name: "a", Address: "1.1.1.1", Port: 1, ListenPort: 10000}})
	if len(start) != 0 {
		t.Errorf("start=%v want none", names(start))
	}
	sort.Strings(stop)
	if !eq(stop, []string{"b"}) {
		t.Errorf("stop=%v want [b]", stop)
	}
}

func TestDiffChangedStopsAndStarts(t *testing.T) {
	run := map[string]target{"a": {Name: "a", Address: "1.1.1.1", Port: 1, ListenPort: 10000}}
	// Same name, new upstream port → must stop the old listener and start the new one.
	start, stop := diffTargets(run, []target{{Name: "a", Address: "1.1.1.1", Port: 9, ListenPort: 10000}})
	if !eq(names(start), []string{"a"}) {
		t.Errorf("start=%v want [a]", names(start))
	}
	if !eq(stop, []string{"a"}) {
		t.Errorf("stop=%v want [a]", stop)
	}
}
