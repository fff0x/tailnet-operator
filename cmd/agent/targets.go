package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"os"
	"sort"
	"strings"
)

// target is one forwarded host. Static configuration must remain comparable: reload and probe
// ownership use value equality, not pointers into a newly decoded configuration.
type target struct {
	Name                  string `json:"name"`
	Address               string `json:"address"`
	Port                  int    `json:"port"`
	ListenPort            int    `json:"listenPort"`
	Mode                  string `json:"mode,omitempty"`
	ConfigID              string `json:"configID,omitempty"`
	DNSName               string `json:"dnsName,omitempty"`
	CertFile              string `json:"certFile,omitempty"`
	KeyFile               string `json:"keyFile,omitempty"`
	BackendServerName     string `json:"backendServerName,omitempty"`
	BackendCAFile         string `json:"backendCAFile,omitempty"`
	RequestTimeout        string `json:"requestTimeout,omitempty"`
	BackendRequestTimeout string `json:"backendRequestTimeout,omitempty"`

	// Canonical certificate policy, not a route list. Empty for legacy/v1/v2.
	requiredCertificateNames [maxAgentTargets + 1]string
	// Additional SNI/Host names routed to this HTTP target. A fixed array keeps target comparable
	// (diffTargets relies on value equality); empty entries are ignored. v3 only.
	dnsAliases [maxAliasesPerTarget]string
}

const maxAgentTargets = 50 // matches both CR admission limits and the bounded probe budget

const maxAliasesPerTarget = 8 // bounded alias fan-out per HTTP expose

var errTargetsConfig = errors.New("invalid targets configuration")

// loadTargets validates the WHOLE configuration before reconciliation can touch a listener.
// Legacy arrays are L4-only, v1/v2 allow one HTTP target, v3 allows a shared HTTP listener.
// Read, parse and validation failures never expose source contents or file paths.
func loadTargets(path string) ([]target, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, errTargetsConfig
	}
	b = bytes.Trim(b, " \t\r\n")
	if len(b) == 0 {
		return nil, errTargetsConfig
	}
	version := 0
	var required [maxAgentTargets + 1]string
	if b[0] == '{' {
		b, version, required, err = versionedTargets(b)
		if err != nil {
			return nil, errTargetsConfig
		}
	}
	b = bytes.Trim(b, " \t\r\n")
	if len(b) == 0 || b[0] != '[' {
		return nil, errTargetsConfig
	}
	var ts []target
	if err := json.Unmarshal(b, &ts); err != nil || len(ts) > maxAgentTargets {
		return nil, errTargetsConfig
	}
	var records []map[string]json.RawMessage
	if err := json.Unmarshal(b, &records); err != nil {
		return nil, errTargetsConfig
	}
	hasHTTP := false
	for i, t := range ts {
		// Presence, even null/empty, cannot silently downgrade extension intent.
		for key := range records[i] {
			if isHTTPExtension(key) && ((version != 2 && version != 3) || t.Mode != "http") {
				return nil, errTargetsConfig
			}
			if strings.EqualFold(key, "dnsAliases") && (version != 3 || t.Mode != "http") {
				return nil, errTargetsConfig
			}
		}
		if t.Mode == "http" {
			hasHTTP = true
			ts[i].requiredCertificateNames = required
			if raw, ok := records[i]["dnsAliases"]; ok {
				var aliases []string
				if json.Unmarshal(raw, &aliases) != nil || len(aliases) > len(ts[i].dnsAliases) {
					return nil, errTargetsConfig
				}
				for j, a := range aliases {
					ts[i].dnsAliases[j] = strings.ToLower(a)
				}
			}
		}
	}
	// Explicit v3 withdrawal removes HTTP routes; it must not retain certificate policy.
	if version == 3 && hasHTTP != (required[0] != "") {
		return nil, errTargetsConfig
	}
	if err := validateTargets(ts, version); err != nil {
		return nil, err
	}
	return ts, nil
}

// requiresName reports whether name (lower case) is one of the certificate names the operator
// requires, whether or not it is also a route.
func (t target) requiresName(name string) bool {
	for _, required := range t.requiredCertificateNames {
		if required != "" && strings.EqualFold(required, name) {
			return true
		}
	}
	return false
}

func validateTargets(ts []target, version int) error {
	if len(ts) > maxAgentTargets {
		return errTargetsConfig
	}
	names, dns := make(map[string]bool), make(map[string]bool)
	ports := make(map[int]string)
	var frontend *target
	httpCount := 0
	for _, t := range ts {
		if t.Name == "" || names[t.Name] || t.Address == "" || t.Port < 1 || t.Port > 65535 || t.ListenPort < 1 || t.ListenPort > 65535 || t.validateHTTP() != nil {
			return errTargetsConfig
		}
		names[t.Name] = true
		if mode, used := ports[t.ListenPort]; used && (mode != "http" || t.Mode != "http") {
			return errTargetsConfig
		}
		ports[t.ListenPort] = t.Mode
		if t.Mode != "http" {
			continue
		}
		httpCount++
		name := strings.ToLower(t.DNSName)
		if dns[name] || version == 0 || (version < 3 && httpCount > 1) {
			return errTargetsConfig
		}
		dns[name] = true
		if frontend != nil && (t.CertFile != frontend.CertFile || t.KeyFile != frontend.KeyFile || t.requiredCertificateNames != frontend.requiredCertificateNames) {
			return errTargetsConfig
		}
		copy := t
		frontend = &copy
		if version == 3 {
			found := false
			for _, required := range t.requiredCertificateNames {
				found = found || required == name
			}
			if !found {
				return errTargetsConfig
			}
		}
		for _, alias := range t.dnsAliases {
			if alias == "" {
				continue
			}
			if !validDNSName(alias) || dns[alias] {
				return errTargetsConfig
			}
			found := false
			for _, required := range t.requiredCertificateNames {
				found = found || required == alias
			}
			if !found {
				return errTargetsConfig
			}
			dns[alias] = true
		}
	}
	return nil
}

func isHTTPExtension(key string) bool {
	for _, field := range []string{"backendServerName", "backendCAFile", "requestTimeout", "backendRequestTimeout"} {
		// Match encoding/json's Unicode case folding, including the long s and Kelvin sign.
		if strings.EqualFold(key, field) {
			return true
		}
	}
	return false
}

// Match envelope keys exactly and reject duplicates. Target record fields retain their existing
// decoding behavior for L4 compatibility. v1/v2 reject the new certificate policy field outright.
func versionedTargets(b []byte) (json.RawMessage, int, [maxAgentTargets + 1]string, error) {
	var required [maxAgentTargets + 1]string
	invalid := func() (json.RawMessage, int, [maxAgentTargets + 1]string, error) {
		return nil, 0, [maxAgentTargets + 1]string{}, errTargetsConfig
	}
	d := json.NewDecoder(bytes.NewReader(b))
	if token, err := d.Token(); err != nil || token != json.Delim('{') {
		return invalid()
	}
	fields := make(map[string]json.RawMessage, 3)
	for d.More() {
		token, err := d.Token()
		key, ok := token.(string)
		if err != nil || !ok || (key != "version" && key != "targets" && key != "certificateDNSNames") || fields[key] != nil {
			return invalid()
		}
		var value json.RawMessage
		if err := d.Decode(&value); err != nil {
			return invalid()
		}
		fields[key] = value
	}
	if token, err := d.Token(); err != nil || token != json.Delim('}') {
		return invalid()
	}
	if err := d.Decode(new(json.RawMessage)); err != io.EOF {
		return invalid()
	}
	var version int
	if json.Unmarshal(fields["version"], &version) != nil || version < 1 || version > 3 {
		return invalid()
	}
	if version < 3 {
		if len(fields) != 2 || fields["certificateDNSNames"] != nil {
			return invalid()
		}
	} else {
		var names []string
		if len(fields) != 3 || json.Unmarshal(fields["certificateDNSNames"], &names) != nil || names == nil || len(names) > len(required) {
			return invalid()
		}
		seen := make(map[string]bool, len(names))
		for i, name := range names {
			if !validDNSName(name) {
				return invalid()
			}
			name = strings.ToLower(name)
			if seen[name] {
				return invalid()
			}
			seen[name], names[i] = true, name
		}
		// Preserve the base first; canonicalize all additional names for stable equality.
		if len(names) > 1 {
			sort.Strings(names[1:])
		}
		copy(required[:], names)
	}
	return fields["targets"], version, required, nil
}

// A shared HTTP listener is one reconciliation unit, but each target keeps its own generation.
// Membership/static changes retire the whole group. Reordering alone never restarts it.
func diffTargets(running map[string]target, desired []target) (start []target, stop []string) {
	want := make(map[string]target, len(desired))
	for _, t := range desired {
		want[t.Name] = t
	}
	httpChanged := false
	for name, r := range running {
		if w, ok := want[name]; !ok || w != r {
			httpChanged = httpChanged || r.Mode == "http" || w.Mode == "http"
		}
	}
	for _, w := range desired {
		if r, ok := running[w.Name]; !ok || r != w {
			httpChanged = httpChanged || w.Mode == "http" || r.Mode == "http"
		}
	}
	for name, r := range running {
		if w, ok := want[name]; !ok || w != r || (httpChanged && r.Mode == "http") {
			stop = append(stop, name)
		}
	}
	for _, w := range desired {
		if r, ok := running[w.Name]; !ok || r != w || (httpChanged && w.Mode == "http") {
			start = append(start, w)
		}
	}
	return start, stop
}
