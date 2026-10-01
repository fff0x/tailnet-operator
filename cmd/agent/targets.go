package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"os"
)

// target is one forwarded host. The operator writes these into the mounted ConfigMap; the agent
// never invents them. Address+Port is the upstream at the far site; ListenPort is the local port the
// agent binds and the Service forwards to.
type target struct {
	Name       string `json:"name"`
	Address    string `json:"address"`
	Port       int    `json:"port"`
	ListenPort int    `json:"listenPort"`
	Mode       string `json:"mode,omitempty"`
	ConfigID   string `json:"configID,omitempty"`
	DNSName    string `json:"dnsName,omitempty"`
	CertFile   string `json:"certFile,omitempty"`
	KeyFile    string `json:"keyFile,omitempty"`
}

const maxAgentTargets = 50 // matches both CR admission limits and the bounded probe budget

var errTargetsConfig = errors.New("invalid targets configuration")

// loadTargets preserves legacy arrays for L4 only. HTTP requires the versioned object protocol:
// legacy agents decode []target and must reject it rather than ignore HTTP fields and serve L4.
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
	versioned := b[0] == '{'
	if versioned {
		b, err = versionedTargets(b)
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
	for _, t := range ts {
		if t.Name == "" || t.Address == "" || t.Port == 0 || t.ListenPort == 0 || (!versioned && t.Mode == "http") {
			return nil, errTargetsConfig
		}
		if err := t.validateHTTP(); err != nil {
			return nil, errTargetsConfig
		}
	}
	return ts, nil
}

// Match envelope keys exactly and reject duplicates; struct decoding would accept alternate
// casing, and map unmarshalling would silently accept the last duplicate. Target record fields
// retain their existing decoding behavior for L4 compatibility.
func versionedTargets(b []byte) (json.RawMessage, error) {
	d := json.NewDecoder(bytes.NewReader(b))
	if token, err := d.Token(); err != nil || token != json.Delim('{') {
		return nil, errTargetsConfig
	}
	fields := make(map[string]json.RawMessage, 2)
	for d.More() {
		token, err := d.Token()
		key, ok := token.(string)
		if err != nil || !ok || (key != "version" && key != "targets") || fields[key] != nil {
			return nil, errTargetsConfig
		}
		var value json.RawMessage
		if err := d.Decode(&value); err != nil {
			return nil, errTargetsConfig
		}
		fields[key] = value
	}
	if token, err := d.Token(); err != nil || token != json.Delim('}') {
		return nil, errTargetsConfig
	}
	if err := d.Decode(new(json.RawMessage)); err != io.EOF {
		return nil, errTargetsConfig
	}
	var version int
	if len(fields) != 2 || json.Unmarshal(fields["version"], &version) != nil || version != 1 {
		return nil, errTargetsConfig
	}
	return fields["targets"], nil
}

// diffTargets compares the running set (keyed by name) against the desired list and returns which
// targets to start and which names to stop. A changed target (same name, different address, port or
// listen port) appears in both: stop the old listener, start the new one. Unchanged targets appear
// in neither. Pure, so the reconcile-on-change logic is unit-tested without binding a socket.
func diffTargets(running map[string]target, desired []target) (start []target, stop []string) {
	want := make(map[string]target, len(desired))
	for _, t := range desired {
		want[t.Name] = t
	}
	for name, r := range running {
		if w, ok := want[name]; !ok || w != r {
			stop = append(stop, name)
		}
	}
	for _, w := range desired {
		if r, ok := running[w.Name]; !ok || r != w {
			start = append(start, w)
		}
	}
	return start, stop
}
