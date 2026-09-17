package main

import (
	"encoding/json"
	"fmt"
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
}

// loadTargets reads and validates the target list from the mounted config file.
func loadTargets(path string) ([]target, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var ts []target
	if err := json.Unmarshal(b, &ts); err != nil {
		return nil, fmt.Errorf("parse %s: %w", path, err)
	}
	for _, t := range ts {
		if t.Name == "" || t.Address == "" || t.Port == 0 || t.ListenPort == 0 {
			return nil, fmt.Errorf("incomplete target %+v", t)
		}
	}
	return ts, nil
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
