// Package kernelcheck records necessary kernel prerequisites without opening a
// TUN device, changing sysctls or claiming that a router can run. Callers must bind
// snapshots to their owned node/pod; self-reported scope is not ownership proof.
package kernelcheck

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"strings"
)

const MaxJSON = 2048

var ErrSnapshot = errors.New("kernel prerequisite snapshot rejected")

type Snapshot struct {
	Version        int    `json:"version"`
	Scope          string `json:"scope"`
	UID            int    `json:"uid"`
	TUN            string `json:"tun"`            // tun, absent, other, unreadable
	IPv4Forwarding string `json:"ipv4Forwarding"` // enabled, disabled, invalid, unreadable
	IPv6Forwarding string `json:"ipv6Forwarding"`
}

func (s Snapshot) Valid() bool {
	return s.Version == 1 && ((s.Scope == "node" && s.UID == 65534) || (s.Scope == "pod" && s.UID == 65532)) &&
		oneOf(s.TUN, "tun", "absent", "other", "unreadable") &&
		oneOf(s.IPv4Forwarding, "enabled", "disabled", "invalid", "unreadable") &&
		oneOf(s.IPv6Forwarding, "enabled", "disabled", "invalid", "unreadable")
}

func oneOf(value string, choices ...string) bool {
	for _, choice := range choices {
		if value == choice {
			return true
		}
	}
	return false
}

// IPv4Prerequisites only checks that the node can supply the modeled HostPath
// and IPv4 forwarding is already enabled in the sampled unprivileged pod netns.
// It proves neither mounting/ioctls nor capabilities, images, bootstrap or traffic.
func IPv4Prerequisites(node, pod Snapshot) bool {
	return node.Valid() && pod.Valid() && node.Scope == "node" && pod.Scope == "pod" && node.TUN == "tun" && pod.IPv4Forwarding == "enabled"
}

// Decode rejects omitted, duplicate, null, unknown, trailing and inconsistent data.
func Decode(raw []byte) (Snapshot, error) {
	var zero Snapshot
	if len(raw) == 0 || len(raw) > MaxJSON {
		return zero, ErrSnapshot
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	token, err := d.Token()
	if err != nil || token != json.Delim('{') {
		return zero, ErrSnapshot
	}
	fields := map[string]json.RawMessage{}
	for d.More() {
		token, err = d.Token()
		key, ok := token.(string)
		if err != nil || !ok || fields[key] != nil || !oneOf(key, "version", "scope", "uid", "tun", "ipv4Forwarding", "ipv6Forwarding") {
			return zero, ErrSnapshot
		}
		var value json.RawMessage
		if d.Decode(&value) != nil || string(value) == "null" {
			return zero, ErrSnapshot
		}
		fields[key] = value
	}
	if token, err = d.Token(); err != nil || token != json.Delim('}') || len(fields) != 6 {
		return zero, ErrSnapshot
	}
	var trailing any
	if d.Decode(&trailing) != io.EOF {
		return zero, ErrSnapshot
	}
	var s Snapshot
	if json.Unmarshal(raw, &s) != nil || !s.Valid() {
		return zero, ErrSnapshot
	}
	return s, nil
}

func forwarding(value []byte, err error) string {
	if err != nil {
		return "unreadable"
	}
	if len(value) > 16 {
		return "invalid"
	}
	// Match the shell preflight: command substitution removes trailing newlines,
	// not arbitrary whitespace. Never retain a raw value or an underlying error.
	switch strings.TrimRight(string(value), "\n") {
	case "1":
		return "enabled"
	case "0":
		return "disabled"
	default:
		return "invalid"
	}
}
