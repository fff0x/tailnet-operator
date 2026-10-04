package kernelcheck

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"
)

func TestSnapshotAndPrerequisites(t *testing.T) {
	node := Snapshot{Version: 1, Scope: "node", UID: 65534, TUN: "tun", IPv4Forwarding: "disabled", IPv6Forwarding: "unreadable"}
	pod := Snapshot{Version: 1, Scope: "pod", UID: 65532, TUN: "absent", IPv4Forwarding: "enabled", IPv6Forwarding: "disabled"}
	if !IPv4Prerequisites(node, pod) {
		t.Fatal("necessary IPv4 conditions rejected")
	}
	for _, s := range []Snapshot{node, pod} {
		b, _ := json.Marshal(s)
		got, err := Decode(b)
		if err != nil || got != s {
			t.Fatal("snapshot roundtrip failed")
		}
	}
	if IPv4Prerequisites(pod, node) {
		t.Fatal("reversed scopes accepted")
	}
	for _, v := range []string{"absent", "other", "unreadable", "private value"} {
		n := node
		n.TUN = v
		if IPv4Prerequisites(n, pod) {
			t.Fatal("node without verified TUN accepted")
		}
	}
	for _, v := range []string{"disabled", "invalid", "unreadable", "private value"} {
		p := pod
		p.IPv4Forwarding = v
		if IPv4Prerequisites(node, p) {
			t.Fatal("pod forwarding not enforced")
		}
	}
	for _, mutate := range []func(*Snapshot){func(s *Snapshot) { s.UID = 0 }, func(s *Snapshot) { s.Version = 2 }, func(s *Snapshot) { s.Scope = "host" }, func(s *Snapshot) { s.IPv6Forwarding = "" }} {
		s := node
		mutate(&s)
		if s.Valid() || IPv4Prerequisites(s, pod) {
			t.Fatal("invalid snapshot accepted")
		}
	}
}

func TestDecodeRejectsMalformed(t *testing.T) {
	good := `{"version":1,"scope":"pod","uid":65532,"tun":"absent","ipv4Forwarding":"enabled","ipv6Forwarding":"disabled"}`
	for _, raw := range []string{
		"", "[]", "null", "{}", good + good, good[:len(good)-1], strings.Repeat(" ", MaxJSON) + good,
		strings.Replace(good, `"version":1`, `"version":1,"version":1`, 1),
		strings.Replace(good, `"version":1`, `"version":null`, 1),
		strings.Replace(good, `"uid":65532`, `"uid":null`, 1),
		strings.Replace(good, `"uid":65532`, `"uid":65534`, 1),
		strings.Replace(good, `"scope":"pod"`, `"scope":null`, 1),
		strings.Replace(good, `"tun":"absent"`, `"tun":null`, 1),
		strings.Replace(good, `"ipv4Forwarding":"enabled"`, `"ipv4Forwarding":null`, 1),
		strings.Replace(good, `"ipv6Forwarding":"disabled"`, `"ipv6Forwarding":null`, 1),
		strings.Replace(good, `"tun":"absent",`, ``, 1),
		strings.Replace(good, `"tun":"absent"`, `"tun":"other","private":"value"`, 1),
	} {
		if s, err := Decode([]byte(raw)); !errors.Is(err, ErrSnapshot) || s != (Snapshot{}) {
			t.Fatal("malformed observation accepted")
		}
	}
}

func TestForwardingRedaction(t *testing.T) {
	for _, tc := range []struct{ raw, want string }{
		{"1\n", "enabled"}, {"0\n", "disabled"}, {"1", "enabled"}, {"", "invalid"},
		{" 1\n", "invalid"}, {"private value", "invalid"}, {"1" + strings.Repeat("\n", 16), "invalid"},
	} {
		if forwarding([]byte(tc.raw), nil) != tc.want {
			t.Fatal("wrong bounded forwarding classification")
		}
	}
	if forwarding([]byte("private value"), errors.New("private failure")) != "unreadable" {
		t.Fatal("raw error was not redacted")
	}
}
