package main

import (
	"strings"
	"testing"
)

func TestParseAgentScrapePeers(t *testing.T) {
	for _, raw := range []string{"", "  ", "[]"} {
		if got, err := parseAgentScrapePeers(raw); err != nil || len(got) != 0 {
			t.Fatalf("%q: %v %v", raw, got, err)
		}
	}
	got, err := parseAgentScrapePeers(`[{"namespaceSelector":{"matchLabels":{"a":"b"}},"podSelector":{"matchLabels":{"c":"d"}}}]`)
	if err != nil || len(got) != 1 || got[0].NamespaceSelector == nil || got[0].PodSelector == nil {
		t.Fatalf("%v %v", got, err)
	}
	for _, raw := range []string{`{}`, `[{}]`, `[{"bogus":1}]`, `[{"podSelector":{}}] x`, `null`, `[null]`, `secret-sentinel`} {
		_, err := parseAgentScrapePeers(raw)
		if err == nil || strings.Contains(err.Error(), "sentinel") {
			t.Fatalf("%q accepted or echoed: %v", raw, err)
		}
	}
}
