package main

import "testing"

// Unset must be an error, not a default: an ingress that lost the variable would otherwise come
// up dialling out as an egress. Spelling is exact because the Deployments write it exactly.
func TestParseMode(t *testing.T) {
	for raw, want := range map[string]string{"egress": "egress", "ingress": "ingress"} {
		if got, err := parseMode(raw); err != nil || got != want {
			t.Fatalf("%q: got %q, %v", raw, got, err)
		}
	}
	for _, raw := range []string{"", "Egress", "both", " egress", "egress\n"} {
		if got, err := parseMode(raw); err == nil || got != "" {
			t.Fatalf("%q accepted as %q", raw, got)
		}
	}
}
