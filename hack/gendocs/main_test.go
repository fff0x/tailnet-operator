package main

import (
	"os"
	"strings"
	"testing"
)

// TestGoldenCRDReference fails when docs/reference/crds.md no longer matches the CRDs.
func TestGoldenCRDReference(t *testing.T) {
	want, err := os.ReadFile("../../docs/reference/crds.md")
	if err != nil {
		t.Fatalf("read golden: %v", err)
	}
	got, err := Render("../../deploy/crds")
	if err != nil {
		t.Fatal(err)
	}
	if string(want) != got {
		t.Fatal("docs/reference/crds.md is stale: run `task docs`")
	}
	for _, kind := range []string{"## Tailnet\n", "## TailnetEgress\n", "## TailnetIngress\n", "## TailnetSite\n", "## TailnetGateway\n"} {
		if !strings.Contains(got, kind) {
			t.Errorf("missing section %q", strings.TrimSpace(kind))
		}
	}
	// A nested required field must keep its path and requirement.
	if !strings.Contains(got, "| `tailnetRef.name` | string | yes |") {
		t.Error("nested required field tailnetRef.name not rendered")
	}
}
