//go:build e2e_kind && !linux

package e2ekind

import (
	"strings"
	"testing"
)

func TestCommandLifecycleUnsupported(t *testing.T) {
	out, err := (&fixture{work: t.TempDir()}).command(t.Context(), "", "/does-not-exist")
	if err == nil || !strings.Contains(err.Error(), "requires Linux") || len(out) != 0 {
		t.Fatal("unsupported OS did not fail closed before running the command")
	}
}
