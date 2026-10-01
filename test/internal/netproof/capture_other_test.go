//go:build !linux

package netproof

import (
	"context"
	"testing"
)

func TestUnsupportedDoesNotCaptureOrDial(t *testing.T) {
	if _, err := Capture(context.Background()); err != ErrUnsupported {
		t.Fatal("unsupported capture accepted")
	}
	if d := CheckExternal(context.Background()); d.IPv4 != OtherFailure || d.IPv6 != OtherFailure {
		t.Fatal("unsupported dial accepted")
	}
}
