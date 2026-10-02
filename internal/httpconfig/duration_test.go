package httpconfig

import (
	"testing"
	"time"
)

func TestParseDuration(t *testing.T) {
	for value, want := range map[string]time.Duration{
		"0s": 0, "600s": 10 * time.Minute, "1h2m3s4ms": time.Hour + 2*time.Minute + 3*time.Second + 4*time.Millisecond,
		"99999h": 99999 * time.Hour, "00000ms": 0,
	} {
		got, err := ParseDuration(value)
		if err != nil || got != want {
			t.Errorf("ParseDuration(%q) = %v, %v; want %v", value, got, err, want)
		}
	}
	for _, value := range []string{"", "0", "-1s", "+1s", "1.5s", "1us", "1ns", "1d", "100000s", "1s1s1s1s1s", " 30s", "NaN", "9999999999999999999h"} {
		if _, err := ParseDuration(value); err == nil {
			t.Errorf("accepted invalid duration %q", value)
		}
	}
}
