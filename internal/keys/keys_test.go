package keys

import (
	"testing"
	"time"
)

func TestEvaluate(t *testing.T) {
	now := time.Date(2026, 9, 17, 12, 0, 0, 0, time.UTC)
	lifetime := 720 * time.Hour // 30 days

	cases := []struct {
		name    string
		expires time.Time
		want    State
	}{
		{"fresh: full lifetime ahead", now.Add(lifetime), OK},
		{"just past half-life", now.Add(lifetime/2 - time.Hour), Due},
		{"exactly at half-life", now.Add(lifetime / 2), Due},
		{"one second before half-life", now.Add(lifetime/2 + time.Second), OK},
		{"expired in the past", now.Add(-time.Hour), Expired},
		{"expires exactly now", now, Expired},
		{"zero value: no key yet", time.Time{}, Expired},
	}
	for _, c := range cases {
		if got := Evaluate(c.expires, lifetime, now); got != c.want {
			t.Errorf("%s: got %v want %v", c.name, got, c.want)
		}
	}
}

// The "failure in the middle" of a swap is a controller invariant: verify the new key before
// expiring the old. Expressed purely: while the old key is still valid (Due, not Expired), a failed
// verification must leave it usable — Evaluate keeps returning Due, never forcing a gap.
func TestDueLeavesOldKeyUsable(t *testing.T) {
	now := time.Date(2026, 9, 17, 12, 0, 0, 0, time.UTC)
	lifetime := 168 * time.Hour
	expires := now.Add(lifetime/2 - time.Hour) // past half-life, still ~83h of validity
	if got := Evaluate(expires, lifetime, now); got != Due {
		t.Fatalf("got %v want Due", got)
	}
	// A rotation attempt that fails does not touch expiry; the key is still valid next tick.
	if got := Evaluate(expires, lifetime, now.Add(time.Minute)); got != Due {
		t.Fatalf("after failed rotation: got %v want Due (must not be Expired)", got)
	}
}
