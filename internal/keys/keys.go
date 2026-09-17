// Package keys holds the pure rotation decision shared by the API key and the pre-auth key. Kept
// separate and side-effect-free so the "renew at half-life, never let it lapse" rule is unit-tested
// once, not reimplemented per caller.
package keys

import "time"

// State is where a credential sits in its life.
type State int

const (
	// OK: valid and not yet at half-life. Do nothing.
	OK State = iota
	// Due: past half-life but still valid. Mint a replacement, verify it, then expire the old one.
	Due
	// Expired: gone (or never existed). Mint fresh; there is no working old key to expire.
	Expired
)

func (s State) String() string {
	switch s {
	case OK:
		return "OK"
	case Due:
		return "Due"
	case Expired:
		return "Expired"
	default:
		return "Unknown"
	}
}

// Evaluate classifies a credential from its expiry and configured lifetime. A zero expiry means no
// key exists yet, which is Expired: the caller must mint. Renewal fires at half-life so a rotation
// has the second half of the lifetime to succeed before anything lapses — that headroom is what lets
// the controller verify the new key before expiring the old one without ever risking a gap.
func Evaluate(expires time.Time, lifetime time.Duration, now time.Time) State {
	if expires.IsZero() || !now.Before(expires) {
		return Expired
	}
	renewAt := expires.Add(-lifetime / 2)
	if !now.Before(renewAt) {
		return Due
	}
	return OK
}
