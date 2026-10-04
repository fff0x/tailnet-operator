package gateway

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net/netip"
	"strings"
	"time"
)

// QuietInterval is the full period during which desired routes must not change,
// including the first installation. Time is always supplied by the caller.
const QuietInterval = 30 * time.Second

// State is a serializable value, not a live timer. Persist it in gateway status
// before requeueing, and restore it on every reconciliation, including after a
// leader change. Hashes are lowercase SHA256 hex. PendingSince is UTC RFC3339Nano;
// a string deliberately allows malformed persisted timestamps to be repaired.
// The zero State starts an initial quiet period. For adoption, establish an
// applied baseline via MarkApplied only after verifying an identical template.
type State struct {
	AppliedHash  string `json:"appliedHash,omitempty"`
	PendingHash  string `json:"pendingHash,omitempty"`
	PendingSince string `json:"pendingSince,omitempty"`
}

// Decision is a value returned by PlanDebounce. Persist Next, then requeue for
// RequeueAfter when Apply is false and RequeueAfter is positive. When Apply is
// true, Next STILL contains pending state: write the desired resource first,
// then call MarkApplied(Next, DesiredHash) and persist that acknowledged state.
// On write failure, keep Next and use the caller's error/backoff retry mechanism;
// the unchanged desired routes remain eligible without another quiet period.
// RequeueAfter is zero for eligible writes or when already applied.
type Decision struct {
	Next         State
	DesiredHash  string
	Apply        bool
	RequeueAfter time.Duration
}

var (
	// ErrInvalidTime means the caller's time is zero or outside JSON's RFC3339
	// year range. No decision may be applied or persisted on this error.
	ErrInvalidTime = errors.New("invalid gateway planner time")
	// ErrInvalidHash means MarkApplied received a noncanonical SHA256 digest.
	ErrInvalidHash = errors.New("invalid gateway route hash")
)

// RouteHash hashes the Routes of a successful PlanRoutes result. It validates
// that the list is nonempty, canonical, strictly sorted and deduplicated; it does
// not recheck the original mandatory LAN/LB fields. SkippedDNS is ignored because
// DNS targets do not change advertised routes. The digest is SHA256 of each route
// followed by a newline, encoded as lowercase hex. Inputs are never modified.
func RouteHash(plan RoutePlan) (string, error) {
	if len(plan.Routes) == 0 {
		return "", fmt.Errorf("%w: Routes", ErrInvalidRoutes)
	}
	h := sha256.New()
	var previous netip.Prefix
	for i, value := range plan.Routes {
		p, ok := routePrefix(value)
		if !ok || i > 0 && comparePrefixes(previous, p) >= 0 {
			return "", fmt.Errorf("%w: Routes[%d]", ErrInvalidRoutes, i)
		}
		h.Write([]byte(value))
		h.Write([]byte{'\n'})
		previous = p
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// PlanDebounce evaluates a quiet-period transition without clocks, goroutines,
// writes or mutation. A changed desired hash restarts the full quiet interval;
// repeated observations do not postpone it. Reverting to AppliedHash cancels
// pending work. At exactly QuietInterval the change becomes eligible, but NEVER
// acknowledged: only MarkApplied records a successful write.
//
// Malformed hashes, missing/noncanonical/future pending timestamps or inconsistent
// pending state restart the interval (unless desired is already applied, in which
// case pending is simply cleared). A malformed applied hash is discarded. Future
// timestamps thus fail safe on clock rollback; elapsed time is computed using
// persisted wall time, not a process-local monotonic clock. Callers must provide
// a trustworthy clock; an undetectable forward clock jump can shorten the wait.
//
// Errors redact inputs and return Next equal to the original state, with Apply
// false. Do not persist or act on an error decision. Reconciliations and resource
// writes for one gateway must be serialized by the caller; this is not a lock.
func PlanDebounce(state State, desired RoutePlan, now time.Time) (Decision, error) {
	hash, err := RouteHash(desired)
	if err != nil {
		return Decision{Next: state}, err
	}
	now = now.UTC().Round(0)
	if now.IsZero() || now.Year() < 1 || now.Year() > 9999 {
		return Decision{Next: state}, ErrInvalidTime
	}
	next := state
	corruptApplied := next.AppliedHash != "" && !validHash(next.AppliedHash)
	if corruptApplied {
		next.AppliedHash = ""
	}
	if next.AppliedHash == hash {
		next.PendingHash, next.PendingSince = "", ""
		return Decision{Next: next, DesiredHash: hash}, nil
	}
	since, parseErr := time.Parse(time.RFC3339Nano, next.PendingSince)
	if corruptApplied || next.PendingHash != hash || parseErr != nil || since.IsZero() ||
		since.After(now) || since.UTC().Format(time.RFC3339Nano) != next.PendingSince {
		next.PendingHash = hash
		next.PendingSince = now.Format(time.RFC3339Nano)
		return Decision{Next: next, DesiredHash: hash, RequeueAfter: QuietInterval}, nil
	}
	remaining := QuietInterval - now.Sub(since)
	if remaining > 0 {
		return Decision{Next: next, DesiredHash: hash, RequeueAfter: remaining}, nil
	}
	return Decision{Next: next, DesiredHash: hash, Apply: true}, nil
}

// MarkApplied acknowledges a hash ONLY after a successful resource write, or an
// identical-template adoption check. Pass the hash of the routes actually written
// (Decision.DesiredHash), not a freshly computed hash of potentially newer desired
// routes. Matching pending work is cleared; different, newer pending work is
// preserved. On invalid hash the original state and ErrInvalidHash are returned.
// This function cannot verify write success, and never performs a write itself.
func MarkApplied(state State, appliedHash string) (State, error) {
	if !validHash(appliedHash) {
		return state, ErrInvalidHash
	}
	state.AppliedHash = appliedHash
	if state.PendingHash == appliedHash {
		state.PendingHash, state.PendingSince = "", ""
	}
	return state, nil
}

func validHash(value string) bool {
	return len(value) == sha256.Size*2 && strings.Trim(value, "0123456789abcdef") == ""
}
