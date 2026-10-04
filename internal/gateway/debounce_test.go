package gateway

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"
)

func debouncePlan(t *testing.T, targets ...string) RoutePlan {
	t.Helper()
	plan, err := PlanRoutes(RouteInputs{LAN: []string{"10.0.0.0/8"}, LoadBalancerCIDR: "192.0.2.0/24", AdvertiseEgressTargets: true, EgressTargets: targets})
	if err != nil {
		t.Fatal(err)
	}
	return plan
}

func debounceDecision(t *testing.T, state State, plan RoutePlan, now time.Time) Decision {
	t.Helper()
	d, err := PlanDebounce(state, plan, now)
	if err != nil {
		t.Fatal(err)
	}
	return d
}

func TestDebounceBoundaryAndAcknowledgement(t *testing.T) {
	t0 := time.Date(2026, 7, 1, 12, 0, 0, 123456789, time.UTC)
	plan := debouncePlan(t)
	initial := debounceDecision(t, State{}, plan, t0)
	if initial.Apply || initial.RequeueAfter != 30*time.Second || initial.Next.AppliedHash != "" || initial.Next.PendingHash != initial.DesiredHash {
		t.Fatalf("initial = %+v", initial)
	}
	for _, elapsed := range []time.Duration{0, time.Second, 29 * time.Second, 30*time.Second - time.Nanosecond, 30 * time.Second, 31 * time.Second} {
		d := debounceDecision(t, initial.Next, plan, t0.Add(elapsed))
		wantWait := max(time.Duration(0), QuietInterval-elapsed)
		if d.Apply != (elapsed >= QuietInterval) || d.RequeueAfter != wantWait || d.Next != initial.Next {
			t.Fatalf("elapsed=%v: %+v", elapsed, d)
		}
	}
	// Simulate a failed resource write by deliberately NOT calling MarkApplied.
	failed := debounceDecision(t, initial.Next, plan, t0.Add(30*time.Second))
	retry := debounceDecision(t, failed.Next, plan, t0.Add(35*time.Second))
	if !retry.Apply || retry.Next.AppliedHash != "" || retry.Next != initial.Next {
		t.Fatalf("failed write incorrectly acknowledged or delayed: %+v", retry)
	}
	applied, err := MarkApplied(retry.Next, retry.DesiredHash)
	if err != nil || applied.AppliedHash != retry.DesiredHash || applied.PendingHash != "" || applied.PendingSince != "" {
		t.Fatalf("acknowledgement = %+v, %v", applied, err)
	}
	if retry.Next != initial.Next {
		t.Fatal("MarkApplied mutated input state")
	}
	done := debounceDecision(t, applied, plan, t0.Add(36*time.Second))
	if done.Apply || done.RequeueAfter != 0 || done.Next != applied {
		t.Fatalf("already applied = %+v", done)
	}
}

func TestDebounceChangesResetAndRevertCancels(t *testing.T) {
	t0 := time.Date(2026, 7, 1, 12, 0, 0, 0, time.UTC)
	a, b, c := debouncePlan(t), debouncePlan(t, "10.0.0.1"), debouncePlan(t, "10.0.0.2")
	hashA, _ := RouteHash(a)
	baseline, err := MarkApplied(State{}, hashA) // Caller already checked identical adoption template.
	if err != nil {
		t.Fatal(err)
	}
	pendingB := debounceDecision(t, baseline, b, t0)
	pendingC := debounceDecision(t, pendingB.Next, c, t0.Add(29*time.Second))
	if pendingC.Apply || pendingC.RequeueAfter != QuietInterval || pendingC.Next.PendingHash == pendingB.Next.PendingHash || pendingC.Next.PendingSince == pendingB.Next.PendingSince {
		t.Fatalf("change did not restart: %+v", pendingC)
	}
	backToB := debounceDecision(t, pendingC.Next, b, t0.Add(30*time.Second))
	if backToB.Apply || backToB.RequeueAfter != QuietInterval || backToB.Next.PendingSince == pendingB.Next.PendingSince {
		t.Fatalf("return to formerly pending routes did not restart: %+v", backToB)
	}
	reverted := debounceDecision(t, backToB.Next, a, t0.Add(31*time.Second))
	if reverted.Apply || reverted.RequeueAfter != 0 || reverted.Next != baseline {
		t.Fatalf("revert = %+v, want baseline %+v", reverted, baseline)
	}
	// An old successful write may be acknowledged without deleting newer pending work.
	ack, err := MarkApplied(pendingC.Next, pendingB.DesiredHash)
	if err != nil || ack.AppliedHash != pendingB.DesiredHash || ack.PendingHash != pendingC.Next.PendingHash || ack.PendingSince != pendingC.Next.PendingSince {
		t.Fatalf("ack of earlier write lost pending state: %+v, %v", ack, err)
	}
}

func TestDebounceJSONRoundTrip(t *testing.T) {
	t0 := time.Date(2026, 7, 1, 12, 0, 0, 123456789, time.FixedZone("caller", 7200))
	plan := debouncePlan(t, "fd12::1")
	initial := debounceDecision(t, State{}, plan, t0)
	encoded, err := json.Marshal(initial.Next)
	if err != nil {
		t.Fatal(err)
	}
	var restored State
	if err := json.Unmarshal(encoded, &restored); err != nil {
		t.Fatal(err)
	}
	if restored != initial.Next || restored.PendingSince != "2026-07-01T10:00:00.123456789Z" {
		t.Fatalf("restored = %+v", restored)
	}
	// The next leader/process needs only status and a caller-supplied wall time.
	before := debounceDecision(t, restored, plan, t0.Add(29*time.Second))
	at := debounceDecision(t, restored, plan, t0.Add(30*time.Second))
	if before.Apply || before.RequeueAfter != time.Second || !at.Apply || at.Next.AppliedHash != "" {
		t.Fatalf("restored timer: before=%+v, at=%+v", before, at)
	}
}

func TestDebounceInvalidStateRestarts(t *testing.T) {
	now := time.Date(2026, 7, 1, 12, 0, 0, 0, time.UTC)
	plan := debouncePlan(t)
	hash, _ := RouteHash(plan)
	old := now.Add(-time.Hour).Format(time.RFC3339Nano)
	cases := []State{
		{},
		{PendingHash: hash},
		{PendingHash: hash, PendingSince: "sensitive-value"},
		{PendingHash: hash, PendingSince: "0001-01-01T00:00:00Z"},
		{PendingHash: hash, PendingSince: "2026-02-30T00:00:00Z"},
		{PendingHash: hash, PendingSince: now.Add(time.Nanosecond).Format(time.RFC3339Nano)},
		{PendingHash: hash, PendingSince: "2026-07-01T10:00:00+00:00"}, // Noncanonical UTC spelling.
		{PendingHash: hash, PendingSince: "2026-07-01T10:00:00.000Z"},
		{PendingHash: "bad-hash", PendingSince: old},
		{PendingSince: old},
		{AppliedHash: "bad-hash", PendingHash: hash, PendingSince: old},
		{AppliedHash: strings.Repeat("F", 64), PendingHash: hash, PendingSince: old},
	}
	for i, state := range cases {
		d := debounceDecision(t, state, plan, now)
		if d.Apply || d.RequeueAfter != QuietInterval || d.Next.PendingHash != hash || d.Next.PendingSince != now.Format(time.RFC3339Nano) || d.Next.AppliedHash != "" {
			t.Errorf("case %d did not restart safely: %+v", i, d)
		}
	}
	// Corrupt pending data cannot force a write of routes already applied.
	state := State{AppliedHash: hash, PendingHash: "bad", PendingSince: "bad"}
	d := debounceDecision(t, state, plan, now)
	if d.Apply || d.RequeueAfter != 0 || d.Next != (State{AppliedHash: hash}) {
		t.Fatalf("corrupt pending data on already-applied routes: %+v", d)
	}
}

func TestDebounceInvalidTimeAndPlanNoAcknowledgement(t *testing.T) {
	plan := debouncePlan(t)
	state := State{AppliedHash: strings.Repeat("a", 64), PendingHash: strings.Repeat("b", 64), PendingSince: "2026-07-01T10:00:00Z"}
	for _, now := range []time.Time{
		{}, time.Date(0, 1, 1, 0, 0, 0, 0, time.UTC), time.Date(10000, 1, 1, 0, 0, 0, 0, time.UTC),
		time.Date(9999, 12, 31, 23, 59, 59, 0, time.FixedZone("west", -3600)),
	} {
		d, err := PlanDebounce(state, plan, now)
		if !errors.Is(err, ErrInvalidTime) || d != (Decision{Next: state}) {
			t.Fatalf("invalid time: %+v, %v", d, err)
		}
	}
	d, err := PlanDebounce(state, RoutePlan{Routes: []string{"sensitive-value"}}, time.Date(2026, 7, 1, 12, 0, 0, 0, time.UTC))
	if !errors.Is(err, ErrInvalidRoutes) || d != (Decision{Next: state}) || strings.Contains(err.Error(), "sensitive-value") {
		t.Fatalf("invalid plan: %+v, %v", d, err)
	}
	for _, hash := range []string{"", "sensitive-value", strings.Repeat("F", 64), strings.Repeat("a", 63), strings.Repeat("g", 64)} {
		got, err := MarkApplied(state, hash)
		if !errors.Is(err, ErrInvalidHash) || got != state {
			t.Fatalf("invalid acknowledgement: %+v, %v", got, err)
		}
	}
}

func TestRouteHashCanonicalAndDNSIndependent(t *testing.T) {
	a := debouncePlan(t, "192.0.2.2", "::ffff:192.0.2.2", "z.example", "fd12::1")
	b := debouncePlan(t, "fd12::1", "192.0.2.2", "a.example")
	before, _ := json.Marshal(a)
	ha, err := RouteHash(a)
	if err != nil {
		t.Fatal(err)
	}
	hb, err := RouteHash(b)
	if err != nil || ha != hb {
		t.Fatalf("canonical routes hash differently: %s %s %v", ha, hb, err)
	}
	digest := sha256.Sum256([]byte("10.0.0.0/8\n192.0.2.0/24\n192.0.2.2/32\nfd12::1/128\n"))
	if ha != hex.EncodeToString(digest[:]) {
		t.Fatal("hash encoding changed")
	}
	after, _ := json.Marshal(a)
	if !reflect.DeepEqual(before, after) {
		t.Fatal("hashing mutated input")
	}
	for _, routes := range [][]string{nil, {}, {"secret"}, {"10.0.0.1/8"}, {"0.0.0.0/0"}, {"10.0.0.0/8", "10.0.0.0/8"}, {"192.0.2.0/24", "10.0.0.0/8"}} {
		if hash, err := RouteHash(RoutePlan{Routes: routes}); !errors.Is(err, ErrInvalidRoutes) || hash != "" {
			t.Fatalf("invalid routes hash = %q, %v", hash, err)
		}
	}
	// DNS-only changes must not restart a pending route update.
	now := time.Date(2026, 7, 1, 12, 0, 0, 0, time.UTC)
	first := debounceDecision(t, State{}, a, now)
	next := debounceDecision(t, first.Next, b, now.Add(29*time.Second))
	if next.Next != first.Next || next.RequeueAfter != time.Second {
		t.Fatalf("DNS-only change restarted quiet period: %+v", next)
	}
}
