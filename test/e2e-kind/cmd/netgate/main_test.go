//go:build linux

package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"
	"this-is-fine.io/tailnet-operator/test/internal/netproof"
)

const testUID = "7df84f6a-1fbc-4114-a0c8-713dbe3716bc"

var testTime = time.Unix(1700000000, 0)

func clock() time.Time { return testTime }
func fakeCapture(context.Context) (netproof.Snapshot, error) {
	return netproof.Snapshot{Version: 1, UID: 65532, Dials: netproof.Dials{IPv4: netproof.NetworkUnreachable, IPv6: netproof.NetworkUnreachable}}, nil
}
func newStore(t *testing.T) (*store, session, string) {
	t.Helper()
	base := t.TempDir()
	s, err := openStore(base)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(s.close)
	v, err := s.initialize(context.Background(), testUID)
	if err != nil {
		t.Fatal(err)
	}
	return s, v, base
}
func document(t *testing.T, s *store) []byte {
	t.Helper()
	var b bytes.Buffer
	if err := s.snapshot(context.Background(), testUID, clock, fakeCapture, &b); err != nil {
		t.Fatal(err)
	}
	return b.Bytes()
}
func approved(v session, b []byte) approval {
	h := sha256.Sum256(b)
	return approval{1, v.PodUID, v.Epoch, hex.EncodeToString(h[:]), testTime.Add(maxAge).UnixMilli()}
}
func encode(t *testing.T, v any) []byte {
	t.Helper()
	b, err := marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return b
}
func assertRejected(t *testing.T, err error) {
	t.Helper()
	if err != rejected {
		t.Fatalf("expected fixed rejection, got %v", err)
	}
}

func TestAuthorizationBeforeFilesOrCapture(t *testing.T) {
	cases := []struct {
		args []string
		uid  int
		pod  string
	}{
		{nil, 65532, testUID}, {[]string{"--action=hold"}, 65532, testUID},
		{[]string{"--action=snapshot", "--fixture=p1.8-http"}, 0, testUID},
		{[]string{"--action=snapshot", "--fixture=p1.8-http"}, 65532, ""},
		{[]string{"--action=snapshot", "--fixture=p1.8-http"}, 65532, "../bad"},
		{[]string{"--action=snapshot", "--fixture=p1.8-http"}, 65532, strings.Repeat("a", 129)},
		{[]string{"--action=snapshot", "--fixture=p1.8-http"}, 65532, "bad\nuid"},
		{[]string{"--action=other", "--fixture=p1.8-http"}, 65532, testUID},
		{[]string{"--action=snapshot", "--fixture=other"}, 65532, testUID},
		{[]string{"--fixture=p1.8-http", "--action=snapshot"}, 65532, testUID},
		{[]string{"--action=snapshot", "--fixture=p1.8-http", "--path=/tmp"}, 65532, testUID},
	}
	for _, tc := range cases {
		base := t.TempDir()
		var out bytes.Buffer
		err := run(context.Background(), tc.args, tc.uid, tc.pod, base, strings.NewReader(""), &out, func(context.Context) (netproof.Snapshot, error) {
			t.Fatal("unauthorized capture")
			return netproof.Snapshot{}, nil
		})
		assertRejected(t, err)
		entries, _ := os.ReadDir(base)
		if len(entries) != 0 || out.Len() != 0 {
			t.Fatal("unauthorized side effects")
		}
	}
	for _, action := range []string{"hold", "snapshot", "release"} {
		if got, err := authorized([]string{"--action=" + action, "--fixture=p1.8-http"}, 65532, testUID); err != nil || got != action {
			t.Fatal("valid authorization rejected")
		}
	}
}
func TestProtocolRoundTrip(t *testing.T) {
	s, v, base := newStore(t)
	b := document(t, s)
	stored, err := s.read("snapshot.json", maxDocument)
	if err != nil || !bytes.Equal(stored, b) {
		t.Fatal("stdout differs from exact stored bytes")
	}
	a := approved(v, b)
	if err := s.release(context.Background(), testUID, bytes.NewReader(encode(t, a)), clock); err != nil {
		t.Fatal(err)
	}
	if err := s.await(context.Background(), v, clock); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"session.json", "snapshot.json", "approval.json", "lock"} {
		st, err := os.Stat(filepath.Join(base, "state", name))
		if err != nil || st.Mode().Perm() != 0600 {
			t.Fatalf("unsafe %s", name)
		}
	}
	st, err := os.Stat(filepath.Join(base, "state"))
	if err != nil || st.Mode().Perm() != 0700 {
		t.Fatal("unsafe directory")
	}
}
func TestBindingHashFreshnessAndSchema(t *testing.T) {
	s, v, _ := newStore(t)
	raw := document(t, s)
	a := approved(v, raw)
	for _, age := range []time.Duration{0, 30 * time.Second} {
		if verify(v, a, raw, testTime.Add(age)) != nil {
			t.Fatal("fresh boundary rejected")
		}
	}
	for _, age := range []time.Duration{-time.Millisecond, 30*time.Second + time.Millisecond} {
		assertRejected(t, verify(v, a, raw, testTime.Add(age)))
	}
	for _, change := range []func(*approval){func(a *approval) { a.Version = 2 }, func(a *approval) { a.PodUID = "wrong" }, func(a *approval) { a.Epoch = strings.Repeat("b", 64) }, func(a *approval) { a.SnapshotSHA256 = strings.Repeat("0", 64) }, func(a *approval) { a.SnapshotSHA256 = strings.ToUpper(a.SnapshotSHA256) }} {
		bad := a
		change(&bad)
		assertRejected(t, verify(v, bad, raw, testTime))
	}
	assertRejected(t, verify(v, a, append(append([]byte{}, raw...), ' '), testTime))
	var d snapshotDocument
	if json.Unmarshal(raw, &d) != nil {
		t.Fatal("decode")
	}
	for _, change := range []func(*snapshotDocument){func(d *snapshotDocument) { d.Version = 2 }, func(d *snapshotDocument) { d.PodUID = "wrong" }, func(d *snapshotDocument) { d.Epoch = strings.Repeat("b", 64) }, func(d *snapshotDocument) { d.CapturedAtMillis = 0 }, func(d *snapshotDocument) { d.CapturedAtMillis = -1 }, func(d *snapshotDocument) { d.Snapshot.UID = 0 }, func(d *snapshotDocument) { d.Snapshot.Dials.IPv6 = netproof.AddressFamilyUnsupported }} {
		bad := d
		change(&bad)
		b := encode(t, bad)
		assertRejected(t, verify(v, approved(v, b), b, testTime))
	}
}
func TestHostProofDeadlineRejectsDelayedDispatch(t *testing.T) {
	s, v, _ := newStore(t)
	b := document(t, s)
	a := approved(v, b)
	// Host capture began two seconds before the Pod snapshot. Its 25s
	// deadline expires at snapshot+23s, even though the Pod is still fresh.
	raw := encode(t, a)
	var m map[string]any
	if json.Unmarshal(raw, &m) != nil {
		t.Fatal("fixture decode")
	}
	m["hostProofExpiresAtMillis"] = testTime.Add(23 * time.Second).UnixMilli()
	raw, _ = json.Marshal(m)
	if json.Unmarshal(raw, &a) != nil {
		t.Fatal("fixture decode")
	}
	assertRejected(t, verify(v, a, b, testTime.Add(26*time.Second)))
	if verify(v, a, b, testTime.Add(23*time.Second)) != nil {
		t.Fatal("valid deadline boundary rejected")
	}
	if err := s.release(context.Background(), testUID, bytes.NewReader(raw), clock); err != nil {
		t.Fatal("fresh host approval rejected")
	}
	assertRejected(t, s.await(context.Background(), v, func() time.Time { return testTime.Add(24 * time.Second) }))
	assertRejected(t, s.release(context.Background(), testUID, bytes.NewReader(raw), func() time.Time { return testTime.Add(24 * time.Second) }))
	delete(m, "hostProofExpiresAtMillis")
	missing, _ := json.Marshal(m)
	assertRejected(t, s.release(context.Background(), testUID, bytes.NewReader(missing), clock))
	for _, expires := range []int64{0, -1, testTime.Add(31 * time.Second).UnixMilli()} {
		a.HostProofExpiresAtMillis = expires
		assertRejected(t, verify(v, a, b, testTime))
	}
}

func TestStrictApprovalJSON(t *testing.T) {
	s, v, _ := newStore(t)
	raw := document(t, s)
	a := string(encode(t, approved(v, raw)))
	cases := []string{"", "null", "{}", "[]", a + "{}", strings.Repeat(" ", maxApproval+1), strings.Replace(a, `"version":1`, `"version":1,"version":1`, 1), strings.Replace(a, `"version":1`, `"Version":1`, 1), strings.Replace(a, `"version":1`, `"version":null`, 1), strings.Replace(a, `"version":1`, `"version":1,"unknown":0`, 1), strings.Replace(a, `"version":1`, `"version":"1"`, 1), a[:len(a)-3]}
	for i, b := range cases {
		t.Run(string(rune('a'+i)), func(t *testing.T) {
			assertRejected(t, s.release(context.Background(), testUID, strings.NewReader(b), clock))
		})
	}
	if _, err := s.read("approval.json", maxApproval); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("invalid approval published")
	}
}
func TestStrictSnapshotJSON(t *testing.T) {
	s, v, _ := newStore(t)
	raw := document(t, s)
	for _, b := range [][]byte{
		bytes.Replace(raw, []byte(`"dials":{`), []byte(`"dials":{"ipv4":"ENETUNREACH",`), 1),
		bytes.Replace(raw, []byte(`"snapshot":{`), []byte(`"snapshot":{"unknown":1,`), 1),
		append(append([]byte{}, raw...), []byte("{}")...),
		bytes.Repeat([]byte(" "), maxDocument+1),
	} {
		assertRejected(t, verify(v, approved(v, b), b, testTime))
	}
}
func TestCaptureFailureNeverPublishes(t *testing.T) {
	for _, category := range []netproof.DialCategory{netproof.Connected, netproof.Refused, netproof.TimedOut, netproof.OtherFailure, netproof.AddressFamilyUnsupported, ""} {
		for _, ipv6 := range []bool{false, true} {
			s, _, _ := newStore(t)
			var out bytes.Buffer
			collect := func(ctx context.Context) (netproof.Snapshot, error) {
				deadline, ok := ctx.Deadline()
				if !ok || time.Until(deadline) > maxCapture {
					t.Fatal("capture not bounded")
				}
				snap, _ := fakeCapture(ctx)
				if ipv6 {
					snap.Dials.IPv6 = category
				} else {
					snap.Dials.IPv4 = category
				}
				return snap, nil
			}
			if category == netproof.TimedOut && !ipv6 {
				// Policy-dropped ICMP: an IPv4 timeout is a valid Pod capture (netproof.PodDials).
				if s.snapshot(context.Background(), testUID, clock, collect, &out) != nil {
					t.Fatal("IPv4 timeout capture rejected")
				}
				continue
			}
			assertRejected(t, s.snapshot(context.Background(), testUID, clock, collect, &out))
			if out.Len() != 0 {
				t.Fatal("failed capture exposed")
			}
			if _, err := s.read("snapshot.json", maxDocument); !errors.Is(err, os.ErrNotExist) {
				t.Fatal("failed capture saved")
			}
		}
	}
	s, _, _ := newStore(t)
	assertRejected(t, s.snapshot(context.Background(), testUID, clock, func(context.Context) (netproof.Snapshot, error) { return netproof.Snapshot{}, errors.New("PRIVATE") }, io.Discard))
}
func TestRestartRejectsStaleReleaseAndInflightCapture(t *testing.T) {
	s, v, _ := newStore(t)
	raw := document(t, s)
	a := approved(v, raw)
	if s.release(context.Background(), testUID, bytes.NewReader(encode(t, a)), clock) != nil {
		t.Fatal("release")
	}
	next, err := s.initialize(context.Background(), testUID)
	if err != nil || next.Epoch == v.Epoch {
		t.Fatal("epoch was reused")
	}
	assertRejected(t, s.release(context.Background(), testUID, bytes.NewReader(encode(t, a)), clock))
	assertRejected(t, s.await(context.Background(), v, clock))
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
	defer cancel()
	// A stale approval stays blocked until this short test deadline.
	assertRejected(t, s.await(ctx, next, clock))
}
func TestSessionChangeDuringCapture(t *testing.T) {
	s, _, _ := newStore(t)
	var out bytes.Buffer
	collect := func(ctx context.Context) (netproof.Snapshot, error) {
		if _, err := s.initialize(ctx, testUID); err != nil {
			t.Fatal(err)
		}
		return fakeCapture(ctx)
	}
	assertRejected(t, s.snapshot(context.Background(), testUID, clock, collect, &out))
	if out.Len() != 0 {
		t.Fatal("stale output")
	}
	if _, err := s.read("snapshot.json", maxDocument); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("stale snapshot stored")
	}
}
func TestCancellationAndDeadlineFailClosed(t *testing.T) {
	s, v, _ := newStore(t)
	for _, deadline := range []bool{false, true} {
		var ctx context.Context
		var cancel context.CancelFunc
		if deadline {
			ctx, cancel = context.WithDeadline(context.Background(), time.Now().Add(-time.Second))
		} else {
			ctx, cancel = context.WithCancel(context.Background())
			cancel()
		}
		assertRejected(t, s.await(ctx, v, clock))
		assertRejected(t, wait(ctx))
		assertRejected(t, s.snapshot(ctx, testUID, clock, func(context.Context) (netproof.Snapshot, error) {
			t.Fatal("capture after cancellation")
			return netproof.Snapshot{}, nil
		}, io.Discard))
		cancel()
	}
	ctx, cancel := context.WithCancel(context.Background())
	assertRejected(t, s.snapshot(ctx, testUID, clock, func(ctx context.Context) (netproof.Snapshot, error) { cancel(); return fakeCapture(ctx) }, io.Discard))
	if maxHold != 5*time.Minute || maxCapture != 6*time.Second || maxAge != 30*time.Second {
		t.Fatal("protocol bounds changed")
	}
}
func TestNewStateClearsInheritedFSGroupSetgid(t *testing.T) {
	base := t.TempDir()
	// Kubelet marks an fsGroup-owned volume directory setgid. Its new child
	// inherits that bit even though mkdir requests only 0700.
	if os.Chmod(base, os.ModeSetgid|0700) != nil {
		t.Fatal("fixture parent mode failed")
	}
	s, err := openStore(base)
	if err != nil {
		t.Fatal("new state under fsGroup volume rejected")
	}
	defer s.close()
	info, err := os.Stat(filepath.Join(base, "state"))
	if err != nil || info.Mode().Perm() != 0700 || info.Mode()&os.ModeSetgid != 0 {
		t.Fatal("new state did not become exactly private")
	}
}

func TestUnsafeStatePathsRejected(t *testing.T) {
	t.Run("base symlink", func(t *testing.T) {
		base := t.TempDir()
		link := filepath.Join(t.TempDir(), "link")
		if os.Symlink(base, link) != nil {
			t.Fatal("symlink")
		}
		if s, err := openStore(link); err == nil {
			s.close()
			t.Fatal("followed base symlink")
		}
	})
	for _, kind := range []string{"symlink", "shared", "file"} {
		t.Run("directory "+kind, func(t *testing.T) {
			base := t.TempDir()
			p := filepath.Join(base, "state")
			switch kind {
			case "symlink":
				if os.Symlink(t.TempDir(), p) != nil {
					t.Fatal("symlink")
				}
			case "shared":
				if os.Mkdir(p, 0700) != nil || os.Chmod(p, 0755) != nil {
					t.Fatal("mkdir")
				}
			case "file":
				if os.WriteFile(p, nil, 0600) != nil {
					t.Fatal("write")
				}
			}
			if s, err := openStore(base); err == nil {
				s.close()
				t.Fatal("unsafe child accepted")
			}
		})
	}
	for _, kind := range []string{"symlink", "shared", "hardlink", "fifo", "directory"} {
		t.Run("file "+kind, func(t *testing.T) {
			s, _, base := newStore(t)
			p := filepath.Join(base, "state", "snapshot.json")
			target := filepath.Join(t.TempDir(), "target")
			if os.WriteFile(target, []byte("private"), 0600) != nil {
				t.Fatal("write")
			}
			var err error
			switch kind {
			case "symlink":
				err = os.Symlink(target, p)
			case "shared":
				err = os.WriteFile(p, nil, 0600)
				if err == nil {
					err = os.Chmod(p, 0644)
				}
			case "hardlink":
				err = os.Link(target, p)
			case "fifo":
				err = unix.Mkfifo(p, 0600)
			case "directory":
				err = os.Mkdir(p, 0600)
			}
			if err != nil {
				t.Fatal(err)
			}
			if _, err = s.read("snapshot.json", maxDocument); err == nil {
				t.Fatal("unsafe read")
			}
			assertRejected(t, s.write("snapshot.json", []byte("changed")))
			b, err := os.ReadFile(target)
			if err != nil || string(b) != "private" {
				t.Fatal("target modified")
			}
		})
	}
}
func TestOversizedStateAndUnsafeLock(t *testing.T) {
	s, _, base := newStore(t)
	if s.write("snapshot.json", bytes.Repeat([]byte("x"), maxDocument+1)) != nil {
		t.Fatal("write")
	}
	if _, err := s.read("snapshot.json", maxDocument); err != rejected {
		t.Fatal("unbounded read")
	}
	if os.Chmod(filepath.Join(base, "state", "lock"), 0644) != nil {
		t.Fatal("chmod")
	}
	called := false
	assertRejected(t, s.locked(context.Background(), func() error { called = true; return nil }))
	if called {
		t.Fatal("unsafe lock used")
	}
}
func TestHoldRevalidatesApproval(t *testing.T) {
	for _, kind := range []string{"stale", "changed snapshot", "wrong uid", "malformed"} {
		t.Run(kind, func(t *testing.T) {
			s, v, _ := newStore(t)
			b := document(t, s)
			a := approved(v, b)
			raw := encode(t, a)
			now := clock
			switch kind {
			case "stale":
				now = func() time.Time { return testTime.Add(31 * time.Second) }
			case "changed snapshot":
				if s.write("snapshot.json", append(b, ' ')) != nil {
					t.Fatal("write")
				}
			case "wrong uid":
				a.PodUID = "wrong"
				raw = encode(t, a)
			case "malformed":
				raw = []byte("private invalid JSON")
			}
			if s.write("approval.json", raw) != nil {
				t.Fatal("write")
			}
			assertRejected(t, s.await(context.Background(), v, now))
		})
	}
}
