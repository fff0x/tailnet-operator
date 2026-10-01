//go:build linux

// netgate is a disposable-kind init-container startup gate, not a network proof.
// The trusted host driver MUST bind the actual Pod UID, node and CNI captures,
// call netproof.VerifyNode and VerifyPod, and recheck stable live metadata before
// release. A digest authenticates only the selected bytes, not their safety.
// Snapshot stdout is PRIVATE evidence: capture it, never print it publicly.
package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/signal"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
	"this-is-fine.io/tailnet-operator/test/internal/netproof"
)

const (
	gatePath     = "/fixture-gate"
	maxHold      = 5 * time.Minute
	maxCapture   = 6 * time.Second
	maxAge       = 30 * time.Second
	maxDocument  = netproof.MaxJSON + 1024
	maxApproval  = 1024
	pollInterval = 50 * time.Millisecond
)

var rejected = errors.New("netgate: startup gate rejected")

type session struct {
	Version int    `json:"version"`
	PodUID  string `json:"podUID"`
	Epoch   string `json:"epoch"`
}
type snapshotDocument struct {
	Version          int               `json:"version"`
	PodUID           string            `json:"podUID"`
	Epoch            string            `json:"epoch"`
	CapturedAtMillis int64             `json:"capturedAtMillis"`
	Snapshot         netproof.Snapshot `json:"snapshot"`
}
type approval struct {
	Version                  int    `json:"version"`
	PodUID                   string `json:"podUID"`
	Epoch                    string `json:"epoch"`
	SnapshotSHA256           string `json:"snapshotSHA256"`
	HostProofExpiresAtMillis int64  `json:"hostProofExpiresAtMillis"`
}

func authorized(args []string, uid int, podUID string) (string, error) {
	if uid != 65532 || !safeUID(podUID) || len(args) != 2 || args[1] != "--fixture=p1.8-http" {
		return "", rejected
	}
	switch args[0] {
	case "--action=hold":
		return "hold", nil
	case "--action=snapshot":
		return "snapshot", nil
	case "--action=release":
		return "release", nil
	}
	return "", rejected
}
func safeUID(s string) bool {
	if len(s) == 0 || len(s) > 128 {
		return false
	}
	for _, c := range s {
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '-') {
			return false
		}
	}
	return true
}
func hex256(s string) bool {
	if len(s) != 64 {
		return false
	}
	b, err := hex.DecodeString(s)
	return err == nil && hex.EncodeToString(b) == s
}
func (s session) valid(uid string) bool {
	return s.Version == 1 && s.PodUID == uid && safeUID(uid) && hex256(s.Epoch)
}

// State operations are relative to a pinned directory descriptor. Never follow
// symlinks, accept shared state permissions, or open a FIFO/device as a file.
// The emptyDir mount itself may have fsGroup permissions; its child is private.
type store struct{ fd int }

func openStore(base string) (*store, error) {
	fd, err := unix.Open(base, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, rejected
	}
	defer unix.Close(fd)
	err = unix.Mkdirat(fd, "state", 0700)
	created := err == nil
	if err != nil && err != unix.EEXIST {
		return nil, rejected
	}
	child, err := unix.Openat(fd, "state", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, rejected
	}
	var st unix.Stat_t
	// An fsGroup-owned emptyDir is setgid. Clear inheritance only on the
	// freshly created, UID-owned child; never normalize existing unsafe state.
	if created {
		if unix.Fstat(child, &st) != nil || st.Uid != uint32(os.Geteuid()) || unix.Fchmod(child, 0700) != nil {
			unix.Close(child)
			return nil, rejected
		}
	}
	if unix.Fstat(child, &st) != nil || st.Mode&07777 != 0700 || st.Uid != uint32(os.Geteuid()) {
		unix.Close(child)
		return nil, rejected
	}
	return &store{child}, nil
}
func (s *store) close() { unix.Close(s.fd) }
func privateFile(fd int) bool {
	var st unix.Stat_t
	return unix.Fstat(fd, &st) == nil && st.Mode&unix.S_IFMT == unix.S_IFREG && st.Mode&07777 == 0600 && st.Uid == uint32(os.Geteuid()) && st.Nlink == 1
}
func (s *store) open(name string, flags int) (*os.File, error) {
	var st unix.Stat_t
	if unix.Fstat(s.fd, &st) != nil || st.Mode&unix.S_IFMT != unix.S_IFDIR || st.Mode&07777 != 0700 || st.Uid != uint32(os.Geteuid()) {
		return nil, rejected
	}
	fd, err := unix.Openat(s.fd, name, flags|unix.O_NOFOLLOW|unix.O_CLOEXEC|unix.O_NONBLOCK, 0600)
	if err != nil {
		if err == unix.ENOENT {
			return nil, os.ErrNotExist
		}
		return nil, rejected
	}
	if !privateFile(fd) {
		unix.Close(fd)
		return nil, rejected
	}
	return os.NewFile(uintptr(fd), "private-state"), nil
}
func (s *store) read(name string, max int) ([]byte, error) {
	f, err := s.open(name, unix.O_RDONLY)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	b, err := io.ReadAll(io.LimitReader(f, int64(max+1)))
	if err != nil || len(b) > max {
		return nil, rejected
	}
	return b, nil
}
func randomHex() (string, error) {
	var b [32]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", rejected
	}
	return hex.EncodeToString(b[:]), nil
}
func (s *store) write(name string, b []byte) error {
	// Existing unsafe targets are rejected, not silently replaced.
	f, err := s.open(name, unix.O_RDONLY)
	if err == nil {
		f.Close()
	} else if !errors.Is(err, os.ErrNotExist) {
		return rejected
	}
	suffix, err := randomHex()
	if err != nil {
		return rejected
	}
	temp := "tmp-" + suffix
	f, err = s.open(temp, unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL)
	if err != nil {
		return rejected
	}
	defer unix.Unlinkat(s.fd, temp, 0)
	n, werr := f.Write(b)
	serr := f.Sync()
	cerr := f.Close()
	if werr != nil || serr != nil || cerr != nil || n != len(b) {
		return rejected
	}
	if unix.Renameat(s.fd, temp, s.fd, name) != nil || unix.Fsync(s.fd) != nil {
		return rejected
	}
	return nil
}
func (s *store) locked(ctx context.Context, fn func() error) error {
	if ctx.Err() != nil {
		return rejected
	}
	f, err := s.open("lock", unix.O_RDWR|unix.O_CREAT)
	if err != nil {
		return rejected
	}
	defer f.Close()
	for {
		if ctx.Err() != nil {
			return rejected
		}
		err = unix.Flock(int(f.Fd()), unix.LOCK_EX|unix.LOCK_NB)
		if err == nil {
			break
		}
		if err != unix.EWOULDBLOCK && err != unix.EAGAIN {
			return rejected
		}
		if wait(ctx) != nil {
			return rejected
		}
	}
	defer unix.Flock(int(f.Fd()), unix.LOCK_UN)
	if ctx.Err() != nil {
		return rejected
	}
	return fn()
}
func wait(ctx context.Context) error {
	timer := time.NewTimer(pollInterval)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return rejected
	case <-timer.C:
		return nil
	}
}

// Reject duplicates (including nested objects), excessive nesting, unknown or
// missing top-level fields, null protocol fields, oversized and trailing JSON.
func jsonValue(d *json.Decoder, depth int) error {
	if depth > 32 {
		return rejected
	}
	t, err := d.Token()
	if err != nil {
		return rejected
	}
	delim, ok := t.(json.Delim)
	if !ok {
		return nil
	}
	switch delim {
	case '{':
		seen := map[string]bool{}
		for d.More() {
			key, err := d.Token()
			k, ok := key.(string)
			if err != nil || !ok || seen[k] {
				return rejected
			}
			seen[k] = true
			if jsonValue(d, depth+1) != nil {
				return rejected
			}
		}
	case '[':
		for d.More() {
			if jsonValue(d, depth+1) != nil {
				return rejected
			}
		}
	default:
		return rejected
	}
	_, err = d.Token()
	if err != nil {
		return rejected
	}
	return nil
}
func decode(r io.Reader, max int, out any, fields ...string) error {
	b, err := io.ReadAll(io.LimitReader(r, int64(max+1)))
	if err != nil || len(b) > max {
		return rejected
	}
	d := json.NewDecoder(bytes.NewReader(b))
	if jsonValue(d, 0) != nil {
		return rejected
	}
	if _, err = d.Token(); err != io.EOF {
		return rejected
	}
	var m map[string]json.RawMessage
	if json.Unmarshal(b, &m) != nil || len(m) != len(fields) {
		return rejected
	}
	for _, k := range fields {
		v, ok := m[k]
		if !ok || bytes.Equal(bytes.TrimSpace(v), []byte("null")) {
			return rejected
		}
	}
	d = json.NewDecoder(bytes.NewReader(b))
	d.DisallowUnknownFields()
	if d.Decode(out) != nil {
		return rejected
	}
	return nil
}
func (s *store) current(uid string) (session, error) {
	var v session
	b, err := s.read("session.json", maxApproval)
	if err != nil || decode(bytes.NewReader(b), maxApproval, &v, "version", "podUID", "epoch") != nil || !v.valid(uid) {
		return session{}, rejected
	}
	return v, nil
}
func (s *store) unchanged(v session) bool {
	got, err := s.current(v.PodUID)
	return err == nil && got == v
}
func marshal(v any) ([]byte, error) {
	b, err := json.Marshal(v)
	if err != nil {
		return nil, rejected
	}
	return append(b, '\n'), nil
}
func (s *store) initialize(ctx context.Context, uid string) (session, error) {
	epoch, err := randomHex()
	if err != nil || !safeUID(uid) {
		return session{}, rejected
	}
	v := session{1, uid, epoch}
	b, err := marshal(v)
	if err != nil {
		return session{}, rejected
	}
	err = s.locked(ctx, func() error { return s.write("session.json", b) })
	return v, err
}

type captureFunc func(context.Context) (netproof.Snapshot, error)

func capture(ctx context.Context) (netproof.Snapshot, error) {
	v, err := netproof.Capture(ctx)
	if err != nil || ctx.Err() != nil {
		return netproof.Snapshot{}, rejected
	}
	v.Dials = netproof.CheckExternal(ctx)
	return v, ctx.Err()
}
func validCapture(s netproof.Snapshot) bool {
	return s.Version == netproof.Version && s.UID == 65532 && netproof.PodDials(s.Dials)
}
func (s *store) snapshot(ctx context.Context, uid string, now func() time.Time, collect captureFunc, out io.Writer) error {
	ctx, cancel := context.WithTimeout(ctx, maxCapture)
	defer cancel()
	var v session
	if s.locked(ctx, func() error { var err error; v, err = s.current(uid); return err }) != nil {
		return rejected
	}
	at := now().UnixMilli()
	snap, err := collect(ctx)
	if err != nil || ctx.Err() != nil || !validCapture(snap) {
		return rejected
	}
	b, err := marshal(snapshotDocument{1, v.PodUID, v.Epoch, at, snap})
	if err != nil || len(b) > maxDocument {
		return rejected
	}
	return s.locked(ctx, func() error {
		if !s.unchanged(v) || ctx.Err() != nil {
			return rejected
		}
		if s.write("snapshot.json", b) != nil || ctx.Err() != nil {
			return rejected
		}
		n, err := out.Write(b)
		if err != nil || n != len(b) {
			return rejected
		}
		return nil
	})
}
func verify(v session, a approval, b []byte, now time.Time) error {
	if !v.valid(v.PodUID) || a.Version != 1 || a.PodUID != v.PodUID || a.Epoch != v.Epoch || !hex256(a.SnapshotSHA256) {
		return rejected
	}
	digest := sha256.Sum256(b)
	if hex.EncodeToString(digest[:]) != a.SnapshotSHA256 {
		return rejected
	}
	var d snapshotDocument
	if decode(bytes.NewReader(b), maxDocument, &d, "version", "podUID", "epoch", "capturedAtMillis", "snapshot") != nil {
		return rejected
	}
	n := now.UnixMilli()
	if d.Version != 1 || d.PodUID != v.PodUID || d.Epoch != v.Epoch || !validCapture(d.Snapshot) || d.CapturedAtMillis <= 0 || d.CapturedAtMillis > n || n-d.CapturedAtMillis > maxAge.Milliseconds() {
		return rejected
	}
	if a.HostProofExpiresAtMillis <= 0 || n > a.HostProofExpiresAtMillis || a.HostProofExpiresAtMillis > d.CapturedAtMillis+maxAge.Milliseconds() {
		return rejected
	}
	return nil
}
func (s *store) release(ctx context.Context, uid string, in io.Reader, now func() time.Time) error {
	var a approval
	if decode(in, maxApproval, &a, "version", "podUID", "epoch", "snapshotSHA256", "hostProofExpiresAtMillis") != nil {
		return rejected
	}
	return s.locked(ctx, func() error {
		v, err := s.current(uid)
		if err != nil {
			return rejected
		}
		b, err := s.read("snapshot.json", maxDocument)
		if err != nil || verify(v, a, b, now()) != nil || !s.unchanged(v) || ctx.Err() != nil {
			return rejected
		}
		raw, err := marshal(a)
		if err != nil {
			return rejected
		}
		return s.write("approval.json", raw)
	})
}
func (s *store) await(ctx context.Context, v session, now func() time.Time) error {
	for {
		ready := false
		err := s.locked(ctx, func() error {
			if !s.unchanged(v) {
				return rejected
			}
			raw, err := s.read("approval.json", maxApproval)
			if errors.Is(err, os.ErrNotExist) {
				return nil
			}
			if err != nil {
				return rejected
			}
			var a approval
			if decode(bytes.NewReader(raw), maxApproval, &a, "version", "podUID", "epoch", "snapshotSHA256", "hostProofExpiresAtMillis") != nil {
				return rejected
			}
			// A previous init's well-formed approval never authorizes this epoch.
			if a.Epoch != v.Epoch {
				return nil
			}
			b, err := s.read("snapshot.json", maxDocument)
			if err != nil || verify(v, a, b, now()) != nil || !s.unchanged(v) || ctx.Err() != nil {
				return rejected
			}
			ready = true
			return nil
		})
		if err != nil || ctx.Err() != nil {
			return rejected
		}
		if ready {
			return nil
		}
		if wait(ctx) != nil {
			return rejected
		}
	}
}
func run(ctx context.Context, args []string, uid int, podUID string, base string, in io.Reader, out io.Writer, collect captureFunc) error {
	action, err := authorized(args, uid, podUID)
	if err != nil || ctx.Err() != nil {
		return rejected
	}
	// Main also enforces this deadline independently of blocking stdin/stdout.
	ctx, cancel := context.WithTimeout(ctx, maxHold)
	defer cancel()
	s, err := openStore(base)
	if err != nil {
		return rejected
	}
	defer s.close()
	switch action {
	case "hold":
		v, err := s.initialize(ctx, podUID)
		if err != nil {
			return rejected
		}
		return s.await(ctx, v, time.Now)
	case "snapshot":
		return s.snapshot(ctx, podUID, time.Now, collect, out)
	case "release":
		return s.release(ctx, podUID, in, time.Now)
	}
	return rejected
}
func main() {
	// Validate before filesystem access, captures, or goroutines performing I/O.
	action, err := authorized(os.Args[1:], os.Geteuid(), os.Getenv("POD_UID"))
	if err != nil {
		fail()
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM, syscall.SIGHUP)
	defer stop()
	limit := maxHold
	if action == "snapshot" {
		limit = maxCapture
	}
	ctx, cancel := context.WithTimeout(ctx, limit)
	defer cancel()
	done := make(chan error, 1)
	go func() {
		done <- run(ctx, os.Args[1:], os.Geteuid(), os.Getenv("POD_UID"), gatePath, os.Stdin, os.Stdout, capture)
	}()
	select {
	case err := <-done:
		if err != nil || ctx.Err() != nil {
			fail()
		}
	case <-ctx.Done():
		fail()
	}
}
func fail() { fmt.Fprintln(os.Stderr, rejected); os.Exit(2) }
