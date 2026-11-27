package console

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/go-logr/logr/funcr"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

type memAnchor struct {
	mu                  sync.Mutex
	head                chainHead
	ok                  bool
	failLoad, failStore bool
}

func (a *memAnchor) load(context.Context) (chainHead, bool, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.failLoad {
		return chainHead{}, false, errors.New("anchor down")
	}
	return a.head, a.ok, nil
}

func (a *memAnchor) store(_ context.Context, h chainHead) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.failStore {
		return errors.New("anchor down")
	}
	a.head, a.ok = h, true
	return nil
}

var testActor = &auditActor{Issuer: "https://id.example", Subject: "alice-sub", Name: "Alice"}

func newTestAudit(t *testing.T, dir string, a anchor) (*auditLog, *strings.Builder) {
	t.Helper()
	logs := &strings.Builder{}
	var mu sync.Mutex
	log := funcr.New(func(prefix, args string) { mu.Lock(); logs.WriteString(prefix + args + "\n"); mu.Unlock() }, funcr.Options{})
	return newAuditLog(dir, a, log, func() time.Time { return time.Date(2026, 11, 27, 13, 0, 0, 0, time.FixedZone("CET", 3600)) }), logs
}

func appendN(t *testing.T, l *auditLog, n int) {
	t.Helper()
	for range n {
		if err := l.append(context.Background(), auditEntry{Action: "grant.create", Actor: testActor, Grant: "console-x", Tailnet: "lab"}); err != nil {
			t.Fatal(err)
		}
	}
}

func lines(t *testing.T, dir string) [][]byte {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(dir, auditFile))
	if err != nil {
		t.Fatal(err)
	}
	return bytes.Split(bytes.TrimSuffix(raw, []byte("\n")), []byte("\n"))
}

func writeLines(t *testing.T, dir string, ls [][]byte) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, auditFile), append(bytes.Join(ls, []byte("\n")), '\n'), 0o600); err != nil {
		t.Fatal(err)
	}
}

// Numbered JSON lines chained by the hash of the previous line; the anchor and
// the pod log carry the head, never an identity.
func TestAuditChain(t *testing.T) {
	dir, a := t.TempDir(), &memAnchor{}
	l, logs := newTestAudit(t, dir, a)
	appendN(t, l, 3)
	ls := lines(t, dir)
	if len(ls) != 3 {
		t.Fatalf("%d lines", len(ls))
	}
	prev := ""
	for i, line := range ls {
		var e auditEntry
		if err := json.Unmarshal(line, &e); err != nil {
			t.Fatal(err)
		}
		if e.V != 1 || e.Seq != uint64(i+1) || e.Prev != prev || e.Time.Location() != time.UTC || e.Time.Hour() != 12 ||
			*e.Actor != *testActor || e.Grant != "console-x" || e.Tailnet != "lab" {
			t.Errorf("line %d = %+v", i+1, e)
		}
		prev = lineHash(line)
	}
	if a.head != (chainHead{3, prev}) {
		t.Errorf("anchor %+v", a.head)
	}
	st := l.state(context.Background())
	if st.Err != nil || len(st.Breaks) != 0 || len(st.Entries) != 3 {
		t.Fatalf("state %+v", st)
	}
	if !strings.Contains(logs.String(), `"seq"=3`) || strings.Contains(logs.String(), "alice") || strings.Contains(logs.String(), "Alice") {
		t.Errorf("pod log:\n%s", logs)
	}
}

// Every kind of break is found, recorded exactly once, and the log goes on.
func TestAuditBreaks(t *testing.T) {
	for name, tc := range map[string]struct {
		tamper func(t *testing.T, dir string, a *memAnchor)
		want   string
	}{
		"changed line": {func(t *testing.T, dir string, _ *memAnchor) {
			ls := lines(t, dir)
			ls[1] = bytes.Replace(ls[1], []byte("Alice"), []byte("Mallory"), 1)
			writeLines(t, dir, ls)
		}, "line 3: does not continue line 2"},
		"removed line": {func(t *testing.T, dir string, _ *memAnchor) {
			ls := lines(t, dir)
			writeLines(t, dir, append(ls[:1:1], ls[2:]...))
		}, "line 2: number 3, expected 2"},
		"unreadable line": {func(t *testing.T, dir string, _ *memAnchor) {
			ls := lines(t, dir)
			ls[0] = []byte("{not json")
			writeLines(t, dir, ls)
		}, "line 1: unreadable"},
		"cut at the end": {func(t *testing.T, dir string, _ *memAnchor) {
			writeLines(t, dir, lines(t, dir)[:2])
		}, "anchor names entry 3"},
		"anchor reset": {func(_ *testing.T, _ string, a *memAnchor) { a.head, a.ok = chainHead{}, false }, "anchor missing, the log has 3 entries"},
		"log lost": {func(t *testing.T, dir string, _ *memAnchor) {
			if err := os.Remove(filepath.Join(dir, auditFile)); err != nil {
				t.Fatal(err)
			}
		}, "anchor names entry 3"},
		"incomplete write": {func(t *testing.T, dir string, _ *memAnchor) {
			f, _ := os.OpenFile(filepath.Join(dir, auditFile), os.O_APPEND|os.O_WRONLY, 0)
			_, _ = f.WriteString(`{"v":1,"seq":4`)
			_ = f.Close()
		}, "last line is incomplete"},
	} {
		t.Run(name, func(t *testing.T) {
			dir, a := t.TempDir(), &memAnchor{}
			l, _ := newTestAudit(t, dir, a)
			appendN(t, l, 3)
			tc.tamper(t, dir, a)
			// A fresh process, as after a restart.
			l, _ = newTestAudit(t, dir, a)
			for range 2 {
				st := l.state(context.Background())
				if st.Err != nil || !slices.ContainsFunc(st.Breaks, func(b string) bool { return strings.HasPrefix(b, tc.want) }) {
					t.Fatalf("breaks %q, err %v", st.Breaks, st.Err)
				}
			}
			appendN(t, l, 1)
			st := l.state(context.Background())
			recorded := 0
			for _, e := range st.Entries {
				if e.Action == actionBroken && strings.HasPrefix(e.Details["break"].(string), tc.want) {
					recorded++
				}
			}
			if recorded != 1 || st.Entries[len(st.Entries)-1].Action != "grant.create" {
				t.Fatalf("break recorded %d times; entries %+v", recorded, st.Entries)
			}
			// The chain goes on from the file as it is: no break appears after the records.
			last := lines(t, dir)
			var e auditEntry
			_ = json.Unmarshal(last[len(last)-1], &e)
			if a.head.Seq != e.Seq || a.head.Hash != lineHash(last[len(last)-1]) {
				t.Errorf("anchor %+v after the break", a.head)
			}
		})
	}
}

// Without a writable log or anchor, append fails, so the change it guards is not made.
func TestAuditUnavailable(t *testing.T) {
	l, _ := newTestAudit(t, filepath.Join(t.TempDir(), "missing"), &memAnchor{})
	if err := l.append(context.Background(), auditEntry{Action: "grant.create"}); err == nil {
		t.Error("append to a missing directory succeeded")
	}
	dir, a := t.TempDir(), &memAnchor{failLoad: true}
	l, _ = newTestAudit(t, dir, a)
	if err := l.append(context.Background(), auditEntry{Action: "grant.create"}); err == nil || l.state(context.Background()).Err == nil {
		t.Error("append without a readable anchor succeeded")
	}
	a.failLoad, a.failStore = false, true
	if err := l.append(context.Background(), auditEntry{Action: "grant.create"}); err == nil {
		t.Error("append without a writable anchor succeeded")
	}
	// This process knows the line it wrote; a restart does not, and reports the gap.
	if st := l.state(context.Background()); len(st.Breaks) != 0 {
		t.Errorf("own unanchored line reported: %q", st.Breaks)
	}
	a.failStore = false
	restarted, _ := newTestAudit(t, dir, a)
	if st := restarted.state(context.Background()); len(st.Breaks) != 1 || !strings.HasPrefix(st.Breaks[0], "anchor missing") {
		t.Errorf("breaks after restart %q", st.Breaks)
	}
}

// Concurrent requests get distinct, gapless numbers.
func TestAuditConcurrent(t *testing.T) {
	dir := t.TempDir()
	l, _ := newTestAudit(t, dir, &memAnchor{})
	var wg sync.WaitGroup
	for range 20 {
		wg.Go(func() {
			if err := l.append(context.Background(), auditEntry{Action: "grant.create"}); err != nil {
				t.Error(err)
			}
		})
	}
	wg.Wait()
	if st := l.state(context.Background()); len(st.Entries) != 20 || len(st.Breaks) != 0 {
		t.Fatalf("%d entries, breaks %q", len(st.Entries), st.Breaks)
	}
}

// The ConfigMap anchor reads an empty ConfigMap as "no anchor" and writes seq and hash.
func TestConfigMapAnchor(t *testing.T) {
	s := runtime.NewScheme()
	_ = corev1.AddToScheme(s)
	c := fake.NewClientBuilder().WithScheme(s).WithObjects(&corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Namespace: "ns", Name: "audit"}}).Build()
	a := configMapAnchor{c: c, namespace: "ns", name: "audit"}
	if _, ok, err := a.load(context.Background()); ok || err != nil {
		t.Fatalf("empty anchor: %t %v", ok, err)
	}
	if err := a.store(context.Background(), chainHead{7, "abc"}); err != nil {
		t.Fatal(err)
	}
	if h, ok, err := a.load(context.Background()); !ok || err != nil || h != (chainHead{7, "abc"}) {
		t.Fatalf("anchor %+v %t %v", h, ok, err)
	}
	missing := configMapAnchor{c: c, namespace: "ns", name: "other"}
	if _, _, err := missing.load(context.Background()); err == nil {
		t.Error("missing ConfigMap read as an anchor")
	}
}
