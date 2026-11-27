package console

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"sync"
	"time"

	"github.com/go-logr/logr"
	corev1 "k8s.io/api/core/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

const (
	auditVersion = 1
	auditFile    = "audit.jsonl"
	actionBroken = "chain.broken"
	actionFailed = "grant.failed"
)

// auditActor is who acted. Only the audit log keeps it; it never reaches the pod log.
type auditActor struct {
	Issuer  string `json:"iss"`
	Subject string `json:"sub"`
	Name    string `json:"name,omitempty"`
}

// auditEntry is one line of the log. Prev is the SHA-256 of the previous line as written, so a
// changed, removed or inserted line breaks the chain from there on.
type auditEntry struct {
	V       int            `json:"v"`
	Seq     uint64         `json:"seq"`
	Time    time.Time      `json:"time"`
	Action  string         `json:"action"`
	Actor   *auditActor    `json:"actor,omitempty"`
	Grant   string         `json:"grant,omitempty"`
	Tailnet string         `json:"tailnet,omitempty"`
	Details map[string]any `json:"details,omitempty"`
	Prev    string         `json:"prev"`
}

// chainHead names the last line: its number and hash. The zero value is an empty log.
type chainHead struct {
	Seq  uint64
	Hash string
}

// anchor keeps the head outside the volume, so a log rewritten or cut on the volume alone shows.
type anchor interface {
	load(ctx context.Context) (head chainHead, ok bool, err error)
	store(ctx context.Context, head chainHead) error
}

// auditState is what the audit page shows.
type auditState struct {
	Entries []auditEntry
	Breaks  []string // every break ever recorded, in the order found
	Err     error    // the log or its anchor cannot be read
}

// auditLog appends to one file on the console's volume. The console has one replica; the mutex
// orders the entries of its requests.
type auditLog struct {
	path   string
	anchor anchor
	log    logr.Logger
	now    func() time.Time

	mu         sync.Mutex
	ready      bool      // the file was verified and its breaks recorded
	head       chainHead // last line of the file
	newline    bool      // the file ends without "\n" (a write cut short)
	unanchored chainHead // a line this process wrote whose anchor update failed
}

func newAuditLog(dir string, a anchor, log logr.Logger, now func() time.Time) *auditLog {
	return &auditLog{path: filepath.Join(dir, auditFile), anchor: a, log: log, now: now}
}

func lineHash(line []byte) string {
	sum := sha256.Sum256(line)
	return hex.EncodeToString(sum[:])
}

// scan reads the whole file and checks the chain line by line.
// ponytail: every check reads the whole log, so its cost grows with the log; a signed checkpoint
// every N entries would bound it.
func (l *auditLog) scan() (entries []auditEntry, breaks []string, head chainHead, cut bool, err error) {
	raw, err := os.ReadFile(l.path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil, chainHead{}, false, nil
	}
	if err != nil {
		return nil, nil, chainHead{}, false, err
	}
	cut = len(raw) > 0 && raw[len(raw)-1] != '\n'
	sc := bufio.NewScanner(bytes.NewReader(raw))
	sc.Buffer(make([]byte, 64<<10), 1<<20)
	want := uint64(1)
	for n := 1; sc.Scan(); n++ {
		line := sc.Bytes()
		var e auditEntry
		switch {
		case json.Unmarshal(line, &e) != nil || e.V == 0:
			breaks = append(breaks, fmt.Sprintf("line %d: unreadable", n))
			e.Seq = want
		case e.Seq != want:
			breaks = append(breaks, fmt.Sprintf("line %d: number %d, expected %d", n, e.Seq, want))
		case e.Prev != head.Hash:
			breaks = append(breaks, fmt.Sprintf("line %d: does not continue line %d", n, n-1))
		}
		if e.Action != "" {
			entries = append(entries, e)
		}
		head = chainHead{Seq: e.Seq, Hash: lineHash(line)}
		want = e.Seq + 1
	}
	if err := sc.Err(); err != nil {
		return nil, nil, chainHead{}, false, err
	}
	if cut {
		breaks = append(breaks, "last line is incomplete")
	}
	return entries, breaks, head, cut, nil
}

// check compares the file with the anchor and returns all breaks. Call with mu held.
func (l *auditLog) check(ctx context.Context) (auditState, error) {
	entries, breaks, head, cut, err := l.scan()
	if err != nil {
		return auditState{}, fmt.Errorf("audit log unreadable: %w", err)
	}
	a, ok, err := l.anchor.load(ctx)
	if err != nil {
		return auditState{}, fmt.Errorf("audit anchor unreadable: %w", err)
	}
	// A line this process wrote just before its anchor update failed is not a break.
	own := l.unanchored == head && head.Seq == a.Seq+1
	switch {
	case a == head || own:
	case !ok:
		breaks = append(breaks, fmt.Sprintf("anchor missing, the log has %d entries", head.Seq))
	default:
		breaks = append(breaks, fmt.Sprintf("anchor names entry %d (%.12s), the log ends at entry %d (%.12s)", a.Seq, a.Hash, head.Seq, head.Hash))
	}
	l.head, l.newline = head, cut
	return auditState{Entries: entries, Breaks: breaks}, nil
}

// ensure verifies the log once and records every break not yet recorded (rules 14 and 15). Call
// with mu held.
func (l *auditLog) ensure(ctx context.Context) (auditState, error) {
	st, err := l.check(ctx)
	if err != nil {
		return st, err
	}
	// A recorded break stays on the page even when its record moved the anchor past it.
	var all []string
	recorded := map[string]bool{}
	for _, e := range st.Entries {
		if b, ok := e.Details["break"].(string); ok && e.Action == actionBroken && !recorded[b] {
			recorded[b] = true
			all = append(all, b)
		}
	}
	for _, b := range st.Breaks {
		if recorded[b] {
			continue
		}
		e, err := l.write(ctx, auditEntry{Action: actionBroken, Details: map[string]any{"break": b}})
		if err != nil {
			return st, err
		}
		recorded[b] = true
		all = append(all, b)
		st.Entries = append(st.Entries, e)
		l.log.Error(nil, "audit chain broken", "seq", e.Seq)
	}
	st.Breaks = all
	l.ready = true
	return st, nil
}

// write appends one entry, syncs it and moves the anchor. Call with mu held.
func (l *auditLog) write(ctx context.Context, e auditEntry) (auditEntry, error) {
	e.V, e.Seq, e.Time, e.Prev = auditVersion, l.head.Seq+1, l.now().UTC(), l.head.Hash
	line, err := json.Marshal(e)
	if err != nil {
		return e, err
	}
	f, err := os.OpenFile(l.path, os.O_WRONLY|os.O_APPEND|os.O_CREATE, 0o600)
	if err != nil {
		return e, fmt.Errorf("audit log not writable: %w", err)
	}
	out := append(line, '\n')
	if l.newline {
		out = append([]byte{'\n'}, out...)
	}
	_, err = f.Write(out)
	if err == nil {
		err = f.Sync()
	}
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		// What reached the disk is unknown: the next write verifies the file again.
		l.ready = false
		return e, fmt.Errorf("audit log not writable: %w", err)
	}
	l.head, l.newline = chainHead{Seq: e.Seq, Hash: lineHash(line)}, false
	if err := l.anchor.store(ctx, l.head); err != nil {
		l.unanchored = l.head
		return e, fmt.Errorf("audit anchor not writable: %w", err)
	}
	l.unanchored = chainHead{}
	l.log.Info("audit head", "seq", l.head.Seq, "hash", l.head.Hash)
	return e, nil
}

// append records e before the change it describes. An error means: do not make the change.
func (l *auditLog) append(ctx context.Context, e auditEntry) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	if !l.ready {
		if _, err := l.ensure(ctx); err != nil {
			return err
		}
	}
	_, err := l.write(ctx, e)
	return err
}

// state verifies the log for display and records new breaks.
func (l *auditLog) state(ctx context.Context) auditState {
	l.mu.Lock()
	defer l.mu.Unlock()
	st, err := l.ensure(ctx)
	st.Err = err
	return st
}

// configMapAnchor keeps the head in a ConfigMap the chart creates empty; only the console may
// write it.
type configMapAnchor struct {
	c         client.Client
	namespace string
	name      string
}

func (a configMapAnchor) load(ctx context.Context) (chainHead, bool, error) {
	var cm corev1.ConfigMap
	if err := a.c.Get(ctx, client.ObjectKey{Namespace: a.namespace, Name: a.name}, &cm); err != nil {
		return chainHead{}, false, err
	}
	seq, hash := cm.Data["seq"], cm.Data["hash"]
	if seq == "" && hash == "" {
		return chainHead{}, false, nil
	}
	n, err := strconv.ParseUint(seq, 10, 64)
	if err != nil {
		return chainHead{}, true, nil // a garbled anchor matches no log
	}
	return chainHead{Seq: n, Hash: hash}, true, nil
}

func (a configMapAnchor) store(ctx context.Context, head chainHead) error {
	var cm corev1.ConfigMap
	if err := a.c.Get(ctx, client.ObjectKey{Namespace: a.namespace, Name: a.name}, &cm); err != nil {
		return err
	}
	cm.Data = map[string]string{"seq": strconv.FormatUint(head.Seq, 10), "hash": head.Hash}
	return a.c.Update(ctx, &cm)
}
