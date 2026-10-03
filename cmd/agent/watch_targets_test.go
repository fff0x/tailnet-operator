package main

import (
	"context"
	"errors"
	"net"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func awaitAgentSignal(t *testing.T, ch <-chan struct{}, what string) {
	t.Helper()
	select {
	case <-ch:
	case <-time.After(3 * time.Second):
		t.Fatalf("timed out waiting for %s", what)
	}
}

// Drive the production watcher loop, not reload directly. Unbuffered sends also
// provide an iteration barrier: accepting the next tick finishes the prior one.
func agentWatcher(t *testing.T, path string, fw *forwarder) (tick func(), stop func()) {
	t.Helper()
	ctx, cancel := context.WithCancel(t.Context())
	ticks := make(chan time.Time)
	done := make(chan struct{})
	go func() {
		defer close(done)
		watchTargetsOnTicks(ctx, path, fw, ticks)
	}()
	var once sync.Once
	stop = func() {
		once.Do(cancel)
		awaitAgentSignal(t, done, "watcher cancellation")
	}
	t.Cleanup(stop)
	return func() {
		t.Helper()
		select {
		case ticks <- time.Now():
		case <-time.After(3 * time.Second):
			t.Fatal("watcher did not accept tick")
		}
	}, stop
}

func watcherRunning(fw *forwarder) map[string]running {
	fw.mu.Lock()
	defer fw.mu.Unlock()
	out := make(map[string]running, len(fw.run))
	for name, r := range fw.run {
		out[name] = r
	}
	return out
}

func TestVirtualHostWatcherStartupReconciliation(t *testing.T) {
	for _, kind := range []string{"failed-bind", "healthy", "startup-window"} {
		t.Run(kind, func(t *testing.T) {
			targets := virtualHostTargets(t)
			l4 := target{Name: "l4", Address: "127.0.0.1", Port: 80, ListenPort: 8443}
			targets = append(targets, l4)
			path := filepath.Join(t.TempDir(), "targets.json")
			writeV3Targets(t, path, targets, virtualNames(targets))
			initialStat, err := os.Stat(path)
			if err != nil {
				t.Fatal(err)
			}
			var httpBinds, l4Binds, failures atomic.Int32
			if kind == "failed-bind" {
				failures.Store(2) // Initial load AND first watcher reconciliation fail.
			}
			fw := &forwarder{mode: "ingress", run: make(map[string]running), changed: make(chan struct{}, 1), listenTailnet: func(network, address string) (net.Listener, error) {
				if network != "tcp" {
					return nil, errors.New("unexpected network")
				}
				if address == ":443" {
					httpBinds.Add(1)
					if failures.Add(-1) >= 0 {
						return nil, errors.New("injected shared bind failure")
					}
				} else if address == ":8443" {
					l4Binds.Add(1)
				} else {
					return nil, errors.New("unexpected port")
				}
				return net.Listen("tcp", "127.0.0.1:0")
			}}
			t.Cleanup(fw.stopAll)
			pending, err := fw.reload(t.Context(), path)
			wantPending := 0
			if kind == "failed-bind" {
				wantPending = 2
			}
			if err != nil || pending != wantPending {
				t.Fatal("initial load", pending, err)
			}
			awaitAgentSignal(t, fw.changed, "initial reload")
			initial := watcherRunning(fw)
			if kind == "startup-window" {
				// Change after the initial load but before watcher mtime capture.
				targets[1].ConfigID = "changed-before-watcher"
				writeV3Targets(t, path, targets, virtualNames(targets))
			}
			assertNoHTTP := func() {
				t.Helper()
				run := watcherRunning(fw)
				if len(run) != 1 || run["l4"].ln != initial["l4"].ln {
					t.Fatal("failed group partially registered or L4 changed")
				}
				p := &prober{}
				if healthCode(p, fw, "Running") != 503 || len(p.snapshotFor(fw)) != 2 {
					t.Fatal("failed desired group disappeared from readiness")
				}
			}
			if kind == "failed-bind" {
				assertNoHTTP()
			}
			tick, stop := agentWatcher(t, path, fw)
			tick()
			awaitAgentSignal(t, fw.changed, "first unconditional reconciliation")
			if kind == "failed-bind" {
				assertNoHTTP()
				tick()
				awaitAgentSignal(t, fw.changed, "unchanged-file pending bind retry")
			}
			run := watcherRunning(fw)
			if len(run) != 3 || run["a"].ln == nil || run["a"].ln != run["b"].ln || run["a"].generation == run["b"].generation {
				t.Fatal("watcher did not register the complete group with distinct generations")
			}
			if run["l4"].ln != initial["l4"].ln || run["l4"].generation != initial["l4"].generation || l4Binds.Load() != 1 {
				t.Fatal("watcher restarted unchanged L4 listener")
			}
			wantBinds := int32(1)
			switch kind {
			case "healthy":
				for _, name := range []string{"a", "b"} {
					if run[name].ln != initial[name].ln || run[name].generation != initial[name].generation {
						t.Fatal("first reconciliation restarted healthy group")
					}
				}
			case "failed-bind":
				wantBinds = 3
				fi, err := os.Stat(path)
				if err != nil || !fi.ModTime().Equal(initialStat.ModTime()) {
					t.Fatal("retry fixture changed mtime", err)
				}
			case "startup-window":
				wantBinds = 2
				if run["b"].t.ConfigID != targets[1].ConfigID || run["a"].ln == initial["a"].ln || run["a"].generation <= initial["a"].generation || initial["a"].ln.(*httpIngress).active() {
					t.Fatal("watcher missed startup-window source change")
				}
			}
			tick() // A subsequent unchanged tick must not bind again.
			stop() // Joins the accepted tick before inspecting ownership/counters.
			after := watcherRunning(fw)
			if httpBinds.Load() != wantBinds || len(fw.changed) != 0 || after["a"].ln != run["a"].ln || after["a"].generation != run["a"].generation {
				t.Fatal("unchanged tick rebound group", httpBinds.Load(), wantBinds)
			}
		})
	}
}

func TestVirtualHostWatcherInvalidReloadKeepsLastGood(t *testing.T) {
	targets := virtualHostTargets(t)
	fw, h, path := virtualForwarder(t, targets)
	before := watcherRunning(fw)
	// Invalid configuration in the startup window is still a whole-config reject.
	targets[1].Name = targets[0].Name
	writeV3Targets(t, path, targets, virtualNames(targets))
	tick, stop := agentWatcher(t, path, fw)
	tick()
	tick() // First iteration has finished; parse failure emits no changed signal.
	stop()
	after := watcherRunning(fw)
	if len(after) != 2 || !h.active() {
		t.Fatal("invalid reload lost last-good group")
	}
	for name, r := range before {
		if after[name].ln != r.ln || after[name].generation != r.generation || after[name].t != r.t {
			t.Fatal("invalid reload changed accepted target", name)
		}
	}
}
