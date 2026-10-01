//go:build e2e_kind && linux

package e2ekind

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

// The helper uses no runtime, network, shell, or inherited test configuration.
// Its child retains both output pipes until killed or the emergency release
// file appears. A finite lifetime also bounds leaks if this test itself fails.
func TestCommandLifecycleHelper(t *testing.T) {
	args := os.Args
	if len(args) < 5 || args[len(args)-3] != "command-lifecycle-helper" {
		return
	}
	mode, dir := args[len(args)-2], args[len(args)-1]
	if mode == "output" {
		if os.Getenv("COMMAND_LIFECYCLE_SECRET") != "" || os.Getenv("HOME") != dir || os.Getenv("TMPDIR") != dir {
			os.Exit(4)
		}
		fmt.Fprint(os.Stdout, "public output")
		fmt.Fprint(os.Stderr, "private stderr")
		os.Exit(0)
	}
	if mode == "child" {
		pgid, err := unix.Getpgid(0)
		if err != nil {
			os.Exit(5)
		}
		ready := filepath.Join(dir, "child-ready")
		if os.WriteFile(ready+".tmp", []byte(fmt.Sprintf("%d %d", os.Getpid(), pgid)), 0600) != nil || os.Rename(ready+".tmp", ready) != nil {
			os.Exit(6)
		}
		for end := time.Now().Add(15 * time.Second); time.Now().Before(end); {
			if _, err := os.Stat(filepath.Join(dir, "release")); err == nil {
				os.Exit(0)
			}
			time.Sleep(10 * time.Millisecond)
		}
		os.Exit(7)
	}
	binary, err := os.Executable()
	if err != nil {
		os.Exit(8)
	}
	if os.WriteFile(filepath.Join(dir, "leader"), []byte(strconv.Itoa(os.Getpid())), 0600) != nil {
		os.Exit(9)
	}
	child := exec.Command(binary, "-test.run=^TestCommandLifecycleHelper$", "--", "command-lifecycle-helper", "child", dir)
	child.Stdout, child.Stderr = os.Stdout, os.Stderr
	if child.Start() != nil {
		os.Exit(10)
	}
	if mode == "exit" {
		for end := time.Now().Add(5 * time.Second); time.Now().Before(end); {
			if _, err := os.Stat(filepath.Join(dir, "child-ready")); err == nil {
				os.Exit(0)
			}
			time.Sleep(10 * time.Millisecond)
		}
		os.Exit(11)
	}
	_ = child.Wait()
	os.Exit(0)
}

func TestCommandLifecycle(t *testing.T) {
	binary, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	for _, mode := range []string{"cancel", "exit"} {
		t.Run(mode, func(t *testing.T) {
			dir := t.TempDir()
			f := &fixture{work: dir}
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			result := make(chan error, 1)
			done := make(chan struct{})
			go func() {
				defer close(done)
				_, err := f.command(ctx, "", binary, "-test.run=^TestCommandLifecycleHelper$", "--", "command-lifecycle-helper", mode, dir)
				result <- err
			}()
			// Failure cleanup releases only our helper, without numeric-PID
			// signalling. The helper's own lifetime is bounded as a backstop.
			defer func() {
				_ = os.WriteFile(filepath.Join(dir, "release"), nil, 0600)
				cancel()
				select {
				case <-done:
				case <-time.After(3 * time.Second):
					t.Error("helper command did not finish during cleanup")
				}
			}()
			var ready []byte
			deadline := time.NewTimer(5 * time.Second)
			defer deadline.Stop()
			ticker := time.NewTicker(10 * time.Millisecond)
			defer ticker.Stop()
			for {
				ready, err = os.ReadFile(filepath.Join(dir, "child-ready"))
				if err == nil {
					break
				}
				select {
				case err := <-result:
					t.Fatalf("command ended before child readiness: %v", err)
				case <-deadline.C:
					t.Fatal("child did not become ready")
				case <-ticker.C:
				}
			}
			var pid, pgid int
			if _, err := fmt.Sscanf(string(ready), "%d %d", &pid, &pgid); err != nil {
				t.Fatal(err)
			}
			leader, err := os.ReadFile(filepath.Join(dir, "leader"))
			if err != nil {
				t.Fatal(err)
			}
			leaderPID, err := strconv.Atoi(string(leader))
			if err != nil || pgid != leaderPID || pgid == unix.Getpgrp() || pid == leaderPID {
				t.Fatal("child is not in the command's private process group")
			}
			childFD, err := unix.PidfdOpen(pid, 0)
			if err != nil {
				t.Fatal(err)
			}
			defer unix.Close(childFD)
			start := time.Now()
			if mode == "cancel" {
				cancel()
			}
			select {
			case err := <-result:
				if err == nil {
					t.Fatal("expected cancellation or pipe-drain timeout")
				}
				if mode == "exit" && !errors.Is(err, exec.ErrWaitDelay) {
					t.Fatalf("expected WaitDelay for child-held pipes, got %v", err)
				}
			case <-time.After(commandWaitDelay + 2*time.Second):
				t.Fatal("command did not return within cancellation/pipe-drain bound")
			}
			// pidfds become readable on exit, including before an orphan is
			// reaped. No /proc race, PID reuse, or assumptions about PID 1.
			fds := []unix.PollFd{{Fd: int32(childFD), Events: unix.POLLIN}}
			if n, err := unix.Poll(fds, 1000); err != nil || n != 1 || fds[0].Revents&unix.POLLIN == 0 {
				t.Fatalf("owned child still running after %s: poll=%d err=%v", time.Since(start), n, err)
			}
		})
	}

	t.Run("closed-env-private-stderr", func(t *testing.T) {
		t.Setenv("COMMAND_LIFECYCLE_SECRET", "must-not-be-inherited")
		dir := t.TempDir()
		out, err := (&fixture{work: dir}).command(t.Context(), "", binary, "-test.run=^TestCommandLifecycleHelper$", "--", "command-lifecycle-helper", "output", dir)
		if err != nil || string(out) != "public output" || strings.Contains(string(out), "private stderr") {
			t.Fatal("command environment/output contract changed")
		}
	})
}

func TestCommandLifecycleNotStarted(t *testing.T) {
	cmd := exec.CommandContext(t.Context(), "/does-not-exist")
	cleanup, err := configureCommandLifecycle(cmd)
	if err != nil {
		t.Fatal(err)
	}
	defer cleanup()
	if !errors.Is(cmd.Cancel(), os.ErrProcessDone) {
		t.Fatal("unstarted command cancellation must not signal any group")
	}
	if err := cmd.Run(); err == nil {
		t.Fatal("missing command unexpectedly started")
	}
}

func TestCommandLifecycleAlreadyExited(t *testing.T) {
	binary, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.CommandContext(t.Context(), binary, "-test.run=^TestCommandLifecycleHelper$")
	cleanup, err := configureCommandLifecycle(cmd)
	if err != nil {
		t.Fatal(err)
	}
	defer cleanup()
	if err := cmd.Run(); err != nil {
		t.Fatal(err)
	}
	if !errors.Is(cmd.Cancel(), os.ErrProcessDone) {
		t.Fatal("exited group must map ESRCH to os.ErrProcessDone")
	}
}
