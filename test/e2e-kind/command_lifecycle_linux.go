//go:build e2e_kind && linux

package e2ekind

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

const commandWaitDelay = time.Second

// Linux 6.9 added process-group signalling through pidfd_send_signal. Unlike
// kill(-pid), this cannot target an unrelated group after the PID is recycled.
const pidfdSignalProcessGroup = 1 << 2

// configureCommandLifecycle must precede Start. The returned cleanup must run
// after Run/Wait, when exec has joined its cancellation goroutine.
func configureCommandLifecycle(cmd *exec.Cmd) (func(), error) {
	// Probe without delivering a signal, before starting any command. Do not
	// fall back to numeric process-group IDs on older/restricted kernels.
	probe, err := unix.PidfdOpen(os.Getpid(), 0)
	if err != nil {
		return nil, fmt.Errorf("command lifecycle requires Linux pidfds: %w", err)
	}
	err = unix.PidfdSendSignal(probe, 0, nil, pidfdSignalProcessGroup)
	_ = unix.Close(probe)
	// ESRCH is expected when this test process is not itself a group leader;
	// the kernel still validated the group flag (older kernels return EINVAL).
	if err != nil && !errors.Is(err, unix.ESRCH) {
		return nil, fmt.Errorf("command lifecycle requires Linux 6.9+ group signalling: %w", err)
	}

	// Keep our own pidfd past Process.Wait: a reaped leader can still have
	// children holding the output pipes. os/exec owns a separate duplicate.
	pidfd := -1
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true, PidFD: &pidfd}
	killGroup := func() error {
		if pidfd < 0 {
			return os.ErrProcessDone
		}
		err := unix.PidfdSendSignal(pidfd, unix.SIGKILL, nil, pidfdSignalProcessGroup)
		if errors.Is(err, unix.ESRCH) {
			return os.ErrProcessDone
		}
		return err
	}
	cmd.Cancel = killGroup
	cmd.WaitDelay = commandWaitDelay
	return func() {
		if pidfd >= 0 {
			// Also stop pipe-holding children if the leader exited before the
			// context expired and WaitDelay, rather than Cancel, ended Run.
			_ = killGroup()
			_ = unix.Close(pidfd)
			pidfd = -1
		}
	}, nil
}
