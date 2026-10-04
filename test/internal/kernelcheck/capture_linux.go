//go:build linux

package kernelcheck

import (
	"io"
	"os"
	"syscall"

	"golang.org/x/sys/unix"
)

// Capture reads only fixed paths. It does not open the TUN device, create nodes,
// load modules, write proc files or execute commands. An unavailable prerequisite
// is an observation, not a capture error or permission to repair the environment.
func Capture(scope string) (Snapshot, error) {
	s := Snapshot{Version: 1, Scope: scope, UID: os.Getuid(), TUN: "unreadable", IPv4Forwarding: "unreadable", IPv6Forwarding: "unreadable"}
	if !s.Valid() {
		return Snapshot{}, ErrSnapshot
	}
	read := func(path string) ([]byte, error) {
		f, err := os.Open(path)
		if err != nil {
			return nil, err
		}
		defer f.Close()
		return io.ReadAll(io.LimitReader(f, 17))
	}
	s.IPv4Forwarding = forwarding(read("/proc/sys/net/ipv4/ip_forward"))
	s.IPv6Forwarding = forwarding(read("/proc/sys/net/ipv6/conf/all/forwarding"))
	info, err := os.Stat("/dev/net/tun")
	switch {
	case os.IsNotExist(err):
		s.TUN = "absent"
	case err != nil:
		s.TUN = "unreadable"
	default:
		s.TUN = "other"
		if stat, ok := info.Sys().(*syscall.Stat_t); ok && info.Mode()&os.ModeCharDevice != 0 && unix.Major(uint64(stat.Rdev)) == 10 && unix.Minor(uint64(stat.Rdev)) == 200 {
			s.TUN = "tun"
		}
	}
	return s, nil
}
