//go:build linux

package netproof

import (
	"context"
	"io"
	"net/netip"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"golang.org/x/sys/unix"
)

// Capture never dials. A complete bounded capture and separate CheckExternal
// result are both necessary for verification. Netlink dumps are not an atomic
// transaction; callers must quiesce their fixture and enforce freshness.
func Capture(ctx context.Context) (Snapshot, error) {
	ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	s := Snapshot{Version: Version, UID: os.Getuid()}
	if ctx.Err() != nil {
		return Snapshot{}, ErrCapture
	}
	links, err := dump(ctx, unix.RTM_GETLINK, unix.RTM_NEWLINK, unix.AF_UNSPEC)
	if err != nil || len(links) > maxLinks {
		return Snapshot{}, ErrCapture
	}
	indices := map[int]int{}
	for _, raw := range links {
		l, name, err := decodeLink(raw)
		if err != nil {
			return Snapshot{}, ErrCapture
		}
		if _, exists := indices[l.Index]; exists {
			return Snapshot{}, ErrCapture
		}
		// Cross-check the kernel link relation through independently read sysfs.
		b, err := readSmall(filepath.Join("/sys/class/net", name, "iflink"), 64)
		if err != nil || ctx.Err() != nil {
			return Snapshot{}, ErrCapture
		}
		peer, err := strconv.Atoi(strings.TrimSpace(string(b)))
		if err != nil || peer != l.PeerIndex {
			return Snapshot{}, ErrCapture
		}
		indices[l.Index] = len(s.Links)
		s.Links = append(s.Links, l)
	}
	addrs, err := dump(ctx, unix.RTM_GETADDR, unix.RTM_NEWADDR, unix.AF_UNSPEC)
	if err != nil || len(addrs) > maxLinks*8 {
		return Snapshot{}, ErrCapture
	}
	for _, raw := range addrs {
		idx, p, err := decodeAddress(raw)
		if err != nil {
			return Snapshot{}, ErrCapture
		}
		i, ok := indices[idx]
		if !ok || len(s.Links[i].Addresses) >= 8 {
			return Snapshot{}, ErrCapture
		}
		s.Links[i].Addresses = append(s.Links[i].Addresses, p)
	}
	for _, f := range []uint8{unix.AF_INET, unix.AF_INET6} {
		routes, err := dump(ctx, unix.RTM_GETROUTE, unix.RTM_NEWROUTE, f)
		if err != nil {
			return Snapshot{}, ErrCapture
		}
		for _, raw := range routes {
			if len(s.Routes) >= maxRoutes || len(raw) == 0 || raw[0] != f {
				return Snapshot{}, ErrCapture
			}
			r, err := decodeRoute(raw)
			if err != nil {
				return Snapshot{}, ErrCapture
			}
			s.Routes = append(s.Routes, r)
		}
		rules, err := dump(ctx, unix.RTM_GETRULE, unix.RTM_NEWRULE, f)
		if err != nil {
			return Snapshot{}, ErrCapture
		}
		for _, raw := range rules {
			if len(s.Rules) >= maxRules || len(raw) == 0 || raw[0] != f {
				return Snapshot{}, ErrCapture
			}
			r, err := decodeRule(raw)
			if err != nil {
				return Snapshot{}, ErrCapture
			}
			s.Rules = append(s.Rules, r)
		}
	}
	if ctx.Err() != nil {
		return Snapshot{}, ErrCapture
	}
	return s, nil
}
func readSmall(path string, limit int64) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, ErrCapture
	}
	defer f.Close()
	b, err := io.ReadAll(io.LimitReader(f, limit+1))
	if err != nil || int64(len(b)) > limit {
		return nil, ErrCapture
	}
	return b, nil
}

func dump(ctx context.Context, request, response uint16, family uint8) ([][]byte, error) {
	fd, err := unix.Socket(unix.AF_NETLINK, unix.SOCK_RAW|unix.SOCK_CLOEXEC|unix.SOCK_NONBLOCK, unix.NETLINK_ROUTE)
	if err != nil {
		return nil, ErrCapture
	}
	defer unix.Close(fd)
	if unix.Bind(fd, &unix.SockaddrNetlink{Family: unix.AF_NETLINK}) != nil {
		return nil, ErrCapture
	}
	sa, err := unix.Getsockname(fd)
	if err != nil {
		return nil, ErrCapture
	}
	local, ok := sa.(*unix.SockaddrNetlink)
	if !ok {
		return nil, ErrCapture
	}
	// Full-size zeroed request header: no table filter or family-unspecified
	// shortcut for routes/rules. NLM_F_REQUEST | NLM_F_DUMP.
	size := 12
	if request == unix.RTM_GETLINK {
		size = 16
	}
	if request == unix.RTM_GETADDR {
		size = 8
	}
	req := make([]byte, 16+size)
	native.PutUint32(req, uint32(len(req)))
	native.PutUint16(req[4:], request)
	native.PutUint16(req[6:], 0x301)
	native.PutUint32(req[8:], 1)
	req[16] = family
	if unix.Sendto(fd, req, 0, &unix.SockaddrNetlink{Family: unix.AF_NETLINK}) != nil {
		return nil, ErrCapture
	}
	d := dumpDecoder{seq: 1, pid: local.Pid, kind: response}
	buf := make([]byte, 1<<16)
	var out [][]byte
	for !d.done {
		if ctx.Err() != nil {
			return nil, ErrCapture
		}
		p := []unix.PollFd{{Fd: int32(fd), Events: unix.POLLIN}}
		_, err := unix.Poll(p, 20)
		if err == unix.EINTR {
			continue
		}
		if err != nil || p[0].Revents & ^int16(unix.POLLIN) != 0 {
			return nil, ErrCapture
		}
		if p[0].Revents == 0 {
			continue
		}
		n, _, flags, from, err := unix.Recvmsg(fd, buf, nil, unix.MSG_DONTWAIT)
		if err == unix.EAGAIN || err == unix.EINTR {
			continue
		}
		kernel, ok := from.(*unix.SockaddrNetlink)
		if err != nil || flags != 0 || !ok || kernel.Pid != 0 || kernel.Groups != 0 {
			return nil, ErrCapture
		}
		msgs, err := d.feed(buf[:n])
		if err != nil {
			return nil, ErrCapture
		}
		out = append(out, msgs...)
	}
	return out, nil
}

func decodeLink(b []byte) (Link, string, error) {
	var l Link
	if len(b) < 16 || b[0] != 0 || b[1] != 0 || native.Uint32(b[12:]) != 0 {
		return l, "", ErrCapture
	}
	l.Index = int(int32(native.Uint32(b[4:])))
	flags := native.Uint32(b[8:])
	// Only ordinary loopback/ethernet flags; tunnels, P2P and promiscuity fail.
	if l.Index <= 0 || flags & ^uint32(0x1|0x2|0x8|0x40|0x1000|0x10000|0x20000) != 0 {
		return l, "", ErrCapture
	}
	l.Up = flags&0x41 == 0x41 // Administratively UP and RUNNING.
	l.Loopback = flags&8 != 0
	// This whitelist is metadata only. MASTER, alternate namespace moves,
	// offload forwarding and unknown future fields are deliberately absent.
	a, err := attributes(b[16:], map[uint16]int{
		1: -1, 2: -1, 3: -1, 4: 4, 5: 4, 6: -1, 7: 96, 13: 4, 14: 32, 15: 4, 16: 1, 17: 1, 18: -1,
		23: -1, 26: -1, 27: 4, 30: 4, 31: 4, 32: 4, 33: 1, 35: 4, 37: 4, 39: 1, 40: 4, 41: 4,
		43: -1, 47: 4, 48: 4, 50: 4, 51: 4, 58: 4, 59: 4, 60: 4, 61: 4, 63: 4, 64: 4,
		0x8012: -1, 0x801a: -1, 0x802b: -1,
		// Newer than x/sys's headers: MAX_PACING_OFFLOAD_HORIZON,
		// NETNS_IMMUTABLE, HEADROOM and TAILROOM (metadata only).
		66: 4, 67: 1, 68: 2, 69: 2,
		// Empty DEVLINK_PORT and DPLL_PIN nests are emitted for veth/lo.
		// Nonempty device/offload configuration remains unsupported.
		0x803e: 0, 0x8041: 0,
	})
	if err != nil || len(a[3]) < 2 || len(a[3]) > 16 || a[3][len(a[3])-1] != 0 {
		return Link{}, "", ErrCapture
	}
	name := string(a[3][:len(a[3])-1])
	if strings.ContainsAny(name, "/\x00") || name == "." || name == ".." {
		return Link{}, "", ErrCapture
	}
	if a[17] != nil && a[17][0] != 0 || a[39] != nil && a[39][0] != 0 {
		return Link{}, "", ErrCapture
	}
	if a[30] != nil && native.Uint32(a[30]) != 0 || a[61] != nil && native.Uint32(a[61]) != 0 {
		return Link{}, "", ErrCapture
	}
	if v := a[23]; v != nil && (len(v) < 192 || len(v) > 256 || len(v)%8 != 0) {
		return Link{}, "", ErrCapture
	}
	if v := a[26]; v != nil && !validAFSpec(v) {
		return Link{}, "", ErrCapture
	}
	if v := a[43]; v != nil {
		x, e := attributes(v, map[uint16]int{2: 1})
		if e != nil || len(x) != 1 || x[2][0] != 0 {
			return Link{}, "", ErrCapture
		}
	}
	l.PeerIndex = l.Index
	if a[5] != nil {
		l.PeerIndex = int(native.Uint32(a[5]))
	}
	hw := native.Uint16(b[2:])
	if l.Loopback {
		if hw != 772 || a[18] != nil {
			return Link{}, "", ErrCapture
		}
		l.Kind = "loopback"
	} else {
		if hw != 1 || a[18] == nil || a[5] == nil {
			return Link{}, "", ErrCapture
		}
		info, e := attributes(a[18], map[uint16]int{1: -1})
		if e != nil || string(info[1]) != "veth\x00" {
			return Link{}, "", ErrCapture
		}
		l.Kind = "veth"
	}
	return l, name, nil
}

// AF_SPEC contains configuration/statistics arrays, not routes. Validate all
// nested attribute identities; do not silently skip a new address family.
func validAFSpec(b []byte) bool {
	families, err := attributes(b, map[uint16]int{2: -1, 10: -1, 0x8002: -1, 0x800a: -1})
	if err != nil {
		return false
	}
	for f, raw := range families {
		allowed := map[uint16]int{1: -1}
		if f == 10 {
			allowed = map[uint16]int{1: 4, 2: -1, 3: -1, 4: -1, 5: 16, 6: -1, 7: 16, 8: 1, 9: 4}
		}
		attrs, err := attributes(raw, allowed)
		if err != nil {
			return false
		}
		for kind, v := range attrs {
			if allowed[kind] == -1 && (len(v) == 0 || len(v) > 4096 || len(v)%4 != 0) {
				return false
			}
		}
	}
	return true
}
func decodeAddress(b []byte) (int, netip.Prefix, error) {
	bad := func() (int, netip.Prefix, error) { return 0, netip.Prefix{}, ErrCapture }
	if len(b) < 8 {
		return bad()
	}
	f, size, err := family(b[0])
	if err != nil || b[1] > uint8(size*8) {
		return bad()
	}
	a, err := attributes(b[8:], map[uint16]int{1: size, 2: size, 3: -1, 4: size, 6: 16, 8: 4, 11: 1})
	if err != nil || a[1] == nil {
		return bad()
	}
	flags := uint32(b[2])
	if a[8] != nil {
		flags = native.Uint32(a[8])
		if byte(flags) != b[2] {
			return bad()
		}
	}
	// Permanent and IPv6 stable-privacy flags only; no tentative, temporary,
	// deprecated, failed-DAD or secondary addresses.
	if flags & ^uint32(0x80|0x800) != 0 {
		return bad()
	}
	addr, err := address(a[1], size)
	if err != nil {
		return bad()
	}
	if a[2] != nil {
		local, e := address(a[2], size)
		if e != nil || local != addr {
			return bad()
		}
	}
	if a[4] != nil && f != 4 {
		return bad()
	}
	scope := b[3]
	if scope != 0 && scope != 253 && scope != 254 {
		return bad()
	}
	idx := int(native.Uint32(b[4:]))
	if idx <= 0 || idx > 1<<30 {
		return bad()
	}
	return idx, netip.PrefixFrom(addr, int(b[1])), nil
}
