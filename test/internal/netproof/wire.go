package netproof

import (
	"encoding/binary"
	"net/netip"
)

// Netlink is native-endian, including on big-endian Linux. No unsafe casts.
var native = binary.NativeEndian

func align(n int) int { return (n + 3) &^ 3 }

// attributes rejects unapproved attribute flags, duplicate attributes (including
// differently flagged aliases), truncation, padding and unlisted attributes.
func attributes(b []byte, allowed map[uint16]int) (map[uint16][]byte, error) {
	out := map[uint16][]byte{}
	for len(b) > 0 {
		if len(b) < 4 {
			return nil, ErrCapture
		}
		n, t := int(native.Uint16(b)), native.Uint16(b[2:])
		size, ok := allowed[t]
		if !ok || n < 4 || align(n) > len(b) || (size >= 0 && n-4 != size) {
			return nil, ErrCapture
		}
		key := t & 0x3fff
		if _, ok := out[key]; ok {
			return nil, ErrCapture
		}
		for _, v := range b[n:align(n)] {
			if v != 0 {
				return nil, ErrCapture
			}
		}
		out[key] = b[4:n]
		b = b[align(n):]
	}
	return out, nil
}
func family(b byte) (int, int, error) {
	switch b {
	case 2:
		return 4, 4, nil
	case 10:
		return 6, 16, nil
	}
	return 0, 0, ErrCapture
}
func address(b []byte, size int) (netip.Addr, error) {
	if len(b) != size {
		return netip.Addr{}, ErrCapture
	}
	a, ok := netip.AddrFromSlice(b)
	if !ok || a.Is4In6() {
		return netip.Addr{}, ErrCapture
	}
	return a, nil
}
func decodeRoute(b []byte) (Route, error) {
	var r Route
	if len(b) < 12 {
		return r, ErrCapture
	}
	f, size, err := family(b[0])
	if err != nil {
		return r, err
	}
	if b[1] > uint8(size*8) || b[2] != 0 || b[3] != 0 || native.Uint32(b[8:]) != 0 {
		return r, ErrCapture
	}
	a, err := attributes(b[12:], map[uint16]int{1: size, 4: 4, 5: size, 6: 4, 7: size, 12: 32, 15: 4, 20: 1})
	if err != nil || a[4] == nil || a[15] == nil {
		return r, ErrCapture
	}
	table := native.Uint32(a[15])
	if table != uint32(b[4]) || (table != 254 && table != 255) {
		return r, ErrCapture
	}
	if v := a[12]; v != nil && (f != 6 || native.Uint32(v[8:]) != 0 || native.Uint32(v[12:]) != 0) {
		return r, ErrCapture
	}
	if v := a[20]; v != nil && (f != 6 || v[0] != 0) {
		return r, ErrCapture
	}
	dst := netip.IPv4Unspecified()
	if f == 6 {
		dst = netip.IPv6Unspecified()
	}
	if a[1] != nil {
		dst, err = address(a[1], size)
		if err != nil {
			return r, err
		}
	} else if b[1] != 0 {
		return r, ErrCapture
	}
	p := netip.PrefixFrom(dst, int(b[1]))
	if p != p.Masked() {
		return r, ErrCapture
	}
	r = Route{Family: f, Destination: p, LinkIndex: int(native.Uint32(a[4])), Table: table, Protocol: b[5], Scope: b[6], Type: b[7]}
	if r.LinkIndex <= 0 || r.LinkIndex > 1<<30 {
		return Route{}, ErrCapture
	}
	if a[5] != nil {
		r.Gateway, err = address(a[5], size)
		if err != nil {
			return Route{}, err
		}
	}
	if a[7] != nil {
		r.Source, err = address(a[7], size)
		if err != nil {
			return Route{}, err
		}
	}
	return r, nil
}
func decodeRule(b []byte) (Rule, error) {
	var r Rule
	if len(b) < 12 {
		return r, ErrCapture
	}
	f, _, err := family(b[0])
	if err != nil {
		return r, err
	}
	if b[1] != 0 || b[2] != 0 || b[3] != 0 || b[5] != 0 || b[6] != 0 || b[7] != 1 || native.Uint32(b[8:]) != 0 {
		return r, ErrCapture
	}
	a, err := attributes(b[12:], map[uint16]int{6: 4, 14: 4, 15: 4, 21: 1})
	if err != nil || a[14] == nil || a[15] == nil || a[21] == nil {
		return r, ErrCapture
	}
	r = Rule{Family: f, Table: native.Uint32(a[15]), Action: b[7], Protocol: a[21][0], SuppressPrefix: native.Uint32(a[14])}
	if r.Table != uint32(b[4]) {
		return Rule{}, ErrCapture
	}
	if a[6] != nil {
		r.Priority = native.Uint32(a[6])
	}
	return r, nil
}

// dumpDecoder accepts a complete unfiltered multipart response only. The socket
// layer separately verifies that each datagram actually came from the kernel.
type dumpDecoder struct {
	seq, pid     uint32
	kind         uint16
	done         bool
	count, bytes int
}

func (d *dumpDecoder) feed(b []byte) ([][]byte, error) {
	if d.done || len(b) == 0 {
		return nil, ErrCapture
	}
	d.bytes += len(b)
	if d.bytes > 4<<20 {
		return nil, ErrCapture
	}
	var out [][]byte
	for len(b) > 0 {
		if len(b) < 16 {
			return nil, ErrCapture
		}
		n := int(native.Uint32(b))
		kind, flags := native.Uint16(b[4:]), native.Uint16(b[6:])
		if n < 16 || align(n) > len(b) || native.Uint32(b[8:]) != d.seq || native.Uint32(b[12:]) != d.pid || flags != 2 {
			return nil, ErrCapture
		}
		for _, v := range b[n:align(n)] {
			if v != 0 {
				return nil, ErrCapture
			}
		}
		payload := b[16:n]
		d.count++
		if d.count > 8192 {
			return nil, ErrCapture
		}
		if kind == 3 { // NLMSG_DONE; NLM_F_DUMP_INTR is rejected above.
			if len(b) != align(n) || (len(payload) != 0 && (len(payload) != 4 || native.Uint32(payload) != 0)) {
				return nil, ErrCapture
			}
			d.done = true
		} else {
			if kind != d.kind {
				return nil, ErrCapture
			} // Includes NLMSG_ERROR/OVERRUN/NOOP.
			out = append(out, append([]byte(nil), payload...))
		}
		b = b[align(n):]
	}
	return out, nil
}
