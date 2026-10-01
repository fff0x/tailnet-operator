//go:build linux

package netproof

import (
	"context"
	"fmt"
	"testing"

	"golang.org/x/sys/unix"
)

func rawLink() []byte {
	b := make([]byte, 16)
	native.PutUint16(b[2:], 1)
	native.PutUint32(b[4:], 2)
	native.PutUint32(b[8:], 0x11043)
	b = append(b, attr(3, []byte("sample0\x00"))...)
	b = append(b, attr(5, u32(7))...)
	b = append(b, attr(0x8012, attr(1, []byte("veth\x00")))...)
	b = append(b, attr(0x802b, attr(2, []byte{0}))...)
	b = append(b, attr(66, u32(0))...)
	b = append(b, attr(67, []byte{0})...)
	b = append(b, attr(68, []byte{0, 0})...)
	b = append(b, attr(69, []byte{0, 0})...)
	b = append(b, attr(0x803e, nil)...)
	b = append(b, attr(0x8041, nil)...)
	b = append(b, attr(26, append(attr(2, attr(1, make([]byte, 132))), attr(10, attr(2, make([]byte, 240)))...))...)
	return b
}
func TestLinuxLinkDecoder(t *testing.T) {
	l, name, err := decodeLink(rawLink())
	if err != nil || l.Kind != "veth" || l.PeerIndex != 7 || name != "sample0" {
		t.Fatal("link decode failed")
	}
	for name, mutate := range map[string]func([]byte) []byte{
		"unknown":                func(b []byte) []byte { return append(b, attr(99, u32(1))...) },
		"master":                 func(b []byte) []byte { return append(b, attr(10, u32(7))...) },
		"duplicate":              func(b []byte) []byte { return append(b, attr(5, u32(7))...) },
		"duplicate nested alias": func(b []byte) []byte { return append(b, attr(18, attr(1, []byte("veth\x00")))...) },
		"unsupported flag":       func(b []byte) []byte { b[9] |= 1; return b },
		"unknown AF":             func(b []byte) []byte { return append(b, attr(26, attr(99, u32(0)))...) },
		"unknown nested config":  func(b []byte) []byte { return append(b, attr(26, attr(2, attr(99, u32(0))))...) },
	} {
		t.Run(name, func(t *testing.T) {
			if _, _, err := decodeLink(mutate(rawLink())); err != ErrCapture {
				t.Fatal("bad link accepted")
			}
		})
	}
}
func rawAddress() []byte {
	b := []byte{2, 24, 0x80, 0, 2, 0, 0, 0}
	native.PutUint32(b[4:], 2)
	b = append(b, attr(1, []byte{10, 77, 4, 19})...)
	b = append(b, attr(2, []byte{10, 77, 4, 19})...)
	b = append(b, attr(8, u32(0x80))...)
	return b
}
func TestLinuxAddressDecoder(t *testing.T) {
	idx, p, err := decodeAddress(rawAddress())
	if err != nil || idx != 2 || p != prefix("10.77.4.19/24") {
		t.Fatal("address decode failed")
	}
	for name, mutate := range map[string]func([]byte) []byte{
		"duplicate":      func(b []byte) []byte { return append(b, attr(1, []byte{10, 77, 4, 19})...) },
		"unknown":        func(b []byte) []byte { return append(b, attr(99, u32(0))...) },
		"flags mismatch": func(b []byte) []byte { b[2] = 0; return b },
		"truncated":      func(b []byte) []byte { return b[:len(b)-1] },
		"point to point": func(b []byte) []byte { b[23] = 20; return b },
	} {
		t.Run(name, func(t *testing.T) {
			if _, _, err := decodeAddress(mutate(rawAddress())); err != ErrCapture {
				t.Fatal("bad address accepted")
			}
		})
	}
}

// Fresh kind veths can still be performing IPv6 duplicate-address detection.
// The caller must wait and recapture, not erase tentative flags from evidence.
func TestTentativeIPv6AddressRejected(t *testing.T) {
	address := func(flags uint32) []byte {
		b := []byte{10, 64, byte(flags), 253, 0, 0, 0, 0}
		native.PutUint32(b[4:], 7)
		b = append(b, attr(1, ip("fe80::17").AsSlice())...)
		return append(b, attr(8, u32(flags))...)
	}
	if _, _, err := decodeAddress(address(0x80)); err != nil {
		t.Fatal("stable link-local address rejected")
	}
	if _, _, err := decodeAddress(address(0x80 | 0x40)); err != ErrCapture {
		t.Fatal("tentative link-local address accepted")
	}
}

func TestDialCategoriesWithoutDialing(t *testing.T) {
	for _, tt := range []struct {
		err  error
		want DialCategory
	}{
		{nil, Connected}, {unix.ENETUNREACH, NetworkUnreachable}, {fmt.Errorf("wrapped: %w", unix.ENETUNREACH), NetworkUnreachable},
		{unix.EAFNOSUPPORT, AddressFamilyUnsupported}, {unix.ECONNREFUSED, Refused},
		{context.DeadlineExceeded, TimedOut}, {unix.EHOSTUNREACH, OtherFailure}, {unix.EACCES, OtherFailure},
		{unix.EPERM, OtherFailure}, {unix.EADDRNOTAVAIL, OtherFailure}, {context.Canceled, OtherFailure},
	} {
		if got := dialCategory(tt.err); got != tt.want {
			t.Fatalf("category %s, want %s", got, tt.want)
		}
	}
}
