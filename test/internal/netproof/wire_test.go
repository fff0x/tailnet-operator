package netproof

import "testing"

func attr(kind uint16, b []byte) []byte {
	out := make([]byte, align(4+len(b)))
	native.PutUint16(out, uint16(4+len(b)))
	native.PutUint16(out[2:], kind)
	copy(out[4:], b)
	return out
}
func u32(n uint32) []byte { b := make([]byte, 4); native.PutUint32(b, n); return b }
func rawRoute() []byte {
	b := []byte{2, 24, 0, 0, 254, 2, 253, 1, 0, 0, 0, 0}
	b = append(b, attr(1, []byte{192, 168, 76, 0})...)
	b = append(b, attr(4, u32(2))...)
	b = append(b, attr(15, u32(254))...)
	return b
}
func rawRule() []byte {
	b := []byte{2, 0, 0, 0, 254, 0, 0, 1, 0, 0, 0, 0}
	b = append(b, attr(6, u32(32766))...)
	b = append(b, attr(14, u32(^uint32(0)))...)
	b = append(b, attr(15, u32(254))...)
	b = append(b, attr(21, []byte{2})...)
	return b
}
func TestDecodeRoute(t *testing.T) {
	r, err := decodeRoute(rawRoute())
	if err != nil || r.Destination != prefix("192.168.76.0/24") {
		t.Fatal("route decode failed")
	}
	for _, kind := range []uint16{2, 3, 8, 9, 10, 11, 13, 14, 16, 17, 18, 19, 21, 22, 23, 24, 25, 26, 27, 30, 99, 0x8004} {
		t.Run("unsupported-attribute", func(t *testing.T) {
			b := append(rawRoute(), attr(kind, u32(1))...)
			if _, err := decodeRoute(b); err != ErrCapture {
				t.Fatal("unsupported route attribute accepted")
			}
		})
	}
	for name, mutate := range map[string]func([]byte) []byte{
		"duplicate":      func(b []byte) []byte { return append(b, attr(4, u32(2))...) },
		"flag":           func(b []byte) []byte { b[8] = 1; return b },
		"src length":     func(b []byte) []byte { b[2] = 32; return b },
		"tos":            func(b []byte) []byte { b[3] = 1; return b },
		"table mismatch": func(b []byte) []byte { b[4] = 100; return b },
		"family":         func(b []byte) []byte { b[0] = 0; return b },
		"truncated":      func(b []byte) []byte { return b[:len(b)-1] },
		"host bits":      func(b []byte) []byte { b[19] = 2; return b },
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := decodeRoute(mutate(rawRoute())); err != ErrCapture {
				t.Fatal("bad route accepted")
			}
		})
	}
	// Gateways are decoded explicitly, not silently discarded; VerifyNode denies
	// them while VerifyPod checks the exact peer-bound gateway.
	b := append(rawRoute(), attr(5, []byte{192, 168, 76, 1})...)
	r, err = decodeRoute(b)
	if err != nil || r.Gateway != ip("192.168.76.1") {
		t.Fatal("gateway lost")
	}
}
func TestIPv6RouteCache(t *testing.T) {
	b := []byte{10, 64, 0, 0, 254, 2, 0, 1, 0, 0, 0, 0}
	b = append(b, attr(1, ip("fe80::").AsSlice())...)
	b = append(b, attr(4, u32(2))...)
	b = append(b, attr(15, u32(254))...)
	b = append(b, attr(20, []byte{0})...)
	if _, err := decodeRoute(append(b, attr(12, make([]byte, 32))...)); err != nil {
		t.Fatal(err)
	}
	for _, offset := range []int{8, 12} {
		cache := make([]byte, 32)
		native.PutUint32(cache[offset:], 1)
		if _, err := decodeRoute(append(b, attr(12, cache)...)); err != ErrCapture {
			t.Fatal("route expiry/error accepted")
		}
	}
}

func TestDecodeRules(t *testing.T) {
	if _, err := decodeRule(rawRule()); err != nil {
		t.Fatal(err)
	}
	// Includes source/destination, fwmark/mask, interface, UID, goto and tunnel ID.
	for _, kind := range []uint16{1, 2, 3, 4, 5, 7, 8, 10, 11, 12, 13, 16, 17, 18, 19, 20, 22, 23, 24, 25, 99} {
		if _, err := decodeRule(append(rawRule(), attr(kind, u32(1))...)); err != ErrCapture {
			t.Fatal("rule selector accepted")
		}
	}
	if _, err := decodeRule(append(rawRule(), attr(15, u32(254))...)); err != ErrCapture {
		t.Fatal("duplicate rule attribute accepted")
	}
	for _, offset := range []int{1, 2, 3, 5, 6, 8} {
		b := rawRule()
		b[offset] = 1
		if _, err := decodeRule(b); err != ErrCapture {
			t.Fatal("rule header selector accepted")
		}
	}
}
func message(kind, flags uint16, payload []byte) []byte {
	b := make([]byte, align(16+len(payload)))
	native.PutUint32(b, uint32(16+len(payload)))
	native.PutUint16(b[4:], kind)
	native.PutUint16(b[6:], flags)
	native.PutUint32(b[8:], 1)
	native.PutUint32(b[12:], 55)
	copy(b[16:], payload)
	return b
}
func TestDumpCompletionAndFailures(t *testing.T) {
	d := dumpDecoder{seq: 1, pid: 55, kind: 24}
	if _, err := d.feed(message(24, 2, rawRoute())); err != nil || d.done {
		t.Fatal("premature completion")
	}
	if _, err := d.feed(message(3, 2, u32(0))); err != nil || !d.done {
		t.Fatal("missing completion")
	}
	if _, err := d.feed(message(3, 2, nil)); err != ErrCapture {
		t.Fatal("data after done accepted")
	}
	good := message(24, 2, rawRoute())
	for name, b := range map[string][]byte{
		"interrupted": message(24, 2|16, rawRoute()), "filtered": message(3, 2|32, nil),
		"error": message(2, 2, u32(0)), "overrun": message(4, 2, nil), "not multipart": message(24, 0, rawRoute()),
		"done error": message(3, 2, u32(1)), "after done": append(message(3, 2, nil), good...), "short": good[:len(good)-1],
		"unexpected kind": message(32, 2, rawRule()),
	} {
		t.Run(name, func(t *testing.T) {
			d := dumpDecoder{seq: 1, pid: 55, kind: 24}
			if _, err := d.feed(b); err != ErrCapture {
				t.Fatal("bad dump accepted")
			}
		})
	}
	for _, offset := range []int{8, 12} {
		b := append([]byte(nil), good...)
		b[offset]++
		d := dumpDecoder{seq: 1, pid: 55, kind: 24}
		if _, err := d.feed(b); err != ErrCapture {
			t.Fatal("foreign dump accepted")
		}
	}
	d = dumpDecoder{seq: 1, pid: 55, kind: 24, bytes: 4 << 20}
	if _, err := d.feed(good); err != ErrCapture {
		t.Fatal("oversize dump accepted")
	}
}
func FuzzWireDecoders(f *testing.F) {
	f.Add(rawRoute())
	f.Add(rawRule())
	f.Add(message(3, 2, nil))
	f.Add([]byte{})
	f.Fuzz(func(t *testing.T, b []byte) {
		if len(b) > 1<<16 {
			t.Skip()
		}
		_, _ = decodeRoute(b)
		_, _ = decodeRule(b)
		d := dumpDecoder{seq: 1, pid: 55, kind: 24}
		_, _ = d.feed(b)
	})
}

func TestAttributeBoundaries(t *testing.T) {
	for _, b := range [][]byte{{1}, {3, 0, 4, 0}, {9, 0, 4, 0, 0, 0, 0, 0}, attr(4, []byte{1})} {
		if _, err := attributes(b, map[uint16]int{4: 4}); err != ErrCapture {
			t.Fatal("malformed attribute accepted")
		}
	}
	b := attr(20, []byte{0})
	b[len(b)-1] = 1
	if _, err := attributes(b, map[uint16]int{20: 1}); err != ErrCapture {
		t.Fatal("nonzero padding accepted")
	}
}
