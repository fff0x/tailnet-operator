// proofverify only verifies caller-bound evidence; it never captures or dials.
package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"os"

	"tsunaro.io/tailnet-operator/test/internal/netproof"
)

var errBinding = errors.New("binding-rejected")

// Decode tokens, not a struct: unknown, duplicate, case-folded and missing keys
// must all fail, as must trailing JSON and unbounded input.
func binding(r io.Reader) (netproof.NodeBinding, netproof.PodBinding, error) {
	var n netproof.NodeBinding
	var p netproof.PodBinding
	raw, err := io.ReadAll(io.LimitReader(r, 1025))
	if err != nil || len(raw) > 1024 {
		return n, p, errBinding
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	token, err := d.Token()
	if err != nil || token != json.Delim('{') {
		return n, p, errBinding
	}
	fields := map[string]string{}
	for d.More() {
		token, err = d.Token()
		key, ok := token.(string)
		if err != nil || !ok {
			return n, p, errBinding
		}
		switch key {
		case "OuterCIDR", "NodeIP", "PodCIDR", "PodIP":
		default:
			return n, p, errBinding
		}
		if _, exists := fields[key]; exists {
			return n, p, errBinding
		}
		var value string
		if d.Decode(&value) != nil || value == "" {
			return n, p, errBinding
		}
		fields[key] = value
	}
	if token, err = d.Token(); err != nil || token != json.Delim('}') || len(fields) != 4 {
		return n, p, errBinding
	}
	if _, err = d.Token(); err != io.EOF {
		return n, p, errBinding
	}
	if n.OuterCIDR, err = netip.ParsePrefix(fields["OuterCIDR"]); err != nil {
		return n, p, errBinding
	}
	if n.PodCIDR, err = netip.ParsePrefix(fields["PodCIDR"]); err != nil {
		return n, p, errBinding
	}
	if n.NodeIP, err = netip.ParseAddr(fields["NodeIP"]); err != nil {
		return n, p, errBinding
	}
	if p.PodIP, err = netip.ParseAddr(fields["PodIP"]); err != nil {
		return n, p, errBinding
	}
	for _, prefix := range []netip.Prefix{n.OuterCIDR, n.PodCIDR} {
		if !prefix.Addr().Is4() || !prefix.Addr().IsPrivate() || prefix.Bits() != 24 || prefix != prefix.Masked() {
			return n, p, errBinding
		}
	}
	usable := func(a netip.Addr, prefix netip.Prefix) bool {
		if !a.Is4() || !prefix.Contains(a) {
			return false
		}
		octets := a.As4()
		return octets[3] != 0 && octets[3] != 255
	}
	if n.OuterCIDR.Overlaps(n.PodCIDR) || !usable(n.NodeIP, n.OuterCIDR) || !usable(p.PodIP, n.PodCIDR) {
		return n, p, errBinding
	}
	return n, p, nil
}

func verify(b, node, pod io.Reader, out io.Writer) error {
	n, p, err := binding(b)
	if err != nil {
		return errBinding
	}
	ns, err := netproof.DecodeSnapshot(node)
	if err != nil {
		return errors.New("snapshot-decode-rejected")
	}
	ps, err := netproof.DecodeSnapshot(pod)
	if err != nil {
		return errors.New("snapshot-decode-rejected")
	}
	proof, err := netproof.VerifyNode(ns, n)
	if err != nil {
		return errors.New("node-classifier-rejected")
	}
	// This CLI verifies the policy-free baseline control. Startup Pods use
	// VerifyPod through their separately bound gate; the control stays strict.
	if !netproof.NodeDials(ps.Dials) || netproof.VerifyPod(ps, p, proof) != nil {
		return errors.New("pod-classifier-rejected")
	}
	if json.NewEncoder(out).Encode(struct {
		NodeClassifierPassed  bool `json:"nodeClassifierPassed"`
		PodClassifierPassed   bool `json:"podClassifierPassed"`
		ExactENETUNREACHCount int  `json:"exactENETUNREACHCount"`
	}{true, true, unreachable(ns.Dials) + unreachable(ps.Dials)}) != nil {
		return errors.New("result-write-rejected")
	}
	return nil
}

func unreachable(d netproof.Dials) int {
	n := 0
	for _, c := range []netproof.DialCategory{d.IPv4, d.IPv6} {
		if c == netproof.NetworkUnreachable {
			n++
		}
	}
	return n
}

func run(args []string, out io.Writer) error {
	if len(args) != 3 {
		return errors.New("arguments-rejected")
	}
	files := make([]*os.File, 0, 3)
	defer func() {
		for _, f := range files {
			_ = f.Close()
		}
	}()
	for _, path := range args {
		f, err := os.Open(path)
		if err != nil {
			return errors.New("evidence-open-rejected")
		}
		info, err := f.Stat()
		if err != nil || !info.Mode().IsRegular() {
			_ = f.Close()
			return errors.New("evidence-open-rejected")
		}
		files = append(files, f)
	}
	return verify(files[0], files[1], files[2], out)
}

func main() {
	if err := run(os.Args[1:], os.Stdout); err != nil {
		fmt.Fprintln(os.Stderr, err.Error()) // Only fixed errors above; never parser input.
		os.Exit(2)
	}
}
