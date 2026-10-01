// Package netproof is a deliberately narrow fixture network classifier. A proof
// does not establish container/bridge ownership, Pod security, or freshness;
// callers must bind captures to live, owned fixtures before trusting them.
package netproof

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"net/netip"
)

const (
	Version   = 1
	MaxJSON   = 1 << 20
	maxLinks  = 128
	maxRoutes = 4096
	maxRules  = 32
)

var (
	ErrCapture     = errors.New("netproof: capture rejected")
	ErrUnsupported = errors.New("netproof: unsupported platform")
	ErrInvalid     = errors.New("netproof: proof rejected")
)

// Prefixes in Addresses retain their host bits. Route destinations are masked.
type Link struct {
	Index     int            `json:"index"`
	PeerIndex int            `json:"peerIndex"`
	Kind      string         `json:"kind"`
	Up        bool           `json:"up"`
	Loopback  bool           `json:"loopback"`
	Addresses []netip.Prefix `json:"addresses"`
}

type Route struct {
	Family      int          `json:"family"` // 4 or 6, independent of platform AF constants
	Destination netip.Prefix `json:"destination"`
	Gateway     netip.Addr   `json:"gateway"`
	Source      netip.Addr   `json:"source"`
	LinkIndex   int          `json:"linkIndex"`
	Table       uint32       `json:"table"`
	Type        uint8        `json:"type"`
	Scope       uint8        `json:"scope"`
	Protocol    uint8        `json:"protocol"`
	Flags       uint32       `json:"flags"`
}

type Rule struct {
	Family         int    `json:"family"`
	Table          uint32 `json:"table"`
	Priority       uint32 `json:"priority"`
	Action         uint8  `json:"action"`
	Protocol       uint8  `json:"protocol"`
	SuppressPrefix uint32 `json:"suppressPrefix"`
}

type DialCategory string

const (
	NetworkUnreachable       DialCategory = "ENETUNREACH"
	AddressFamilyUnsupported DialCategory = "EAFNOSUPPORT"
	Refused                  DialCategory = "refused"
	TimedOut                 DialCategory = "timeout"
	Connected                DialCategory = "connected"
	OtherFailure             DialCategory = "other"
)

type Dials struct {
	IPv4 DialCategory `json:"ipv4"`
	IPv6 DialCategory `json:"ipv6"`
}

type Snapshot struct {
	Version int     `json:"version"`
	UID     int     `json:"uid"`
	Links   []Link  `json:"links"`
	Routes  []Route `json:"routes"`
	Rules   []Rule  `json:"rules"`
	Dials   Dials   `json:"dials"`
}

// NodeBinding is an assertion from the caller's separate live ownership gate.
// Only canonical private /24 networks are supported by this routed-veth model.
type NodeBinding struct {
	OuterCIDR netip.Prefix
	NodeIP    netip.Addr
	PodCIDR   netip.Prefix
}
type PodBinding struct{ PodIP netip.Addr }

// NodeProof cannot be constructed or modified outside this package. It retains
// copies, never caller-owned slices. Its zero value is not evidence.
type NodeProof struct{ state *nodeState }
type nodeState struct {
	binding NodeBinding
	peers   map[int]Link
	returns map[netip.Addr]int
}

// DecodeSnapshot bounds private evidence input. Verification is still required.
func DecodeSnapshot(r io.Reader) (Snapshot, error) {
	var s Snapshot
	b, err := io.ReadAll(io.LimitReader(r, MaxJSON+1))
	if err != nil || len(b) > MaxJSON {
		return s, ErrInvalid
	}
	d := json.NewDecoder(bytes.NewReader(b))
	d.DisallowUnknownFields()
	if d.Decode(&s) != nil {
		return Snapshot{}, ErrInvalid
	}
	var extra any
	if d.Decode(&extra) != io.EOF {
		return Snapshot{}, ErrInvalid
	}
	return s, nil
}

func validBinding(b NodeBinding) bool {
	return private24(b.OuterCIDR) && private24(b.PodCIDR) &&
		!b.OuterCIDR.Overlaps(b.PodCIDR) && usable(b.NodeIP, b.OuterCIDR)
}
func private24(p netip.Prefix) bool {
	return p.IsValid() && p.Addr().Is4() && p.Bits() == 24 && p == p.Masked() && p.Addr().IsPrivate()
}
func last(p netip.Prefix) netip.Addr {
	a := p.Masked().Addr().As4()
	a[3] = 255
	return netip.AddrFrom4(a)
}
func usable(a netip.Addr, p netip.Prefix) bool {
	return a.Is4() && p.Contains(a) && a != p.Addr() && a != last(p)
}
func host(a netip.Addr) netip.Prefix { return netip.PrefixFrom(a, a.BitLen()) }
func hasAddress(l Link, a netip.Addr) bool {
	for _, p := range l.Addresses {
		if p.Addr() == a {
			return true
		}
	}
	return false
}
func ipv4(l Link) netip.Prefix {
	for _, p := range l.Addresses {
		if p.Addr().Is4() {
			return p
		}
	}
	return netip.Prefix{}
}

// NodeDials is authoritative for isolation: the node namespace has no default
// route, so both documentation-address dials must fail with ENETUNREACH.
func NodeDials(d Dials) bool { return d.IPv4 == NetworkUnreachable && d.IPv6 == NetworkUnreachable }

// PodDials accepts the Pod-side outcome under an active NetworkPolicy. The Pod
// routes IPv4 via the node, whose ICMP unreachable reply is dropped by
// kube-network-policies before conntrack confirmation, so the SYN times out
// instead of failing fast. IPv6 has no default route and stays strict. The
// Pod is only trusted together with a fresh NodeProof in the same window.
func PodDials(d Dials) bool {
	return d.IPv6 == NetworkUnreachable && (d.IPv4 == NetworkUnreachable || d.IPv4 == TimedOut)
}

func common(s Snapshot, uid int) (map[int]Link, error) {
	if s.Version != Version || s.UID != uid || len(s.Links) < 2 || len(s.Links) > maxLinks ||
		len(s.Routes) == 0 || len(s.Routes) > maxRoutes || !standardRules(s.Rules) {
		return nil, ErrInvalid
	}
	links := make(map[int]Link)
	loops := 0
	for _, l := range s.Links {
		if l.Index <= 0 || l.Index > 1<<30 || l.PeerIndex <= 0 || l.PeerIndex > 1<<30 || !l.Up || len(l.Addresses) == 0 || len(l.Addresses) > 8 {
			return nil, ErrInvalid
		}
		if _, exists := links[l.Index]; exists {
			return nil, ErrInvalid
		}
		if l.Loopback {
			loops++
			if l.Kind != "loopback" || l.PeerIndex != l.Index {
				return nil, ErrInvalid
			}
		} else if l.Kind != "veth" {
			return nil, ErrInvalid
		}
		seen := map[netip.Prefix]bool{}
		n4 := 0
		for _, p := range l.Addresses {
			if !p.IsValid() || p.Addr().Zone() != "" || p.Addr().Is4In6() || seen[p] {
				return nil, ErrInvalid
			}
			seen[p] = true
			if l.Loopback {
				if p != netip.MustParsePrefix("127.0.0.1/8") && p != netip.MustParsePrefix("::1/128") {
					return nil, ErrInvalid
				}
			} else if p.Addr().Is4() {
				n4++
			} else if !p.Addr().IsLinkLocalUnicast() || p.Bits() != 64 {
				return nil, ErrInvalid
			}
		}
		if !l.Loopback && n4 != 1 {
			return nil, ErrInvalid
		}
		links[l.Index] = l
	}
	if loops != 1 {
		return nil, ErrInvalid
	}
	for _, r := range s.Routes {
		l, ok := links[r.LinkIndex]
		if !ok || !r.Destination.IsValid() || r.Destination != r.Destination.Masked() || r.Flags != 0 ||
			r.Destination.Addr().Is4In6() || r.Destination.Addr().Zone() != "" ||
			(r.Family != 4 && r.Family != 6) || (r.Family == 4) != r.Destination.Addr().Is4() ||
			(r.Table != 254 && r.Table != 255) || (r.Source.IsValid() && !hasAddress(l, r.Source)) ||
			(r.Source.IsValid() && r.Source.Is4() != (r.Family == 4)) {
			return nil, ErrInvalid
		}
		if r.Family == 6 && !local6(r, l) {
			return nil, ErrInvalid
		}
		if r.Family == 4 && l.Loopback && !local4(r, l) {
			return nil, ErrInvalid
		}
	}
	return links, nil
}

func standardRules(rs []Rule) bool {
	if len(rs) != 5 {
		return false
	}
	seen := map[[2]uint32]bool{}
	for _, r := range rs {
		if r.Action != 1 || r.Protocol != 2 || r.SuppressPrefix != ^uint32(0) {
			return false
		}
		want := uint32(0)
		switch r.Table {
		case 255:
			want = 0
		case 254:
			want = 32766
		case 253:
			if r.Family != 4 {
				return false
			}
			want = 32767
		default:
			return false
		}
		k := [2]uint32{uint32(r.Family), r.Table}
		if (r.Family != 4 && r.Family != 6) || r.Priority != want || seen[k] {
			return false
		}
		seen[k] = true
	}
	return true
}

// local4 accepts only addresses and broadcast endpoints of an actual prefix.
func local4(r Route, l Link) bool {
	if r.Gateway.IsValid() || r.Protocol != 2 || r.Table != 255 {
		return false
	}
	p := ipv4(l)
	if !p.IsValid() {
		return false
	}
	if r.Type == 2 && r.Scope == 254 {
		return r.Destination == host(p.Addr()) || (l.Loopback && r.Destination == p.Masked())
	}
	if r.Type == 3 && r.Scope == 253 && r.Destination.Bits() == 32 && p.Bits() < 32 {
		// Broadcast computation also handles the loopback /8.
		a := p.Masked().Addr().As4()
		bits := uint32(a[0])<<24 | uint32(a[1])<<16 | uint32(a[2])<<8 | uint32(a[3])
		bits |= ^uint32(0) >> p.Bits()
		end := netip.AddrFrom4([4]byte{byte(bits >> 24), byte(bits >> 16), byte(bits >> 8), byte(bits)})
		return r.Destination.Addr() == p.Masked().Addr() || r.Destination.Addr() == end
	}
	return false
}
func local6(r Route, l Link) bool {
	if r.Gateway.IsValid() || (r.Protocol != 2 && r.Protocol != 3) || r.Scope != 0 {
		return false
	}
	if l.Loopback {
		return r.Table == 255 && r.Type == 2 && r.Destination == netip.MustParsePrefix("::1/128") && hasAddress(l, r.Destination.Addr())
	}
	if r.Type == 5 && r.Table == 255 && r.Destination == netip.MustParsePrefix("ff00::/8") {
		return true
	}
	for _, p := range l.Addresses {
		if !p.Addr().Is6() || !p.Addr().IsLinkLocalUnicast() {
			continue
		}
		if r.Type == 2 && r.Table == 255 && r.Destination == host(p.Addr()) {
			return true
		}
		if r.Type == 1 && r.Table == 254 && r.Destination == p.Masked() {
			return true
		}
	}
	return false
}

func VerifyNode(s Snapshot, b NodeBinding) (NodeProof, error) {
	if !validBinding(b) || !NodeDials(s.Dials) {
		return NodeProof{}, ErrInvalid
	}
	links, err := common(s, 65534)
	if err != nil {
		return NodeProof{}, err
	}
	st := &nodeState{binding: b, peers: map[int]Link{}, returns: map[netip.Addr]int{}}
	outer := 0
	for _, l := range links {
		if l.Loopback {
			continue
		}
		p := ipv4(l)
		if p == netip.PrefixFrom(b.NodeIP, b.OuterCIDR.Bits()) {
			if outer != 0 {
				return NodeProof{}, ErrInvalid
			}
			outer = l.Index
		} else {
			if p.Bits() != 32 || !usable(p.Addr(), b.PodCIDR) {
				return NodeProof{}, ErrInvalid
			}
			l.Addresses = append([]netip.Prefix(nil), l.Addresses...)
			st.peers[l.Index] = l
		}
	}
	if outer == 0 {
		return NodeProof{}, ErrInvalid
	}
	connected := 0
	for _, r := range s.Routes {
		l := links[r.LinkIndex]
		if r.Family == 6 || l.Loopback {
			continue
		}
		if r.Gateway.IsValid() {
			return NodeProof{}, ErrInvalid
		}
		if local4(r, l) {
			continue
		}
		if r.LinkIndex == outer {
			if r.Destination != b.OuterCIDR || r.Table != 254 || r.Type != 1 || r.Scope != 253 || r.Protocol != 2 {
				return NodeProof{}, ErrInvalid
			}
			connected++
		} else {
			if r.Destination.Bits() != 32 || !usable(r.Destination.Addr(), b.PodCIDR) || r.Table != 254 || r.Type != 1 || r.Scope != 254 || r.Protocol != 3 {
				return NodeProof{}, ErrInvalid
			}
			if _, exists := st.returns[r.Destination.Addr()]; exists {
				return NodeProof{}, ErrInvalid
			}
			st.returns[r.Destination.Addr()] = r.LinkIndex
		}
	}
	if connected != 1 {
		return NodeProof{}, ErrInvalid
	}
	return NodeProof{state: st}, nil
}

func VerifyPod(s Snapshot, b PodBinding, proof NodeProof) error {
	st := proof.state
	if st == nil || !usable(b.PodIP, st.binding.PodCIDR) || !PodDials(s.Dials) {
		return ErrInvalid
	}
	links, err := common(s, 65532)
	if err != nil {
		return err
	}
	var pod Link
	for _, l := range links {
		if !l.Loopback {
			if pod.Index != 0 {
				return ErrInvalid
			}
			pod = l
		}
	}
	if ipv4(pod) != netip.PrefixFrom(b.PodIP, st.binding.PodCIDR.Bits()) {
		return ErrInvalid
	}
	peer, ok := st.peers[pod.PeerIndex]
	if !ok || peer.PeerIndex != pod.Index || st.returns[b.PodIP] != peer.Index {
		return ErrInvalid
	}
	gateway := ipv4(peer).Addr()
	if gateway == b.PodIP {
		return ErrInvalid
	}
	defaults, subnets, direct := 0, 0, 0
	for _, r := range s.Routes {
		if r.Family == 6 || links[r.LinkIndex].Loopback {
			continue
		}
		if local4(r, pod) {
			continue
		}
		if r.LinkIndex != pod.Index || r.Type != 1 || r.Table != 254 || r.Protocol != 3 {
			return ErrInvalid
		}
		if r.Gateway.IsValid() {
			if r.Gateway != gateway || r.Scope != 0 {
				return ErrInvalid
			}
			switch r.Destination {
			case netip.MustParsePrefix("0.0.0.0/0"):
				defaults++
			case st.binding.PodCIDR:
				subnets++
			default:
				return ErrInvalid
			}
		} else {
			if r.Destination != host(gateway) || r.Scope != 253 {
				return ErrInvalid
			}
			direct++
		}
	}
	if defaults != 1 || subnets != 1 || direct != 1 {
		return ErrInvalid
	}
	return nil
}
