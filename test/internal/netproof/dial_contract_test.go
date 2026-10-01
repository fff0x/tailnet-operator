package netproof

import "testing"

func TestDialContracts(t *testing.T) {
	categories := []DialCategory{NetworkUnreachable, AddressFamilyUnsupported, Refused, TimedOut, Connected, OtherFailure, "", "unknown"}
	for _, v4 := range categories {
		for _, v6 := range categories {
			d := Dials{IPv4: v4, IPv6: v6}
			if NodeDials(d) != (v4 == NetworkUnreachable && v6 == NetworkUnreachable) {
				t.Fatal("node dial contract differs")
			}
			if PodDials(d) != (v6 == NetworkUnreachable && (v4 == NetworkUnreachable || v4 == TimedOut)) {
				t.Fatal("pod dial contract differs")
			}
		}
	}
}

func TestTimeoutStillRequiresBoundNodeProof(t *testing.T) {
	n, p, nb, pb := fixture()
	p.Dials.IPv4 = TimedOut
	if VerifyPod(p, pb, NodeProof{}) == nil {
		t.Fatal("timeout accepted without node proof")
	}
	for _, bad := range []DialCategory{TimedOut, Refused, Connected, OtherFailure, AddressFamilyUnsupported, "", "unknown"} {
		n.Dials.IPv4 = bad
		proof, err := VerifyNode(n, nb)
		if err == nil || VerifyPod(p, pb, proof) == nil {
			t.Fatal("invalid node outcome authorized timeout")
		}
	}
	n.Dials.IPv4 = NetworkUnreachable
	n.Links[2].PeerIndex = 99
	proof, err := VerifyNode(n, nb)
	if err != nil || VerifyPod(p, pb, proof) == nil {
		t.Fatal("timeout did not require reciprocal node binding")
	}
}
