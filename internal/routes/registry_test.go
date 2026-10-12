package routes

import (
	"fmt"
	"testing"
	"time"
)

var (
	t0     = time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	fabric = []string{"tag:fabric"}
)

func site(name string, created time.Time, prefixes ...string) Site {
	return Site{Name: name, Created: created, Prefixes: prefixes, Tags: fabric}
}

func TestBuildBlocksReservedOverlap(t *testing.T) {
	res := Build(
		[]Site{site("mgmt", t0, "100.64.8.0/22")},
		[]Reserved{{Name: "nodes", Prefixes: []string{"100.64.0.0/16"}}}, nil)
	st := res.States["mgmt"]
	if st.Blocked == nil || st.Blocked.Reason != OverlapsReserved || st.Blocked.Other != "nodes" || st.Blocked.Prefix != "100.64.8.0/22" {
		t.Fatalf("blocked = %+v", st.Blocked)
	}
	if len(res.Shipped) != 0 {
		t.Fatalf("shipped = %v", res.Shipped)
	}
	if got := st.Blocked.Message(); got != "100.64.8.0/22 overlaps reserved network nodes" {
		t.Fatalf("message = %q", got)
	}
}

func TestBuildYoungerSiteBlockedOlderUntouched(t *testing.T) {
	older := site("branch-a", t0, "10.1.1.0/24")
	younger := site("branch-b", t0.Add(time.Hour), "10.1.0.0/16") // covers branch-a
	res := Build([]Site{younger, older}, nil, nil)                // input order must not matter
	if res.States["branch-a"].Blocked != nil {
		t.Fatalf("older site blocked: %+v", res.States["branch-a"].Blocked)
	}
	b := res.States["branch-b"].Blocked
	if b == nil || b.Reason != OverlapsSite || b.Other != "branch-a" || b.Prefix != "10.1.0.0/16" {
		t.Fatalf("younger blocked = %+v", b)
	}
	if len(res.Shipped) != 1 || res.Shipped[0].Name != "branch-a" {
		t.Fatalf("shipped = %v", res.Shipped)
	}
	// Same timestamp: the name decides, deterministically.
	res = Build([]Site{site("b", t0, "10.1.1.0/24"), site("a", t0, "10.1.1.128/25")}, nil, nil)
	if res.States["a"].Blocked != nil || res.States["b"].Blocked == nil {
		t.Fatalf("tie-break: a=%+v b=%+v", res.States["a"].Blocked, res.States["b"].Blocked)
	}
}

func TestBuildBlockedSiteDoesNotBlockOthers(t *testing.T) {
	// A site blocked by a reserved network is not "older" for anyone: a later site overlapping
	// only the blocked one ships.
	res := Build(
		[]Site{site("bad", t0, "100.64.1.0/24"), site("good", t0.Add(time.Minute), "100.64.1.0/25")},
		[]Reserved{{Name: "nodes", Prefixes: []string{"100.64.1.0/24"}}}, nil)
	if res.States["bad"].Blocked == nil || res.States["good"].Blocked == nil {
		t.Fatalf("both must be blocked by the reserved net: %+v %+v", res.States["bad"].Blocked, res.States["good"].Blocked)
	}
	res = Build(
		[]Site{site("bad", t0, "100.64.1.0/24", "10.5.0.0/24"), site("good", t0.Add(time.Minute), "10.5.0.0/25")},
		[]Reserved{{Name: "nodes", Prefixes: []string{"100.64.0.0/16"}}}, nil)
	if res.States["good"].Blocked != nil {
		t.Fatalf("good blocked by a site that itself is blocked: %+v", res.States["good"].Blocked)
	}
}

func TestBuildUnmanagedReportsNeverBlocks(t *testing.T) {
	nodes := []Node{
		{Name: "router", Tags: fabric, Available: []string{"10.1.1.0/24"}, Approved: []string{"10.1.1.0/24"}},
		{Name: "laptop", Tags: []string{"tag:debug"}, Available: []string{"10.1.1.0/26"}},
		{Name: "other", Tags: []string{"tag:debug"}, Available: []string{"10.9.0.0/24"}},
	}
	res := Build([]Site{site("branch-a", t0, "10.1.1.0/24")}, nil, nodes)
	st := res.States["branch-a"]
	if st.Blocked != nil {
		t.Fatalf("blocked = %+v", st.Blocked)
	}
	if len(st.Unmanaged) != 1 || st.Unmanaged[0] != "laptop" {
		t.Fatalf("unmanaged = %v", st.Unmanaged)
	}
	if len(st.Advertised) != 1 || len(st.Approved) != 1 {
		t.Fatalf("advertised=%v approved=%v", st.Advertised, st.Approved)
	}
}

func TestBuildAdvertisedApprovedExactPrefixesHostRoutes(t *testing.T) {
	nodes := []Node{
		// Two HA routers with the same tag: the union counts; a covering aggregate does NOT count
		// as advertising the exact /32 (sites are advertised as-is).
		{Name: "r1", Tags: fabric, Available: []string{"10.2.0.1/32", "10.2.0.0/24"}, Approved: []string{"10.2.0.1/32"}},
		{Name: "r2", Tags: fabric, Available: []string{"10.2.0.2/32"}, Approved: []string{"10.2.0.2/32"}},
	}
	res := Build([]Site{site("hosts", t0, "10.2.0.1/32", "10.2.0.2/32", "10.2.0.3/32")}, nil, nodes)
	st := res.States["hosts"]
	want := []string{"10.2.0.1/32", "10.2.0.2/32"}
	if fmt.Sprint(st.Advertised) != fmt.Sprint(want) || fmt.Sprint(st.Approved) != fmt.Sprint(want) {
		t.Fatalf("advertised=%v approved=%v", st.Advertised, st.Approved)
	}
	if len(st.Unmanaged) != 0 {
		t.Fatalf("unmanaged = %v", st.Unmanaged)
	}
}

// TestBuildLegacySiteShapeHasNoConflicts mirrors the shape of a real multi-branch deployment
// (addresses synthetic): eight /24 branches, four stray hosts, two management supernets in CGNAT
// space next to a /16 node prefix, plus two clusters' LAN/pod/service/LB ranges. Zero conflicts
// is the precondition for migrating such a site set onto TailnetSite CRs.
func TestBuildLegacySiteShapeHasNoConflicts(t *testing.T) {
	var sites []Site
	for i := 1; i <= 8; i++ {
		sites = append(sites, site(fmt.Sprintf("branch-%d", i), t0.Add(time.Duration(i)*time.Minute), fmt.Sprintf("10.1.%d.0/24", i)))
	}
	sites = append(sites,
		site("stray-hosts", t0.Add(time.Hour), "10.2.5.201/32", "10.3.10.45/32", "172.17.1.11/32", "10.1.60.215/32"),
		Site{Name: "mikrotik-mgmt", Created: t0.Add(2 * time.Hour), Tags: []string{"tag:fabric"}, Prefixes: []string{"100.100.16.0/20", "100.112.0.0/14"}},
	)
	reserved := []Reserved{
		{Name: "nodes", Prefixes: []string{"100.64.0.0/16"}},
		{Name: "cluster-a", Prefixes: []string{"10.200.19.0/24", "172.20.0.0/16", "172.21.0.0/16", "10.103.0.16/28"}},
		{Name: "cluster-b", Prefixes: []string{"10.210.1.0/24", "10.244.0.0/16", "10.96.0.0/12", "10.103.2.16/28"}},
	}
	res := Build(sites, reserved, nil)
	if len(res.Shipped) != len(sites) {
		for name, st := range res.States {
			if st.Blocked != nil {
				t.Errorf("%s: %s", name, st.Blocked.Message())
			}
		}
		t.Fatalf("shipped %d of %d", len(res.Shipped), len(sites))
	}
	// Shipped is oldest first regardless of input order.
	if res.Shipped[0].Name != "branch-1" || res.Shipped[len(res.Shipped)-1].Name != "mikrotik-mgmt" {
		t.Fatalf("order: %s … %s", res.Shipped[0].Name, res.Shipped[len(res.Shipped)-1].Name)
	}
}
