package console

import (
	"errors"
	"fmt"
	"strings"
	"testing"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	tnv1 "tsunaro.io/tailnet-operator/api/v1alpha1"
)

func mapTailnet() *tnv1.Tailnet {
	return &tnv1.Tailnet{ObjectMeta: metav1.ObjectMeta{Name: "lab"},
		Spec: tnv1.TailnetSpec{Server: "https://hs.example", Policy: tnv1.PolicySpec{BaseConfigMap: "base", Mode: "Apply",
			Spokes: []tnv1.SpokeRef{{Name: "zeta"}, {Name: "alpha", TagPatterns: []string{"tag:shared-*"}}}}},
		Status: tnv1.TailnetStatus{Version: "0.29.6", Conditions: []metav1.Condition{cond("PolicyApplied", "True", "Applied")},
			Spokes: []tnv1.SpokeStatus{
				{Name: "zeta", PendingHash: "sha256:1", Conditions: []metav1.Condition{cond("SpokeReachable", "True", "Fetched"),
					cond("SpokeFragmentValid", "True", "Valid"), cond("SpokeFragmentApproved", "True", "Approved")}},
				{Name: "alpha", Conditions: []metav1.Condition{cond("SpokeReachable", "False", "Unreachable")}},
			}}}
}

func cells(l mapList) map[string]mapCell {
	out := map[string]mapCell{}
	for _, c := range l.Cells {
		out[c.Label] = c
	}
	return out
}

func TestMapRules(t *testing.T) {
	ins := []tnv1.TailnetIngress{{ObjectMeta: metav1.ObjectMeta{Namespace: "apps", Name: "web"},
		Spec:   tnv1.TailnetIngressSpec{AllowFrom: []string{"alice@"}, Exposes: []tnv1.Expose{{Port: 443, Mode: "http"}}},
		Status: tnv1.TailnetIngressStatus{Tag: "tag:web-zeta-1", Conditions: []metav1.Condition{cond("Ready", "True", "Ready")}}}}
	sites := []tnv1.TailnetSite{{ObjectMeta: metav1.ObjectMeta{Name: "office"},
		Spec:   tnv1.TailnetSiteSpec{Prefixes: []tnv1.GatewayPrefix{"10.20.0.0/16"}, Owner: "network team"},
		Status: tnv1.TailnetSiteStatus{Conditions: []metav1.Condition{cond("Ready", "False", "NoGateway")}}}}
	data := tailnetData{
		Nodes: []taggedNode{{Online: true, Tags: []string{"tag:db-zeta-1"}}, {Tags: []string{"tag:db-zeta-1"}},
			{Tags: []string{"tag:cache-zeta-1"}}, {Online: true, Tags: []string{"tag:web-zeta-1"}}, {Tags: []string{"tag:shared-a"}}},
		Policy: `{"grants": [
			{"src": ["alice@"], "dst": ["tag:db-zeta-1"], "ip": ["tcp:5432"]},
			{"src": ["group:ops"], "dst": ["tag:db-zeta-1", "tag:api-zeta-2"], "ip": ["tcp:6432"]},
			{"src": ["*"], "dst": ["tag:shared-zeta-1"], "ip": ["tcp:80"]},
			{"src": ["*"], "dst": ["tag:ci"], "ip": ["tcp:22"]}]}`,
	}
	m := buildMap(mapTailnet(), ins, sites, data, nil)
	if m.Problem || m.Name != "lab" {
		t.Fatalf("map = %+v", m)
	}
	// Rule 1: hub left, spokes right by name.
	if len(m.Spokes) != 2 || m.Spokes[0].Title != "Spoke · alpha" || m.Spokes[1].Title != "Spoke · zeta" || m.Hub.X >= m.Spokes[0].X {
		t.Fatalf("spokes %+v", m.Spokes)
	}
	// Rule 2: Tailnet rows, ingress with Ready and node state, site with Ready only.
	if m.Hub.Sub != "https://hs.example" || m.Hub.Rows[0].Value.Text != "0.29.6" || m.Hub.Rows[1].Value.Text != "Apply" ||
		m.Hub.Rows[2].Value != (state{"Applied", "ok"}) {
		t.Errorf("hub rows %+v", m.Hub.Rows)
	}
	if c := cells(m.Hub.Lists[0])["apps/web"]; c.Ready.Class != "ok" || c.Nodes != "online" || !strings.Contains(c.Tip, "443/http") {
		t.Errorf("ingress cell %+v", c)
	}
	if c := cells(m.Hub.Lists[1])["office"]; c.Ready != (state{"NoGateway", "bad"}) || c.Nodes != "" || !strings.Contains(c.Tip, "10.20.0.0/16") {
		t.Errorf("site cell %+v", c)
	}
	// Rule 3: conditions and pending; an unreachable spoke is dashed.
	alpha, zeta := m.Spokes[0], m.Spokes[1]
	if !alpha.Dashed || alpha.Rows[0].Value.Class != "bad" || alpha.Rows[2].Value.Class != "unknown" || alpha.Rows[3].Value.Text != "no" {
		t.Errorf("alpha rows %+v", alpha.Rows)
	}
	if zeta.Dashed || zeta.Rows[2].Value != (state{"Approved", "ok"}) || zeta.Rows[3].Value.Text != "yes" || len(m.Links) != 2 || !m.Links[0].Dashed {
		t.Errorf("zeta rows %+v, links %+v", zeta.Rows, m.Links)
	}
	// Rules 4–6: tags from nodes and rules, first matching spoke, hub ingress tags never; ports; node state.
	z := cells(zeta.Lists[0])
	if len(z) != 3 || z["tag:web-zeta-1"].Label != "" || z["tag:shared-zeta-1"].Label != "" || z["tag:ci"].Label != "" {
		t.Errorf("zeta tags %v", z)
	}
	for tag, want := range map[string]struct{ ready, ports string }{
		"tag:db-zeta-1": {"ok", "tcp:5432, tcp:6432"}, "tag:cache-zeta-1": {"bad", "— (no live rule)"}, "tag:api-zeta-2": {"unknown", "tcp:6432"},
	} {
		if c := z[tag]; c.Ready.Class != want.ready || !strings.Contains(c.Tip, "ports: "+want.ports) {
			t.Errorf("%s = %+v, want %+v", tag, c, want)
		}
	}
	if a := cells(alpha.Lists[0]); len(a) != 2 || a["tag:shared-zeta-1"].Ready.Class != "unknown" || a["tag:shared-a"].Ready.Class != "bad" {
		t.Errorf("alpha tags %v", a)
	}
	// Rule 8: no user reference, source or owner in any text of the map.
	text := fmt.Sprintf("%+v", m)
	for _, leak := range []string{"alice", "group:ops", "network team"} {
		if strings.Contains(text, leak) {
			t.Errorf("map contains %q", leak)
		}
	}
}

// Rule 7: up to 12 entries one by one; above, the first 12 by name and "+N more", counting the
// hidden entries that are not ready.
func TestMapCap(t *testing.T) {
	sites := func(n int, bad ...int) []tnv1.TailnetSite {
		var out []tnv1.TailnetSite
		for i := n - 1; i >= 0; i-- {
			status := "True"
			for _, b := range bad {
				if b == i {
					status = "False"
				}
			}
			out = append(out, tnv1.TailnetSite{ObjectMeta: metav1.ObjectMeta{Name: fmt.Sprintf("s%02d", i)},
				Status: tnv1.TailnetSiteStatus{Conditions: []metav1.Condition{cond("Ready", status, "R")}}})
		}
		return out
	}
	for name, tc := range map[string]struct {
		sites      []tnv1.TailnetSite
		cells      int
		more, last string
	}{
		"12":             {sites(12), 12, "", "s11"},
		"13":             {sites(13), 13, "+1 more", "s11"},
		"13, hidden bad": {sites(13, 12), 13, "+1 more, 1 not ready", "s11"},
		"14, shown bad":  {sites(14, 0, 13), 13, "+2 more, 1 not ready", "s11"},
		"none":           {nil, 0, "", ""},
	} {
		t.Run(name, func(t *testing.T) {
			l := buildMap(mapTailnet(), nil, tc.sites, tailnetData{}, nil).Hub.Lists[1]
			if len(l.Cells) != tc.cells {
				t.Fatalf("cells = %d, want %d", len(l.Cells), tc.cells)
			}
			if tc.cells == 0 {
				if l.Empty == "" || l.Heading != "Sites (0)" {
					t.Fatalf("empty list %+v", l)
				}
				return
			}
			if l.Cells[0].Label != "s00" || l.Cells[11].Label != tc.last {
				t.Errorf("order %s … %s", l.Cells[0].Label, l.Cells[11].Label)
			}
			last := l.Cells[len(l.Cells)-1]
			if (tc.more == "") == last.More || (tc.more != "" && last.Label != tc.more) {
				t.Errorf("last cell %+v, want %q", last, tc.more)
			}
		})
	}
}

// Boxes do not overlap, every cell lies inside its box, and the map is tall enough for all.
func TestMapLayout(t *testing.T) {
	var sites []tnv1.TailnetSite
	var ins []tnv1.TailnetIngress
	for i := range 20 {
		sites = append(sites, tnv1.TailnetSite{ObjectMeta: metav1.ObjectMeta{Name: fmt.Sprintf("site-with-a-very-long-name-%02d", i)}})
		ins = append(ins, tnv1.TailnetIngress{ObjectMeta: metav1.ObjectMeta{Namespace: "ns", Name: fmt.Sprintf("in%02d", i)}})
	}
	var nodes []taggedNode
	for i := range 7 {
		nodes = append(nodes, taggedNode{Tags: []string{fmt.Sprintf("tag:x%d-zeta-1", i), fmt.Sprintf("tag:shared-%d", i)}})
	}
	m := buildMap(mapTailnet(), ins, sites, tailnetData{Nodes: nodes}, nil)
	boxes := append([]mapBox{m.Hub}, m.Spokes...)
	for i, b := range boxes {
		if b.X < 0 || b.X+b.W > mapWidth || b.Y+b.H > m.Height {
			t.Errorf("box %s outside the map: %+v (height %d)", b.Title, b, m.Height)
		}
		for j := i + 1; j < len(boxes); j++ {
			o := boxes[j]
			if b.X < o.X+o.W && o.X < b.X+b.W && b.Y < o.Y+o.H && o.Y < b.Y+b.H {
				t.Errorf("boxes %s and %s overlap", b.Title, o.Title)
			}
		}
		for _, l := range b.Lists {
			for _, c := range l.Cells {
				if c.X < b.X || c.X+c.W > b.X+b.W || c.Y < b.Y || c.Y+cellH > b.Y+b.H {
					t.Errorf("cell %s outside box %s", c.Label, b.Title)
				}
				if len([]rune(c.Label)) > labelMax {
					t.Errorf("label %q not shortened", c.Label)
				}
			}
		}
	}
	if c := m.Hub.Lists[1].Cells[0]; c.Label != "site-with-a-very-long…" || !strings.Contains(c.Tip, "site-with-a-very-long-name-00") {
		t.Errorf("shortened cell %+v", c)
	}
}

// Without an answer of the console API the map shows the Kubernetes objects with unknown nodes.
func TestMapWithoutAPIData(t *testing.T) {
	ins := []tnv1.TailnetIngress{{ObjectMeta: metav1.ObjectMeta{Namespace: "apps", Name: "web"}, Status: tnv1.TailnetIngressStatus{Tag: "tag:web"}}}
	m := buildMap(mapTailnet(), ins, nil, tailnetData{}, errors.New("console API nodes: HTTP 502"))
	if !m.Problem || cells(m.Hub.Lists[0])["apps/web"].Nodes != "unknown" || len(m.Spokes[1].Lists[0].Cells) != 0 {
		t.Fatalf("map = %+v", m)
	}
	if !buildMap(mapTailnet(), nil, nil, tailnetData{Policy: "{"}, nil).Problem {
		t.Error("unreadable policy not flagged")
	}
}
