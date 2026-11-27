package console

import (
	"fmt"
	"slices"
	"strings"

	tnv1 "tsunaro.io/tailnet-operator/api/v1alpha1"
	"tsunaro.io/tailnet-operator/internal/policy"
)

// Map geometry in SVG units. Go places every element; the template only prints coordinates.
const (
	mapWidth  = 960
	mapMargin = 24
	hubX      = 24
	hubW      = 432
	spokeX    = 528
	spokeW    = 408
	boxGap    = 24
	boxPad    = 12
	cellH     = 32
	cellGap   = 8
	rowH      = 20
	mapCap    = 12 // entries per list before "+N more"
	labelMax  = 22 // characters before a label is shortened
)

type mapRow struct {
	Y     int
	Label string
	Value state
}

// mapCell is one entry. Ready colours its square; Nodes ("online", "offline", "unknown") draws a
// circle, "" draws none. Tip is the full text for the tooltip and screen readers.
type mapCell struct {
	X, Y, W int
	Label   string
	Tip     string
	Ready   state
	Nodes   string
	More    bool
}

type mapList struct {
	Y       int // heading baseline
	Heading string
	Cells   []mapCell
	Empty   string
	EmptyY  int
}

type mapBox struct {
	X, Y, W, H int
	Title, Sub string
	Rows       []mapRow
	Lists      []mapList
	Dashed     bool // a spoke the hub cannot reach
}

type mapLink struct {
	D      string
	Dashed bool
}

type tailnetMap struct {
	Name    string
	Height  int
	Grid    string
	Hub     mapBox
	Spokes  []mapBox
	Links   []mapLink
	Problem bool // the operator's console API gave no nodes or no readable policy
}

// entry is a cell before layout.
type entry struct {
	label, tip string
	ready      state
	nodes      string
	notReady   bool
}

// buildMap draws one Tailnet by the rules of the map:
//  1. The hub on the left, one box per spec.policy.spokes[] entry on the right, sorted by name.
//  2. The hub shows the Tailnet, its TailnetIngresses (Ready, node state) and TailnetSites (Ready).
//  3. A spoke shows its three conditions, whether a change waits, and its entries.
//  4. Spoke entries are tags: the tags of tagged nodes and the tag destinations of the live rules.
//     A tag belongs to the first spoke (by name) whose patterns match it; hub ingress tags never.
//  5. A spoke entry's ports are the ports of all live rules with that tag as destination.
//  6. Node state of a tag: online (a node is online), offline (nodes, none online), unknown.
//  7. Over 12 entries a list shows the first 12 by name and "+N more", with ", k not ready" when
//     hidden entries are not ready (Ready not True; for a spoke entry: not online).
//  8. User references, node names, sources and spec.owner never appear.
func buildMap(tn *tnv1.Tailnet, ins []tnv1.TailnetIngress, sites []tnv1.TailnetSite, data tailnetData, dataErr error) tailnetMap {
	m := tailnetMap{Name: tn.Name, Problem: dataErr != nil}
	_, rules, err := parseLive(data.Policy)
	if err != nil {
		m.Problem, rules = true, nil
	}
	nodes := func(tag string) string {
		seen, online := false, false
		for _, n := range data.Nodes {
			if slices.Contains(n.Tags, tag) {
				seen, online = true, online || n.Online
			}
		}
		switch {
		case online:
			return "online"
		case seen:
			return "offline"
		}
		return "unknown"
	}

	hubTags := map[string]bool{}
	var ingressEntries, siteEntries []entry
	for i := range ins {
		in := &ins[i]
		if in.Status.Tag != "" {
			hubTags[in.Status.Tag] = true
		}
		ready := condState(in.Status.Conditions, "Ready")
		ns := nodes(in.Status.Tag)
		if in.Status.Tag == "" {
			ns = "unknown"
		}
		tip := []string{"ingress " + in.Namespace + "/" + in.Name, "tag: " + or(in.Status.Tag, "—"),
			"ports: " + strings.Join(exposePorts(in), ", ")}
		if len(in.Status.Hosts) > 0 {
			tip = append(tip, "hosts: "+strings.Join(in.Status.Hosts, ", "))
		}
		tip = append(tip, "ready: "+ready.Text, "nodes: "+ns)
		ingressEntries = append(ingressEntries, entry{label: in.Namespace + "/" + in.Name, tip: strings.Join(tip, "\n"),
			ready: ready, nodes: ns, notReady: ready.Class != "ok"})
	}
	for i := range sites {
		st := &sites[i]
		ready := condState(st.Status.Conditions, "Ready")
		var prefixes []string
		for _, p := range st.Spec.Prefixes {
			prefixes = append(prefixes, string(p))
		}
		siteEntries = append(siteEntries, entry{label: st.Name, ready: ready, notReady: ready.Class != "ok",
			tip: strings.Join([]string{"site " + st.Name, "prefixes: " + strings.Join(prefixes, ", "), "ready: " + ready.Text}, "\n")})
	}

	ver := or(tn.Status.Version, "—")
	m.Hub = mapBox{X: hubX, Y: mapMargin, W: hubW, Title: "Hub · " + tn.Name, Sub: tn.Spec.Server}
	y := m.Hub.header([]mapRow{{Label: "Headscale", Value: state{Text: ver}}, {Label: "Policy mode", Value: state{Text: policyMode(tn)}},
		{Label: "Policy", Value: policyState(tn.Status.Conditions)}})
	y = m.Hub.list(y, "Ingresses", ingressEntries, "No TailnetIngress.")
	y = m.Hub.list(y, "Sites", siteEntries, "No TailnetSite.")
	m.Hub.H = y + boxPad - m.Hub.Y

	refs := slices.Clone(tn.Spec.Policy.Spokes)
	slices.SortFunc(refs, func(a, b tnv1.SpokeRef) int { return strings.Compare(a.Name, b.Name) })
	owned := map[string][]entry{}
	for _, st := range spokeTags(tn, hubTags, data, rules) {
		ns := nodes(st.tag)
		tip := []string{st.tag, "spoke " + st.spoke, "ports: " + or(strings.Join(st.ports, ", "), "— (no live rule)"), "nodes: " + ns}
		owned[st.spoke] = append(owned[st.spoke], entry{label: st.tag, tip: strings.Join(tip, "\n"),
			ready: state{Text: ns, Class: map[string]string{"online": "ok", "offline": "bad", "unknown": "unknown"}[ns]}, notReady: ns != "online"})
	}

	statuses := map[string]tnv1.SpokeStatus{}
	for _, st := range tn.Status.Spokes {
		statuses[st.Name] = st
	}
	y = mapMargin
	for _, sp := range refs {
		st := statuses[sp.Name]
		b := mapBox{X: spokeX, Y: y, W: spokeW, Title: "Spoke · " + sp.Name}
		reach := condState(st.Conditions, "SpokeReachable")
		b.Dashed = reach.Class != "ok"
		pending := "no"
		if st.PendingHash != "" {
			pending = "yes"
		}
		end := b.header([]mapRow{{Label: "Reachable", Value: reach}, {Label: "Fragment", Value: condState(st.Conditions, "SpokeFragmentValid")},
			{Label: "Approved", Value: condState(st.Conditions, "SpokeFragmentApproved")}, {Label: "Pending change", Value: state{Text: pending}}})
		end = b.list(end, "Tags", owned[sp.Name], "No tag of this spoke is known.")
		b.H = end + boxPad - b.Y
		m.Spokes = append(m.Spokes, b)
		m.Links = append(m.Links, mapLink{D: fmt.Sprintf("M%d %dH%dV%dH%d", hubX+hubW, m.Hub.Y+21, (hubX+hubW+spokeX)/2, b.Y+21, spokeX),
			Dashed: b.Dashed})
		y += b.H + boxGap
	}
	m.Height = max(m.Hub.Y+m.Hub.H, y-boxGap) + mapMargin
	var grid strings.Builder
	for gy := mapMargin + 36; gy < m.Height-mapMargin; gy += 60 {
		fmt.Fprintf(&grid, "M%d %dH%d", mapMargin, gy, mapWidth-mapMargin)
	}
	for gx := 120; gx < mapWidth-mapMargin; gx += 120 {
		fmt.Fprintf(&grid, "M%d %dV%d", gx, mapMargin, m.Height-mapMargin)
	}
	m.Grid = grid.String()
	return m
}

type spokeTag struct {
	spoke, tag string
	ports      []string // as the live rules write them, sorted
}

// spokeTags applies rules 4 and 5: candidate tags are those of tagged nodes and the tag
// destinations of the live rules; each goes to the first spoke by name whose patterns match it,
// except a tag of the hub's own ingresses. The result is sorted by tag.
func spokeTags(tn *tnv1.Tailnet, hubTags map[string]bool, data tailnetData, rules []liveRule) []spokeTag {
	refs := slices.Clone(tn.Spec.Policy.Spokes)
	slices.SortFunc(refs, func(a, b tnv1.SpokeRef) int { return strings.Compare(a.Name, b.Name) })
	ports := map[string][]string{}
	for _, n := range data.Nodes {
		for _, t := range n.Tags {
			if _, ok := ports[t]; !ok {
				ports[t] = nil
			}
		}
	}
	for _, r := range rules {
		for _, d := range r.dst {
			if strings.HasPrefix(d, "tag:") {
				if _, ok := ports[d]; !ok {
					ports[d] = nil
				}
				for _, p := range r.ports {
					if !slices.Contains(ports[d], p) {
						ports[d] = append(ports[d], p)
					}
				}
			}
		}
	}
	var out []spokeTag
	for tag, ps := range ports {
		if hubTags[tag] {
			continue
		}
		for _, sp := range refs {
			if policy.Allowed(tag, spokePatterns(&sp)) {
				slices.Sort(ps)
				out = append(out, spokeTag{spoke: sp.Name, tag: tag, ports: ps})
				break
			}
		}
	}
	slices.SortFunc(out, func(a, b spokeTag) int { return strings.Compare(a.tag, b.tag) })
	return out
}

// header places the condition rows (Y is a text baseline; title at Y+26, subtitle at Y+46) and
// returns where the lists begin.
func (b *mapBox) header(rows []mapRow) int {
	y := b.Y + 50
	if b.Sub != "" {
		y += 18
	}
	for _, r := range rows {
		r.Y = y
		b.Rows = append(b.Rows, r)
		y += rowH
	}
	return y
}

// list places a heading and the cells in two columns and returns the y below them (rule 7).
func (b *mapBox) list(y int, heading string, entries []entry, empty string) int {
	slices.SortFunc(entries, func(a, b entry) int { return strings.Compare(a.label, b.label) })
	l := mapList{Y: y + 22, Heading: fmt.Sprintf("%s (%d)", heading, len(entries))}
	y += 32
	if len(entries) == 0 {
		l.Empty, l.EmptyY = empty, y+14
		b.Lists = append(b.Lists, l)
		return y + rowH
	}
	shown := entries
	var more *mapCell
	if len(entries) > mapCap {
		shown = entries[:mapCap]
		text := fmt.Sprintf("+%d more", len(entries)-mapCap)
		bad := 0
		for _, e := range entries[mapCap:] {
			if e.notReady {
				bad++
			}
		}
		if bad > 0 {
			text += fmt.Sprintf(", %d not ready", bad)
		}
		more = &mapCell{Label: text, Tip: text + "; the tables below list every entry.", More: true}
	}
	w := (b.W - 2*boxPad - cellGap) / 2
	place := func(i int, c mapCell) {
		c.X, c.Y, c.W = b.X+boxPad+(i%2)*(w+cellGap), y+(i/2)*(cellH+cellGap), w
		l.Cells = append(l.Cells, c)
	}
	for i, e := range shown {
		place(i, mapCell{Label: shorten(e.label), Tip: e.tip, Ready: e.ready, Nodes: e.nodes})
	}
	n := len(shown)
	if more != nil {
		place(n, *more)
		n++
	}
	b.Lists = append(b.Lists, l)
	return y + (n+1)/2*(cellH+cellGap) - cellGap
}

func shorten(s string) string {
	r := []rune(s)
	if len(r) <= labelMax {
		return s
	}
	return string(r[:labelMax-1]) + "…"
}

func or(s, fallback string) string {
	if s == "" {
		return fallback
	}
	return s
}

// spokePatterns repeats the operator's default (internal/controller spokeTagPatterns).
func spokePatterns(sp *tnv1.SpokeRef) []string {
	if len(sp.TagPatterns) > 0 {
		return sp.TagPatterns
	}
	return []string{"tag:*-" + sp.Name + "-*"}
}

// exposePorts lists an ingress's ports as "443/http".
func exposePorts(in *tnv1.TailnetIngress) []string {
	var out []string
	for _, e := range in.Spec.Exposes {
		mode := e.Mode
		if mode == "" {
			mode = "l4" // the API default; only an object that skipped admission lacks it
		}
		out = append(out, fmt.Sprintf("%d/%s", e.Port, mode))
	}
	return out
}
