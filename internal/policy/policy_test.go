package policy

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"
)

const base = `{
  // comments survive parsing, not rendering
  "groups": {"group:operator": ["alice@"], "group:ops": ["ops@"], "group:shop": ["shop@"]},
  "tagOwners": {
    "tag:fabric": ["group:operator"],
    "tag:egress-legacy": ["group:legacy"],
  },
  "hosts": {"site-dns": "10.0.0.53/32"},
  "autoApprovers": {"routes": {"10.0.0.0/24": ["tag:fabric"], "10.0.10.20/32": ["tag:other"]}},
  "grants": [
    {"src": ["autogroup:member"], "dst": ["site-dns"], "ip": ["udp:53"]},
  ],
  "ssh": [{"action": "accept", "src": ["group:operator"], "dst": ["autogroup:self"], "users": ["root"]}],
  "randomizeClientPort": true,
}`

var inputs = Inputs{
	TagOwners:              []string{"group:operator"},
	RouteApprovers:         []string{"tag:fabric"},
	IngressSourceAllowlist: []string{"group:*"},
	Egresses: []Egress{
		{Tag: "tag:egress-billing-dev", Targets: []Target{
			{CIDR: "10.0.10.20/32", Port: 1521},
			{CIDR: "10.0.10.21/32", Port: 1521},
			{CIDR: "10.0.20.10/32", Port: 5672},
		}},
		{Tag: "tag:egress-legacy", Targets: []Target{{CIDR: "10.0.10.20/32", Port: 1521}}},
	},
	Ingresses: []Ingress{
		{Tag: "tag:ingress-shop", AllowFrom: []string{"group:shop"}, Ports: []int32{443, 443, 8443}},
		{Tag: "tag:ingress-bad", AllowFrom: []string{"tag:bot"}, Ports: []int32{22}},
	},
}

func TestRender(t *testing.T) {
	out, sum, err := Render([]byte(base), inputs)
	if err != nil {
		t.Fatal(err)
	}
	var doc map[string]any
	if err := json.Unmarshal(out, &doc); err != nil {
		t.Fatal(err)
	}
	// tagOwners: legacy tag kept with its base owner; three new tags declared.
	owners := doc["tagOwners"].(map[string]any)
	if got := owners["tag:egress-legacy"].([]any)[0]; got != "group:legacy" {
		t.Fatalf("base tagOwner overwritten: %v", got)
	}
	for _, tag := range []string{"tag:egress-billing-dev", "tag:ingress-shop", "tag:ingress-bad"} {
		if got := owners[tag].([]any)[0]; got != "group:operator" {
			t.Fatalf("tag %s owner = %v", tag, got)
		}
	}
	if sum.Tags != 3 {
		t.Fatalf("tags added = %d", sum.Tags)
	}
	// autoApprovers: existing approver kept and extended; new /32s added; /24 untouched.
	routes := doc["autoApprovers"].(map[string]any)["routes"].(map[string]any)
	if got := routes["10.0.10.20/32"].([]any); len(got) != 2 || got[0] != "tag:other" || got[1] != "tag:fabric" {
		t.Fatalf("10.0.10.20/32 approvers = %v", got)
	}
	if _, ok := routes["10.0.20.10/32"]; !ok || len(routes) != 4 || sum.Routes != 3 {
		t.Fatalf("routes = %v (added %d)", routes, sum.Routes)
	}
	// grants: base kept first; billing-dev → 2 grants (per port), legacy → 1, shop → 1, bad → denied.
	grants := doc["grants"].([]any)
	if len(grants) != 5 || sum.Grants != 4 {
		t.Fatalf("grants = %d (added %d): %s", len(grants), sum.Grants, out)
	}
	g1 := grants[1].(map[string]any)
	if g1["src"].([]any)[0] != "tag:egress-billing-dev" || len(g1["dst"].([]any)) != 2 || g1["ip"].([]any)[0] != "tcp:1521" {
		t.Fatalf("grant[1] = %v", g1)
	}
	shop := grants[4].(map[string]any)
	if shop["dst"].([]any)[0] != "tag:ingress-shop" || len(shop["ip"].([]any)) != 2 {
		t.Fatalf("shop grant = %v", shop)
	}
	if len(sum.Denied) != 1 || sum.Denied[0] != "tag:ingress-bad" {
		t.Fatalf("denied = %v", sum.Denied)
	}
	// Unknown blocks pass through.
	if doc["randomizeClientPort"] != true || len(doc["ssh"].([]any)) != 1 || doc["hosts"] == nil {
		t.Fatalf("passthrough lost: %s", out)
	}
	if strings.Contains(string(out), "//") {
		t.Fatal("comments must not survive rendering")
	}

	// Idempotent: rendering the rendered document adds nothing.
	again, sum2, err := Render(out, inputs)
	if err != nil {
		t.Fatal(err)
	}
	if sum2.Tags+sum2.Grants+sum2.Routes != 0 || string(again) != string(out) {
		t.Fatalf("second render changed the document: %+v", sum2)
	}
	// Normalize ignores formatting.
	n1, _ := Normalize(out)
	n2, _ := Normalize([]byte(" " + strings.ReplaceAll(string(out), "\n", "\n\n")))
	if n1 != n2 || Hash(n1) != Hash(n2) || len(Hash(n1)) != 64 {
		t.Fatal("normalize not canonical")
	}
}

func TestRenderGuards(t *testing.T) {
	if _, _, err := Render([]byte(`{"tagOwners": {}}`), inputs); !errors.Is(err, ErrEmpty) {
		t.Fatalf("empty base: %v", err)
	}
	if _, _, err := Render([]byte(`{"grants": [{}]}`), inputs); !errors.Is(err, ErrEmpty) {
		t.Fatalf("no tagOwners: %v", err)
	}
	if _, _, err := Render([]byte(`not json`), inputs); !errors.Is(err, ErrBaseInvalid) {
		t.Fatalf("invalid: %v", err)
	}
	if _, _, err := Render([]byte(`[]`), inputs); !errors.Is(err, ErrBaseInvalid) {
		t.Fatalf("array: %v", err)
	}
}

func TestParserRedactsInvalidLiterals(t *testing.T) {
	const secret = "synthetic-credential-do-not-emit"
	doc := []byte(`{"value":"` + secret + `\q"}`)
	for _, check := range []struct {
		name string
		call func() error
	}{
		{"render", func() error { _, _, err := Render(doc, inputs); return err }},
		{"normalize", func() error { _, err := Normalize(doc); return err }},
		{"approvers", func() error { _, err := Approvers(doc); return err }},
	} {
		t.Run(check.name, func(t *testing.T) {
			err := check.call()
			if !errors.Is(err, ErrBaseInvalid) {
				t.Fatal("invalid literal must retain its error classification")
			}
			if strings.Contains(err.Error(), secret) {
				t.Fatal("parser disclosed an input literal (output withheld)")
			}
		})
	}
}

func TestAllowed(t *testing.T) {
	if !Allowed("group:shop", []string{"group:*"}) || Allowed("tag:bot", []string{"group:*"}) || Allowed("group:x", nil) {
		t.Fatal("glob allowlist wrong")
	}
}

func TestApprovers(t *testing.T) {
	got, err := Approvers([]byte(`{ // hujson
  "autoApprovers": { "routes": { "10.0.0.0/24": ["tag:fabric"], "10.1.1.1/32": ["tag:a", "group:b"] } },
}`))
	if err != nil || len(got) != 2 || len(got["10.1.1.1/32"]) != 2 || got["10.0.0.0/24"][0] != "tag:fabric" {
		t.Fatalf("got %v, %v", got, err)
	}
	if got, err := Approvers([]byte(`{"grants": []}`)); err != nil || len(got) != 0 {
		t.Fatalf("missing block: got %v, %v", got, err)
	}
}

func TestRenderGateways(t *testing.T) {
	in := Inputs{
		TagOwners: []string{"group:operator"}, RouteApprovers: []string{"tag:fabric"},
		Gateways: []Gateway{
			{Tags: []string{"tag:site", "tag:fabric"}, Routes: []string{"10.0.0.0/24", "198.51.100.0/28", "10.0.10.20/32"}},
			{Tags: []string{"tag:fabric"}, Routes: []string{"198.51.100.0/28"}}, // same prefix, same tag: no change
		},
	}
	out, sum, err := Render([]byte(base), in)
	if err != nil {
		t.Fatal(err)
	}
	var doc map[string]any
	if err := json.Unmarshal(out, &doc); err != nil {
		t.Fatal(err)
	}
	owners := doc["tagOwners"].(map[string]any)
	if got := owners["tag:site"].([]any); len(got) != 1 || got[0] != "group:operator" || owners["tag:fabric"].([]any)[0] != "group:operator" || sum.Tags != 1 {
		t.Fatalf("gateway tags not declared exactly once without touching base owners: %v (added %d)", owners, sum.Tags)
	}
	routes := doc["autoApprovers"].(map[string]any)["routes"].(map[string]any)
	approvers := func(cidr string) string {
		var s []string
		for _, a := range routes[cidr].([]any) {
			s = append(s, a.(string))
		}
		return strings.Join(s, ",")
	}
	// base approver kept first, gateway tags merged in; new prefixes get only the gateway tags.
	if approvers("10.0.0.0/24") != "tag:fabric,tag:site" || approvers("198.51.100.0/28") != "tag:fabric,tag:site" || approvers("10.0.10.20/32") != "tag:other,tag:fabric,tag:site" {
		t.Fatalf("gateway approvers = %v", routes)
	}
	if sum.Routes != 3 {
		t.Fatalf("routes added = %d", sum.Routes)
	}
	again, _, err := Render([]byte(base), in)
	if err != nil || string(again) != string(out) {
		t.Fatal("render is not deterministic")
	}
	// A gateway must not change what the policy says about other prefixes.
	plain, _, _ := Render([]byte(base), Inputs{TagOwners: in.TagOwners, RouteApprovers: in.RouteApprovers})
	var before map[string]any
	_ = json.Unmarshal(plain, &before)
	if len(before["autoApprovers"].(map[string]any)["routes"].(map[string]any)) != 2 {
		t.Fatal("fixture drifted")
	}
}

func TestRenderSites(t *testing.T) {
	plain, _, err := Render([]byte(base), inputs)
	if err != nil {
		t.Fatal(err)
	}
	// No sites: the document is byte-identical to the pre-site render, so upgrading never writes.
	withEmpty := inputs
	withEmpty.Sites = []Site{}
	same, _, _ := Render([]byte(base), withEmpty)
	if string(same) != string(plain) {
		t.Fatal("empty Sites changed the rendered policy")
	}

	in := inputs
	in.Sites = []Site{
		{Prefixes: []string{"10.1.1.0/24", "10.0.0.0/24"}, Approvers: []string{"tag:fabric"}}, // second prefix already in base: no change
		{Prefixes: []string{"100.100.16.0/20"}, Approvers: []string{"tag:mgmt-router", "tag:fabric"}},
	}
	out, sum, err := Render([]byte(base), in)
	if err != nil {
		t.Fatal(err)
	}
	aps, _ := Approvers(out)
	if strings.Join(aps["10.1.1.0/24"], ",") != "tag:fabric" || strings.Join(aps["10.0.0.0/24"], ",") != "tag:fabric" || strings.Join(aps["100.100.16.0/20"], ",") != "tag:fabric,tag:mgmt-router" {
		t.Fatalf("site approvers = %v", aps)
	}
	// Sites add approvers only: tagOwners and grants are untouched.
	var withSites, without map[string]any
	_ = json.Unmarshal(out, &withSites)
	_ = json.Unmarshal(plain, &without)
	if len(withSites["grants"].([]any)) != len(without["grants"].([]any)) || len(withSites["tagOwners"].(map[string]any)) != len(without["tagOwners"].(map[string]any)) {
		t.Fatal("sites changed grants or tagOwners")
	}
	_, plainSum, _ := Render([]byte(base), inputs)
	if sum.Routes != plainSum.Routes+2 {
		t.Fatalf("routes added = %d, want %d", sum.Routes, plainSum.Routes+2)
	}
}

// spokeInputs is a second cluster's CRs: its own tags, an egress target and an ingress.
var spokeInputs = Inputs{
	TagOwners:              []string{"group:operator"},
	RouteApprovers:         []string{"tag:fabric"},
	IngressSourceAllowlist: []string{"group:*"},
	Egresses:               []Egress{{Tag: "tag:egress-spoke-db", Targets: []Target{{CIDR: "10.9.0.5/32", Port: 5432}}}},
	Ingresses:              []Ingress{{Tag: "tag:ingress-spoke-api", AllowFrom: []string{"group:ops"}, Ports: []int32{443}}},
}

func TestRenderFragment(t *testing.T) {
	out, sum, err := RenderFragment(spokeInputs)
	if err != nil {
		t.Fatal(err)
	}
	var doc map[string]any
	if err := json.Unmarshal(out, &doc); err != nil {
		t.Fatal(err)
	}
	// Only the three additive blocks, nothing else (no acls/groups/ssh/hosts).
	if len(doc) != 3 || doc["acls"] != nil || doc["groups"] != nil {
		t.Fatalf("fragment carried unexpected keys: %s", out)
	}
	owners := doc["tagOwners"].(map[string]any)
	if len(owners) != 2 || owners["tag:egress-spoke-db"].([]any)[0] != "group:operator" {
		t.Fatalf("fragment tagOwners = %v", owners)
	}
	routes := doc["autoApprovers"].(map[string]any)["routes"].(map[string]any)
	if len(routes) != 1 || routes["10.9.0.5/32"].([]any)[0] != "tag:fabric" {
		t.Fatalf("fragment routes = %v", routes)
	}
	if len(doc["grants"].([]any)) != 2 || sum.Tags != 2 || sum.Grants != 2 || sum.Routes != 1 {
		t.Fatalf("fragment summary = %+v", sum)
	}
	// Deterministic and allowlist-aware: a denied source never reaches the fragment.
	again, _, _ := RenderFragment(spokeInputs)
	if string(again) != string(out) {
		t.Fatal("RenderFragment not deterministic")
	}
	denied := spokeInputs
	denied.IngressSourceAllowlist = nil
	_, dsum, _ := RenderFragment(denied)
	if dsum.Grants != 1 || len(dsum.Denied) != 1 {
		t.Fatalf("denied ingress leaked into fragment: %+v", dsum)
	}
}

func TestRenderWithFragments(t *testing.T) {
	frag, _, err := RenderFragment(spokeInputs)
	if err != nil {
		t.Fatal(err)
	}
	out, sum, err := Render([]byte(base), inputs, frag)
	if err != nil {
		t.Fatal(err)
	}
	var doc map[string]any
	if err := json.Unmarshal(out, &doc); err != nil {
		t.Fatal(err)
	}
	// The spoke's tags, route and grants are now in the hub render.
	owners := doc["tagOwners"].(map[string]any)
	if owners["tag:egress-spoke-db"] == nil || owners["tag:ingress-spoke-api"] == nil {
		t.Fatalf("spoke tags not merged: %v", owners)
	}
	routes := doc["autoApprovers"].(map[string]any)["routes"].(map[string]any)
	if routes["10.9.0.5/32"] == nil {
		t.Fatalf("spoke route not merged: %v", routes)
	}
	base0, base0Sum, _ := Render([]byte(base), inputs)
	var baseDoc map[string]any
	_ = json.Unmarshal(base0, &baseDoc)
	if len(doc["grants"].([]any)) != len(baseDoc["grants"].([]any))+2 || sum.Grants != base0Sum.Grants+2 {
		t.Fatalf("spoke grants not merged: %d vs %d", len(doc["grants"].([]any)), len(baseDoc["grants"].([]any)))
	}

	// Base wins: a fragment re-declaring a base-owned tag does not overwrite it.
	collide := []byte(`{"tagOwners":{"tag:egress-legacy":["group:evil"]},"grants":[]}`)
	out2, _, err := Render([]byte(base), inputs, collide)
	if err != nil {
		t.Fatal(err)
	}
	_ = json.Unmarshal(out2, &doc)
	if doc["tagOwners"].(map[string]any)["tag:egress-legacy"].([]any)[0] != "group:legacy" {
		t.Fatal("fragment overwrote a base tagOwner")
	}

	// Idempotent: merging the same fragment twice adds nothing the second time, but both count.
	dup, dupSum, _ := Render([]byte(base), inputs, frag, frag)
	if string(dup) != string(out) || dupSum.Grants != sum.Grants || sum.Fragments != 1 || dupSum.Fragments != 2 {
		t.Fatalf("duplicate fragment changed the render: %+v / %+v", sum, dupSum)
	}

	// Fail closed on a foreign key or a non-object fragment.
	for _, bad := range []string{`{"acls":[{"action":"accept"}]}`, `{"groups":{"group:x":["a@"]}}`, `[]`, `not json`} {
		if _, _, err := Render([]byte(base), inputs, []byte(bad)); !errors.Is(err, ErrFragment) {
			t.Fatalf("fragment %q accepted: %v", bad, err)
		}
	}
}
