package policy

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"
)

const base = `{
  // comments survive parsing, not rendering
  "groups": {"group:operator": ["alice@"]},
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
