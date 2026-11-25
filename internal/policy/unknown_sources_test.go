package policy

import (
	"encoding/json"
	"slices"
	"testing"
)

// grantSrcs returns the src list of the first grant whose dst contains want, or nil.
func grantSrcs(t *testing.T, doc []byte, want string) []string {
	t.Helper()
	var m map[string]any
	if err := json.Unmarshal(doc, &m); err != nil {
		t.Fatal(err)
	}
	for _, g := range m["grants"].([]any) {
		gm := g.(map[string]any)
		for _, d := range gm["dst"].([]any) {
			if d == want {
				var out []string
				for _, s := range gm["src"].([]any) {
					out = append(out, s.(string))
				}
				return out
			}
		}
	}
	return nil
}

// An undeclared tag: source is dropped from the generated grant; the other sources stay. This is
// the robustness fix for 2026-11-18: one unknown source tag must not freeze the whole policy.
func TestDropUnknownSourceKeepsOthers(t *testing.T) {
	in := Inputs{
		TagOwners:              []string{"group:operator"},
		IngressSourceAllowlist: []string{"group:*", "tag:*"},
		Ingresses: []Ingress{
			{Tag: "tag:ingress-app", AllowFrom: []string{"group:ops", "tag:does-not-exist"}, Ports: []int32{443}},
		},
	}
	out, sum, err := Render([]byte(base), in)
	if err != nil {
		t.Fatal(err)
	}
	if got := grantSrcs(t, out, "tag:ingress-app"); !slices.Equal(got, []string{"group:ops"}) {
		t.Fatalf("src = %v, want [group:ops]", got)
	}
	if !slices.Equal(sum.UnknownSources, []string{"tag:does-not-exist"}) {
		t.Fatalf("UnknownSources = %v", sum.UnknownSources)
	}
}

// If every source of a generated grant is undeclared, the grant vanishes entirely (no empty-src
// grant that Headscale would reject) and the count reflects it.
func TestDropUnknownSourceRemovesEmptyGrant(t *testing.T) {
	in := Inputs{
		TagOwners:              []string{"group:operator"},
		IngressSourceAllowlist: []string{"tag:*"},
		Ingresses: []Ingress{
			{Tag: "tag:ingress-app", AllowFrom: []string{"tag:ghost"}, Ports: []int32{443}},
		},
	}
	out, sum, err := Render([]byte(base), in)
	if err != nil {
		t.Fatal(err)
	}
	if got := grantSrcs(t, out, "tag:ingress-app"); got != nil {
		t.Fatalf("expected no grant, got src %v", got)
	}
	if sum.Grants != 0 || !slices.Equal(sum.UnknownSources, []string{"tag:ghost"}) {
		t.Fatalf("Grants=%d UnknownSources=%v", sum.Grants, sum.UnknownSources)
	}
}

// A tag declared by a merged spoke fragment is NOT unknown: a hub ingress may grant a spoke's
// egress tag (a spoke-exported bridge tag). The tag survives because the fragment adds its tagOwner first.
func TestFragmentDeclaredTagSourceSurvives(t *testing.T) {
	in := Inputs{
		TagOwners:              []string{"group:operator"},
		IngressSourceAllowlist: []string{"tag:*"},
		Ingresses: []Ingress{
			{Tag: "tag:ingress-app", AllowFrom: []string{"tag:egress-spoke-db"}, Ports: []int32{443}},
		},
	}
	out, sum, err := Render([]byte(base), in, []byte(spokeFragmentPolicy))
	if err != nil {
		t.Fatal(err)
	}
	if got := grantSrcs(t, out, "tag:ingress-app"); !slices.Equal(got, []string{"tag:egress-spoke-db"}) {
		t.Fatalf("src = %v, want [tag:egress-spoke-db]", got)
	}
	if len(sum.UnknownSources) != 0 {
		t.Fatalf("UnknownSources = %v, want none", sum.UnknownSources)
	}
}

// A base grant that references an otherwise-undeclared tag is the admin's word and is never touched.
func TestBaseGrantSourcesUntouched(t *testing.T) {
	const baseWithTagSrc = `{"tagOwners":{"tag:fabric":["group:operator"]},` +
		`"groups":{"group:operator":["a@"]},` +
		`"grants":[{"src":["tag:external"],"dst":["tag:fabric"],"ip":["tcp:443"]}]}`
	out, sum, err := Render([]byte(baseWithTagSrc), Inputs{TagOwners: []string{"group:operator"}})
	if err != nil {
		t.Fatal(err)
	}
	if got := grantSrcs(t, out, "tag:fabric"); !slices.Equal(got, []string{"tag:external"}) {
		t.Fatalf("base grant src = %v, want [tag:external]", got)
	}
	if len(sum.UnknownSources) != 0 {
		t.Fatalf("UnknownSources = %v, want none (base untouched)", sum.UnknownSources)
	}
}

// spokeFragmentPolicy declares an egress tag a hub ingress may reference.
const spokeFragmentPolicy = `{"tagOwners":{"tag:egress-spoke-db":["group:operator"]},` +
	`"autoApprovers":{"routes":{}},"grants":[]}`

// An undeclared group: source is dropped like an undeclared tag; Headscale 0.29 rejects a grant
// naming a group the policy does not define. Declared groups and unknown users stay.
func TestDropUnknownGroupSource(t *testing.T) {
	in := Inputs{
		TagOwners:              []string{"group:operator"},
		IngressSourceAllowlist: []string{"group:*", "*@"},
		Ingresses: []Ingress{
			{Tag: "tag:ingress-app", AllowFrom: []string{"group:ghost", "group:ops", "nobody@"}, Ports: []int32{443}},
			{Tag: "tag:ingress-gone", AllowFrom: []string{"group:ghost"}, Ports: []int32{443}},
		},
	}
	out, sum, err := Render([]byte(base), in)
	if err != nil {
		t.Fatal(err)
	}
	if got := grantSrcs(t, out, "tag:ingress-app"); !slices.Equal(got, []string{"group:ops", "nobody@"}) {
		t.Fatalf("src = %v, want [group:ops nobody@]", got)
	}
	if got := grantSrcs(t, out, "tag:ingress-gone"); got != nil {
		t.Fatalf("expected no grant, got src %v", got)
	}
	if sum.Grants != 1 || !slices.Equal(sum.UnknownSources, []string{"group:ghost"}) {
		t.Fatalf("Grants=%d UnknownSources=%v", sum.Grants, sum.UnknownSources)
	}
}

// A spoke fragment grant is filtered against the hub's groups; a base grant is not.
func TestUnknownGroupFragmentFilteredBaseUntouched(t *testing.T) {
	const hub = `{"tagOwners":{"tag:fabric":["group:operator"]},"groups":{"group:operator":["a@"]},` +
		`"grants":[{"src":["group:external"],"dst":["tag:fabric"],"ip":["tcp:443"]}]}`
	const fragment = `{"tagOwners":{"tag:egress-spoke-db":["group:operator"]},` +
		`"grants":[{"src":["group:spoke-only","group:operator"],"dst":["tag:egress-spoke-db"],"ip":["tcp:5432"]}]}`
	out, sum, err := Render([]byte(hub), Inputs{TagOwners: []string{"group:operator"}}, []byte(fragment))
	if err != nil {
		t.Fatal(err)
	}
	if got := grantSrcs(t, out, "tag:fabric"); !slices.Equal(got, []string{"group:external"}) {
		t.Fatalf("base grant src = %v, want [group:external]", got)
	}
	if got := grantSrcs(t, out, "tag:egress-spoke-db"); !slices.Equal(got, []string{"group:operator"}) {
		t.Fatalf("fragment grant src = %v, want [group:operator]", got)
	}
	if !slices.Equal(sum.UnknownSources, []string{"group:spoke-only"}) {
		t.Fatalf("UnknownSources = %v", sum.UnknownSources)
	}
}

// Checking groups must not add a groups key to a base without one: the rendered hash of every
// installation would change and the policy would be rewritten.
func TestUnknownGroupCheckAddsNoGroupsKey(t *testing.T) {
	const noGroups = `{"tagOwners":{"tag:fabric":[]},"acls":[{"action":"accept","src":["*"],"dst":["192.0.2.1:443"]}]}`
	in := Inputs{
		TagOwners:              []string{"tag:fabric"},
		IngressSourceAllowlist: []string{"group:*"},
		Ingresses:              []Ingress{{Tag: "tag:ingress-app", AllowFrom: []string{"group:ghost"}, Ports: []int32{443}}},
	}
	out, sum, err := Render([]byte(noGroups), in)
	if err != nil {
		t.Fatal(err)
	}
	var doc map[string]any
	if err := json.Unmarshal(out, &doc); err != nil {
		t.Fatal(err)
	}
	if _, ok := doc["groups"]; ok {
		t.Fatal("render added a groups key")
	}
	if !slices.Equal(sum.UnknownSources, []string{"group:ghost"}) {
		t.Fatalf("UnknownSources = %v", sum.UnknownSources)
	}
}
