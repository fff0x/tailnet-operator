package controller

import (
	"slices"
	"testing"

	"this-is-fine.io/tailnet-operator/internal/headscale"
)

// approvals must approve exactly the advertised routes covered by an approver prefix that names one
// of the node's tags, keep existing approvals, and ignore non-tag aliases.
func TestApprovals(t *testing.T) {
	approvers := map[string][]string{
		"10.0.10.0/24": {"tag:fabric"},
		"10.0.20.5/32": {"tag:fabric", "tag:other"},
		"10.0.30.0/24": {"group:netadmins"},
		"not-a-prefix": {"tag:fabric"},
		"10.0.40.0/24": {"tag:other"},
	}
	nodes := []headscale.Node{
		{ID: "1", Tags: []string{"tag:fabric"},
			AvailableRoutes: []string{"10.0.10.7/32", "10.0.20.5/32", "10.0.30.1/32", "10.0.40.1/32", "10.0.0.0/8", "10.0.10.1/32"},
			ApprovedRoutes:  []string{"10.0.10.1/32"}},
		{ID: "2", Tags: []string{"tag:bot"}, AvailableRoutes: []string{"10.0.10.8/32"}},
		{ID: "3", Tags: []string{"tag:fabric"}, AvailableRoutes: []string{"10.0.10.9/32"}, ApprovedRoutes: []string{"10.0.10.9/32"}},
	}
	got := approvals(nodes, approvers)
	if len(got) != 1 {
		t.Fatalf("want delta for node 1 only, got %v", got)
	}
	a := got["1"]
	if want := []string{"10.0.10.7/32", "10.0.20.5/32"}; !slices.Equal(a.Added, want) {
		t.Fatalf("added: got %v, want %v", a.Added, want)
	}
	if want := []string{"10.0.10.1/32", "10.0.10.7/32", "10.0.20.5/32"}; !slices.Equal(a.Routes, want) {
		t.Fatalf("routes: got %v, want %v", a.Routes, want)
	}
}
