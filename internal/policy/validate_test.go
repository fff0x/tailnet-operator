package policy

import (
	"errors"
	"net/netip"
	"strings"
	"testing"
)

// spokeFixture is the shape a spoke in mode Export produces for a cluster "prod-2": its gateway
// tag (owned by the hub base as well), ingress tags with peer grants, an egress with /32 host
// grants, and the routes its gateway advertises (LAN, tailnet-LB pool, site hosts, one management
// supernet).
const spokeFixture = `{
  "tagOwners": {
    "tag:fabric": ["group:operator"],
    "tag:ingress-prod-2-k8s": ["group:operator"],
    "tag:ingress-prod-2-shop": ["group:operator"],
    "tag:egress-prod-2-billing": ["group:operator"]
  },
  "autoApprovers": {
    "routes": {
      "192.0.2.0/24": ["tag:fabric"],
      "198.51.100.16/28": ["tag:fabric"],
      "203.0.113.7/32": ["tag:fabric"],
      "203.0.113.9/32": ["tag:fabric"],
      "100.80.0.0/14": ["tag:fabric"]
    }
  },
  "grants": [
    {"src": ["group:operator", "tag:bot"], "dst": ["tag:ingress-prod-2-k8s"], "ip": ["tcp:6443"]},
    {"src": ["autogroup:member"], "dst": ["tag:ingress-prod-2-shop"], "ip": ["tcp:443"]},
    {"src": ["tag:egress-prod-2-billing"], "dst": ["203.0.113.7/32", "203.0.113.9/32"], "ip": ["tcp:1528"]}
  ]
}`

func spokeRules() FragmentRules {
	return FragmentRules{
		TagPatterns:            []string{"tag:*-prod-2-*"},
		BaseTags:               map[string]bool{"tag:fabric": true},
		TagOwners:              []string{"group:operator"},
		RouteApprovers:         []string{"tag:fabric"},
		IngressSourceAllowlist: []string{"group:*", "tag:bot", "autogroup:member"},
		Allowed: []netip.Prefix{
			netip.MustParsePrefix("192.0.2.0/24"),     // TailnetSite prod-2-lan
			netip.MustParsePrefix("100.80.0.0/14"),    // TailnetSite mgmt
			netip.MustParsePrefix("198.51.100.16/28"), // spoke routeAllowlist: tailnet-LB pool
		},
		Reserved: []netip.Prefix{
			netip.MustParsePrefix("100.64.0.0/16"),
			netip.MustParsePrefix("10.244.0.0/16"),
			netip.MustParsePrefix("10.96.0.0/12"),
		},
		ContainRoutes: true,
	}
}

func TestValidateFragmentAcceptsSpokeExport(t *testing.T) {
	if err := ValidateFragment([]byte(spokeFixture), spokeRules()); err != nil {
		t.Fatalf("spoke export rejected: %v", err)
	}
	// The Git-reviewed path has no containment and no tag patterns beyond "tag:*".
	git := spokeRules()
	git.TagPatterns = []string{"tag:*"}
	git.Allowed = nil
	git.ContainRoutes = false
	if err := ValidateFragment([]byte(spokeFixture), git); err != nil {
		t.Fatalf("git fragment rejected: %v", err)
	}
}

func TestValidateFragmentRejects(t *testing.T) {
	cases := []struct {
		name string
		doc  string
		want string
	}{
		{"foreign top-level key", `{"acls": []}`, `unexpected key "acls"`},
		{"groups smuggled", `{"groups": {"group:operator": ["x@y"]}}`, `unexpected key "groups"`},
		{"tag outside the spoke's patterns", `{"tagOwners": {"tag:ingress-prod-1-k8s": ["group:operator"]}}`, "does not match the spoke's tag patterns"},
		{"non-tag owner key", `{"tagOwners": {"group:evil": ["group:operator"]}}`, "is not a tag"},
		{"owner outside the hub's tagOwners", `{"tagOwners": {"tag:ingress-prod-2-x": ["autogroup:member"]}}`, "is not in the hub's tagOwners"},
		{"empty owner list", `{"tagOwners": {"tag:ingress-prod-2-x": []}}`, "non-empty list"},
		{"autoApprovers.exitNode", `{"autoApprovers": {"exitNode": ["tag:ingress-prod-2-x"]}}`, "autoApprovers.exitNode is not allowed"},
		{"default route", `{"autoApprovers": {"routes": {"0.0.0.0/0": ["tag:fabric"]}}}`, "default route"},
		{"reserved overlap route", `{"autoApprovers": {"routes": {"100.64.8.0/22": ["tag:fabric"]}}}`, "overlaps reserved network 100.64.0.0/16"},
		{"non-canonical prefix", `{"autoApprovers": {"routes": {"192.0.2.5/24": ["tag:fabric"]}}}`, "not a canonical prefix"},
		{"uncontained route", `{"autoApprovers": {"routes": {"203.0.113.0/24": ["tag:fabric"]}}}`, "lies in no TailnetSite or routeAllowlist prefix"},
		{"foreign approver", `{"autoApprovers": {"routes": {"203.0.113.7/32": ["tag:exit"]}}}`, "neither a fragment tag nor a hub route approver"},
		{"grant with via", `{"grants": [{"src": ["tag:bot"], "dst": ["203.0.113.7/32"], "ip": ["tcp:22"], "via": ["tag:fabric"]}]}`, "grants[0].via is not allowed"},
		{"grant src wildcard", `{"grants": [{"src": ["*"], "dst": ["203.0.113.7/32"], "ip": ["tcp:22"]}]}`, `src "*" is neither a fragment tag nor allowed`},
		{"grant src foreign tag", `{"grants": [{"src": ["tag:ingress-prod-1-k8s"], "dst": ["203.0.113.7/32"], "ip": ["tcp:22"]}]}`, `src "tag:ingress-prod-1-k8s"`},
		{"grant dst wildcard", `{"grants": [{"src": ["tag:bot"], "dst": ["*"], "ip": ["tcp:22"]}]}`, `dst "*" is not a fragment tag or a prefix`},
		{"grant dst foreign tag", `{"grants": [{"src": ["tag:bot"], "dst": ["tag:fabric"], "ip": ["tcp:22"]}]}`, `dst "tag:fabric" is not a fragment tag`},
		{"grant dst autogroup", `{"grants": [{"src": ["tag:bot"], "dst": ["autogroup:internet"], "ip": ["tcp:22"]}]}`, `dst "autogroup:internet"`},
		{"grant dst reserved", `{"grants": [{"src": ["tag:bot"], "dst": ["10.96.0.10/32"], "ip": ["tcp:53"]}]}`, "overlaps reserved network 10.96.0.0/12"},
		{"grant dst uncontained subnet", `{"grants": [{"src": ["tag:bot"], "dst": ["203.0.113.0/24"], "ip": ["tcp:22"]}]}`, "lies in no TailnetSite"},
		{"grant ip wildcard", `{"grants": [{"src": ["tag:bot"], "dst": ["203.0.113.7/32"], "ip": ["*"]}]}`, `ip "*" is not tcp:<port>`},
		{"grant ip udp", `{"grants": [{"src": ["tag:bot"], "dst": ["203.0.113.7/32"], "ip": ["udp:53"]}]}`, `ip "udp:53"`},
		{"grant ip port range", `{"grants": [{"src": ["tag:bot"], "dst": ["203.0.113.7/32"], "ip": ["tcp:1-65535"]}]}`, `ip "tcp:1-65535"`},
		{"grant ip port zero", `{"grants": [{"src": ["tag:bot"], "dst": ["203.0.113.7/32"], "ip": ["tcp:0"]}]}`, `ip "tcp:0"`},
		{"grant empty ip", `{"grants": [{"src": ["tag:bot"], "dst": ["203.0.113.7/32"], "ip": []}]}`, "ip must be a non-empty list"},
		{"grant not an object", `{"grants": ["x"]}`, "grants[0] is not an object"},
		{"not an object", `[]`, "not valid policy HuJSON"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			err := ValidateFragment([]byte(c.doc), spokeRules())
			if err == nil {
				t.Fatalf("accepted: %s", c.doc)
			}
			if !errors.Is(err, ErrFragment) {
				t.Fatalf("not ErrFragment: %v", err)
			}
			if !strings.Contains(err.Error(), c.want) {
				t.Fatalf("message %q lacks %q", err.Error(), c.want)
			}
		})
	}
}

// Without containment a host route anywhere is fine, a subnet route only needs to avoid reserved
// space — the Git review is the gate for fragmentConfigMaps.
func TestValidateFragmentContainmentIsPerRules(t *testing.T) {
	doc := `{"autoApprovers": {"routes": {"203.0.113.0/24": ["tag:fabric"]}}}`
	r := spokeRules()
	if err := ValidateFragment([]byte(doc), r); err == nil {
		t.Fatal("contained rules accepted an uncontained subnet")
	}
	r.ContainRoutes = false
	if err := ValidateFragment([]byte(doc), r); err != nil {
		t.Fatalf("uncontained rules rejected a clean subnet: %v", err)
	}
}
