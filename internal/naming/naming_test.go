package naming

import (
	"strings"
	"testing"
)

func TestRender(t *testing.T) {
	cases := []struct{ tmpl, name, want string }{
		{"tag:egress-{name}", "billing-dev", "tag:egress-billing-dev"},
		{"egress-{name}", "billing-dev", "egress-billing-dev"},
		{"{name}-{name}", "x", "x-x"},             // every occurrence
		{"tag:fixed", "billing-dev", "tag:fixed"}, // no placeholder → passthrough
	}
	for _, c := range cases {
		if got := Render(c.tmpl, c.name); got != c.want {
			t.Errorf("Render(%q,%q)=%q want %q", c.tmpl, c.name, got, c.want)
		}
	}
}

func TestValidateTag(t *testing.T) {
	ok := []string{"tag:egress-billing-dev", "tag:ns-billing-dev", "tag:fabric", "tag:a1"}
	for _, s := range ok {
		if err := ValidateTag(s); err != nil {
			t.Errorf("ValidateTag(%q) unexpected error: %v", s, err)
		}
	}
	bad := []string{
		"egress-billing-dev", // no prefix
		"tag:",               // empty label
		"tag:-abc",           // leading hyphen
		"tag:abc-",           // trailing hyphen
		"tag:ABC",            // uppercase
		"tag:abc_dev",        // underscore
		"tag:a.b",            // dot
	}
	for _, s := range bad {
		if err := ValidateTag(s); err == nil {
			t.Errorf("ValidateTag(%q) expected error, got nil", s)
		}
	}
}

func TestRenderDNSName(t *testing.T) {
	got := RenderDNSName("{name}-{namespace}.prod-1.tailnet.example.internal", "shop", "webshop")
	if want := "shop-webshop.prod-1.tailnet.example.internal"; got != want {
		t.Fatalf("got %q want %q", got, want)
	}
	if err := ValidateDNSName(got); err != nil {
		t.Errorf("unexpected error: %v", err)
	}
	for _, s := range []string{"", "Shop.x", "a..b", "-a.b", "a.b-"} {
		if err := ValidateDNSName(s); err == nil {
			t.Errorf("ValidateDNSName(%q) expected error, got nil", s)
		}
	}
}

func TestValidateDNSNameBoundaries(t *testing.T) {
	for _, tc := range []struct {
		name string
		dns  string
		ok   bool
	}{
		{"label-63", strings.Repeat("a", 63) + ".example", true},
		{"label-64", strings.Repeat("a", 64) + ".example", false},
		{"rendered-label-81", RenderDNSName("{name}-{namespace}.cluster.example", strings.Repeat("a", 40), strings.Repeat("b", 40)), false},
		{"separate-labels", RenderDNSName("{name}.{namespace}.cluster.example", strings.Repeat("a", 40), strings.Repeat("b", 40)), true},
		{"total-253", strings.Repeat("a", 63) + "." + strings.Repeat("b", 63) + "." + strings.Repeat("c", 63) + "." + strings.Repeat("d", 61), true},
		{"total-254", strings.Repeat("a", 63) + "." + strings.Repeat("b", 63) + "." + strings.Repeat("c", 63) + "." + strings.Repeat("d", 62), false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if err := ValidateDNSName(tc.dns); (err == nil) != tc.ok {
				t.Fatalf("ValidateDNSName(%q) = %v, want valid=%t", tc.dns, err, tc.ok)
			}
		})
	}
}

func TestZoneOf(t *testing.T) {
	for _, tc := range []struct{ template, want string }{
		{"{name}-{namespace}.prod-1.tailnet.example.com", "prod-1.tailnet.example.com"},
		{"{name}-app.{namespace}.tailnet.example", "tailnet.example"},
		{"{name}-app.prod.example", "prod.example"},
		{"{name}.internal", "internal"},
		{"fixed.prod.example", ""},
		{"", ""},
		{"{name}", ""},
		{"{name}.{namespace}", ""},
		{"{name}.UPPER.example", ""},
		{"{name}..example", ""},
		{"{unknown}.example", ""},
		{"{name.example", ""},
	} {
		t.Run(tc.template, func(t *testing.T) {
			if got := ZoneOf(tc.template); got != tc.want {
				t.Fatalf("ZoneOf(%q) = %q, want %q", tc.template, got, tc.want)
			}
		})
	}
}

func TestValidateHostname(t *testing.T) {
	if err := ValidateHostname("egress-billing-dev"); err != nil {
		t.Errorf("unexpected error: %v", err)
	}
	long := make([]byte, 64)
	for i := range long {
		long[i] = 'a'
	}
	for _, s := range []string{"", "-x", "x-", "Up", string(long)} {
		if err := ValidateHostname(s); err == nil {
			t.Errorf("ValidateHostname(%q) expected error, got nil", s)
		}
	}
}
