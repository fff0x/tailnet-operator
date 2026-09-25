package naming

import "testing"

func TestRender(t *testing.T) {
	cases := []struct{ tmpl, name, want string }{
		{"tag:egress-{name}", "isd-dev", "tag:egress-isd-dev"},
		{"egress-{name}", "isd-dev", "egress-isd-dev"},
		{"{name}-{name}", "x", "x-x"},         // every occurrence
		{"tag:fixed", "isd-dev", "tag:fixed"}, // no placeholder → passthrough
	}
	for _, c := range cases {
		if got := Render(c.tmpl, c.name); got != c.want {
			t.Errorf("Render(%q,%q)=%q want %q", c.tmpl, c.name, got, c.want)
		}
	}
}

func TestValidateTag(t *testing.T) {
	ok := []string{"tag:egress-isd-dev", "tag:ns-isd-dev", "tag:fabric", "tag:a1"}
	for _, s := range ok {
		if err := ValidateTag(s); err != nil {
			t.Errorf("ValidateTag(%q) unexpected error: %v", s, err)
		}
	}
	bad := []string{
		"egress-isd-dev", // no prefix
		"tag:",           // empty label
		"tag:-isd",       // leading hyphen
		"tag:isd-",       // trailing hyphen
		"tag:ISD",        // uppercase
		"tag:isd_dev",    // underscore
		"tag:a.b",        // dot
	}
	for _, s := range bad {
		if err := ValidateTag(s); err == nil {
			t.Errorf("ValidateTag(%q) expected error, got nil", s)
		}
	}
}

func TestRenderDNSName(t *testing.T) {
	got := RenderDNSName("{name}-{namespace}.hcloud-1.tailnet.example.internal", "shop", "webshop")
	if want := "shop-webshop.hcloud-1.tailnet.example.internal"; got != want {
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

func TestValidateHostname(t *testing.T) {
	if err := ValidateHostname("egress-isd-dev"); err != nil {
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
