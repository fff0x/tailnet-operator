// Package naming renders the Tailnet templates and validates the results. Kept pure and separate so
// the one place that turns a CR name into a tailnet identity is unit-tested, not buried in reconcile.
package naming

import (
	"fmt"
	"strings"

	apivalidation "k8s.io/apimachinery/pkg/util/validation"
)

// Render substitutes {name} in a template. That is the only placeholder; anything else is passed
// through, so an operator can hard-code a fixed tag by leaving {name} out entirely.
func Render(tmpl, name string) string {
	return strings.ReplaceAll(tmpl, "{name}", name)
}

// ValidateTag checks a tailnet tag: the "tag:" prefix plus a DNS-1123 label. Headscale itself only
// checks the prefix (tagOwners are not consulted at mint time), so a typo mints a useless node —
// this is the guard that turns that into a rejected CR instead.
func ValidateTag(tag string) error {
	rest, ok := strings.CutPrefix(tag, "tag:")
	if !ok {
		return fmt.Errorf("tag %q must start with 'tag:'", tag)
	}
	if errs := apivalidation.IsDNS1123Label(rest); len(errs) > 0 {
		return fmt.Errorf("tag %q: %s", tag, strings.Join(errs, "; "))
	}
	return nil
}

// RenderDNSName substitutes {name} and {namespace}; everything else (zone, cluster) is literal in
// the template, because the operator knows neither.
func RenderDNSName(tmpl, name, namespace string) string {
	return strings.ReplaceAll(Render(tmpl, name), "{namespace}", namespace)
}

// ValidateDNSName checks a rendered DNS name is a DNS-1123 subdomain (≤253, lowercase labels).
func ValidateDNSName(n string) error {
	if errs := apivalidation.IsDNS1123Subdomain(n); len(errs) > 0 {
		return fmt.Errorf("dns name %q: %s", n, strings.Join(errs, "; "))
	}
	return nil
}

// ValidateHostname checks a tailnet hostname is a DNS-1123 label (≤63, no leading/trailing hyphen).
func ValidateHostname(h string) error {
	if errs := apivalidation.IsDNS1123Label(h); len(errs) > 0 {
		return fmt.Errorf("hostname %q: %s", h, strings.Join(errs, "; "))
	}
	return nil
}
