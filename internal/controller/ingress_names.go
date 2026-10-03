package controller

import (
	"net"
	"sort"

	tnv1 "tsunaro.io/tailnet-operator/api/v1alpha1"
	"tsunaro.io/tailnet-operator/internal/naming"
)

// ingressDNSPlan separates HTTP routes (keyed by expose identifier) from certificate SANs.
// The base name is always the first SAN when HTTP is present, but is not an implicit route.
// L4-only plans have no HTTP names or certificate names.
type ingressDNSPlan struct {
	baseName         string
	exposeNames      map[string]string
	aliasNames       map[string]string
	certificateNames []string
}

// resolveIngressDNSNames derives names from the current spec and metadata, never status, and
// returns only bounded failure reasons. It is consumed by TLS resolution, target rendering,
// status and the DNS claim model. Typed string fields cannot distinguish an omitted dnsLabel from
// an explicitly empty one on L4 exposes; admission enforces that raw-field presence constraint.
// Nonempty L4 labels are rejected here. TLS source/material validation remains the responsibility
// of TLS resolution.
func resolveIngressDNSNames(in *tnv1.TailnetIngress, tn *tnv1.Tailnet) (ingressDNSPlan, string) {
	if in == nil || tn == nil || len(in.Spec.Exposes) == 0 || len(in.Spec.Exposes) > 50 {
		return ingressDNSPlan{}, "TLSConfigurationInvalid"
	}
	names, labels := make(map[string]bool), make(map[string]bool)
	l4Ports := make(map[int32]bool)
	hasHTTP := false
	for _, expose := range in.Spec.Exposes {
		if naming.ValidateHostname(expose.Name) != nil || names[expose.Name] || expose.Port < 1 || expose.Port > 65535 {
			return ingressDNSPlan{}, "TLSConfigurationInvalid"
		}
		names[expose.Name] = true
		switch expose.Mode {
		case "", "l4":
			if expose.DNSLabel != "" || expose.Alias || l4Ports[expose.Port] || expose.Backend.TLS != nil || expose.Timeouts != nil {
				return ingressDNSPlan{}, "TLSConfigurationInvalid"
			}
			l4Ports[expose.Port] = true
		case "http":
			if expose.Port != 443 || labels[expose.DNSLabel] ||
				(expose.DNSLabel != "" && naming.ValidateHostname(expose.DNSLabel) != nil) {
				return ingressDNSPlan{}, "TLSConfigurationInvalid"
			}
			labels[expose.DNSLabel] = true
			hasHTTP = true
		default:
			return ingressDNSPlan{}, "TLSConfigurationInvalid"
		}
	}
	if hasHTTP && l4Ports[443] {
		return ingressDNSPlan{}, "TLSConfigurationInvalid"
	}

	var plan ingressDNSPlan
	tmpl := tn.Spec.DNS.IngressNameTemplate
	if tmpl != "" {
		plan.baseName = naming.RenderDNSName(tmpl, in.Name, in.Namespace)
		if naming.ValidateDNSName(plan.baseName) != nil {
			return ingressDNSPlan{}, "TLSInvalidDNSName"
		}
	}
	if !hasHTTP {
		return plan, ""
	}
	if plan.baseName == "" || net.ParseIP(plan.baseName) != nil {
		return ingressDNSPlan{}, "TLSInvalidDNSName"
	}

	// Aliases must resolve, so they are only allowed in the SAME literal zone as the primary
	// template: that is the only zone the platform guarantees over the tailnet.
	aliasTmpl := tn.Spec.DNS.IngressAliasTemplate
	aliasZoneOK := aliasTmpl != "" && naming.ZoneOf(aliasTmpl) != "" && naming.ZoneOf(aliasTmpl) == naming.ZoneOf(tmpl)

	plan.exposeNames = make(map[string]string)
	effectiveNames := make(map[string]bool)
	additionalNames := make([]string, 0, len(in.Spec.Exposes))
	for _, expose := range in.Spec.Exposes {
		if expose.Mode != "http" {
			continue
		}
		label := in.Name
		name := plan.baseName
		if expose.DNSLabel != "" {
			label = expose.DNSLabel
			name = naming.RenderDNSName(tmpl, expose.DNSLabel, in.Namespace)
		}
		if naming.ValidateDNSName(name) != nil || net.ParseIP(name) != nil || effectiveNames[name] {
			return ingressDNSPlan{}, "TLSInvalidDNSName"
		}
		effectiveNames[name] = true
		plan.exposeNames[expose.Name] = name
		if name != plan.baseName {
			additionalNames = append(additionalNames, name)
		}
		if !expose.Alias {
			continue
		}
		if !aliasZoneOK {
			return ingressDNSPlan{}, "TLSInvalidDNSName"
		}
		alias := naming.RenderDNSName(aliasTmpl, label, in.Namespace)
		if naming.ValidateDNSName(alias) != nil || net.ParseIP(alias) != nil || alias == plan.baseName || effectiveNames[alias] {
			return ingressDNSPlan{}, "TLSInvalidDNSName"
		}
		effectiveNames[alias] = true
		if plan.aliasNames == nil {
			plan.aliasNames = make(map[string]string)
		}
		plan.aliasNames[expose.Name] = alias
		additionalNames = append(additionalNames, alias)
	}
	sort.Strings(additionalNames)
	plan.certificateNames = append([]string{plan.baseName}, additionalNames...)
	return plan, ""
}
