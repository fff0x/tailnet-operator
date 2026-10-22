package controller

import (
	"context"
	"fmt"
	"sort"
	"strings"

	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"

	tnv1 "tsunaro.io/tailnet-operator/api/v1alpha1"
	"tsunaro.io/tailnet-operator/internal/naming"
)

// splitDNSCondition verifies the Headscale split-DNS zone from the outside: Headscale has no DNS
// API, but every node's netmap carries dns.nameservers.split, so one online agent of this Tailnet
// is enough to read the zone back and compare it with the pinned gateway DNS address. Returns
// false whenever the condition is not True so the caller requeues quickly.
func splitDNSCondition(ctx context.Context, c client.Client, tn *tnv1.Tailnet) bool {
	zone := naming.ZoneOf(tn.Spec.DNS.IngressNameTemplate)
	if zone == "" {
		meta.RemoveStatusCondition(&tn.Status.Conditions, "SplitDNS")
		return true
	}
	set := func(status metav1.ConditionStatus, reason, msg string) bool {
		setCond(&tn.Status.Conditions, tn.Generation, "SplitDNS", status, reason, msg)
		return status == metav1.ConditionTrue
	}

	want := gatewayDNSAddresses(ctx, c, tn.Name)
	if len(want) == 0 {
		return set(metav1.ConditionUnknown, "CannotVerify",
			fmt.Sprintf("no TailnetGateway binds this Tailnet; expected dns.nameservers.split.%s to point to your gateway DNS Service IP", zone))
	}
	observer, routes, err := observeDNSRoutes(ctx, c, tn.Name)
	if err != nil {
		return set(metav1.ConditionUnknown, "CannotVerify",
			fmt.Sprintf("no online agent to observe the netmap; expected dns.nameservers.split.%s → %s", zone, strings.Join(want, ", ")))
	}
	status, reason, msg := evaluateSplitDNS(zone, want, routes)
	return set(status, reason, msg+" (observed by "+observer+")")
}

// evaluateSplitDNS compares the netmap's split-DNS routes with the expected resolver set.
func evaluateSplitDNS(zone string, want []string, routes map[string][]string) (metav1.ConditionStatus, string, string) {
	zone = strings.ToLower(strings.TrimSuffix(zone, "."))
	got, ok := routes[zone]
	if !ok {
		return metav1.ConditionFalse, "Missing",
			fmt.Sprintf("dns.nameservers.split.%s is absent from the netmap; expected %s", zone, strings.Join(want, ", "))
	}
	if !sameSet(got, want) {
		return metav1.ConditionFalse, "Mismatch",
			fmt.Sprintf("dns.nameservers.split.%s resolves via %s; expected %s", zone, strings.Join(got, ", "), strings.Join(want, ", "))
	}
	return metav1.ConditionTrue, "Configured", fmt.Sprintf("dns.nameservers.split.%s → %s", zone, strings.Join(want, ", "))
}

func sameSet(a, b []string) bool {
	a, b = append([]string(nil), a...), append([]string(nil), b...)
	sort.Strings(a)
	sort.Strings(b)
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// gatewayDNSAddresses lists the pinned split-DNS LoadBalancer IPs of every gateway bound to tn.
func gatewayDNSAddresses(ctx context.Context, c client.Client, tn string) []string {
	var gws tnv1.TailnetGatewayList
	if err := c.List(ctx, &gws); err != nil {
		return nil
	}
	var out []string
	for _, g := range gws.Items {
		if string(g.Spec.TailnetRef.Name) == tn && g.Spec.Service.LoadBalancerIP != "" {
			out = append(out, string(g.Spec.Service.LoadBalancerIP))
		}
	}
	sort.Strings(out)
	return out
}

// observeDNSRoutes scrapes /dns from the first running agent of this Tailnet, ingresses first.
// ponytail: one observer is enough — Headscale sends the same DNS config to every node.
func observeDNSRoutes(ctx context.Context, c client.Client, tn string) (string, map[string][]string, error) {
	type agentRef struct {
		ns, name string
		labels   map[string]string
	}
	var candidates []agentRef
	var ins tnv1.TailnetIngressList
	if err := c.List(ctx, &ins); err == nil {
		for _, in := range ins.Items {
			if in.Spec.TailnetRef.Name == tn {
				candidates = append(candidates, agentRef{in.Namespace, in.Name, ingressSelectorLabels(in.Name)})
			}
		}
	}
	var egs tnv1.TailnetEgressList
	if err := c.List(ctx, &egs); err == nil {
		for _, eg := range egs.Items {
			if eg.Spec.TailnetRef.Name == tn {
				candidates = append(candidates, agentRef{eg.Namespace, eg.Name, selectorLabels(eg.Name)})
			}
		}
	}
	var body struct {
		Routes map[string][]string `json:"routes"`
	}
	for _, cand := range candidates {
		ip := runningAgentIP(ctx, c, cand.ns, cand.labels)
		if ip == "" {
			continue
		}
		if err := scrapeJSON(ctx, ip, "dns", &body); err == nil {
			return cand.ns + "/" + cand.name, body.Routes, nil
		}
	}
	return "", nil, errNoAgentPod
}
