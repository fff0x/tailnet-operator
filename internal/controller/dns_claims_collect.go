package controller

import (
	"context"
	"fmt"

	"sigs.k8s.io/controller-runtime/pkg/client"

	tnv1 "tsunaro.io/tailnet-operator/api/v1alpha1"
)

// collectDNSClaimDecisions derives the desired DNS claims of every CR bound to tn and arbitrates
// them oldest-owner-wins. CRs whose own derivation fails are skipped: their own reconciler sets
// them Ready=False with the derivation reason and they never serve, so one tenant's
// misconfiguration cannot block unrelated owners.
// ponytail: cluster-wide List from the cache, like the DNS reconciler; no per-peer watch, so
// recovery after the winner disappears relies on each reconciler's bounded requeue.
func collectDNSClaimDecisions(ctx context.Context, c client.Reader, tn *tnv1.Tailnet, operatorNamespace string) (map[dnsClaimOwnerKey]dnsClaimDecision, error) {
	if tn == nil || tn.Spec.DNS.HostsConfigMap == "" {
		return map[dnsClaimOwnerKey]dnsClaimDecision{}, nil
	}
	var sets []dnsDesiredClaims
	var egs tnv1.TailnetEgressList
	if err := c.List(ctx, &egs, client.InNamespace(operatorNamespace)); err != nil {
		return nil, err
	}
	for i := range egs.Items {
		if set, reason := desiredEgressDNSClaims(&egs.Items[i], tn, operatorNamespace); reason == "" && set != nil {
			sets = append(sets, *set)
		}
	}
	var ins tnv1.TailnetIngressList
	if err := c.List(ctx, &ins); err != nil {
		return nil, err
	}
	for i := range ins.Items {
		if set, reason := desiredIngressDNSClaims(&ins.Items[i], tn, operatorNamespace); reason == "" && set != nil {
			sets = append(sets, *set)
		}
	}
	decisions, reason := arbitrateDNSClaims(sets)
	if reason != "" {
		return nil, fmt.Errorf("dns claim arbitration failed: %s", reason)
	}
	out := make(map[dnsClaimOwnerKey]dnsClaimDecision, len(decisions))
	for _, d := range decisions {
		out[d.Desired.Owner.dnsClaimOwnerKey] = d
	}
	return out, nil
}

// dnsConflictError renders a DNSNameConflict condition message for a losing owner.
func dnsConflictError(conflict *dnsClaimConflict) error {
	return fmt.Errorf("dns name %q is already claimed by %s %s/%s",
		conflict.Name, conflict.Owner.Kind, conflict.Owner.Namespace, conflict.Owner.Name)
}
