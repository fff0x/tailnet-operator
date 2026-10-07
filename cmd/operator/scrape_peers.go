package main

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"

	networkingv1 "k8s.io/api/networking/v1"
)

// parseAgentScrapePeers accepts a JSON array of NetworkPolicy peers that may reach the agents'
// health/metrics port. A peer without any selector would admit every source, so it is rejected.
// Like the other agent defaults it never echoes the input.
func parseAgentScrapePeers(raw string) ([]networkingv1.NetworkPolicyPeer, error) {
	if strings.TrimSpace(raw) == "" {
		return nil, nil
	}
	invalid := fmt.Errorf("must be a JSON array of NetworkPolicy peers (namespaceSelector, podSelector or ipBlock), each naming at least one")
	if !strings.HasPrefix(strings.TrimSpace(raw), "[") {
		return nil, invalid
	}
	var peers []networkingv1.NetworkPolicyPeer
	decoder := json.NewDecoder(strings.NewReader(raw))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&peers) != nil || decoder.Decode(new(any)) != io.EOF {
		return nil, invalid
	}
	for _, p := range peers {
		if p.NamespaceSelector == nil && p.PodSelector == nil && p.IPBlock == nil {
			return nil, invalid
		}
	}
	return peers, nil
}
