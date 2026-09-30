package metrics

import (
	"slices"
	"strings"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	tnv1 "this-is-fine.io/tailnet-operator/api/v1alpha1"
	"this-is-fine.io/tailnet-operator/internal/headscale"
)

// ObserveNodes follows a successful status update and successful Headscale ListNodes. Matching
// follows the controller's tag/hostname association; no node ID, peer name or address is a label.
// Without an online match, the latest known offline lastSeen is used. An online node's unknown
// lastSeen stays absent rather than borrowing a timestamp from an obsolete offline duplicate.
func (m *Metrics) ObserveNodes(obj metav1.Object, nodes []headscale.Node, tag, hostname string) {
	if m == nil {
		return
	}
	var kind, tailnet string
	switch o := obj.(type) {
	case *tnv1.TailnetEgress:
		kind, tailnet = "TailnetEgress", o.Spec.TailnetRef.Name
	case *tnv1.TailnetIngress:
		kind, tailnet = "TailnetIngress", o.Spec.TailnetRef.Name
	default:
		return
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	id := identity{kind, obj.GetNamespace(), obj.GetName()}
	h := m.objects[id]
	if h == nil || h.uid != obj.GetUID() || h.tailnet != tailnet || h.generation != obj.GetGeneration() {
		return // deleted/recreated after the observed status write, or no successful write yet
	}
	var selected *headscale.Node
	for i := range nodes {
		node := &nodes[i]
		if !slices.Contains(node.Tags, tag) ||
			(node.GivenName != hostname && !strings.HasPrefix(node.GivenName, hostname+"-")) {
			continue
		}
		if node.Online {
			selected = node // association also selects the last online match
		} else if selected == nil || (!selected.Online && node.LastSeen != nil &&
			(selected.LastSeen == nil || node.LastSeen.After(*selected.LastSeen))) {
			selected = node
		}
	}
	labels := []string{kind, obj.GetNamespace(), obj.GetName()}
	m.nodeOnline.WithLabelValues(labels...).Set(truth(selected != nil && selected.Online))
	m.nodeLastSeen.DeleteLabelValues(labels...)
	if selected != nil && selected.LastSeen != nil && selected.LastSeen.Unix() > 0 {
		m.nodeLastSeen.WithLabelValues(labels...).Set(float64(selected.LastSeen.Unix()))
	}
}
