package metrics

import (
	"testing"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	tnv1 "this-is-fine.io/tailnet-operator/api/v1alpha1"
	"this-is-fine.io/tailnet-operator/internal/headscale"
)

func TestNodeObservations(t *testing.T) {
	old := time.Date(2026, 9, 1, 0, 0, 0, 0, time.UTC)
	recent := old.Add(time.Hour)
	for _, kind := range []string{"TailnetEgress", "TailnetIngress"} {
		for _, tc := range []struct {
			name   string
			nodes  []headscale.Node
			online float64
			seen   *time.Time
		}{
			{"absent", nil, 0, nil},
			{"online", []headscale.Node{{GivenName: "node", Tags: []string{"tag:fixture"}, Online: true, LastSeen: &recent}}, 1, &recent},
			{"suffixed", []headscale.Node{{GivenName: "node-1", Tags: []string{"tag:fixture"}, Online: true}}, 1, nil},
			{"wrong-tag", []headscale.Node{{GivenName: "node", Tags: []string{"tag:another"}, Online: true, LastSeen: &recent}}, 0, nil},
			{"wrong-name", []headscale.Node{{GivenName: "nodeother", Tags: []string{"tag:fixture"}, Online: true, LastSeen: &recent}}, 0, nil},
			{"latest-offline", []headscale.Node{
				{GivenName: "node", Tags: []string{"tag:fixture"}, LastSeen: &recent},
				{GivenName: "node-1", Tags: []string{"tag:fixture"}, LastSeen: &old},
			}, 0, &recent},
			{"online-unknown-time", []headscale.Node{
				{GivenName: "node", Tags: []string{"tag:fixture"}, Online: true},
				{GivenName: "node-1", Tags: []string{"tag:fixture"}, LastSeen: &recent},
			}, 1, nil},
		} {
			t.Run(kind+"/"+tc.name, func(t *testing.T) {
				m, reg := isolated(t)
				meta := metav1.ObjectMeta{Name: "resource", Namespace: "ns", UID: "first", Generation: 1}
				var obj metav1.Object = &tnv1.TailnetEgress{ObjectMeta: meta}
				if kind == "TailnetIngress" {
					obj = &tnv1.TailnetIngress{ObjectMeta: meta}
				}
				m.ObserveNodes(obj, tc.nodes, "tag:fixture", "node")
				if len(samples(t, reg, "tailnet_node_online")) != 0 {
					t.Fatal("node metrics emitted without successfully observed status")
				}
				m.Observe(obj)
				m.ObserveNodes(obj, tc.nodes, "tag:fixture", "node")
				value(t, reg, "tailnet_node_online", map[string]string{"kind": kind, "namespace": "ns", "name": "resource"}, tc.online)
				if len(samples(t, reg, "tailnet_node_online")[0].Label) != 3 {
					t.Fatal("node identity or peer details became labels")
				}
				if tc.seen == nil {
					if len(samples(t, reg, "tailnet_node_last_seen_seconds")) != 0 {
						t.Fatal("unknown lastSeen invented a timestamp")
					}
				} else {
					value(t, reg, "tailnet_node_last_seen_seconds", nil, float64(tc.seen.Unix()))
				}
				// A later failed/early reconciliation persists status without a successful node list.
				m.Observe(obj)
				if len(samples(t, reg, "tailnet_node_online")) != 0 || len(samples(t, reg, "tailnet_node_last_seen_seconds")) != 0 {
					t.Fatal("new status retained stale node observations")
				}
				obj.SetGeneration(2)
				m.ObserveNodes(obj, tc.nodes, "tag:fixture", "node")
				if len(samples(t, reg, "tailnet_node_online")) != 0 {
					t.Fatal("unpersisted generation published node observations")
				}
				m.Delete(kind, "ns", "resource")
				m.ObserveNodes(obj, tc.nodes, "tag:fixture", "node")
				if len(samples(t, reg, "tailnet_node_online")) != 0 {
					t.Fatal("deleted object recreated node metrics")
				}
			})
		}
	}
}
