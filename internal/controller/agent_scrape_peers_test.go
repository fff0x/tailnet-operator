package controller

import (
	"testing"

	networkingv1 "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	tnv1 "tsunaro.io/tailnet-operator/api/v1alpha1"
)

func TestAgentNetworkPoliciesAdmitConfiguredScrapePeers(t *testing.T) {
	peer := networkingv1.NetworkPolicyPeer{
		NamespaceSelector: &metav1.LabelSelector{MatchLabels: map[string]string{"kubernetes.io/metadata.name": "monitoring"}},
		PodSelector:       &metav1.LabelSelector{MatchLabels: map[string]string{"app.kubernetes.io/name": "prometheus"}},
	}
	in := &tnv1.TailnetIngress{ObjectMeta: metav1.ObjectMeta{Name: "web", Namespace: "tenant"}}
	eg := &tnv1.TailnetEgress{ObjectMeta: metav1.ObjectMeta{Name: "db", Namespace: "tenant"}}
	for name, build := range map[string]func([]networkingv1.NetworkPolicyPeer) *networkingv1.NetworkPolicy{
		"ingress": func(p []networkingv1.NetworkPolicyPeer) *networkingv1.NetworkPolicy {
			return ingressNetworkPolicy(in, "tenant", "operator", p)
		},
		"egress": func(p []networkingv1.NetworkPolicyPeer) *networkingv1.NetworkPolicy {
			return egressNetworkPolicy(eg, "tenant", "operator", p)
		},
	} {
		t.Run(name, func(t *testing.T) {
			base := len(build(nil).Spec.Ingress)
			rules := build([]networkingv1.NetworkPolicyPeer{peer}).Spec.Ingress
			if len(rules) != base+1 {
				t.Fatalf("rules=%d, want %d", len(rules), base+1)
			}
			last := rules[len(rules)-1]
			if len(last.From) != 1 || last.From[0].PodSelector == nil || len(last.Ports) != 1 || last.Ports[0].Port.IntValue() != int(agentHealthPort) {
				t.Fatalf("scrape rule must admit only the peer on the health port: %+v", last)
			}
		})
	}
}
