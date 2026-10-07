package controller

import (
	"testing"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	tnv1 "tsunaro.io/tailnet-operator/api/v1alpha1"
	"tsunaro.io/tailnet-operator/internal/gateway"
)

func TestServiceReadyFollowsLoadBalancerAllocation(t *testing.T) {
	g := &tnv1.TailnetGateway{}
	pending := serviceReady(g, gateway.FreshObservation{})
	if pending.Status != metav1.ConditionFalse || pending.Reason != "LBPending" {
		t.Fatalf("%+v", pending)
	}
	assigned := serviceReady(g, gateway.FreshObservation{LoadBalancerIPs: []string{"192.0.2.17"}})
	if assigned.Status != metav1.ConditionTrue || assigned.Reason != "LoadBalancerAssigned" {
		t.Fatalf("%+v", assigned)
	}
}
