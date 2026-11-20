package controller

import (
	"errors"
	"testing"

	tnv1 "tsunaro.io/tailnet-operator/api/v1alpha1"
)

// A scrape failure must not masquerade as NoGrant/Unreachable: with an empty netmap the classifier
// would say NoGrant for an advertised+approved route — ProbeFailed overrides it.
func TestComputeTargetStatusProbeFailed(t *testing.T) {
	r := &TailnetEgressReconciler{}
	eg := &tnv1.TailnetEgress{}
	eg.Name, eg.Namespace = "e", "ns"
	eg.Spec.Targets = []tnv1.Target{{Name: "db", Address: "10.0.0.5", Port: 5432}}
	eg.Status.NodeID = "1"
	approved := map[string]bool{"10.0.0.5/32": true}
	r.computeTargetStatus(eg, map[string]int32{"db": 10000}, map[string]bool{}, approved, approved, nil, nil, errors.New("dial tcp: connection refused"))
	if got := eg.Status.Targets[0].Reason; got != "ProbeFailed" {
		t.Fatalf("target reason = %s, want ProbeFailed", got)
	}
	for _, c := range []string{"RoutesGranted", "TargetsReachable"} {
		if got := condReason(eg.Status.Conditions, c); got != "ProbeFailed" {
			t.Fatalf("%s reason = %s, want ProbeFailed", c, got)
		}
	}
	// Same inputs with a successful scrape -> the classifier's verdict stands.
	r.computeTargetStatus(eg, map[string]int32{"db": 10000}, map[string]bool{}, approved, approved, map[string]bool{}, nil, nil)
	if got := eg.Status.Targets[0].Reason; got != "NoGrant" {
		t.Fatalf("target reason = %s, want NoGrant", got)
	}
}
