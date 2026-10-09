package controller

import (
	"errors"
	"testing"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	tnv1 "tsunaro.io/tailnet-operator/api/v1alpha1"
)

// Ready=False names the first blocking condition in a fixed order instead of a generic NotReady,
// because TailnetResourceNotReady carries the Ready reason as its alert label.
func TestReadyReasonNamesBlockingCondition(t *testing.T) {
	r := &TailnetEgressReconciler{}
	eg := &tnv1.TailnetEgress{}
	eg.Name, eg.Namespace = "e", "ns"
	eg.Spec.Targets = []tnv1.Target{{Name: "db", Address: "10.0.0.5", Port: 5432}}
	approved := map[string]bool{"10.0.0.5/32": true}
	listen := map[string]int32{"db": 10000}

	// No node yet: Registered wins over the route and probe verdicts.
	setCond(&eg.Status.Conditions, 1, "Registered", metav1.ConditionFalse, "NotRegistered", "no node")
	r.computeTargetStatus(eg, listen, approved, approved, approved, map[string]bool{"db": true}, nil)
	if got := condReason(eg.Status.Conditions, "Ready"); got != "NotRegistered" {
		t.Fatalf("Ready reason = %s, want NotRegistered", got)
	}

	// Node registered, scrape failed: ProbeFailed (via RoutesGranted) instead of NotReady.
	eg.Status.NodeID = "1"
	setCond(&eg.Status.Conditions, 1, "Registered", metav1.ConditionTrue, "Registered", "ok")
	r.computeTargetStatus(eg, listen, map[string]bool{}, approved, approved, nil, errors.New("dial tcp: connection refused"))
	if got := condReason(eg.Status.Conditions, "Ready"); got != "ProbeFailed" {
		t.Fatalf("Ready reason = %s, want ProbeFailed", got)
	}

	// Routes present, one target dead: Unreachable.
	r.computeTargetStatus(eg, listen, approved, approved, approved, map[string]bool{"db": false}, nil)
	if got := condReason(eg.Status.Conditions, "Ready"); got != "Unreachable" {
		t.Fatalf("Ready reason = %s, want Unreachable", got)
	}

	// Everything served: Ready.
	r.computeTargetStatus(eg, listen, approved, approved, approved, map[string]bool{"db": true}, nil)
	if got := condReason(eg.Status.Conditions, "Ready"); got != "Ready" {
		t.Fatalf("Ready reason = %s, want Ready", got)
	}

	// Ingress: the same rule over Registered, PolicyGranted, BackendsReachable.
	ri := &TailnetIngressReconciler{}
	in := &tnv1.TailnetIngress{}
	in.Spec.Exposes = []tnv1.Expose{{Name: "web", Port: 443, Backend: tnv1.Backend{Service: "web", Port: 8080}}}
	in.Status.NodeID = "2"
	setCond(&in.Status.Conditions, 1, "Registered", metav1.ConditionTrue, "Registered", "ok")
	setCond(&in.Status.Conditions, 1, "PolicyGranted", metav1.ConditionFalse, "PolicyDenied", "no grant")
	ri.computeExposeStatus(in, map[string]bool{"web": false}, nil)
	if got := condReason(in.Status.Conditions, "Ready"); got != "PolicyDenied" {
		t.Fatalf("ingress Ready reason = %s, want PolicyDenied", got)
	}
	setCond(&in.Status.Conditions, 1, "PolicyGranted", metav1.ConditionTrue, "Granted", "ok")
	ri.computeExposeStatus(in, map[string]bool{"web": false}, nil)
	if got := condReason(in.Status.Conditions, "Ready"); got != "Unreachable" {
		t.Fatalf("ingress Ready reason = %s, want Unreachable", got)
	}
}

func TestBlockingReasonFallsBackToNotReady(t *testing.T) {
	if reason, _ := blockingReason(nil, "Registered"); reason != "NotReady" {
		t.Fatalf("reason = %s, want NotReady", reason)
	}
}
