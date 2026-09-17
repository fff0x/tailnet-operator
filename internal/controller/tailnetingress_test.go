package controller

import (
	"encoding/json"
	"testing"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	tnv1 "fr0st.dev/tailnet-operator/api/v1alpha1"
)

func ingress(name, ns string, exposes ...tnv1.Expose) *tnv1.TailnetIngress {
	return &tnv1.TailnetIngress{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: ns},
		Spec:       tnv1.TailnetIngressSpec{Exposes: exposes},
	}
}

// exposesConfigMap must map an expose to the agentTarget the agent already parses: the tailnet
// listen port is ListenPort, and the in-cluster backend becomes a full cluster-DNS Address:Port.
func TestExposesConfigMap(t *testing.T) {
	in := ingress("shop", "shop-dev",
		tnv1.Expose{Name: "postgres", Port: 5432, Backend: tnv1.Backend{Service: "shop-db-rw", Port: 5555}},
	)
	cm, err := exposesConfigMap(in, in.Namespace)
	if err != nil {
		t.Fatalf("exposesConfigMap: %v", err)
	}
	var got []agentTarget
	if err := json.Unmarshal([]byte(cm.Data[targetsFile]), &got); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("want 1 target, got %d", len(got))
	}
	want := agentTarget{
		Name:       "postgres",
		Address:    "shop-db-rw.shop-dev.svc.cluster.local",
		Port:       5555, // backend port
		ListenPort: 5432, // tailnet listen port
	}
	if got[0] != want {
		t.Fatalf("target = %+v, want %+v", got[0], want)
	}
}

func condStatus(conds []metav1.Condition, typ string) metav1.ConditionStatus {
	for _, c := range conds {
		if c.Type == typ {
			return c.Status
		}
	}
	return "missing"
}

// computeExposeStatus rolls per-expose probes up into BackendsReachable and Ready. Ready needs both
// a registered node AND every backend reachable; a single unreachable backend blocks both.
func TestComputeExposeStatus(t *testing.T) {
	r := &TailnetIngressReconciler{}
	exposes := []tnv1.Expose{
		{Name: "a", Port: 1, Backend: tnv1.Backend{Service: "sa", Port: 1}},
		{Name: "b", Port: 2, Backend: tnv1.Backend{Service: "sb", Port: 2}},
	}

	// Node up, one backend down -> BackendsReachable False, Ready False, reason on b.
	in := ingress("x", "ns", exposes...)
	in.Status.NodeID = "1"
	r.computeExposeStatus(in, map[string]bool{"a": true, "b": false})
	if s := condStatus(in.Status.Conditions, "BackendsReachable"); s != metav1.ConditionFalse {
		t.Fatalf("BackendsReachable = %s, want False", s)
	}
	if s := condStatus(in.Status.Conditions, "Ready"); s != metav1.ConditionFalse {
		t.Fatalf("Ready = %s, want False", s)
	}
	var bReason string
	for _, e := range in.Status.Exposes {
		if e.Name == "b" {
			bReason = e.Reason
		}
	}
	if bReason != "Unreachable" {
		t.Fatalf("expose b reason = %q, want Unreachable", bReason)
	}

	// Node up, all backends reachable -> Ready True.
	in2 := ingress("y", "ns", exposes...)
	in2.Status.NodeID = "1"
	r.computeExposeStatus(in2, map[string]bool{"a": true, "b": true})
	if s := condStatus(in2.Status.Conditions, "Ready"); s != metav1.ConditionTrue {
		t.Fatalf("Ready = %s, want True", s)
	}

	// All backends reachable but not registered -> Ready False (no node yet).
	in3 := ingress("z", "ns", exposes...)
	r.computeExposeStatus(in3, map[string]bool{"a": true, "b": true})
	if s := condStatus(in3.Status.Conditions, "Ready"); s != metav1.ConditionFalse {
		t.Fatalf("Ready (no node) = %s, want False", s)
	}
}
