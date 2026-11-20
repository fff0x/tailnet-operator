package controller

import (
	"context"
	"io"
	"net/http"
	"strings"
	"testing"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	tnv1 "tsunaro.io/tailnet-operator/api/v1alpha1"
)

func TestAgentScrapeEgressCallers(t *testing.T) {
	// Serial test: restore the process-private client before returning. Exercise the
	// real callers, not a guessed endpoint list; the route netmap comes from /status.
	original := agentScrapeHTTPClient
	defer func() { agentScrapeHTTPClient = original }()
	calls := 0
	agentScrapeHTTPClient = &http.Client{Transport: agentRoundTripper(func(req *http.Request) (*http.Response, error) {
		calls++
		body := ""
		switch req.URL.Path {
		case "/status":
			body = `{"Peer":{"node":{"PrimaryRoutes":["10.0.0.1/32"]}}}`
		case "/targets":
			body = `[{"name":"db","reachable":true}]`
		default:
			t.Fatal("caller requested an unsupported agent endpoint")
		}
		return &http.Response{StatusCode: 200, ContentLength: -1, Body: io.NopCloser(strings.NewReader(body))}, nil
	})}
	scheme := runtime.NewScheme()
	if err := corev1.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	pod := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "agent", Namespace: "tenant", Labels: selectorLabels("app")},
		Status: corev1.PodStatus{Phase: corev1.PodRunning, PodIP: "192.0.2.1"}}
	r := &TailnetEgressReconciler{Client: fake.NewClientBuilder().WithScheme(scheme).WithObjects(pod).Build()}
	netmap, netmapErr := r.scrapeNetmap(context.Background(), "tenant", "app")
	probes, _, probeErr := r.scrapeTargets(context.Background(), "tenant", "app")
	eg := &tnv1.TailnetEgress{Spec: tnv1.TailnetEgressSpec{Targets: []tnv1.Target{{Name: "db", Address: "10.0.0.1", Port: 5432}}},
		Status: tnv1.TailnetEgressStatus{NodeID: "node"}}
	r.computeTargetStatus(eg, map[string]int32{"db": 5432}, netmap,
		map[string]bool{"10.0.0.1/32": true}, map[string]bool{"10.0.0.1/32": true}, probes, nil, netmapErr)
	if netmapErr != nil || probeErr != nil || calls != 2 || !netmap["10.0.0.1/32"] || condStatus(eg.Status.Conditions, "Ready") != metav1.ConditionTrue {
		t.Fatal("shared endpoint filter broke healthy egress route/backend observations")
	}
}
