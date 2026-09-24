package main

import (
	"context"
	"net"
	"testing"
)

// A probe result must vanish with its target: after a rename the old name would otherwise keep
// reporting its last (stale) reachability and the new name would wait a full interval.
func TestProbeDropsStaleResults(t *testing.T) {
	backend, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer backend.Close()
	port := backend.Addr().(*net.TCPAddr).Port

	// ingress mode dials with the plain netns, so no tsnet is needed to exercise the prober.
	fw := &forwarder{mode: "ingress", run: map[string]running{}}
	fw.run["a"] = running{t: target{Name: "a", Address: "127.0.0.1", Port: port}, ln: backend, cancel: func() {}}
	pr := &prober{results: map[string]probeResult{}}
	ctx := context.Background()

	pr.probe(ctx, fw)
	if r, ok := pr.results["a"]; !ok || !r.Reachable {
		t.Fatalf("a should be reachable, got %+v", pr.results)
	}

	delete(fw.run, "a")
	fw.run["b"] = running{t: target{Name: "b", Address: "127.0.0.1", Port: port}, ln: backend, cancel: func() {}}
	pr.probe(ctx, fw)
	if _, ok := pr.results["a"]; ok {
		t.Error("stale result for a survived the probe")
	}
	if r, ok := pr.results["b"]; !ok || !r.Reachable {
		t.Errorf("b should be reachable, got %+v", pr.results)
	}
}
