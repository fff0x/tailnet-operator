package main

import (
	"context"
	"fmt"
	"net"
	"sync/atomic"
	"testing"
	"time"
)

func TestFullProbeVisitsEverySupportedL4Target(t *testing.T) {
	const count = 50 // the existing CR target limit
	fw := &forwarder{run: make(map[string]running)}
	for i := range count {
		name := fmt.Sprintf("target-%d", i)
		fw.run[name] = running{t: target{Name: name}, generation: 1}
	}
	probes := fw.probeTargets()
	p := &prober{results: make(map[string]probeResult)}
	var started atomic.Int32
	allStarted := make(chan struct{})
	for i := range probes {
		probes[i].dial = func(ctx context.Context, _ target) (net.Conn, error) {
			if started.Add(1) == count {
				close(allStarted)
			}
			<-ctx.Done()
			return nil, ctx.Err()
		}
		// A full pass must replace each previously successful observation, not leave
		// arbitrary targets green because early unreachable dials consumed its budget.
		p.results[probes[i].t.Name] = probeResult{Name: probes[i].t.Name, Reachable: true, owner: probes[i]}
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan struct{})
	go func() { p.probeBatch(ctx, fw, probes, false); close(done) }()
	select {
	case <-allStarted:
	case <-time.After(2 * time.Second):
		cancel()
		<-done
		t.Fatalf("only %d/%d L4 targets got a probe", started.Load(), count)
	}
	cancel()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("canceled L4 probes did not join")
	}
	for _, result := range p.snapshot() {
		if result.Reachable {
			t.Fatal("an old successful L4 observation survived the failed full pass")
		}
	}
}
