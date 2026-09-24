package main

import (
	"context"
	"encoding/json"
	"log"
	"net/http"
	"sync"
	"time"

	"tailscale.com/ipn/ipnstate"
	"tailscale.com/tsnet"
)

// statuser is the slice of the tsnet LocalClient the health server needs. An interface keeps this
// file off the exact client package, which has moved around across tailscale releases.
type statuser interface {
	Status(ctx context.Context) (*ipnstate.Status, error)
}

// probeResult is the last reachability check for one target, served at /targets and scraped by the
// operator into per-target status.
type probeResult struct {
	Name      string    `json:"name"`
	Reachable bool      `json:"reachable"`
	LastProbe time.Time `json:"lastProbe"`
	Error     string    `json:"error,omitempty"`
}

type prober struct {
	mu      sync.Mutex
	results map[string]probeResult
}

func (p *prober) snapshot() []probeResult {
	p.mu.Lock()
	defer p.mu.Unlock()
	out := make([]probeResult, 0, len(p.results))
	for _, r := range p.results {
		out = append(out, r)
	}
	return out
}

// replace swaps the whole result set, so a target that stopped running (removed, renamed, or failed
// to bind) disappears instead of reporting its last result forever.
func (p *prober) replace(results map[string]probeResult) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.results = results
}

// serveHealth runs the :9080 endpoints and, unless disabled, the periodic reachability probe.
//
//	/healthz  503 until the backend is Running, then 200 — drives the pod readiness gate
//	/status   the raw ipnstate.Status, so the operator can classify missing routes
//	/targets  the last probe result per target
func serveHealth(ctx context.Context, addr string, ts *tsnet.Server, lc statuser, fw *forwarder, interval time.Duration) {
	pr := &prober{results: map[string]probeResult{}}
	if interval > 0 {
		go pr.loop(ctx, ts, fw, interval)
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		st, err := lc.Status(r.Context())
		if err != nil || st == nil || st.BackendState != "Running" {
			http.Error(w, "not ready", http.StatusServiceUnavailable)
			return
		}
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("ok"))
	})
	mux.HandleFunc("/status", func(w http.ResponseWriter, r *http.Request) {
		st, err := lc.Status(r.Context())
		if err != nil {
			http.Error(w, err.Error(), http.StatusServiceUnavailable)
			return
		}
		writeJSON(w, st)
	})
	mux.HandleFunc("/targets", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, pr.snapshot())
	})

	srv := &http.Server{Addr: addr, Handler: mux, ReadHeaderTimeout: 5 * time.Second}
	go func() {
		<-ctx.Done()
		sctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		srv.Shutdown(sctx)
	}()
	if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		log.Printf("health server: %v", err)
	}
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(v)
}

// probe dials every running target and closes immediately. A connect is enough: egress proves
// grant, route approval and the far-side path in one shot; ingress proves the in-cluster backend
// answers. A refusal (RST) still counts as reachable — the host answered; only a timeout or dial
// error is unreachable. fw.dial picks the right leg, so the probe mirrors real traffic.
func (p *prober) probe(ctx context.Context, fw *forwarder) {
	cur := fw.current()
	results := make(map[string]probeResult, len(cur))
	for _, t := range cur {
		dctx, cancel := context.WithTimeout(ctx, 5*time.Second)
		c, err := fw.dial(dctx, t)
		cancel()
		res := probeResult{Name: t.Name, LastProbe: time.Now()}
		if err != nil {
			res.Error = err.Error()
		} else {
			res.Reachable = true
			c.Close()
		}
		results[t.Name] = res
	}
	p.replace(results)
}

// loop probes on the interval and whenever the forwarder started a listener, so a new or renamed
// target is judged right away instead of after up to one full interval.
func (p *prober) loop(ctx context.Context, ts *tsnet.Server, fw *forwarder, interval time.Duration) {
	tick := time.NewTicker(interval)
	defer tick.Stop()
	p.probe(ctx, fw) // once at startup, don't wait a full interval for the first result
	for {
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
			p.probe(ctx, fw)
		case <-fw.changed:
			p.probe(ctx, fw)
		}
	}
}
