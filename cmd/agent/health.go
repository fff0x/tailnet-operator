package main

import (
	"context"
	"encoding/json"
	"log"
	"net"
	"net/http"
	"sync"
	"time"

	"tailscale.com/ipn/ipnstate"
	"tailscale.com/tsnet"
)

// statuser is the slice of the tsnet LocalClient the health server needs.
type statuser interface {
	Status(ctx context.Context) (*ipnstate.Status, error)
}

const (
	httpProbeInterval = 20 * time.Second
	httpProofMaxAge   = 30 * time.Second
	probeTimeout      = 5 * time.Second
	probeWorkers      = maxAgentTargets // every supported target gets a slot in a full pass
)

// HTTP Reachable combines backend proof (verified TLS when configured, otherwise TCP)
// with local frontend TLS readiness. Peer end-to-end acceptance remains a separate check.
type probeResult struct {
	Name               string     `json:"name"`
	Reachable          bool       `json:"reachable"`
	LastProbe          time.Time  `json:"lastProbe"`
	Error              string     `json:"error,omitempty"`
	ConfigID           string     `json:"configID,omitempty"`
	BackendReachable   *bool      `json:"backendReachable,omitempty"`
	TLSReady           *bool      `json:"tlsReady,omitempty"`
	TLSCertSHA256      string     `json:"tlsCertSHA256,omitempty"`
	TLSNotAfter        *time.Time `json:"tlsNotAfter,omitempty"`
	BackendCAHash      string     `json:"backendCAHash,omitempty"`
	BackendTLSNotAfter *time.Time `json:"backendTLSNotAfter,omitempty"`
	BackendTLSReason   string     `json:"backendTLSReason,omitempty"`
	owner              probeTarget
}

type prober struct {
	mu      sync.Mutex
	results map[string]probeResult
}

// snapshot is for inspecting completed work in tests. HTTP endpoints always use snapshotFor,
// which checks listener ownership, age and fresh certificate validity before disclosing proof.
func (p *prober) snapshot() []probeResult {
	p.mu.Lock()
	defer p.mu.Unlock()
	out := make([]probeResult, 0, len(p.results))
	for _, r := range p.results {
		out = append(out, r)
	}
	return out
}

func falseBool() *bool { v := false; return &v }

func invalidateTLS(r *probeResult, reason string) {
	r.TLSReady = falseBool()
	r.Reachable = false
	r.TLSCertSHA256 = ""
	r.TLSNotAfter = nil
	r.Error = reason
}

func validateBackendProof(r *probeResult, h *httpIngress) {
	if r.owner.t.BackendServerName == "" {
		return
	}
	age := time.Since(r.LastProbe)
	if r.BackendReachable != nil && *r.BackendReachable && r.BackendTLSNotAfter != nil && h != nil && age >= 0 && age <= httpProofMaxAge && h.currentBackendProof(r.BackendCAHash, *r.BackendTLSNotAfter) {
		return
	}
	r.BackendReachable = falseBool()
	r.Reachable = false
	r.BackendCAHash = ""
	r.BackendTLSNotAfter = nil
	if r.BackendTLSReason == "" {
		r.BackendTLSReason = backendTLSProofStale
	}
	r.Error = "backend TLS proof unavailable or stale"
}

// snapshotFor also includes configured HTTP targets with missing binds or no observations.
// Lock ordering is always forwarder -> prober; reload cannot replace an instance mid-validation.
func (p *prober) snapshotFor(fw *forwarder) []probeResult {
	fw.mu.Lock()
	defer fw.mu.Unlock()
	p.mu.Lock()
	defer p.mu.Unlock()
	out := make([]probeResult, 0, len(p.results))
	seen := make(map[string]bool)
	for name, r := range p.results {
		if !fw.owns(r.owner) {
			delete(p.results, name)
			continue
		}
		if r.owner.t.Mode == "http" {
			h, _ := r.owner.ln.(*httpIngress)
			valid := r.TLSReady != nil && *r.TLSReady && r.TLSNotAfter != nil && h != nil
			age := time.Since(r.LastProbe)
			if !valid || age < 0 || age > httpProofMaxAge || !h.currentProof(tlsObservation{sha256: r.TLSCertSHA256, notAfter: *r.TLSNotAfter}) {
				invalidateTLS(&r, "local TLS proof unavailable or stale")
			}
			validateBackendProof(&r, h)
			p.results[name] = r // invalidated proofs cannot resurrect on a later read
		}
		out = append(out, r)
		seen[name] = true
	}
	missing := func(t target) {
		if t.Mode == "http" && !seen[t.Name] {
			r := probeResult{Name: t.Name, ConfigID: t.ConfigID, TLSReady: falseBool(), BackendReachable: falseBool(), Error: "HTTP listener or probe unavailable"}
			if t.BackendServerName != "" {
				r.BackendTLSReason = backendTLSProofStale
			}
			out = append(out, r)
			seen[t.Name] = true
		}
	}
	for _, t := range fw.desired {
		missing(t)
	}
	for _, r := range fw.run {
		missing(r.t)
	}
	return out
}

func (p *prober) httpReady(fw *forwarder) bool {
	for _, r := range p.snapshotFor(fw) {
		if r.TLSReady != nil && !r.Reachable {
			return false
		}
	}
	return true // retain Running-only readiness for L4
}

func healthMux(lc statuser, fw *forwarder, pr *prober) *http.ServeMux {
	mux := http.NewServeMux()
	if fw.metrics != nil {
		mux.Handle("/metrics", fw.metrics.handler())
	}
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		st, err := lc.Status(r.Context())
		if err != nil || st == nil || st.BackendState != "Running" || !pr.httpReady(fw) {
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
		writeJSON(w, pr.snapshotFor(fw))
	})
	return mux
}

// serveHealth retains the tsnet Running gate. HTTP also requires current local TLS and backend
// TCP or verified backend TLS proof. With probes disabled HTTP fails closed; L4 is unchanged.
func serveHealth(ctx context.Context, addr string, ts *tsnet.Server, lc statuser, fw *forwarder, interval time.Duration) {
	pr := &prober{results: map[string]probeResult{}}
	if interval > 0 {
		go pr.loop(ctx, ts, fw, interval)
	}
	srv := &http.Server{Addr: addr, Handler: healthMux(lc, fw, pr), ReadHeaderTimeout: 5 * time.Second}
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

type probeTarget struct {
	t          target
	dial       upstreamDial
	ln         net.Listener
	generation uint64
}

// owns must be called under f.mu. Generation rejects ABA (same name/static fields after removal).
func (f *forwarder) owns(p probeTarget) bool {
	r, ok := f.run[p.t.Name]
	return ok && r.t == p.t && r.ln == p.ln && r.generation == p.generation
}

// Capture listener ownership and metric generations together under the reload lock. Keep these
// out of target: diffTargets compares only static, comparable configuration.
func (f *forwarder) probeTargets() []probeTarget {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := make([]probeTarget, 0, len(f.run))
	for _, r := range f.run {
		out = append(out, probeTarget{t: r.t, dial: f.metrics.connection(r.t.Name).wrapDial(f.dial), ln: r.ln, generation: r.generation})
	}
	return out
}

func (p *prober) publish(fw *forwarder, r probeResult) {
	fw.mu.Lock()
	defer fw.mu.Unlock()
	if !fw.owns(r.owner) {
		return
	}
	if r.owner.t.Mode == "http" && r.TLSReady != nil && *r.TLSReady {
		h, ok := r.owner.ln.(*httpIngress)
		if !ok || r.TLSNotAfter == nil || !h.currentProof(tlsObservation{sha256: r.TLSCertSHA256, notAfter: *r.TLSNotAfter}) {
			invalidateTLS(&r, "local TLS proof unavailable or stale")
		}
	}
	if r.owner.t.Mode == "http" {
		h, _ := r.owner.ln.(*httpIngress)
		validateBackendProof(&r, h)
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.results == nil {
		p.results = make(map[string]probeResult)
	}
	p.results[r.Name] = r
}

func probeOne(ctx context.Context, probe probeTarget) probeResult {
	t := probe.t
	ctx, cancel := context.WithTimeout(ctx, probeTimeout)
	defer cancel()
	r := probeResult{Name: t.Name, owner: probe, LastProbe: time.Now()}
	if t.Mode == "http" {
		r.ConfigID = t.ConfigID
		r.TLSReady = falseBool()
		if h, ok := probe.ln.(*httpIngress); ok {
			// Closure cancels backend work as well as the component handshake.
			stop := context.AfterFunc(h.ctx, cancel)
			defer stop()
			proof, err := h.probeTLS(ctx)
			if err == nil {
				ready := true
				r.TLSReady = &ready
				r.TLSCertSHA256 = proof.sha256
				r.TLSNotAfter = &proof.notAfter
			}
		}
	}
	if t.Mode == "http" && t.BackendServerName != "" {
		r.BackendTLSReason = backendTLSProofStale
		if h, ok := probe.ln.(*httpIngress); ok {
			hash, expiry, reason := h.probeBackendTLS(ctx)
			r.BackendTLSReason = reason
			if reason == "" {
				r.BackendCAHash = hash
				r.BackendTLSNotAfter = &expiry
				r.Reachable = true
			}
		}
	} else {
		c, err := probe.dial(ctx, t)
		if err == nil {
			c.Close()
			r.Reachable = true
		} else {
			r.Error = err.Error() // retain L4 error behavior
		}
	}
	if t.Mode == "http" {
		backend := r.Reachable
		r.BackendReachable = &backend
		r.Reachable = backend && *r.TLSReady
		switch {
		case !*r.TLSReady:
			r.Error = "local TLS component probe failed"
		case !backend && t.BackendServerName != "":
			r.Error = "backend TLS probe failed"
		case !backend:
			r.Error = "backend TCP probe failed"
		default:
			r.Error = ""
		}
	}
	return r
}

func (p *prober) probe(ctx context.Context, fw *forwarder) {
	p.probeSelected(ctx, fw, false)
}

// Two bounded worker pools avoid serial dead L4 targets delaying HTTP proof. Each pass has a
// fixed time budget and at most the validated configuration limit of workers. All supported L4
// targets get a slot, even when every dial blocks; old successes cannot survive budget starvation.
// Results are published individually, not behind a batch barrier.
func (p *prober) probeSelected(ctx context.Context, fw *forwarder, httpOnly bool) {
	p.probeBatch(ctx, fw, fw.probeTargets(), httpOnly)
}

func (p *prober) probeBatch(ctx context.Context, fw *forwarder, cur []probeTarget, httpOnly bool) {
	p.snapshotFor(fw) // prune removed/replaced observations, including on an empty pass
	ctx, cancel := context.WithTimeout(ctx, probeTimeout)
	defer cancel()
	var jobs [2][]probeTarget
	for _, probe := range cur {
		if probe.t.Mode == "http" {
			jobs[0] = append(jobs[0], probe)
		} else if !httpOnly {
			jobs[1] = append(jobs[1], probe)
		}
	}
	var workers sync.WaitGroup
	for _, group := range jobs {
		queue := make(chan probeTarget, len(group))
		for _, probe := range group {
			queue <- probe
		}
		close(queue)
		for range min(probeWorkers, len(group)) {
			workers.Go(func() {
				for probe := range queue {
					if ctx.Err() != nil {
						return
					}
					r := probeOne(ctx, probe)
					p.publish(fw, r)
				}
			})
		}
	}
	workers.Wait()
}

// HTTP cadence is independent of the default five-minute backend/L4 interval. Zero explicitly
// disables all probing (HTTP therefore has no proof); a listener change requests a full pass.
func (p *prober) loop(ctx context.Context, _ *tsnet.Server, fw *forwarder, interval time.Duration) {
	if interval <= 0 {
		return
	}
	tick := time.NewTicker(min(interval, httpProbeInterval))
	defer tick.Stop()
	lastFull := time.Now()
	p.probe(ctx, fw)
	for {
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
			httpOnly := time.Since(lastFull) < interval
			if !httpOnly {
				lastFull = time.Now()
			}
			p.probeSelected(ctx, fw, httpOnly)
		case <-fw.changed:
			lastFull = time.Now()
			p.probe(ctx, fw)
		}
	}
}
