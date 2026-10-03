// Command tailnet-agent is the data plane: one per TailnetEgress or TailnetIngress CR. It joins the
// tailnet as a userspace tsnet node (no NET_ADMIN, no /dev/net/tun) and forwards a fixed set of
// connections. Direction is set by AGENT_MODE:
//
//	egress  (default) — listen on a local port, Dial the far address over the tailnet
//	                    (needs --accept-routes so netstack emits toward subnet-routed hosts)
//	ingress           — Listen on the tailnet, Dial an in-cluster backend with the normal netns
//
// No SOCKS5, no second container: one tsnet stack plus the process's own netns is the whole hop.
package main

import (
	"context"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"os/signal"
	"strconv"
	"sync"
	"syscall"
	"time"

	"tailscale.com/ipn"
	"tailscale.com/ipn/store/mem"
	"tailscale.com/tsnet"
)

func env(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

func main() {
	authKey := os.Getenv("TS_AUTHKEY")
	controlURL := os.Getenv("CONTROL_URL")
	hostname := os.Getenv("TS_HOSTNAME")
	mode := env("AGENT_MODE", "egress")
	targetsFile := env("TARGETS_FILE", "/config/targets.json")
	healthAddr := env("HEALTH_ADDR", ":9080")
	probeInterval, _ := time.ParseDuration(env("PROBE_INTERVAL", "5m"))

	if authKey == "" || controlURL == "" || hostname == "" {
		log.Fatal("TS_AUTHKEY, CONTROL_URL and TS_HOSTNAME are required")
	}
	if mode != "egress" && mode != "ingress" {
		log.Fatalf("AGENT_MODE must be egress or ingress, got %q", mode)
	}
	// Never phone home; the operator carries the status the netmap already knows.
	os.Setenv("TS_NO_LOGS_NO_SUPPORT", "1")

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	store, _ := mem.New(nil, "")
	ts := &tsnet.Server{
		Hostname:   hostname,
		Ephemeral:  true, // no volume, no state secret; a lost pod re-registers from the authkey
		AuthKey:    authKey,
		ControlURL: controlURL,
		Store:      store, // memory only: every start is a clean registration
		// Explicit Dir: the published image is scratch (no $HOME), so tsnet's default
		// os.UserConfigDir() would fail. Point it at a writable mount (emptyDir) instead.
		Dir:  env("TS_STATE_DIR", "/state"),
		Logf: log.Printf,
	}
	defer ts.Close()

	upCtx, cancel := context.WithTimeout(ctx, 90*time.Second)
	defer cancel()
	if _, err := ts.Up(upCtx); err != nil {
		log.Fatalf("tsnet up: %v", err)
	}
	lc, err := ts.LocalClient()
	if err != nil {
		log.Fatalf("local client: %v", err)
	}
	// Egress only: without RouteAll, netstack refuses to emit toward a subnet-routed address and
	// every Dial dies. Which routes actually arrive is decided by this node's grants — Headscale
	// filters the netmap per node. Ingress dials in-cluster via the pod netns, so it needs none.
	if mode == "egress" {
		if _, err := lc.EditPrefs(ctx, &ipn.MaskedPrefs{
			Prefs:       ipn.Prefs{RouteAll: true},
			RouteAllSet: true,
		}); err != nil {
			log.Fatalf("edit prefs (RouteAll): %v", err)
		}
	}
	log.Printf("tailnet-agent up: mode=%s hostname=%s", mode, hostname)

	fw := &forwarder{ts: ts, mode: mode, run: map[string]running{}, changed: make(chan struct{}, 1), metrics: newAgentMetrics(mode)}
	defer fw.stopAll()

	// First load must parse; after that a bad reload is logged and the last good set stays up.
	// A listener that failed to bind is retried by watchTargets.
	if _, err := fw.reload(ctx, targetsFile); err != nil {
		log.Fatalf("initial targets load: %v", err)
	}
	go watchTargets(ctx, targetsFile, fw)
	go serveHealth(ctx, healthAddr, ts, lc, fw, probeInterval)

	<-ctx.Done()
	log.Printf("shutting down")
}

// running is one active listener and the cancel for its in-flight dials.
type running struct {
	t          target
	ln         net.Listener
	cancel     context.CancelFunc
	generation uint64
}

// stop closes the listener synchronously. A rename keeps the listen port (ports.Assign hands the
// freed port to the new name), so the old socket must be gone before reload binds the new one.
func (r running) stop() {
	r.cancel()
	r.ln.Close()
}

// forwarder owns the set of listeners and reconciles it against the desired targets. mode decides
// which side of each hop is the tailnet: egress listens local and dials the tailnet; ingress listens
// on the tailnet and dials the in-cluster backend.
type forwarder struct {
	ts *tsnet.Server
	// Optional owned-listener seam for unit tests; production always uses tsnet.Listen.
	listenTailnet func(network, address string) (net.Listener, error)
	mode          string
	mu            sync.Mutex
	run           map[string]running
	metrics       *agentMetrics
	// desired includes failed binds: absence from run must not make HTTP ready.
	desired        []target
	nextGeneration uint64
	// changed gets a non-blocking signal whenever a listener was started; the prober drains it.
	// nil (tests) is fine: the send falls through to default.
	changed chan struct{}
}

// current returns a snapshot of the running targets for value-based diffing.
func (f *forwarder) current() map[string]target {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := make(map[string]target, len(f.run))
	for name, r := range f.run {
		out[name] = r.t
	}
	return out
}

// reload reads the targets file and applies the diff: stop removed/changed, start new/changed.
// err is a load/parse error (the running set is left untouched); pending counts targets whose
// listener failed to bind — they are absent from run and reappear in the next diff.
func (f *forwarder) reload(ctx context.Context, path string) (pending int, err error) {
	desired, err := loadTargets(path)
	if err != nil {
		return 0, err
	}
	for _, t := range desired {
		if t.Mode == "http" && f.mode != "ingress" {
			return 0, fmt.Errorf("HTTP targets require ingress mode")
		}
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	current := make(map[string]target, len(f.run))
	for name, r := range f.run {
		current[name] = r.t
	}
	start, stop := diffTargets(current, desired)
	f.desired = desired
	// Removals and failed binds also invalidate readiness immediately.
	defer func() {
		select {
		case f.changed <- struct{}{}:
		default:
		}
	}()
	for _, name := range stop {
		if r, ok := f.run[name]; ok {
			r.stop()
			f.metrics.remove(name)
			delete(f.run, name)
			log.Printf("target %s: listener stopped", name)
		}
	}
	var httpTargets []target
	for _, t := range start {
		if t.Mode == "http" {
			httpTargets = append(httpTargets, t)
			continue
		}
		lctx, lcancel := context.WithCancel(ctx)
		ln, err := f.listen(lctx, t)
		if err != nil {
			lcancel()
			pending++
			log.Printf("target %s: listen :%d failed: %v", t.Name, t.ListenPort, err)
			continue
		}
		f.nextGeneration++
		f.run[t.Name] = running{t: t, ln: ln, cancel: lcancel, generation: f.nextGeneration}
		log.Printf("target %s: :%d -> %s:%d", t.Name, t.ListenPort, t.Address, t.Port)
		select {
		case f.changed <- struct{}{}:
		default:
		}
	}
	if len(httpTargets) != 0 {
		lctx, lcancel := context.WithCancel(ctx)
		ln, err := f.listenHTTP(lctx, httpTargets)
		if err != nil {
			lcancel()
			pending += len(httpTargets)
			log.Printf("HTTP group: listen :443 failed")
		} else {
			group := running{ln: ln, cancel: lcancel}
			for _, t := range httpTargets {
				f.nextGeneration++
				group.t, group.generation = t, f.nextGeneration
				f.run[t.Name] = group
			}
		}
	}
	return pending, nil
}

func (f *forwarder) bindTailnet(port int) (net.Listener, error) {
	if f.listenTailnet != nil {
		return f.listenTailnet("tcp", fmt.Sprintf(":%d", port))
	}
	return f.ts.Listen("tcp", fmt.Sprintf(":%d", port))
}

func (f *forwarder) listenHTTP(ctx context.Context, targets []target) (net.Listener, error) {
	if f.mode != "ingress" {
		return nil, fmt.Errorf("HTTP targets require ingress mode")
	}
	ln, err := f.bindTailnet(443)
	if err != nil {
		return nil, err
	}
	// Group admission, certificate policy and SNI metric selection ship as one unit.
	h, err := serveHTTPIngressGroup(ctx, ln, targets, f.dial, f.metrics)
	if err != nil {
		ln.Close()
		return nil, err
	}
	return h, nil
}

// listen binds one listen port and forwards every connection to the target. Egress binds a local
// port; ingress binds the same port on the tailnet (tsnet netstack) so peers dial it by node name.
// The caller owns the returned listener and closes it via running.stop.
func (f *forwarder) listen(ctx context.Context, t target) (net.Listener, error) {
	if err := t.validateHTTP(); err != nil {
		return nil, err
	}
	if t.Mode == "http" {
		return f.listenHTTP(ctx, []target{t})
	}
	var ln net.Listener
	var err error
	if f.mode == "ingress" {
		ln, err = f.bindTailnet(t.ListenPort)
	} else {
		ln, err = net.Listen("tcp", fmt.Sprintf(":%d", t.ListenPort))
	}
	if err != nil {
		return nil, err
	}
	metrics := f.metrics.connection(t.Name)
	dial := metrics.wrapDial(f.dial)
	if f.metrics != nil {
		ln = &measuredListener{Listener: ln, metrics: metrics}
	}
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return // listener closed by running.stop
			}
			go f.handle(ctx, c, t, dial)
		}
	}()
	return ln, nil
}

func (f *forwarder) handle(ctx context.Context, client net.Conn, t target, dial upstreamDial) {
	dctx, dcancel := context.WithTimeout(ctx, 10*time.Second)
	defer dcancel()
	upstream, err := dial(dctx, t)
	if err != nil {
		log.Printf("target %s: dial %s:%d: %v", t.Name, t.Address, t.Port, err)
		client.Close()
		return
	}
	pipe(client, upstream)
}

// dial opens the upstream leg of a hop: ingress dials the in-cluster backend with the process netns
// (cluster DNS + ClusterIP), egress dials the far address over the tailnet. Shared by handle and the
// health prober so both measure the same path. Callers capture generation-bound metrics separately.
func (f *forwarder) dial(ctx context.Context, t target) (net.Conn, error) {
	addr := net.JoinHostPort(t.Address, strconv.Itoa(t.Port))
	if f.mode == "ingress" {
		var d net.Dialer
		return d.DialContext(ctx, "tcp", addr)
	}
	return f.ts.Dial(ctx, "tcp", addr)
}

func (f *forwarder) stopAll() {
	f.mu.Lock()
	defer f.mu.Unlock()
	for name, r := range f.run {
		r.stop()
		f.metrics.remove(name)
		delete(f.run, name)
	}
}

// closeWriter is net.TCPConn and tsnet's gonet.TCPConn — both let us half-close so an upstream that
// waits for EOF (many line protocols) is not left hanging when one side is done writing.
type closeWriter interface{ CloseWrite() error }

// pipe copies bidirectionally with half-close, then closes both ends once each direction is done.
func pipe(a, b net.Conn) {
	done := make(chan struct{}, 2)
	cp := func(dst, src net.Conn) {
		io.Copy(dst, src)
		if cw, ok := dst.(closeWriter); ok {
			cw.CloseWrite()
		}
		done <- struct{}{}
	}
	go cp(a, b)
	go cp(b, a)
	<-done
	<-done
	a.Close()
	b.Close()
}

// watchTargets re-applies the target set when the mounted file's mtime changes, and keeps retrying
// while any listener failed to bind. Polling, not fsnotify: a ConfigMap mount updates via a symlink
// swap that fsnotify handles awkwardly, the set is tiny, and 10s of lag on adding a target is
// invisible in practice. ponytail: 10s poll, not events.
func watchTargets(ctx context.Context, path string, fw *forwarder) {
	tick := time.NewTicker(10 * time.Second)
	defer tick.Stop()
	watchTargetsOnTicks(ctx, path, fw, tick.C)
}

func watchTargetsOnTicks(ctx context.Context, path string, fw *forwarder, ticks <-chan time.Time) {
	var last time.Time
	// Reconcile once even without an mtime change: the initial load may have failed
	// binds, or the file may have changed before this watcher captured its mtime.
	retry := true
	if fi, err := os.Stat(path); err == nil {
		last = fi.ModTime()
	}
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticks:
			fi, err := os.Stat(path)
			if err != nil || (!retry && !fi.ModTime().After(last)) {
				continue
			}
			last = fi.ModTime()
			pending, err := fw.reload(ctx, path)
			if err != nil {
				log.Printf("reload after change failed, keeping last good set: %v", err)
			}
			retry = pending > 0
		}
	}
}
