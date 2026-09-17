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
	log.Printf("tailnet-agent up: mode=%s hostname=%s control=%s", mode, hostname, controlURL)

	fw := &forwarder{ts: ts, mode: mode, run: map[string]running{}}
	defer fw.stopAll()

	// First load must succeed; after that a bad reload is logged and the last good set stays up.
	if err := fw.reload(ctx, targetsFile); err != nil {
		log.Fatalf("initial targets load: %v", err)
	}
	go watchTargets(ctx, targetsFile, fw)
	go serveHealth(ctx, healthAddr, ts, lc, fw, probeInterval)

	<-ctx.Done()
	log.Printf("shutting down")
}

// running is one active listener and the cancel that tears it down.
type running struct {
	t      target
	cancel context.CancelFunc
}

// forwarder owns the set of listeners and reconciles it against the desired targets. mode decides
// which side of each hop is the tailnet: egress listens local and dials the tailnet; ingress listens
// on the tailnet and dials the in-cluster backend.
type forwarder struct {
	ts   *tsnet.Server
	mode string
	mu   sync.Mutex
	run  map[string]running
}

// current returns a snapshot of the running targets (for diffing and for the probe).
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
func (f *forwarder) reload(ctx context.Context, path string) error {
	desired, err := loadTargets(path)
	if err != nil {
		return err
	}
	start, stop := diffTargets(f.current(), desired)

	f.mu.Lock()
	defer f.mu.Unlock()
	for _, name := range stop {
		if r, ok := f.run[name]; ok {
			r.cancel()
			delete(f.run, name)
			log.Printf("target %s: listener stopped", name)
		}
	}
	for _, t := range start {
		lctx, lcancel := context.WithCancel(ctx)
		if err := f.listen(lctx, t); err != nil {
			lcancel()
			log.Printf("target %s: listen :%d failed: %v", t.Name, t.ListenPort, err)
			continue
		}
		f.run[t.Name] = running{t: t, cancel: lcancel}
		log.Printf("target %s: :%d -> %s:%d", t.Name, t.ListenPort, t.Address, t.Port)
	}
	return nil
}

// listen binds one listen port and forwards every connection to the target. Egress binds a local
// port; ingress binds the same port on the tailnet (tsnet netstack) so peers dial it by node name.
func (f *forwarder) listen(ctx context.Context, t target) error {
	var ln net.Listener
	var err error
	if f.mode == "ingress" {
		ln, err = f.ts.Listen("tcp", fmt.Sprintf(":%d", t.ListenPort))
	} else {
		ln, err = net.Listen("tcp", fmt.Sprintf(":%d", t.ListenPort))
	}
	if err != nil {
		return err
	}
	go func() {
		<-ctx.Done()
		ln.Close()
	}()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return // listener closed on ctx cancel
			}
			go f.handle(ctx, c, t)
		}
	}()
	return nil
}

func (f *forwarder) handle(ctx context.Context, client net.Conn, t target) {
	dctx, dcancel := context.WithTimeout(ctx, 10*time.Second)
	defer dcancel()
	upstream, err := f.dial(dctx, t)
	if err != nil {
		log.Printf("target %s: dial %s:%d: %v", t.Name, t.Address, t.Port, err)
		client.Close()
		return
	}
	pipe(client, upstream)
}

// dial opens the upstream leg of a hop: ingress dials the in-cluster backend with the process netns
// (cluster DNS + ClusterIP), egress dials the far address over the tailnet. Shared by handle and the
// health prober so both measure the same path.
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
		r.cancel()
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

// watchTargets re-applies the target set when the mounted file's mtime changes. Polling, not
// fsnotify: a ConfigMap mount updates via a symlink swap that fsnotify handles awkwardly, the set is
// tiny, and 10s of lag on adding a target is invisible in practice. ponytail: 10s poll, not events.
func watchTargets(ctx context.Context, path string, fw *forwarder) {
	var last time.Time
	if fi, err := os.Stat(path); err == nil {
		last = fi.ModTime()
	}
	tick := time.NewTicker(10 * time.Second)
	defer tick.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
			fi, err := os.Stat(path)
			if err != nil || !fi.ModTime().After(last) {
				continue
			}
			last = fi.ModTime()
			if err := fw.reload(ctx, path); err != nil {
				log.Printf("reload after change failed, keeping last good set: %v", err)
			}
		}
	}
}
