package main

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"go4.org/netipx"
	"tailscale.com/types/ipproto"
	"tailscale.com/types/views"
	"tailscale.com/wgengine/filter"
)

func freePort(t *testing.T) int {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	return ln.Addr().(*net.TCPAddr).Port
}

func writeTargets(t *testing.T, path string, ts []target) {
	b, _ := json.Marshal(ts)
	if err := os.WriteFile(path, b, 0o644); err != nil {
		t.Fatal(err)
	}
}

// A rename keeps the listen port (ports.Assign hands the freed port to the new name). The old
// listener must be closed before the new one binds, or the new target silently never serves.
func TestReloadSamePortRebinds(t *testing.T) {
	port := freePort(t)
	path := filepath.Join(t.TempDir(), "targets.json")
	fw := &forwarder{mode: "egress", run: map[string]running{}}
	defer fw.stopAll()
	ctx := context.Background()

	writeTargets(t, path, []target{{Name: "a", Address: "10.0.0.1", Port: 1, ListenPort: port}})
	fw.reload(ctx, path)
	if _, ok := fw.current()["a"]; !ok {
		t.Fatal("initial target a not running")
	}

	writeTargets(t, path, []target{{Name: "b", Address: "10.0.0.1", Port: 1, ListenPort: port}})
	fw.reload(ctx, path)
	cur := fw.current()
	if _, ok := cur["a"]; ok {
		t.Error("old target a still running")
	}
	if _, ok := cur["b"]; !ok {
		t.Error("renamed target b not running: listener was not rebound on the same port")
	}
}

// filterPermits must answer what the packet filter answers for the packet that opens a connection.
// The agent reaches the filter through tsnet's unstable Sys; this pins the semantics it relies on.
func TestFilterPermitsLikeANewConnection(t *testing.T) {
	self, peer, other := netip.MustParseAddr("100.64.0.1"), netip.MustParseAddr("100.64.0.2"), netip.MustParseAddr("100.64.0.3")
	var local netipx.IPSetBuilder
	local.Add(self)
	localNets, _ := local.IPSet()
	f := filter.New([]filter.Match{{
		IPProto: views.SliceOf([]ipproto.Proto{ipproto.TCP}),
		Srcs:    []netip.Prefix{netip.PrefixFrom(peer, 32)},
		Dsts:    []filter.NetPortRange{{Net: netip.PrefixFrom(self, 32), Ports: filter.PortRange{First: 8443, Last: 8443}}},
	}}, nil, localNets, &netipx.IPSet{}, nil, t.Logf)
	at := func(a netip.Addr, port uint16) netip.AddrPort { return netip.AddrPortFrom(a, port) }
	for _, tc := range []struct {
		name     string
		f        *filter.Filter
		src, dst netip.AddrPort
		want     bool
	}{
		{"granted port", f, at(peer, 50000), at(self, 8443), true},
		{"IPv4-mapped source", f, at(netip.AddrFrom16(peer.As16()), 50000), at(self, 8443), true},
		{"another port of the same node", f, at(peer, 50000), at(self, 9), false},
		{"another source", f, at(other, 50000), at(self, 8443), false},
		{"not this node", f, at(peer, 50000), at(other, 8443), false},
		{"address families differ", f, at(netip.MustParseAddr("fd7a:115c:a1e0::2"), 50000), at(self, 8443), false},
		{"no filter", nil, at(peer, 50000), at(self, 8443), false},
		{"filter without netmap", filter.NewAllowNone(t.Logf, &netipx.IPSet{}), at(peer, 50000), at(self, 8443), false},
		{"unknown source", f, netip.AddrPort{}, at(self, 8443), false},
		{"unknown destination", f, at(peer, 50000), netip.AddrPort{}, false},
	} {
		if got := filterPermits(tc.f, tc.src, tc.dst); got != tc.want {
			t.Errorf("%s: permitted=%t, want %t", tc.name, got, tc.want)
		}
	}
}

type closeRecorder struct{ closed chan struct{} }

func (c *closeRecorder) Close() error { close(c.closed); return nil }

// The backend leg is closed with the client leg, also when the backend dial returns after the
// revocation. A backend that ignores a half-close would otherwise keep its session.
func TestRevocationClosesLinkedConnection(t *testing.T) {
	client, far := net.Pipe()
	defer far.Close()
	l := &trackedListener{conns: map[*trackedConn]struct{}{}}
	tc := &trackedConn{Conn: client, owner: l}
	l.conns[tc] = struct{}{}
	early, late := &closeRecorder{make(chan struct{})}, &closeRecorder{make(chan struct{})}
	tc.link(early)
	if n := l.revoke(func(netip.AddrPort, netip.AddrPort) bool { return true }); n != 0 || len(l.conns) != 1 {
		t.Fatalf("permitted connection closed: n=%d", n)
	}
	if n := l.revoke(func(netip.AddrPort, netip.AddrPort) bool { return false }); n != 1 || len(l.conns) != 0 {
		t.Fatalf("revoked connection kept: n=%d tracked=%d", n, len(l.conns))
	}
	tc.link(late)
	for _, c := range []*closeRecorder{early, late} {
		select {
		case <-c.closed:
		default:
			t.Fatal("linked connection left open")
		}
	}
	if _, err := far.Read(make([]byte, 1)); err != io.EOF {
		t.Fatalf("client leg left open: %v", err)
	}
}

func shortRevokeInterval(t *testing.T) {
	t.Helper()
	old := revokeInterval
	revokeInterval = 10 * time.Millisecond
	t.Cleanup(func() { revokeInterval = old })
}

// deniedSources is a test policy: every source is permitted until it is denied.
type deniedSources struct{ sync.Map }

func (d *deniedSources) permit(src, _ netip.AddrPort) bool { _, denied := d.Load(src); return !denied }
func (d *deniedSources) deny(c net.Conn)                   { d.Store(addrPort(c.LocalAddr()), true) }

// An L4 ingress connection ends on both legs when the policy stops admitting its source. Another
// source keeps its connection, also after the target's listener stopped: enforcement lasts as long
// as the connections do.
func TestRevokedL4ConnectionEnds(t *testing.T) {
	shortRevokeInterval(t)
	backend, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer backend.Close()
	backendEOF := make(chan struct{}, 2)
	go func() {
		for {
			c, err := backend.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				io.Copy(c, c) // echo; returns when the agent closes or half-closes its leg
				backendEOF <- struct{}{}
			}()
		}
	}()
	var policy deniedSources
	m := newAgentMetrics("ingress")
	fw := &forwarder{mode: "ingress", run: map[string]running{}, metrics: m, permit: policy.permit, listenTailnet: func(string, string) (net.Listener, error) {
		return net.Listen("tcp", "127.0.0.1:0")
	}}
	ln, err := fw.listen(context.Background(), target{Name: "db", Address: "127.0.0.1", Port: backend.Addr().(*net.TCPAddr).Port, ListenPort: 5432})
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	dial := func() net.Conn {
		c, err := net.Dial("tcp", ln.Addr().String())
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { c.Close() })
		return c
	}
	echo := func(c net.Conn) error {
		c.SetDeadline(time.Now().Add(3 * time.Second))
		if _, err := c.Write([]byte("x")); err != nil {
			return err
		}
		_, err := io.ReadFull(c, make([]byte, 1))
		return err
	}
	ended := func(c net.Conn, what string) {
		t.Helper()
		c.SetDeadline(time.Now().Add(3 * time.Second))
		_, err := c.Read(make([]byte, 1))
		var timeout net.Error
		if err == nil || (errors.As(err, &timeout) && timeout.Timeout()) {
			t.Fatalf("%s: connection left open: %v", what, err)
		}
		select {
		case <-backendEOF:
		case <-time.After(3 * time.Second):
			t.Fatalf("%s: backend leg left open", what)
		}
	}
	revoked, kept := dial(), dial()
	if echo(revoked) != nil || echo(kept) != nil {
		t.Fatal("exchange before revocation failed")
	}
	if got := metricValue(t, m, "tailnet_agent_connections_active", "", ""); got != 2 {
		t.Fatalf("active connections = %v, want 2", got)
	}
	policy.deny(revoked)
	ended(revoked, "revoked source")
	if err := echo(kept); err != nil {
		t.Fatalf("permitted connection closed with the revoked one: %v", err)
	}
	if got := metricValue(t, m, "tailnet_agent_connections_active", "", ""); got != 1 {
		t.Fatalf("active connections = %v, want 1", got)
	}
	ln.Close() // the target is removed or changed
	if err := echo(kept); err != nil {
		t.Fatalf("stopped listener closed an open connection: %v", err)
	}
	policy.deny(kept)
	ended(kept, "revoked after the listener stopped")
}
