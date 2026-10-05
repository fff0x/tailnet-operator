package main

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"testing"
	"time"

	"tailscale.com/ipn"
	"tailscale.com/ipn/ipnstate"
	"tailscale.com/types/key"
	"tailscale.com/types/views"
	proof "tsunaro.io/tailnet-operator/test/internal/gatewayprobe"
)

var testConfig = proof.Config{TargetIPv4: "10.244.0.8", GatewayIPv4: "100.64.0.2"}

func selectedStatus(prefixes ...string) *ipnstate.Status {
	list := []netip.Prefix{}
	for _, p := range prefixes {
		list = append(list, netip.MustParsePrefix(p))
	}
	allowed := views.SliceOf(list)
	return &ipnstate.Status{BackendState: "Running", Peer: map[key.NodePublic]*ipnstate.PeerStatus{
		{}: {TailscaleIPs: []netip.Addr{netip.MustParseAddr(testConfig.GatewayIPv4)}, AllowedIPs: &allowed, InNetworkMap: true},
	}}
}

func TestRouteSelection(t *testing.T) {
	gateway, target := netip.MustParseAddr(testConfig.GatewayIPv4), netip.MustParseAddr(testConfig.TargetIPv4)
	prefs := &ipn.Prefs{RouteAll: true}
	for _, tc := range []struct {
		name   string
		status *ipnstate.Status
		prefs  *ipn.Prefs
		want   bool
	}{
		{"selected", selectedStatus("10.244.0.8/32"), prefs, true},
		{"no status", nil, prefs, false},
		{"no prefs", selectedStatus("10.244.0.8/32"), nil, false},
		{"not accepting", selectedStatus("10.244.0.8/32"), &ipn.Prefs{}, false},
		{"only tail address", selectedStatus("100.64.0.2/32"), prefs, false},
		{"broad route", selectedStatus("10.244.0.0/16"), prefs, false},
		{"wrong host", selectedStatus("10.244.0.9/32"), prefs, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := routeSelected(tc.status, tc.prefs, gateway, target); got != tc.want {
				t.Fatal(got)
			}
		})
	}
	for _, mutate := range []func(*ipnstate.Status){
		func(s *ipnstate.Status) { s.BackendState = "Stopped" },
		func(s *ipnstate.Status) {
			s.Peer[key.NodePublic{}].TailscaleIPs = []netip.Addr{netip.MustParseAddr("100.64.0.3")}
		},
		func(s *ipnstate.Status) { s.Peer[key.NodePublic{}].InNetworkMap = false },
		func(s *ipnstate.Status) {
			p := s.Peer[key.NodePublic{}]
			p.PrimaryRoutes = p.AllowedIPs
			p.AllowedIPs = nil
		},
		func(s *ipnstate.Status) { s.Peer[key.NewNode().Public()] = s.Peer[key.NodePublic{}] },
	} {
		s := selectedStatus("10.244.0.8/32")
		mutate(s)
		if routeSelected(s, prefs, gateway, target) {
			t.Fatal("false selected route")
		}
	}
}

func requireValidResult(t *testing.T, r proof.Result) {
	t.Helper()
	b, _ := json.Marshal(r)
	if _, err := proof.DecodeResult(b); err != nil {
		t.Fatalf("invalid result %+v", r)
	}
}

func TestProbeDialSelectionFreshRouteAndFixedErrors(t *testing.T) {
	native, overlay, checks := 0, 0, 0
	selected := false
	stateErr := false
	d := probeDeps{
		native: func(ctx context.Context, n, a string) (net.Conn, error) {
			native++
			if n != "tcp" || a != "10.244.0.8:8081" {
				t.Fatal(n, a)
			}
			return nil, errors.New("credential secret")
		},
		overlay: func(ctx context.Context, n, a string) (net.Conn, error) {
			overlay++
			if n != "tcp" || a != "10.244.0.8:8081" {
				t.Fatal(n, a)
			}
			return nil, errors.New("credential secret")
		},
		prefs: func(context.Context) (*ipn.Prefs, error) { return &ipn.Prefs{RouteAll: true}, nil },
		status: func(ctx context.Context) (*ipnstate.Status, error) {
			checks++
			deadline, ok := ctx.Deadline()
			if !ok || time.Until(deadline) > probeTimeout {
				t.Fatal("unbounded")
			}
			if stateErr {
				return nil, errors.New("secret")
			}
			if selected {
				return selectedStatus("10.244.0.8/32"), nil
			}
			return selectedStatus(), nil
		},
	}
	r := probe(context.Background(), testConfig, "underlay", d)
	requireValidResult(t, r)
	if native != 1 || overlay != 0 || checks != 0 || r.RouteSelected || r.Error != proof.ErrorDial {
		t.Fatal(r)
	}
	r = probe(context.Background(), testConfig, "forward", d)
	requireValidResult(t, r)
	if native != 1 || overlay != 0 || checks != 1 || r.RouteSelected || r.Error != proof.ErrorNoRoute {
		t.Fatal(r)
	}
	selected = true
	r = probe(context.Background(), testConfig, "forward", d)
	requireValidResult(t, r)
	if overlay != 1 || checks != 2 || !r.RouteSelected || r.Error != proof.ErrorDial {
		t.Fatal(r)
	}
	selected = false
	r = probe(context.Background(), testConfig, "forward", d)
	if overlay != 1 || checks != 3 || r.RouteSelected || r.Error != proof.ErrorNoRoute {
		t.Fatal("cached route", r)
	}
	stateErr = true
	r = probe(context.Background(), testConfig, "forward", d)
	requireValidResult(t, r)
	if r.Error != proof.ErrorState || overlay != 1 {
		t.Fatal(r)
	}
}

func TestControlRequests(t *testing.T) {
	calls := 0
	h := controlHandler(func(ctx context.Context, mode string) proof.Result {
		calls++
		return proof.Result{Mode: mode, Error: proof.ErrorDial}
	})
	for _, mode := range []string{"underlay", "forward", "dns-udp", "dns-tcp"} {
		w := httptest.NewRecorder()
		h.ServeHTTP(w, httptest.NewRequest(http.MethodPost, "/probe", strings.NewReader(proof.RequestBody(mode))))
		if w.Code != 200 || w.Header().Get("Cache-Control") != "no-store" {
			t.Fatal(w.Code)
		}
	}
	if calls != 4 {
		t.Fatal(calls)
	}
	for _, tc := range []struct{ method, path, body string }{
		{"POST", "/probe?endpoint=evil", proof.RequestBody("forward")},
		{"GET", "/probe", proof.RequestBody("forward")},
		{"POST", "/probe", `{"mode":"forward","mode":"forward"}`},
		{"POST", "/probe", `{"mode":"forward","address":"evil"}`},
		{"POST", "/probe", `{"mode":"forward"} {}`},
		{"POST", "/probe", `{"mode":"forward"}` + "\n"},
		{"POST", "/probe", `{"mode":null}`},
		{"POST", "/probe", `{"mode":"FORWARD"}`},
		{"POST", "/probe", strings.Repeat("x", 129)},
		{"POST", "/readyz", ""}, {"GET", "/readyz?x=1", ""}, {"GET", "/readyz", "body"},
	} {
		w := httptest.NewRecorder()
		h.ServeHTTP(w, httptest.NewRequest(tc.method, tc.path, strings.NewReader(tc.body)))
		if w.Code < 400 {
			t.Fatal("accepted", tc)
		}
	}
	if calls != 4 {
		t.Fatal("bad request reached probe")
	}
	for _, handler := range []http.Handler{h, controlHandler(nil)} {
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, httptest.NewRequest("GET", "/readyz", nil))
		if w.Code != 204 {
			t.Fatal(w.Code)
		}
	}
	w := httptest.NewRecorder()
	controlHandler(nil).ServeHTTP(w, httptest.NewRequest("POST", "/probe", strings.NewReader(proof.RequestBody("forward"))))
	if w.Code < 400 {
		t.Fatal("target probe")
	}
}

func startTestTarget(t *testing.T) net.Listener {
	t.Helper()
	l, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- serveTarget(ctx, l) }()
	t.Cleanup(func() {
		cancel()
		if err := <-done; err != nil {
			t.Error(err)
		}
	})
	return l
}

func TestActualChallengeTargetAndFreshConnections(t *testing.T) {
	l := startTestTarget(t)
	for range 2 {
		c, err := net.DialTimeout("tcp", l.Addr().String(), time.Second)
		if err != nil {
			t.Fatal(err)
		}
		_ = c.SetDeadline(time.Now().Add(time.Second))
		challenge, err := newChallenge()
		if err != nil {
			t.Fatal(err)
		}
		source, code := exchangeChallenge(c, challenge)
		observed := c.LocalAddr().(*net.TCPAddr).AddrPort().Addr().String()
		_ = c.Close()
		if code != "" || source != observed {
			t.Fatal(source, observed, code)
		}
	}
	// Oversized requests cannot smuggle a claimed source or another challenge.
	c, err := net.DialTimeout("tcp", l.Addr().String(), time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(time.Second))
	challenge, _ := newChallenge()
	_ = writeFull(c, append(append([]byte(requestMarker), challenge...), []byte("10.244.0.2")...))
	_ = c.(*net.TCPConn).CloseWrite()
	reply, _ := io.ReadAll(c)
	if len(reply) != 0 {
		t.Fatal("accepted oversized request")
	}
}

func TestProbeReportsActualSourceNotExpectedGateway(t *testing.T) {
	l := startTestTarget(t)
	calls := 0
	localDial := func(ctx context.Context, _, _ string) (net.Conn, error) {
		calls++
		return (&net.Dialer{}).DialContext(ctx, "tcp", l.Addr().String())
	}
	d := probeDeps{
		native: localDial, overlay: localDial,
		prefs:  func(context.Context) (*ipn.Prefs, error) { return &ipn.Prefs{RouteAll: true}, nil },
		status: func(context.Context) (*ipnstate.Status, error) { return selectedStatus("10.244.0.8/32"), nil },
	}
	for _, mode := range []string{"underlay", "forward"} {
		r := probe(context.Background(), testConfig, mode, d)
		requireValidResult(t, r)
		if !r.Connected || !r.TargetVerified || r.SourceIPv4 != "127.0.0.1" || r.Error != "" || r.RouteSelected != (mode == "forward") {
			t.Fatal(r)
		}
		// Deliberately simulated native shortcut: even a selected-route flag cannot
		// forge the source. The parent must compare it with the actual Gateway PodIP.
		if r.SourceIPv4 == testConfig.GatewayIPv4 {
			t.Fatal("fabricated source")
		}
	}
	if calls != 2 {
		t.Fatal("reused connection")
	}
}

func TestTargetCancellationClosesAcceptedSockets(t *testing.T) {
	l, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- serveTarget(ctx, l) }()
	c, err := net.DialTimeout("tcp", l.Addr().String(), time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(time.Second))
	_, _ = c.Write([]byte(requestMarker)) // An unfinished request must not pin shutdown.
	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("target failed to shut down")
	}
	var b [1]byte
	if _, err := c.Read(b[:]); err == nil {
		t.Fatal("socket remained open")
	}
}

func TestReplyRejectsReflectionsStaleAndFalseSources(t *testing.T) {
	challenge, _ := newChallenge()
	other, _ := newChallenge()
	if string(challenge) == string(other) {
		t.Fatal("reused challenge")
	}
	good := append(append([]byte(replyMarker), challenge...), 10, 244, 0, 2)
	if source, err := parseReply(good, challenge); err != nil || source != "10.244.0.2" {
		t.Fatal(source, err)
	}
	for _, reply := range [][]byte{
		append([]byte(requestMarker), challenge...),
		append(append([]byte(replyMarker), other...), 10, 244, 0, 2),
		append(append([]byte(replyMarker), challenge...), 0, 0, 0, 0),
		append(append([]byte(replyMarker), challenge...), 224, 0, 0, 1),
		append(append([]byte(replyMarker), challenge...), 255, 255, 255, 255),
		append(append([]byte{}, good...), 0), good[:len(good)-1], nil,
	} {
		if _, err := parseReply(reply, challenge); err == nil {
			t.Fatal("accepted invalid reply")
		}
	}
}
