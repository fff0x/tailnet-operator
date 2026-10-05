package main

import (
	"context"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/netip"
	"strconv"
	"time"

	"tailscale.com/ipn"
	"tailscale.com/ipn/ipnstate"
	proof "tsunaro.io/tailnet-operator/test/internal/gatewayprobe"
)

const probeTimeout = 5 * time.Second

type dialFunc func(context.Context, string, string) (net.Conn, error)

type probeDeps struct {
	native  dialFunc
	overlay dialFunc
	status  func(context.Context) (*ipnstate.Status, error)
	prefs   func(context.Context) (*ipn.Prefs, error)
}

// AllowedIPs is the selected netmap route, not merely an advertised or approved
// PrimaryRoutes entry. An ambiguous exact route also fails closed.
func routeSelected(status *ipnstate.Status, prefs *ipn.Prefs, gateway, destination netip.Addr) bool {
	if status == nil || status.BackendState != "Running" || prefs == nil || !prefs.RouteAll {
		return false
	}
	wanted := netip.PrefixFrom(destination, 32)
	matches := 0
	selected := false
	for _, p := range status.Peer {
		if p == nil || !p.InNetworkMap || p.AllowedIPs == nil {
			continue
		}
		isGateway := false
		for _, ip := range p.TailscaleIPs {
			if ip == gateway {
				isGateway = true
			}
		}
		for _, prefix := range p.AllowedIPs.All() {
			if prefix == wanted {
				matches++
				selected = isGateway
			}
		}
	}
	return matches == 1 && selected
}

func probe(ctx context.Context, config proof.Config, mode string, d probeDeps) proof.Result {
	r := proof.Result{Mode: mode}
	ctx, cancel := context.WithTimeout(ctx, probeTimeout)
	defer cancel()
	dial := d.native
	network, address := "tcp", net.JoinHostPort(config.TargetIPv4, strconv.Itoa(proof.TargetPort))
	dns := mode == "dns-udp" || mode == "dns-tcp"
	if mode != "underlay" {
		gateway := netip.MustParseAddr(config.GatewayIPv4)
		destination := netip.MustParseAddr(config.TargetIPv4)
		if dns {
			destination = gateway
		}
		prefs, err := d.prefs(ctx)
		if err != nil {
			r.Error = proof.ErrorState
			return r
		}
		status, err := d.status(ctx) // Fresh state on every request, before any overlay dial.
		if err != nil || ctx.Err() != nil {
			r.Error = proof.ErrorState
			return r
		}
		if !routeSelected(status, prefs, gateway, destination) {
			r.Error = proof.ErrorNoRoute
			return r
		}
		r.RouteSelected = mode == "forward"
		dial = d.overlay
	}
	var request []byte
	var id uint16
	var err error
	if dns {
		address = net.JoinHostPort(config.GatewayIPv4, "53")
		if mode == "dns-udp" {
			network = "udp"
		}
		request, id, err = dnsQuery()
	} else {
		request, err = newChallenge()
	}
	if err != nil {
		r.Error = proof.ErrorRandom
		return r
	}
	c, err := dial(ctx, network, address)
	if err != nil || c == nil {
		if c != nil {
			_ = c.Close()
		}
		r.Error = proof.ErrorDial
		return r
	}
	defer c.Close()
	r.Connected = true
	deadline, _ := ctx.Deadline()
	stop := context.AfterFunc(ctx, func() { _ = c.Close() })
	defer stop()
	if c.SetDeadline(deadline) != nil {
		r.Error = proof.ErrorExchange
		return r
	}
	if dns {
		r.Error = exchangeDNS(c, network, request, id)
		if r.Error == "" && ctx.Err() == nil {
			r.DNSVerified = true
			r.AnswerIPv4 = proof.DNSAnswer
		}
	} else {
		r.SourceIPv4, r.Error = exchangeChallenge(c, request)
		r.TargetVerified = r.Error == "" && ctx.Err() == nil
	}
	if ctx.Err() != nil {
		r.Error = proof.ErrorExchange
		r.TargetVerified = false
		r.DNSVerified = false
		r.SourceIPv4 = ""
		r.AnswerIPv4 = ""
	}
	return r
}

func decodeRequest(reader io.Reader) (string, error) {
	b, err := io.ReadAll(io.LimitReader(reader, 129))
	if err != nil || len(b) > 128 {
		return "", errRejected
	}
	for _, mode := range []string{"underlay", "forward", "dns-udp", "dns-tcp"} {
		if string(b) == proof.RequestBody(mode) {
			return mode, nil
		}
	}
	return "", errRejected
}

// A nil probe is the target role: only readiness exists there.
func controlHandler(doProbe func(context.Context, string) proof.Result) http.Handler {
	slots := make(chan struct{}, 4)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		if r.URL.RequestURI() == "/readyz" && r.Method == http.MethodGet && r.ContentLength == 0 && len(r.TransferEncoding) == 0 {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		if doProbe == nil || r.URL.RequestURI() != "/probe" || r.Method != http.MethodPost {
			http.Error(w, "rejected", http.StatusNotFound)
			return
		}
		select {
		case slots <- struct{}{}:
			defer func() { <-slots }()
		default:
			http.Error(w, "busy", http.StatusServiceUnavailable)
			return
		}
		mode, err := decodeRequest(r.Body)
		if err != nil {
			http.Error(w, "rejected", http.StatusBadRequest)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(doProbe(r.Context(), mode))
	})
}
