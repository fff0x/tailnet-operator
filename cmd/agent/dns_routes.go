package main

import (
	"context"
	"log"
	"net"
	"net/url"
	"strings"
	"sync"
	"time"

	"tailscale.com/client/local"
	"tailscale.com/ipn"
	"tailscale.com/types/dnstype"
)

// dnsRoutes mirrors the split-DNS routes of the latest netmap: zone → resolver hosts. Headscale
// has no DNS API, so the netmap this node receives is the only place the operator can read the
// configured dns.nameservers.split zones back from.
type dnsRoutes struct {
	mu     sync.Mutex
	seen   bool
	routes map[string][]string
}

// snapshot returns a copy of the routes and whether a netmap has been observed at all.
func (d *dnsRoutes) snapshot() (map[string][]string, bool) {
	d.mu.Lock()
	defer d.mu.Unlock()
	out := make(map[string][]string, len(d.routes))
	for k, v := range d.routes {
		out[k] = append([]string(nil), v...)
	}
	return out, d.seen
}

func (d *dnsRoutes) set(routes map[string][]*dnstype.Resolver) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.seen = true
	d.routes = normalizeDNSRoutes(routes)
}

// normalizeDNSRoutes lowercases zones, drops trailing dots and reduces every resolver Addr form
// (ip, ip:port, scheme://host[:port]/path) to its host, so the operator compares plain addresses.
func normalizeDNSRoutes(routes map[string][]*dnstype.Resolver) map[string][]string {
	out := make(map[string][]string, len(routes))
	for zone, rs := range routes {
		z := strings.ToLower(strings.TrimSuffix(zone, "."))
		hosts := make([]string, 0, len(rs))
		for _, r := range rs {
			if r != nil {
				hosts = append(hosts, resolverHost(r.Addr))
			}
		}
		out[z] = hosts
	}
	return out
}

func resolverHost(addr string) string {
	if strings.Contains(addr, "://") {
		if u, err := url.Parse(addr); err == nil && u.Hostname() != "" {
			return u.Hostname()
		}
	}
	if h, _, err := net.SplitHostPort(addr); err == nil {
		return h
	}
	return addr
}

// watch follows the IPN bus and records every netmap's DNS routes until ctx ends. A broken
// stream is reopened after a short pause; the last good snapshot stays visible meanwhile.
func (d *dnsRoutes) watch(ctx context.Context, lc *local.Client) {
	for ctx.Err() == nil {
		if err := d.follow(ctx, lc); err != nil && ctx.Err() == nil {
			log.Printf("dns routes watch: %v", err)
		}
		select {
		case <-ctx.Done():
		case <-time.After(5 * time.Second):
		}
	}
}

func (d *dnsRoutes) follow(ctx context.Context, lc *local.Client) error {
	w, err := lc.WatchIPNBus(ctx, ipn.NotifyInitialNetMap)
	if err != nil {
		return err
	}
	defer w.Close()
	for {
		n, err := w.Next()
		if err != nil {
			return err
		}
		if n.NetMap != nil {
			d.set(n.NetMap.DNS.Routes)
		}
	}
}
