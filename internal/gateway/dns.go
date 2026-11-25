package gateway

import (
	"errors"
	"fmt"
	"maps"
	"net/netip"
	"slices"
	"strings"

	"k8s.io/apimachinery/pkg/util/validation"
	tnv1 "tsunaro.io/tailnet-operator/api/v1alpha1"
)

const (
	// DNSWorkingDirectory is required when starting CoreDNS with the rendered
	// Corefile. Project the configuration directory, never an immutable subPath.
	DNSWorkingDirectory = "/etc/coredns"
	DNSZoneFile         = "zone.db"
	// DNSHostsFile is rendered only when dns.extraZones is set: the hosts-source
	// names that fall inside those zones, served ahead of the upstream forward.
	DNSHostsFile      = "hosts"
	dnsHostsHeader    = "# rendered by tailnet-operator from the Tailnet hosts source for dns.extraZones; do not edit\n"
	maxDNSConfigBytes = 1 << 20 // Combined ConfigMap data, not just source hosts.
	maxDNSHostsBytes  = 1 << 20
	maxDNSHostNames   = 16384
)

var ErrDNSConfiguration = errors.New("gateway DNS configuration is invalid")

// DNSInputs contains public DNS configuration, never Secret contents. Hosts is
// a snapshot of the selected Tailnet's owned hosts ConfigMap; ownership and scope
// must be checked by the caller. Names outside the primary zone are served only
// when they fall inside a dns.extraZones entry (as hosts overrides of that zone)
// or a dns.aliasZones entry (answered from the hosts source alone).
// Serial must advance for every zone-data change, including hosts-only changes;
// gateway generation alone is not sufficient. This renderer has no clock or I/O.
// BindAddresses must be chosen explicitly. CoreDNS's -dns.port flag selects the
// port (default 53). The rendered Corefile enables `prometheus :9153` for pod
// scraping and the `reload` plugin so a new Corefile applies without a Pod
// restart.
type DNSInputs struct {
	Config        tnv1.GatewayDNS
	ServerIP      string
	Hosts         string
	Serial        uint32
	BindAddresses []netip.Addr
}

// DNSPlan describes the files for a fresh gateway's configuration ConfigMap.
// It is not an adoption projection, apply document or evidence of DNS health.
// Dynamic records replace a static record's entire RRset, not only its family.
// The original hosts ConfigMap remains owned by the Tailnet DNS reconciler.
// HostsFile is empty (and no ConfigMap key is written) unless dns.extraZones
// is set, so a Gateway without extra zones renders exactly as before.
type DNSPlan struct {
	Corefile  string
	ZoneFile  string
	HostsFile string
}

// RenderDNS compiles one authoritative file zone. Keeping all known names in the
// same zone gives NODATA for missing types and prevents upstream/wildcard leaks.
// Wildcards use DNS file semantics, not the template plugin. Unknown zones are
// refused; no system resolver is used.
//
// Each dns.extraZones entry becomes a forwarding server block: hosts-source
// names inside that zone are answered locally (hosts plugin, A/AAAA only),
// everything else in the zone is forwarded to the listed upstreams. This is the
// weaker hosts+forward contract by design: every name the hosts source does not
// carry is forwarded, and before CoreDNS 1.15 so was a non-address query type for
// a locally known name (1.15 answers it NODATA). Extra zones never overlap
// the primary zone or each other, and an upstream is never the gateway itself.
//
// Each dns.aliasZones entry becomes a server block that answers only the
// hosts-source names inside that zone, inline and without an upstream. Alias
// zones overlap neither the primary zone, an extra zone nor each other.
//
// The Corefile exposes Prometheus metrics on :9153 and enables the global reload
// plugin so a Corefile change (e.g. a new static record targeting CNAME) takes
// effect on the running Pod without a restart; zone-file changes are picked up
// by the per-zone file reload. Image support, Service allocation, ownership and
// reachability are caller checks.
func RenderDNS(in DNSInputs) (DNSPlan, error) {
	cfg := in.Config
	server, ok := dnsAddress(in.ServerIP)
	if !ok || !dnsZone(string(cfg.Zone)) || in.Serial == 0 || len(in.BindAddresses) == 0 || len(in.BindAddresses) > 2 || len(cfg.StaticRecords) > 128 || len(in.Hosts) > maxDNSHostsBytes {
		return DNSPlan{}, ErrDNSConfiguration
	}
	extraZones, err := dnsExtraZones(cfg, server)
	if err != nil {
		return DNSPlan{}, err
	}
	aliasZones, err := dnsAliasZones(cfg, extraZones)
	if err != nil {
		return DNSPlan{}, err
	}
	binds := make([]string, 0, len(in.BindAddresses))
	for _, addr := range in.BindAddresses {
		if !addr.IsValid() || addr.Zone() != "" || addr.Is4In6() || addr.IsLinkLocalUnicast() || !(addr.IsUnspecified() || addr.IsLoopback() || addr.IsGlobalUnicast()) {
			return DNSPlan{}, ErrDNSConfiguration
		}
		binds = append(binds, addr.String())
	}
	slices.Sort(binds)
	binds = slices.Compact(binds)
	records := make(map[string][]netip.Addr)
	cnames := make(map[string]string)
	for _, record := range cfg.StaticRecords {
		if len(validation.IsDNS1123Label(record.Name)) != 0 || len(record.Name)+1+len(cfg.Zone) > 253 {
			return DNSPlan{}, ErrDNSConfiguration
		}
		name := record.Name + "." + string(cfg.Zone)
		if records[name] != nil || cnames[name] != "" {
			return DNSPlan{}, ErrDNSConfiguration
		}
		switch {
		case record.Address != "" && record.Target != "":
			return DNSPlan{}, ErrDNSConfiguration
		case record.Address != "":
			addr, ok := dnsAddress(string(record.Address))
			if !ok {
				return DNSPlan{}, ErrDNSConfiguration
			}
			records[name] = []netip.Addr{addr}
		case record.Target != "":
			target := string(record.Target)
			if !dnsZone(target) || len(target) > 253 || target == name ||
				!(target == string(cfg.Zone) || strings.HasSuffix(target, "."+string(cfg.Zone))) {
				return DNSPlan{}, ErrDNSConfiguration
			}
			cnames[name] = target
		default:
			return DNSPlan{}, ErrDNSConfiguration
		}
	}
	if cfg.WildcardAddress != "" {
		addr, ok := dnsAddress(string(cfg.WildcardAddress))
		if !ok || len(cfg.Zone)+2 > 253 {
			return DNSPlan{}, ErrDNSConfiguration
		}
		records["*."+string(cfg.Zone)] = []netip.Addr{addr}
	}
	hosts, err := parseDNSHosts(in.Hosts)
	if err != nil {
		return DNSPlan{}, err
	}
	extraHosts := make(map[string][]netip.Addr)
	aliasHosts := make(map[string]map[string][]netip.Addr, len(aliasZones))
	for _, zone := range aliasZones {
		aliasHosts[zone] = make(map[string][]netip.Addr)
	}
	for name, addresses := range hosts {
		if name == string(cfg.Zone) {
			// Keep the authoritative apex/nameserver tied to the gateway Service.
			return DNSPlan{}, ErrDNSConfiguration
		}
		if strings.HasSuffix(name, "."+string(cfg.Zone)) {
			// Dynamic A/AAAA for a name shadows any static CNAME for the same name:
			// hosts data is authoritative over the configured alias.
			records[name] = addresses
			delete(cnames, name)
			continue
		}
		for _, extra := range extraZones {
			if name == extra.zone || strings.HasSuffix(name, "."+extra.zone) {
				extraHosts[name] = addresses
				break
			}
		}
		for _, zone := range aliasZones {
			if name == zone || strings.HasSuffix(name, "."+zone) {
				aliasHosts[zone][name] = addresses
				break
			}
		}
	}
	records[string(cfg.Zone)] = []netip.Addr{server}

	var zone strings.Builder
	// The apex is its own nameserver. A fixed reserved SOA mailbox avoids adding
	// a label to a zone already at the DNS wire limit. No mail is sent here.
	fmt.Fprintf(&zone, "%s. 30 IN SOA %s. hostmaster.invalid. %d 7200 3600 1209600 30\n", cfg.Zone, cfg.Zone, in.Serial)
	fmt.Fprintf(&zone, "%s. 30 IN NS %s.\n", cfg.Zone, cfg.Zone)
	names := make([]string, 0, len(records)+len(cnames))
	for name := range records {
		names = append(names, name)
	}
	for name := range cnames {
		names = append(names, name)
	}
	slices.Sort(names)
	names = slices.Compact(names)
	for _, name := range names {
		if target, ok := cnames[name]; ok {
			fmt.Fprintf(&zone, "%s. 30 IN CNAME %s.\n", name, target)
			continue
		}
		addresses := records[name]
		slices.SortFunc(addresses, func(a, b netip.Addr) int { return a.Compare(b) })
		for _, addr := range slices.Compact(addresses) {
			rr := "A"
			if addr.Is6() {
				rr = "AAAA"
			}
			fmt.Fprintf(&zone, "%s. 30 IN %s %s\n", name, rr, addr)
		}
	}
	// `prometheus :9153` serves CoreDNS metrics on every bound interface; the
	// global `reload` plugin picks up Corefile changes (e.g. a newly rendered
	// static record) without restarting the Pod. Per-zone `file` reload stays at
	// 1s so zone.db changes still land fast.
	bind := strings.Join(binds, " ")
	core := fmt.Sprintf("%s {\n    bind %s\n    errors\n    prometheus :9153\n    file %s %s {\n        reload 1s\n    }\n    reload\n}\n", cfg.Zone, bind, DNSZoneFile, cfg.Zone)
	var hostsFile strings.Builder
	if len(extraZones) != 0 {
		// One server block per extra zone. `prometheus` and `reload` are shared
		// across blocks by CoreDNS; `cache 30` matches the forwarded TTL ceiling
		// of the legacy sidecars this replaces. The hosts file is one file for
		// all extra zones; each block only serves its own zone from it.
		hostsFile.WriteString(dnsHostsHeader)
		for _, name := range slices.Sorted(maps.Keys(extraHosts)) {
			addresses := extraHosts[name]
			slices.SortFunc(addresses, func(a, b netip.Addr) int { return a.Compare(b) })
			for _, addr := range slices.Compact(addresses) {
				fmt.Fprintf(&hostsFile, "%s %s\n", addr, name)
			}
		}
		for _, extra := range extraZones {
			core += fmt.Sprintf("%s {\n    bind %s\n    errors\n    prometheus :9153\n    hosts %s %s {\n        fallthrough\n    }\n    cache 30\n    forward . %s {\n        max_concurrent 1000\n    }\n    reload\n}\n",
				extra.zone, bind, DNSHostsFile, extra.zone, strings.Join(extra.upstreams, " "))
		}
	}
	// Alias zones carry their entries inline, so neither the ConfigMap keys nor the
	// projected Pod template change and adding a zone needs no Pod restart. /dev/null is
	// an always-present empty file for the plugin's mandatory file argument.
	// ponytail: hosts plugin without SOA, so an unknown name in an alias zone is SERVFAIL,
	// not NXDOMAIN. Upgrade path: one generated file zone per alias zone.
	for _, zone := range aliasZones {
		var entries strings.Builder
		for _, name := range slices.Sorted(maps.Keys(aliasHosts[zone])) {
			addresses := aliasHosts[zone][name]
			slices.SortFunc(addresses, func(a, b netip.Addr) int { return a.Compare(b) })
			for _, addr := range slices.Compact(addresses) {
				fmt.Fprintf(&entries, "        %s %s\n", addr, name)
			}
		}
		core += fmt.Sprintf("%s {\n    bind %s\n    errors\n    prometheus :9153\n    hosts /dev/null %s {\n%s    }\n    reload\n}\n", zone, bind, zone, entries.String())
	}
	if len(core)+zone.Len()+hostsFile.Len() > maxDNSConfigBytes {
		return DNSPlan{}, ErrDNSConfiguration
	}
	return DNSPlan{Corefile: core, ZoneFile: zone.String(), HostsFile: hostsFile.String()}, nil
}

type dnsExtraZone struct {
	zone      string
	upstreams []string
}

// dnsExtraZones validates dns.extraZones against the primary zone and the
// gateway address and returns them in spec order with canonical upstreams.
func dnsExtraZones(cfg tnv1.GatewayDNS, server netip.Addr) ([]dnsExtraZone, error) {
	if len(cfg.ExtraZones) > 16 {
		return nil, ErrDNSConfiguration
	}
	zones := []string{string(cfg.Zone)}
	out := make([]dnsExtraZone, 0, len(cfg.ExtraZones))
	for _, extra := range cfg.ExtraZones {
		zone := string(extra.Zone)
		if !dnsZone(zone) || len(extra.Upstreams) == 0 || len(extra.Upstreams) > 8 {
			return nil, ErrDNSConfiguration
		}
		for _, known := range zones {
			if zone == known || strings.HasSuffix(zone, "."+known) || strings.HasSuffix(known, "."+zone) {
				return nil, ErrDNSConfiguration
			}
		}
		zones = append(zones, zone)
		upstreams := make([]string, 0, len(extra.Upstreams))
		for _, raw := range extra.Upstreams {
			addr, ok := dnsAddress(string(raw))
			if !ok || addr == server || slices.Contains(upstreams, addr.String()) {
				return nil, ErrDNSConfiguration
			}
			upstreams = append(upstreams, addr.String())
		}
		out = append(out, dnsExtraZone{zone: zone, upstreams: upstreams})
	}
	return out, nil
}

// dnsAliasZones validates dns.aliasZones against the primary zone, the extra
// zones and each other and returns them sorted, so spec order never changes
// the rendered Corefile.
func dnsAliasZones(cfg tnv1.GatewayDNS, extraZones []dnsExtraZone) ([]string, error) {
	if len(cfg.AliasZones) > 16 {
		return nil, ErrDNSConfiguration
	}
	known := []string{string(cfg.Zone)}
	for _, extra := range extraZones {
		known = append(known, extra.zone)
	}
	out := make([]string, 0, len(cfg.AliasZones))
	for _, raw := range cfg.AliasZones {
		zone := string(raw)
		if !dnsZone(zone) {
			return nil, ErrDNSConfiguration
		}
		for _, other := range slices.Concat(known, out) {
			if zone == other || strings.HasSuffix(zone, "."+other) || strings.HasSuffix(other, "."+zone) {
				return nil, ErrDNSConfiguration
			}
		}
		out = append(out, zone)
	}
	slices.Sort(out)
	return out, nil
}

func parseDNSHosts(raw string) (map[string][]netip.Addr, error) {
	hosts := make(map[string][]netip.Addr)
	for _, line := range strings.Split(raw, "\n") {
		line, _, _ = strings.Cut(line, "#")
		fields := strings.Fields(line)
		if len(fields) == 0 {
			continue
		}
		addr, ok := dnsAddress(fields[0])
		if !ok || len(fields) < 2 {
			return nil, ErrDNSConfiguration
		}
		for _, name := range fields[1:] {
			if !dnsZone(name) {
				return nil, ErrDNSConfiguration
			}
			hosts[name] = append(hosts[name], addr)
			if len(hosts) > maxDNSHostNames {
				return nil, ErrDNSConfiguration
			}
		}
	}
	return hosts, nil
}

func dnsZone(value string) bool {
	if len(value) == 0 || len(value) > 253 {
		return false
	}
	for _, label := range strings.Split(value, ".") {
		if len(validation.IsDNS1123Label(label)) != 0 {
			return false
		}
	}
	return true
}

func dnsAddress(value string) (netip.Addr, bool) {
	addr, err := netip.ParseAddr(value)
	return addr, err == nil && addr.Zone() == "" && !addr.Is4In6() && addr.IsGlobalUnicast() && !addr.IsLinkLocalUnicast() && addr.String() == value
}
