package gateway

import (
	"errors"
	"fmt"
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
	maxDNSConfigBytes   = 1 << 20 // Combined ConfigMap data, not just source hosts.
	maxDNSHostsBytes    = 1 << 20
	maxDNSHostNames     = 16384
)

var (
	ErrDNSConfiguration = errors.New("gateway DNS configuration is invalid")
	// hosts+forward can send unsupported types for a locally known name to the
	// upstream. Do not render that weaker contract while strict locality is open.
	ErrDNSForwardingUnsupported = errors.New("gateway DNS forwarding is not implemented")
)

// DNSInputs contains public DNS configuration, never Secret contents. Hosts is
// a snapshot of the selected Tailnet's owned hosts ConfigMap; ownership and scope
// must be checked by the caller. Names outside the primary zone are not served.
// Serial must advance for every zone-data change, including hosts-only changes;
// gateway generation alone is not sufficient. This renderer has no clock or I/O.
// BindAddresses must be chosen explicitly. CoreDNS's -dns.port flag selects the
// port (default 53). No management/metrics listener is rendered.
type DNSInputs struct {
	Config        tnv1.GatewayDNS
	ServerIP      string
	Hosts         string
	Serial        uint32
	BindAddresses []netip.Addr
}

// DNSPlan describes two files for a fresh gateway's configuration ConfigMap.
// It is not an adoption projection, apply document or evidence of DNS health.
// Dynamic records replace a static record's entire RRset, not only its family.
// The original hosts ConfigMap remains owned by the Tailnet DNS reconciler.
type DNSPlan struct {
	Corefile string
	ZoneFile string
}

// RenderDNS compiles one authoritative file zone. Keeping all known names in the
// same zone gives NODATA for missing types and prevents upstream/wildcard leaks.
// Wildcards use DNS file semantics, not the template plugin. Unknown zones are
// refused; no system resolver is used. Extra forwarding zones are fail-closed
// until strict known-name locality can be implemented and tested for them.
// Image support, Service allocation, ownership and reachability are caller checks.
func RenderDNS(in DNSInputs) (DNSPlan, error) {
	cfg := in.Config
	if len(cfg.ExtraZones) != 0 {
		return DNSPlan{}, ErrDNSForwardingUnsupported
	}
	server, ok := dnsAddress(in.ServerIP)
	if !ok || !dnsZone(string(cfg.Zone)) || in.Serial == 0 || len(in.BindAddresses) == 0 || len(in.BindAddresses) > 2 || len(cfg.StaticRecords) > 128 || len(in.Hosts) > maxDNSHostsBytes {
		return DNSPlan{}, ErrDNSConfiguration
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
	for _, record := range cfg.StaticRecords {
		if len(validation.IsDNS1123Label(record.Name)) != 0 || len(record.Name)+1+len(cfg.Zone) > 253 {
			return DNSPlan{}, ErrDNSConfiguration
		}
		name := record.Name + "." + string(cfg.Zone)
		addr, ok := dnsAddress(string(record.Address))
		if !ok || records[name] != nil {
			return DNSPlan{}, ErrDNSConfiguration
		}
		records[name] = []netip.Addr{addr}
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
	for name, addresses := range hosts {
		if name == string(cfg.Zone) {
			// Keep the authoritative apex/nameserver tied to the gateway Service.
			return DNSPlan{}, ErrDNSConfiguration
		}
		if strings.HasSuffix(name, "."+string(cfg.Zone)) {
			records[name] = addresses
		}
	}
	records[string(cfg.Zone)] = []netip.Addr{server}

	var zone strings.Builder
	// The apex is its own nameserver. A fixed reserved SOA mailbox avoids adding
	// a label to a zone already at the DNS wire limit. No mail is sent here.
	fmt.Fprintf(&zone, "%s. 30 IN SOA %s. hostmaster.invalid. %d 7200 3600 1209600 30\n", cfg.Zone, cfg.Zone, in.Serial)
	fmt.Fprintf(&zone, "%s. 30 IN NS %s.\n", cfg.Zone, cfg.Zone)
	names := make([]string, 0, len(records))
	for name := range records {
		names = append(names, name)
	}
	slices.Sort(names)
	for _, name := range names {
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
	core := fmt.Sprintf("%s {\n    bind %s\n    errors\n    file %s %s {\n        reload 1s\n    }\n}\n", cfg.Zone, strings.Join(binds, " "), DNSZoneFile, cfg.Zone)
	if len(core)+zone.Len() > maxDNSConfigBytes {
		return DNSPlan{}, ErrDNSConfiguration
	}
	return DNSPlan{Corefile: core, ZoneFile: zone.String()}, nil
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
