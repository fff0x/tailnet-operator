//go:build gatewaydns

// Package gatewaydns checks rendered files against an explicitly supplied CoreDNS
// binary. All listeners are loopback-only; no Kubernetes context is used.
package gatewaydns

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/net/dns/dnsmessage"
	tnv1 "tsunaro.io/tailnet-operator/api/v1alpha1"
	"tsunaro.io/tailnet-operator/internal/gateway"
)

func exchange(network, address, name string, typ dnsmessage.Type) (dnsmessage.Message, error) {
	var result dnsmessage.Message
	qname, err := dnsmessage.NewName(name + ".")
	if err != nil {
		return result, errors.New("invalid fixture name")
	}
	request := dnsmessage.Message{Header: dnsmessage.Header{ID: 421, RecursionDesired: true}, Questions: []dnsmessage.Question{{Name: qname, Type: typ, Class: dnsmessage.ClassINET}}}
	packet, err := request.Pack()
	if err != nil {
		return result, errors.New("pack fixture")
	}
	conn, err := net.DialTimeout(network, address, 300*time.Millisecond)
	if err != nil {
		return result, errors.New("dial fixture")
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(500 * time.Millisecond))
	if network == "tcp" {
		packet = append(binary.BigEndian.AppendUint16(nil, uint16(len(packet))), packet...)
	}
	if _, err := conn.Write(packet); err != nil {
		return result, errors.New("send fixture")
	}
	response := make([]byte, 65535)
	var n int
	if network == "tcp" {
		if _, err = io.ReadFull(conn, response[:2]); err == nil {
			n = int(binary.BigEndian.Uint16(response[:2]))
			_, err = io.ReadFull(conn, response[:n])
		}
	} else {
		n, err = conn.Read(response)
	}
	if err != nil || result.Unpack(response[:n]) != nil {
		return result, errors.New("receive fixture")
	}
	if !result.Response || result.ID != request.ID || result.Truncated || len(result.Questions) != 1 || result.Questions[0] != request.Questions[0] {
		return result, errors.New("mismatched fixture response")
	}
	return result, nil
}

func assertAnswer(t *testing.T, address, name string, typ dnsmessage.Type, code dnsmessage.RCode, want string) {
	t.Helper()
	for _, network := range []string{"udp", "tcp"} {
		m, err := exchange(network, address, name, typ)
		if err != nil {
			t.Fatalf("%s query failed for fixture %s", network, name)
		}
		if m.RCode != code {
			t.Fatalf("%s fixture %s: rcode=%d want=%d", network, name, m.RCode, code)
		}
		if want == "" {
			if len(m.Answers) != 0 {
				t.Fatalf("%s fixture %s unexpectedly answered a negative query", network, name)
			}
			continue
		}
		if len(m.Answers) != 1 {
			t.Fatalf("%s fixture %s: expected one record", network, name)
		}
		var got string
		switch record := m.Answers[0].Body.(type) {
		case *dnsmessage.AResource:
			got = netip.AddrFrom4(record.A).String()
		case *dnsmessage.AAAAResource:
			got = netip.AddrFrom16(record.AAAA).String()
		default:
			t.Fatal("unexpected fixture answer type")
		}
		if got != want || m.Answers[0].Header.Name.String() != name+"." {
			t.Fatalf("%s fixture %s returned the wrong destination", network, name)
		}
	}
}

// Both directions are owned loopback sockets. Return distinct records for every
// name/type so erroneous fallthrough for known names cannot pass as NODATA.
func upstream(t *testing.T) (string, *atomic.Int64) {
	t.Helper()
	tcp, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal("bind upstream TCP")
	}
	udp, err := net.ListenPacket("udp4", tcp.Addr().String())
	if err != nil {
		tcp.Close()
		t.Fatal("bind upstream UDP")
	}
	count := new(atomic.Int64)
	answer := func(packet []byte) []byte {
		var request dnsmessage.Message
		if request.Unpack(packet) != nil || len(request.Questions) != 1 {
			return nil
		}
		count.Add(1)
		q := request.Questions[0]
		response := dnsmessage.Message{Header: dnsmessage.Header{ID: request.ID, Response: true, Authoritative: true, RecursionAvailable: true, RecursionDesired: request.RecursionDesired}, Questions: request.Questions}
		if strings.HasPrefix(q.Name.String(), "absent.") {
			response.RCode = dnsmessage.RCodeNameError
		} else {
			var body dnsmessage.ResourceBody
			switch q.Type {
			case dnsmessage.TypeA:
				body = &dnsmessage.AResource{A: [4]byte{192, 0, 2, 222}}
			case dnsmessage.TypeAAAA:
				body = &dnsmessage.AAAAResource{AAAA: netip.MustParseAddr("2001:db8::222").As16()}
			case dnsmessage.TypeTXT:
				body = &dnsmessage.TXTResource{TXT: []string{"upstream"}}
			}
			if body != nil {
				response.Answers = []dnsmessage.Resource{{Header: dnsmessage.ResourceHeader{Name: q.Name, Type: q.Type, Class: dnsmessage.ClassINET, TTL: 1}, Body: body}}
			}
		}
		out, _ := response.Pack()
		return out
	}
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		b := make([]byte, 65535)
		for {
			n, addr, err := udp.ReadFrom(b)
			if err != nil {
				return
			}
			if packet := answer(b[:n]); packet != nil {
				_, _ = udp.WriteTo(packet, addr)
			}
		}
	}()
	go func() {
		defer wg.Done()
		for {
			conn, err := tcp.Accept()
			if err != nil {
				return
			}
			_ = conn.SetDeadline(time.Now().Add(time.Second))
			var header [2]byte
			if _, err := io.ReadFull(conn, header[:]); err == nil {
				b := make([]byte, int(binary.BigEndian.Uint16(header[:])))
				if _, err := io.ReadFull(conn, b); err == nil {
					packet := answer(b)
					_, _ = conn.Write(append(binary.BigEndian.AppendUint16(nil, uint16(len(packet))), packet...))
				}
			}
			conn.Close()
		}
	}()
	t.Cleanup(func() { tcp.Close(); udp.Close(); wg.Wait() })
	return tcp.Addr().String(), count
}

// Model a ConfigMap directory projection: stable file symlinks, atomic ..data
// replacement, no subPath. Only synthetic fixture contents are written.
func project(t *testing.T, root, revision string, files map[string]string, initial bool) {
	t.Helper()
	if os.MkdirAll(filepath.Join(root, revision), 0700) != nil {
		t.Fatal("create projection")
	}
	for name, content := range files {
		if os.WriteFile(filepath.Join(root, revision, name), []byte(content), 0600) != nil {
			t.Fatal("write projection")
		}
		if initial && os.Symlink(filepath.Join("..data", name), filepath.Join(root, name)) != nil {
			t.Fatal("link projection")
		}
	}
	if os.Symlink(revision, filepath.Join(root, "..data-new")) != nil || os.Rename(filepath.Join(root, "..data-new"), filepath.Join(root, "..data")) != nil {
		t.Fatal("publish projection")
	}
}

func waitAnswer(t *testing.T, address, name, want string) {
	t.Helper()
	deadline := time.Now().Add(8 * time.Second)
	for time.Now().Before(deadline) {
		m, err := exchange("udp", address, name, dnsmessage.TypeA)
		if err == nil && m.RCode == dnsmessage.RCodeSuccess && len(m.Answers) == 1 {
			if a, ok := m.Answers[0].Body.(*dnsmessage.AResource); ok && netip.AddrFrom4(a.A).String() == want {
				return
			}
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatal("DNS fixture did not converge before deadline")
}

func start(t *testing.T, binary, root, probe, bind string) string {
	t.Helper()
	listener, err := net.Listen("tcp", net.JoinHostPort(bind, "0"))
	if err != nil {
		t.Fatal("select DNS fixture port")
	}
	address := listener.Addr().String()
	port := listener.Addr().(*net.TCPAddr).Port
	listener.Close() // A bind race fails the fixture; it never uses a live resolver.
	log, err := os.OpenFile(filepath.Join(root, "coredns.log"), os.O_CREATE|os.O_WRONLY, 0600)
	if err != nil {
		t.Fatal("create private CoreDNS log")
	}
	cmd := exec.Command(binary, "-conf", filepath.Join(root, "Corefile"), "-dns.port", fmt.Sprint(port))
	cmd.Dir = root
	cmd.Stdout = log
	cmd.Stderr = log
	// No inherited Corefile substitutions or resolver/runtime configuration.
	cmd.Env = []string{"HOME=" + root, "PATH=/no-external-commands"}
	if cmd.Start() != nil {
		log.Close()
		t.Fatal("start isolated CoreDNS")
	}
	done := make(chan struct{})
	go func() { _ = cmd.Wait(); close(done) }()
	t.Cleanup(func() {
		_ = cmd.Process.Signal(os.Interrupt)
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			_ = cmd.Process.Kill()
			<-done
			t.Error("CoreDNS required forced cleanup")
		}
		log.Close()
	})
	waitAnswer(t, address, probe, "192.0.2.7")
	select {
	case <-done:
		t.Fatal("owned CoreDNS exited during startup")
	default:
	}
	return address
}

func coreDNSBinary(t *testing.T) string {
	t.Helper()
	binary := os.Getenv("COREDNS_BINARY")
	if !filepath.IsAbs(binary) {
		t.Fatal("set COREDNS_BINARY to an explicit trusted CoreDNS binary")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	version, err := exec.CommandContext(ctx, binary, "-version").Output()
	if err != nil || !strings.HasPrefix(string(version), "CoreDNS-") {
		t.Fatal("cannot verify CoreDNS binary")
	}
	return binary
}

func TestRenderedDNS(t *testing.T) {
	binary := coreDNSBinary(t)
	for _, wildcard := range []string{"", "192.0.2.80", "2001:db8::80"} {
		name := "no-wildcard"
		if wildcard != "" {
			name = "wildcard-" + fmt.Sprint(netip.MustParseAddr(wildcard).BitLen())
		}
		t.Run(name, func(t *testing.T) {
			root := t.TempDir()
			in := gateway.DNSInputs{Config: tnv1.GatewayDNS{Zone: "tail.example", WildcardAddress: tnv1.GatewayIP(wildcard), StaticRecords: []tnv1.GatewayStaticRecord{{Name: "static", Address: "192.0.2.10"}, {Name: "app", Address: "2001:db8::bad"}}}, ServerIP: "192.0.2.1", Serial: 1, BindAddresses: []netip.Addr{netip.MustParseAddr("127.0.0.1")}, Hosts: "192.0.2.7 app.tail.example\n2001:db8::7 v6.tail.example\n192.0.2.9 dyn.site.example\n"}
			plan, err := gateway.RenderDNS(in)
			if err != nil {
				t.Fatal("render DNS fixture")
			}
			project(t, root, "v1", map[string]string{"Corefile": plan.Corefile, "zone.db": plan.ZoneFile}, true)
			address := start(t, binary, root, "app.tail.example", "127.0.0.1")
			assertAnswer(t, address, "app.tail.example", dnsmessage.TypeA, dnsmessage.RCodeSuccess, "192.0.2.7")
			assertAnswer(t, address, "app.tail.example", dnsmessage.TypeAAAA, dnsmessage.RCodeSuccess, "")
			assertAnswer(t, address, "app.tail.example", dnsmessage.TypeTXT, dnsmessage.RCodeSuccess, "")
			assertAnswer(t, address, "v6.tail.example", dnsmessage.TypeAAAA, dnsmessage.RCodeSuccess, "2001:db8::7")
			assertAnswer(t, address, "v6.tail.example", dnsmessage.TypeA, dnsmessage.RCodeSuccess, "")
			for _, owner := range []string{"app.tail.example", "v6.tail.example", "static.tail.example"} {
				for _, typ := range []dnsmessage.Type{dnsmessage.TypeTXT, dnsmessage.TypeMX, dnsmessage.TypeSRV, dnsmessage.Type(64), dnsmessage.Type(65), dnsmessage.Type(257)} {
					assertAnswer(t, address, owner, typ, dnsmessage.RCodeSuccess, "")
				}
			}
			assertAnswer(t, address, "child.app.tail.example", dnsmessage.TypeA, dnsmessage.RCodeNameError, "")
			assertAnswer(t, address, "static.tail.example", dnsmessage.TypeA, dnsmessage.RCodeSuccess, "192.0.2.10")
			assertAnswer(t, address, "static.tail.example", dnsmessage.TypeAAAA, dnsmessage.RCodeSuccess, "")
			assertAnswer(t, address, "tail.example", dnsmessage.TypeA, dnsmessage.RCodeSuccess, "192.0.2.1")
			for _, typ := range []dnsmessage.Type{dnsmessage.TypeA, dnsmessage.TypeAAAA, dnsmessage.TypeTXT} {
				code, want := dnsmessage.RCodeSuccess, ""
				if wildcard == "" {
					code = dnsmessage.RCodeNameError
				} else if (typ == dnsmessage.TypeA && netip.MustParseAddr(wildcard).Is4()) || (typ == dnsmessage.TypeAAAA && netip.MustParseAddr(wildcard).Is6()) {
					want = wildcard
				}
				assertAnswer(t, address, "missing.tail.example", typ, code, want)
			}
			assertAnswer(t, address, "dyn.site.example", dnsmessage.TypeA, dnsmessage.RCodeRefused, "")
			assertAnswer(t, address, "unserved.example", dnsmessage.TypeA, dnsmessage.RCodeRefused, "")
			in.Serial = 2
			in.Hosts = strings.Replace(in.Hosts, "192.0.2.7", "192.0.2.8", 1)
			updated, err := gateway.RenderDNS(in)
			if err != nil {
				t.Fatal("render updated hosts snapshot")
			}
			project(t, root, "v2", map[string]string{"Corefile": updated.Corefile, "zone.db": updated.ZoneFile}, false)
			waitAnswer(t, address, "app.tail.example", "192.0.2.8")
			assertAnswer(t, address, "app.tail.example", dnsmessage.TypeA, dnsmessage.RCodeSuccess, "192.0.2.8")
			in.Serial = 3
			in.Config.StaticRecords[0].Address = "192.0.2.11"
			in.Hosts = strings.Replace(in.Hosts, "2001:db8::7 v6.tail.example\n", "", 1)
			updated, err = gateway.RenderDNS(in)
			if err != nil {
				t.Fatal("render updated zone")
			}
			project(t, root, "v3", map[string]string{"Corefile": updated.Corefile, "zone.db": updated.ZoneFile}, false)
			waitAnswer(t, address, "static.tail.example", "192.0.2.11")
			assertAnswer(t, address, "static.tail.example", dnsmessage.TypeA, dnsmessage.RCodeSuccess, "192.0.2.11")
			code, want := dnsmessage.RCodeSuccess, ""
			if wildcard == "" {
				code = dnsmessage.RCodeNameError
			} else if netip.MustParseAddr(wildcard).Is6() {
				want = wildcard
			}
			assertAnswer(t, address, "v6.tail.example", dnsmessage.TypeAAAA, code, want)
		})
	}
}

// assertCNAMEResolves verifies CoreDNS returns a CNAME chain followed by the
// target's address, mirroring what a real resolver would see.
func assertCNAMEResolves(t *testing.T, address, name, target, want string) {
	t.Helper()
	for _, network := range []string{"udp", "tcp"} {
		m, err := exchange(network, address, name, dnsmessage.TypeA)
		if err != nil {
			t.Fatalf("%s query failed for CNAME fixture %s", network, name)
		}
		if m.RCode != dnsmessage.RCodeSuccess || len(m.Answers) < 2 {
			t.Fatalf("%s fixture %s: rcode=%d answers=%d (want chain)", network, name, m.RCode, len(m.Answers))
		}
		cname, ok := m.Answers[0].Body.(*dnsmessage.CNAMEResource)
		if !ok || cname.CNAME.String() != target+"." {
			t.Fatalf("%s fixture %s: first answer not CNAME to %s", network, name, target)
		}
		final, ok := m.Answers[len(m.Answers)-1].Body.(*dnsmessage.AResource)
		if !ok || netip.AddrFrom4(final.A).String() != want {
			t.Fatalf("%s fixture %s: CNAME chain did not resolve to %s", network, name, want)
		}
	}
}

// Static CNAME records within the zone resolve to the target's A/AAAA records,
// and the Corefile that the operator renders enables the metrics (prometheus)
// and in-place reload plugins so CoreDNS can be probed and so Corefile
// changes land without a Pod restart.
func TestRenderedDNSCNAME(t *testing.T) {
	binary := coreDNSBinary(t)
	root := t.TempDir()
	in := gateway.DNSInputs{
		Config: tnv1.GatewayDNS{Zone: "tail.example", StaticRecords: []tnv1.GatewayStaticRecord{
			{Name: "k8s", Target: "app.tail.example"},
			{Name: "nested", Target: "deep.sub.tail.example"},
		}},
		ServerIP:      "192.0.2.1",
		Serial:        1,
		BindAddresses: []netip.Addr{netip.MustParseAddr("127.0.0.1")},
		Hosts:         "192.0.2.7 app.tail.example\n192.0.2.8 deep.sub.tail.example\n",
	}
	plan, err := gateway.RenderDNS(in)
	if err != nil {
		t.Fatal("render CNAME fixture")
	}
	// The operator's render MUST wire the metrics plugin and the global reload
	// so Corefile changes propagate without restart.
	if !strings.Contains(plan.Corefile, "prometheus :9153") {
		t.Fatal("rendered Corefile missing prometheus listener")
	}
	if !strings.Contains(plan.Corefile, "\n    reload\n") {
		t.Fatal("rendered Corefile missing global reload plugin")
	}
	project(t, root, "v1", map[string]string{"Corefile": plan.Corefile, "zone.db": plan.ZoneFile}, true)
	address := start(t, binary, root, "app.tail.example", "127.0.0.1")
	// In-zone CNAME follows to the target's A record.
	assertCNAMEResolves(t, address, "k8s.tail.example", "app.tail.example", "192.0.2.7")
	// Nested FQDN target (host under a sub-label) is also followed.
	assertCNAMEResolves(t, address, "nested.tail.example", "deep.sub.tail.example", "192.0.2.8")
	// Direct A query for the target host still works.
	assertAnswer(t, address, "app.tail.example", dnsmessage.TypeA, dnsmessage.RCodeSuccess, "192.0.2.7")
}

func TestRenderedDNSIPv6(t *testing.T) {
	binary := coreDNSBinary(t)
	root := t.TempDir()
	in := gateway.DNSInputs{Config: tnv1.GatewayDNS{Zone: "tail.example"}, ServerIP: "2001:db8::1", Hosts: "192.0.2.7 app.tail.example\n2001:db8::7 v6.tail.example\n", Serial: 1, BindAddresses: []netip.Addr{netip.IPv6Loopback()}}
	plan, err := gateway.RenderDNS(in)
	if err != nil {
		t.Fatal("render IPv6 fixture")
	}
	project(t, root, "v1", map[string]string{"Corefile": plan.Corefile, "zone.db": plan.ZoneFile}, true)
	address := start(t, binary, root, "app.tail.example", "::1")
	assertAnswer(t, address, "tail.example", dnsmessage.TypeAAAA, dnsmessage.RCodeSuccess, "2001:db8::1")
	assertAnswer(t, address, "tail.example", dnsmessage.TypeA, dnsmessage.RCodeSuccess, "")
	assertAnswer(t, address, "v6.tail.example", dnsmessage.TypeAAAA, dnsmessage.RCodeSuccess, "2001:db8::7")
	assertAnswer(t, address, "v6.tail.example", dnsmessage.TypeTXT, dnsmessage.RCodeSuccess, "")
}

// This is an intentionally unsafe control, not renderer output. It demonstrates
// why hosts+forward is not accepted as the gateway's strict-locality contract.
func TestCoreDNSForwardingBoundary(t *testing.T) {
	binary := coreDNSBinary(t)
	root := t.TempDir()
	upstreamAddress, count := upstream(t)
	core := fmt.Sprintf("tail.example {\n bind 127.0.0.1\n hosts hosts.d/hosts {\n no_reverse\n fallthrough\n }\n forward . %s\n}\n", upstreamAddress)
	project(t, root, "v1", map[string]string{"Corefile": core}, true)
	project(t, filepath.Join(root, "hosts.d"), "v1", map[string]string{"hosts": "192.0.2.7 app.tail.example\n"}, true)
	address := start(t, binary, root, "app.tail.example", "127.0.0.1")
	before := count.Load()
	assertAnswer(t, address, "app.tail.example", dnsmessage.TypeAAAA, dnsmessage.RCodeSuccess, "")
	if count.Load() != before {
		t.Fatal("A-only host unexpectedly forwarded AAAA")
	}
	for _, network := range []string{"udp", "tcp"} {
		m, err := exchange(network, address, "app.tail.example", dnsmessage.TypeTXT)
		if err != nil || m.RCode != dnsmessage.RCodeSuccess || len(m.Answers) != 1 {
			t.Fatal("unsafe control did not reproduce TXT fallthrough")
		}
		rr, ok := m.Answers[0].Body.(*dnsmessage.TXTResource)
		if !ok || len(rr.TXT) != 1 || rr.TXT[0] != "upstream" {
			t.Fatal("unsafe control did not answer from the owned upstream")
		}
	}
	if count.Load() <= before {
		t.Fatal("control never reached the owned upstream")
	}
}
