package main

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"net"
	"net/http"
	"strings"
	"testing"
)

func TestVirtualHostProbeNamesAreFixedAndPaired(t *testing.T) {
	for _, sni := range []string{publicDNS, virtualDNS, virtualAlias, virtualBridge} {
		for _, host := range []string{publicDNS, virtualDNS, virtualAlias, virtualBridge} {
			for _, h2 := range []bool{false, true} {
				raw, _ := json.Marshal(map[string]any{"target": "100.64.0.8", "http2": h2, "sni": sni, "host": host})
				input, err := decodeProbe(strings.NewReader(string(raw)))
				if err != nil || input.SNI != sni || input.Host != host {
					t.Fatal("fixed SNI/Host pair rejected")
				}
				pool := x509.NewCertPool()
				_, tr := probeClient(pool, func(_ context.Context, network, address string) (net.Conn, error) {
					if network != "tcp" || address != "100.64.0.8:443" {
						t.Fatal("SNI/Host changed fixed dial destination")
					}
					return nil, errRejected
				}, input)
				if tr.TLSClientConfig.ServerName != sni || tr.TLSClientConfig.RootCAs != pool || tr.TLSClientConfig.InsecureSkipVerify || tr.Proxy != nil {
					t.Fatal("SNI verification or explicit trust changed")
				}
				_, _ = tr.DialContext(context.Background(), "udp", "elsewhere:80")
				tr.CloseIdleConnections()
				calls := 0
				probe(context.Background(), input, func(req *http.Request) (*http.Response, error) {
					calls++
					if req.URL.String() != "https://"+sni+"/accept?fixed=1" || req.Host != host || req.Method != "GET" {
						t.Fatal("wire authority/SNI mismatch was normalized away")
					}
					return nil, errRejected
				})
				if calls != 1 {
					t.Fatal("fixed-name probe did not execute")
				}
			}
		}
	}
	for _, extra := range []string{
		`"sni":"admin.fixture.test"`,
		`"host":"admin.fixture.test"`,
		`"sni":"","host":""`,
		`"sni":null,"host":"admin.fixture.test"`,
		`"sni":"admin.fixture.test","host":false`,
		`"sni":"elsewhere.fixture.test","host":"admin.fixture.test"`,
		`"sni":"admin.fixture.test","host":"admin.fixture.test:443"`,
		`"sni":"admin.fixture.test.","host":"admin.fixture.test"`,
		`"sni":"100.64.0.8","host":"admin.fixture.test"`,
		`"sni":"admin.fixture.test","host":"admin.fixture.test","sni":"http-agent.fixture.test"`,
		`"sni":"admin.fixture.test","host":"admin.fixture.test","host":"http-agent.fixture.test"`,
		`"sni":"admin.fixture.test","host":"admin.fixture.test","path":"/arbitrary"`,
	} {
		if _, err := decodeProbe(strings.NewReader(`{"target":"100.64.0.8","http2":false,` + extra + `}`)); err != errRejected {
			t.Fatal("invalid SNI/Host shape accepted")
		}
	}
	for _, input := range []probeInput{
		{Target: publicDNS, SNI: virtualDNS},
		{Target: publicDNS, Host: virtualDNS},
		{Target: publicDNS, SNI: "elsewhere.fixture.test", Host: virtualDNS},
	} {
		_, tr := probeClient(x509.NewCertPool(), func(context.Context, string, string) (net.Conn, error) {
			t.Fatal("invalid names reached dial")
			return nil, errRejected
		}, input)
		if _, err := tr.DialContext(context.Background(), "tcp", "ignored:443"); err != errRejected {
			t.Fatal("transport accepted invalid names")
		}
		probe(context.Background(), input, func(*http.Request) (*http.Response, error) {
			t.Fatal("invalid names reached request")
			return nil, errRejected
		})
	}
}
