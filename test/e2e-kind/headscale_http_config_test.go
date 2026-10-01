//go:build e2e_kind

package e2ekind

import (
	"encoding/json"
	"testing"
)

func TestHeadscaleHTTPConfig(t *testing.T) {
	var c struct {
		URL            string `json:"server_url"`
		Listen         string `json:"listen_addr"`
		Metrics        string `json:"metrics_listen_addr"`
		GRPC           string `json:"grpc_listen_addr"`
		Cert           string `json:"tls_cert_path"`
		Key            string `json:"tls_key_path"`
		ACME           string `json:"tls_letsencrypt_hostname"`
		DisableUpdates bool   `json:"disable_check_updates"`
		Policy         struct {
			Mode string `json:"mode"`
		} `json:"policy"`
		Logtail struct {
			Enabled bool `json:"enabled"`
		} `json:"logtail"`
		DERP struct {
			URLs       []string `json:"urls"`
			Paths      []string `json:"paths"`
			AutoUpdate bool     `json:"auto_update_enabled"`
			Server     struct {
				Enabled bool   `json:"enabled"`
				Verify  bool   `json:"verify_clients"`
				AutoAdd bool   `json:"automatically_add_embedded_derp_region"`
				Stun    string `json:"stun_listen_addr"`
				V4      string `json:"ipv4"`
				V6      string `json:"ipv6"`
			} `json:"server"`
		} `json:"derp"`
		DNS struct {
			Magic       bool   `json:"magic_dns"`
			Base        string `json:"base_domain"`
			Override    bool   `json:"override_local_dns"`
			Nameservers struct {
				Global []string            `json:"global"`
				Split  map[string][]string `json:"split"`
			} `json:"nameservers"`
		} `json:"dns"`
		Node struct {
			Routes struct {
				HA struct {
					Probe string `json:"probe_interval"`
				} `json:"ha"`
			} `json:"routes"`
		} `json:"node"`
	}
	if json.Unmarshal([]byte(headscaleHTTPConfig), &c) != nil {
		t.Fatal("invalid fixture config")
	}
	if c.URL != "https://fixture-headscale.tailnet-system.svc:8443" || c.Listen != "0.0.0.0:8443" || c.Metrics != "127.0.0.1:9090" || c.GRPC != "127.0.0.1:50443" || c.Cert != "/headscale-tls/tls.crt" || c.Key != "/headscale-tls/tls.key" || c.ACME != "" || c.Policy.Mode != "database" {
		t.Fatal("fixture endpoints or TLS changed")
	}
	if !c.DisableUpdates || c.Logtail.Enabled || c.DERP.AutoUpdate || c.DERP.URLs == nil || len(c.DERP.URLs) != 0 || c.DERP.Paths == nil || len(c.DERP.Paths) != 0 || c.Node.Routes.HA.Probe != "0s" {
		t.Fatal("external bootstrap sources enabled")
	}
	if !c.DERP.Server.Enabled || !c.DERP.Server.Verify || !c.DERP.Server.AutoAdd || c.DERP.Server.Stun != "0.0.0.0:3478" || c.DERP.Server.V4 != "" || c.DERP.Server.V6 != "" {
		t.Fatal("owned DNS-based DERP changed")
	}
	if !c.DNS.Magic || c.DNS.Base != "fixture.test" || c.DNS.Override || len(c.DNS.Nameservers.Global) != 0 || len(c.DNS.Nameservers.Split) != 0 {
		t.Fatal("fixture DNS changed")
	}
}
