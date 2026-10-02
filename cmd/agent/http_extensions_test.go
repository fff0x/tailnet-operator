package main

import (
	"context"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestHTTPExtensionsProtocolAndValidation(t *testing.T) {
	for _, version := range []int{0, 1, 2} {
		for _, mode := range []string{"l4", "http"} {
			for _, field := range []string{"backendServerName", "backendCAFile", "requestTimeout", "backendRequestTimeout", "BackendServerName", "requeſtTimeout", "bacKendCAFile"} {
				for _, value := range []any{"", nil, "bad-value"} {
					cfg := validHTTPTarget(t)
					cfg.Mode = mode
					raw, _ := json.Marshal(cfg)
					var record map[string]any
					json.Unmarshal(raw, &record)
					record[field] = value
					var source any = []any{record}
					if version != 0 {
						source = map[string]any{"version": version, "targets": source}
					}
					raw, _ = json.Marshal(source)
					path := filepath.Join(t.TempDir(), "targets.json")
					if err := os.WriteFile(path, raw, 0600); err != nil {
						t.Fatal(err)
					}
					_, err := loadTargets(path)
					if (version != 2 || mode != "http" || value == "bad-value") && err == nil {
						t.Fatalf("extension accepted: version=%d mode=%s field=%s value=%v", version, mode, field, value)
					}
				}
			}
		}
	}
	good := validHTTPTarget(t)
	good.BackendServerName, good.BackendCAFile = backendDNS, "/projection/ca.crt"
	good.RequestTimeout, good.BackendRequestTimeout = "1m", "0s"
	path := filepath.Join(t.TempDir(), "targets.json")
	write := func(cfg target) {
		t.Helper()
		raw, _ := json.Marshal(map[string]any{"version": 2, "targets": []target{cfg}})
		if err := os.WriteFile(path, raw, 0600); err != nil {
			t.Fatal(err)
		}
	}
	write(good)
	got, err := loadTargets(path)
	if err != nil || len(got) != 1 || got[0] != good {
		t.Fatalf("valid v2 rejected: %v", err)
	}
	for _, mutate := range []func(*target){
		func(c *target) { c.BackendServerName = "" }, func(c *target) { c.BackendCAFile = "" },
		func(c *target) { c.BackendServerName = "127.0.0.1" }, func(c *target) { c.BackendServerName = "https://backend" },
		func(c *target) { c.RequestTimeout = "-1s" }, func(c *target) { c.BackendRequestTimeout = "forever" },
	} {
		cfg := good
		mutate(&cfg)
		write(cfg)
		if _, err := loadTargets(path); err == nil {
			t.Fatalf("invalid config accepted: %+v", cfg)
		}
	}
	for _, mutate := range []func(*target){
		func(c *target) { c.BackendServerName = "new.backend.test" }, func(c *target) { c.BackendCAFile = "/new/ca" },
		func(c *target) { c.RequestTimeout = "2m" }, func(c *target) { c.BackendRequestTimeout = "1s" },
	} {
		cfg := good
		mutate(&cfg)
		start, stop := diffTargets(map[string]target{good.Name: good}, []target{cfg})
		if len(start) != 1 || len(stop) != 1 {
			t.Fatal("extension change did not rebind listener")
		}
	}
	// Reference pre-extension decoder accepts only v1, independent of unknown record fields.
	raw, _ := os.ReadFile(path)
	var old struct {
		Version int `json:"version"`
	}
	if json.Unmarshal(raw, &old) != nil || old.Version == 1 {
		t.Fatal("v1 reference agent would accept extension envelope")
	}
}

func TestHTTPExtensionsRejectedReloadAndRemoval(t *testing.T) {
	h, cfg := localHTTPIngress(t, http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	fw := probeForwarder(h, cfg)
	path := filepath.Join(t.TempDir(), "targets.json")
	extended := cfg
	extended.RequestTimeout = "1m"
	writeVersionedTargets(t, path, []target{extended}) // deliberately invalid v1 extension
	if _, err := fw.reload(context.Background(), path); err == nil {
		t.Fatal("v1 extension reload accepted")
	}
	if !h.active() || fw.current()[cfg.Name] != cfg {
		t.Fatal("rejected reload changed the last accepted configuration")
	}
	// Parse failure intentionally keeps the accepted listener; deployment protocol annotation
	// changes/Recreate, covered by controller tests, are the skew safety boundary.
	if err := os.WriteFile(path, []byte(`{"version":2,"targets":[]}`), 0600); err != nil {
		t.Fatal(err)
	}
	if pending, err := fw.reload(context.Background(), path); err != nil || pending != 0 {
		t.Fatalf("v2 removal failed: %d %v", pending, err)
	}
	if h.active() || len(fw.current()) != 0 {
		t.Fatal("v2 removal retained old listener")
	}
	h.transport.mu.Lock()
	closed := h.transport.closed
	h.transport.mu.Unlock()
	if !closed {
		t.Fatal("reload removal did not close backend resources")
	}
}

func TestHTTPBackendHeaderTimeoutIntegration(t *testing.T) {
	for _, timeout := range []string{"20ms", "0s"} {
		t.Run(timeout, func(t *testing.T) {
			b := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				select {
				case <-time.After(80 * time.Millisecond):
					w.WriteHeader(200)
				case <-r.Context().Done():
				}
			}))
			defer b.Close()
			cfg := validHTTPTarget(t)
			cfg.BackendRequestTimeout = timeout
			ln, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			h, err := serveHTTPIngress(context.Background(), ln, cfg, func(ctx context.Context, _ target) (net.Conn, error) {
				return (&net.Dialer{}).DialContext(ctx, "tcp", b.Listener.Addr().String())
			})
			if err != nil {
				ln.Close()
				t.Fatal(err)
			}
			defer h.Close()
			client := localHTTPClient(t, h, cfg, false)
			response, err := client.Get("https://" + testDNS)
			if err != nil {
				t.Fatal(err)
			}
			response.Body.Close()
			want := 504
			if timeout == "0s" {
				want = 200
			}
			if response.StatusCode != want {
				t.Fatalf("status %d want %d", response.StatusCode, want)
			}
		})
	}
}
