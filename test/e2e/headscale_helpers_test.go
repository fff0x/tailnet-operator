//go:build e2e

package e2e

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	_ "embed"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"this-is-fine.io/tailnet-operator/internal/headscale"
)

// Hashes from the official release checksums.txt, reviewed with each matrix update.
//
//go:embed headscale-checksums.txt
var checksums string

func headscaleBinary(version string) (string, error) {
	if runtime.GOOS != "linux" || (runtime.GOARCH != "amd64" && runtime.GOARCH != "arm64") {
		return "", fmt.Errorf("Tier 1 assets currently support Linux amd64/arm64 only")
	}
	cache := os.Getenv("E2E_HEADSCALE_DIR")
	if cache == "" {
		base, err := os.UserCacheDir()
		if err != nil {
			return "", err
		}
		cache = filepath.Join(base, "tailnet-operator-e2e", "headscale")
	}
	path := filepath.Join(cache, strings.TrimPrefix(version, "v"), "headscale-linux-"+runtime.GOARCH)
	asset := "headscale_" + strings.TrimPrefix(version, "v") + "_linux_" + runtime.GOARCH
	var expected string
	for line := range strings.SplitSeq(checksums, "\n") {
		fields := strings.Fields(line)
		if len(fields) == 2 && fields[1] == asset {
			expected = fields[0]
		}
	}
	if expected == "" {
		return "", fmt.Errorf("no pinned Headscale checksum for %s", asset)
	}
	f, err := os.Open(path)
	if err != nil {
		return "", fmt.Errorf("Headscale asset missing; run task e2e: %w", err)
	}
	defer f.Close()
	hash := sha256.New()
	if _, err := io.Copy(hash, f); err != nil {
		return "", err
	}
	if fmt.Sprintf("%x", hash.Sum(nil)) != expected {
		return "", fmt.Errorf("Headscale checksum mismatch for %s", asset)
	}
	return path, nil
}

type policyWrite struct {
	at     time.Time
	status int
}

type headscaleProcess struct {
	url, key string
	mu       sync.Mutex
	writes   []policyWrite

	// Private fixture lifecycle, accessed only by the test goroutine (not the recorder).
	binary, configPath, dir, directURL string
	childEnv                           []string
	processCtx                         context.Context
	serverLog                          *os.File
	cmd                                *exec.Cmd
	done                               chan struct{}
	processErr                         error
}

func (h *headscaleProcess) policyWrites() []policyWrite {
	h.mu.Lock()
	defer h.mu.Unlock()
	return append([]policyWrite(nil), h.writes...)
}

func (h *headscaleProcess) client() *headscale.Client { return headscale.New(h.url, h.key) }

// startHeadscale runs a real server and a transparent loopback recorder. The recorder observes
// only PUT status/timing, never bearer headers or bodies, and does not synthesize API responses.
func startHeadscale(t *testing.T, ctx context.Context, version, mode string, seed bool) *headscaleProcess {
	t.Helper()
	binary, err := headscaleBinary(version)
	if err != nil {
		t.Fatal(err)
	}
	// A short path avoids the Unix-socket path limit; MkdirTemp creates mode 0700.
	dir, err := os.MkdirTemp("", "hs-e2e-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := os.RemoveAll(dir); err != nil {
			t.Errorf("remove Headscale fixture: %v", err)
		}
	})
	write := func(name string, data []byte) string {
		t.Helper()
		path := filepath.Join(dir, name)
		if err := os.WriteFile(path, data, 0600); err != nil {
			t.Fatal(err)
		}
		return path
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	address := listener.Addr().String()
	if err := listener.Close(); err != nil {
		t.Fatal(err)
	}
	policyPath := write("policy.hujson", []byte("{}"))
	// Headscale requires a DERP region, but an empty static region needs no network peer.
	derpPath := write("derp.yaml", []byte("regions:\n  999:\n    regionid: 999\n    regioncode: isolated\n    regionname: Isolated fixture\n    nodes: []\n"))
	cfg := map[string]any{
		"server_url": "http://" + address, "listen_addr": address,
		"metrics_listen_addr": "", "grpc_listen_addr": "127.0.0.1:0", "grpc_allow_insecure": false,
		"noise":       map[string]any{"private_key_path": filepath.Join(dir, "noise.key")},
		"prefixes":    map[string]any{"v4": "100.64.0.0/10"},
		"database":    map[string]any{"type": "sqlite", "sqlite": map[string]any{"path": filepath.Join(dir, "db.sqlite")}},
		"unix_socket": filepath.Join(dir, "headscale.sock"), "unix_socket_permission": "0600",
		"policy":                map[string]any{"mode": mode, "path": policyPath},
		"derp":                  map[string]any{"server": map[string]any{"enabled": false}, "urls": []string{}, "paths": []string{derpPath}, "auto_update_enabled": false},
		"dns":                   map[string]any{"magic_dns": false, "override_local_dns": false, "nameservers": map[string]any{"global": []string{}, "split": map[string]any{}}},
		"disable_check_updates": true, "logtail": map[string]any{"enabled": false},
		"log": map[string]any{"level": "warn", "format": "json"},
	}
	if version == "v0.29.3" {
		cfg["node"] = map[string]any{"routes": map[string]any{"ha": map[string]any{"probe_interval": "0s"}}}
	}
	configJSON, err := json.Marshal(cfg)
	if err != nil {
		t.Fatal(err)
	}
	configPath := write("config.json", configJSON)
	// Whitelist instead of inheriting HEADSCALE_*, proxies, credentials, or user config paths.
	childEnv := []string{"PATH=" + os.Getenv("PATH"), "HOME=" + dir, "TMPDIR=" + dir, "LANG=C.UTF-8", "TZ=UTC", "TS_NO_LOGS_NO_SUPPORT=1"}
	serverLog, err := os.OpenFile(filepath.Join(dir, "server.log"), os.O_CREATE|os.O_WRONLY, 0600)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = serverLog.Close() })
	// Keep the server alive through CR cleanup even though t.Context is canceled before Cleanup.
	processCtx, cancel := context.WithTimeout(context.Background(), 170*time.Second)
	directURL := "http://" + address
	h := &headscaleProcess{
		binary: binary, configPath: configPath, dir: dir, directURL: directURL,
		childEnv: childEnv, processCtx: processCtx, serverLog: serverLog,
	}
	t.Cleanup(func() { defer cancel(); h.stop() })
	h.start(t, ctx)
	if err := json.Unmarshal(h.cli(t, ctx, "apikeys", "create", "--expiration", "1h", "--output", "json"), &h.key); err != nil || h.key == "" {
		t.Fatal("Headscale did not return a JSON API-key string")
	}
	if mode == "database" && seed {
		h.cli(t, ctx, "policy", "set", "--file", policyPath)
	}
	target, err := url.Parse(directURL)
	if err != nil {
		t.Fatal(err)
	}
	proxy := httputil.NewSingleHostReverseProxy(target)
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.Proxy = nil
	proxy.Transport = transport
	t.Cleanup(transport.CloseIdleConnections)
	proxy.ModifyResponse = func(resp *http.Response) error {
		if resp.Request.Method == http.MethodPut && resp.Request.URL.Path == "/api/v1/policy" {
			h.mu.Lock()
			h.writes = append(h.writes, policyWrite{at: time.Now(), status: resp.StatusCode})
			h.mu.Unlock()
		}
		return nil
	}
	server := httptest.NewServer(proxy) // httptest binds 127.0.0.1, not all interfaces.
	t.Cleanup(server.Close)
	h.url = server.URL
	return h
}

func (h *headscaleProcess) command(ctx context.Context, args ...string) *exec.Cmd {
	cmd := exec.CommandContext(ctx, h.binary, append([]string{"--config", h.configPath}, args...)...)
	cmd.Env = h.childEnv
	return cmd
}

func (h *headscaleProcess) start(t *testing.T, ctx context.Context) {
	t.Helper()
	if h.cmd != nil {
		t.Fatal("Headscale fixture already running")
	}
	cmd := h.command(h.processCtx, "serve")
	cmd.Stdout, cmd.Stderr = h.serverLog, h.serverLog
	if err := cmd.Start(); err != nil {
		t.Fatal("start Headscale fixture failed (details withheld)")
	}
	h.cmd, h.done = cmd, make(chan struct{})
	go func() { h.processErr = cmd.Wait(); close(h.done) }()
	startup, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	eventually(t, startup, "Headscale health", func() bool {
		select {
		case <-h.done:
			t.Fatalf("Headscale exited at startup: %v (raw logs withheld)", h.processErr)
		default:
		}
		return headscale.New(h.directURL, "").Health(startup) == nil
	})
}

// stop always reaps the process before the private SQLite database can be opened.
func (h *headscaleProcess) stop() {
	if h.cmd == nil {
		return
	}
	_ = h.cmd.Process.Signal(syscall.SIGTERM)
	select {
	case <-h.done:
	case <-time.After(5 * time.Second):
		_ = h.cmd.Process.Kill()
		<-h.done
	}
	h.cmd = nil
}

// runChild bounds every CLI/SQLite child by both the fixture lifetime and the caller context.
// No inherited credentials, user configuration, command arguments or raw output are logged.
func (h *headscaleProcess) runChild(t *testing.T, ctx context.Context, binary string, args []string, input string) []byte {
	t.Helper()
	callCtx, cancel := context.WithTimeout(h.processCtx, 10*time.Second)
	defer cancel()
	stopCancel := context.AfterFunc(ctx, cancel)
	defer stopCancel()
	cmd := exec.CommandContext(callCtx, binary, args...)
	cmd.Env = h.childEnv
	cmd.Stdin = strings.NewReader(input)
	var stdout bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, io.Discard
	if err := cmd.Run(); err != nil {
		t.Fatal("fixture child failed (arguments and output withheld)")
	}
	return stdout.Bytes()
}

func (h *headscaleProcess) cli(t *testing.T, ctx context.Context, args ...string) []byte {
	t.Helper()
	return h.runChild(t, ctx, h.binary, append([]string{"--config", h.configPath}, args...), "")
}

// registerRouteNode uses the real v0.29.3 debug registration flow. Unlike REST's string ID,
// CLI JSON uses a numeric ID (and snake_case fields). Routes disappear during auth register;
// seedAdvertisedRoutes restores them offline, not by pretending this is a live tsnet client.
func (h *headscaleProcess) registerRouteNode(t *testing.T, ctx context.Context, name, tag string) string {
	t.Helper()
	var random [12]byte
	if _, err := rand.Read(random[:]); err != nil {
		t.Fatal("generate fixture auth ID failed")
	}
	authID := fmt.Sprintf("hskey-authreq-%x", random)
	h.cli(t, ctx, "debug", "create-node", "--user", "fixture", "--name", name, "--key", authID, "--route", "192.0.2.7/32")
	var node struct {
		ID uint64 `json:"id"`
	}
	if err := json.Unmarshal(h.cli(t, ctx, "auth", "register", "--user", "fixture", "--auth-id", authID, "--output", "json"), &node); err != nil || node.ID == 0 {
		t.Fatal("fixture registration did not return a numeric node ID")
	}
	id := strconv.FormatUint(node.ID, 10)
	h.cli(t, ctx, "nodes", "tag", "--identifier", id, "--tags", tag, "--output", "json")
	return id
}

// seedAdvertisedRoutes is a white-box, v0.29.3-only fixture: no client connects or advertises
// routes over the control protocol. It modifies only nodes.host_info in the stopped fixture's
// private DB, preserves all other JSON fields, then restarts the same server/config/database.
// Approval assertions after startup still exercise the real Headscale REST API and operator.
func (h *headscaleProcess) seedAdvertisedRoutes(t *testing.T, ctx context.Context, routes map[string][]string) {
	t.Helper()
	sqlite, err := exec.LookPath("sqlite3")
	if err != nil {
		t.Fatal("route fixture requires sqlite3 on PATH")
	}
	h.stop()
	sql := func(statement string) []byte {
		return h.runChild(t, ctx, sqlite, []string{"-batch", "-bail", "-init", "/dev/null", filepath.Join(h.dir, "db.sqlite")}, statement)
	}
	for id, advertised := range routes {
		numeric, err := strconv.ParseUint(id, 10, 64)
		if err != nil || numeric == 0 || strconv.FormatUint(numeric, 10) != id {
			t.Fatal("invalid fixture node ID")
		}
		var info map[string]json.RawMessage
		if err := json.Unmarshal(sql("SELECT host_info FROM nodes WHERE id = "+id+";"), &info); err != nil || info == nil {
			t.Fatal("fixture node host_info is not a JSON object")
		}
		info["RoutableIPs"], err = json.Marshal(advertised)
		if err != nil {
			t.Fatal("encode fixture routes failed")
		}
		encoded, err := json.Marshal(info)
		if err != nil {
			t.Fatal("encode fixture host_info failed")
		}
		// Hex-encoded JSON cannot escape the SQL literal; the only interpolated ID is decimal.
		result := sql(fmt.Sprintf("UPDATE nodes SET host_info = CAST(X'%x' AS TEXT) WHERE id = %s; SELECT changes();", encoded, id))
		if strings.TrimSpace(string(result)) != "1" {
			t.Fatal("fixture route update did not affect exactly one node")
		}
	}
	h.start(t, ctx)
}
