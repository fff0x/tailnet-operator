package main

import (
	"context"
	"encoding/json"
	"net"
	"os"
	"path/filepath"
	"testing"
)

func freePort(t *testing.T) int {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	return ln.Addr().(*net.TCPAddr).Port
}

func writeTargets(t *testing.T, path string, ts []target) {
	b, _ := json.Marshal(ts)
	if err := os.WriteFile(path, b, 0o644); err != nil {
		t.Fatal(err)
	}
}

// A rename keeps the listen port (ports.Assign hands the freed port to the new name). The old
// listener must be closed before the new one binds, or the new target silently never serves.
func TestReloadSamePortRebinds(t *testing.T) {
	port := freePort(t)
	path := filepath.Join(t.TempDir(), "targets.json")
	fw := &forwarder{mode: "egress", run: map[string]running{}}
	defer fw.stopAll()
	ctx := context.Background()

	writeTargets(t, path, []target{{Name: "a", Address: "10.0.0.1", Port: 1, ListenPort: port}})
	fw.reload(ctx, path)
	if _, ok := fw.current()["a"]; !ok {
		t.Fatal("initial target a not running")
	}

	writeTargets(t, path, []target{{Name: "b", Address: "10.0.0.1", Port: 1, ListenPort: port}})
	fw.reload(ctx, path)
	cur := fw.current()
	if _, ok := cur["a"]; ok {
		t.Error("old target a still running")
	}
	if _, ok := cur["b"]; !ok {
		t.Error("renamed target b not running: listener was not rebound on the same port")
	}
}
