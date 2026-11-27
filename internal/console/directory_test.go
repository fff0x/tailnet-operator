package console

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// fakeOperator answers the console API for Tailnet "lab" with the given users and policy JSON.
func fakeOperator(t *testing.T, users, policy string) (*httptest.Server, *atomic.Int32, *atomic.Value) {
	t.Helper()
	calls := &atomic.Int32{}
	token := &atomic.Value{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		token.Store(r.Header.Get("Authorization"))
		switch r.URL.Path {
		case "/v1/tailnets/lab/users":
			_, _ = w.Write([]byte(`{"users":` + users + `}`))
		case "/v1/tailnets/lab/policy":
			_, _ = w.Write([]byte(`{"policy":` + policy + `}`))
		case "/v1/tailnets/lab/nodes":
			_, _ = w.Write([]byte(`{"nodes":[{"name":"db-1","online":true,"tags":["tag:db"]},{"name":"db-1-zeta","tags":["tag:db-zeta-1"]},` +
				`{"name":"wiki-1","tags":["tag:wiki"]}]}`))
		case "/v1/tailnets/slow/users":
			<-r.Context().Done() // an operator behind a policy that drops the packets
		case "/v1/tailnets/down/users":
			w.WriteHeader(http.StatusBadGateway)
			_, _ = w.Write([]byte("upstream detail"))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	t.Cleanup(srv.Close)
	return srv, calls, token
}

func tokenFile(t *testing.T, value string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "token")
	if err := os.WriteFile(path, []byte(value), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestDirectoryTokenCacheAndErrors(t *testing.T) {
	srv, calls, token := fakeOperator(t, `[{"id":"1","name":"alice","providerId":"https://id/1"}]`, `"{\"grants\":[]}"`)
	file := tokenFile(t, "first\n")
	d := newDirectory(srv.URL+"/", file)
	now := time.Unix(1000, 0)
	d.now = func() time.Time { return now }
	data, err := d.get(context.Background(), "lab")
	if err != nil || len(data.Users) != 1 || data.Users[0].ProviderID != "https://id/1" || data.Policy != `{"grants":[]}` ||
		len(data.Nodes) != 3 || !data.Nodes[0].Online || data.Nodes[0].Tags[0] != "tag:db" {
		t.Fatalf("data = %+v, err = %v", data, err)
	}
	if token.Load() != "Bearer first" || calls.Load() != 3 {
		t.Fatalf("token %v, calls %d", token.Load(), calls.Load())
	}
	now = now.Add(directoryTTL - time.Second)
	if _, err := d.get(context.Background(), "lab"); err != nil || calls.Load() != 3 {
		t.Fatalf("cached answer not used: calls %d", calls.Load())
	}
	// The kubelet rotates the projected token; the next call after expiry presents the new one.
	if err := os.WriteFile(file, []byte("second"), 0o600); err != nil {
		t.Fatal(err)
	}
	now = now.Add(2 * time.Second)
	if _, err := d.get(context.Background(), "lab"); err != nil || calls.Load() != 6 || token.Load() != "Bearer second" {
		t.Fatalf("after expiry: calls %d, token %v, err %v", calls.Load(), token.Load(), err)
	}
	_, err = d.get(context.Background(), "down")
	if err == nil || strings.Contains(err.Error(), "upstream") || !strings.Contains(err.Error(), "502") {
		t.Fatalf("error = %v", err)
	}
	// A failure is kept like an answer: polling viewers do not hammer a failing operator.
	before := calls.Load()
	if _, again := d.get(context.Background(), "down"); again == nil || calls.Load() != before {
		t.Fatalf("failure not cached: calls %d → %d, err %v", before, calls.Load(), again)
	}
	now = now.Add(directoryTTL)
	if _, again := d.get(context.Background(), "down"); again == nil || calls.Load() != before+1 {
		t.Fatalf("failure not retried after TTL: calls %d", calls.Load())
	}
	if _, err := newDirectory(srv.URL, filepath.Join(t.TempDir(), "missing")).get(context.Background(), "lab"); err == nil {
		t.Fatal("missing token file accepted")
	}
	if _, err := newDirectory("http://127.0.0.1:1", file).get(context.Background(), "lab"); err == nil {
		t.Fatal("unreachable operator accepted")
	}
}

// An operator that does not answer costs one deadline; the failure is then kept like any other.
func TestDirectoryDeadline(t *testing.T) {
	srv, calls, _ := fakeOperator(t, `[]`, `""`)
	d := newDirectory(srv.URL, tokenFile(t, "tok"))
	if d.timeout != loadTimeout {
		t.Fatalf("timeout = %s", d.timeout)
	}
	d.timeout = 50 * time.Millisecond
	start := time.Now()
	for range 2 {
		if _, err := d.get(context.Background(), "slow"); err == nil {
			t.Fatal("hanging operator accepted")
		}
	}
	if calls.Load() != 1 || time.Since(start) > 2*time.Second {
		t.Fatalf("calls = %d after %s", calls.Load(), time.Since(start))
	}
}

// Concurrent viewers of one Tailnet cause one read of the three paths, not one per viewer.
func TestDirectoryConcurrentReadsOnce(t *testing.T) {
	srv, calls, _ := fakeOperator(t, `[]`, `""`)
	d := newDirectory(srv.URL, tokenFile(t, "tok"))
	var wg sync.WaitGroup
	for range 20 {
		wg.Go(func() {
			if _, err := d.get(context.Background(), "lab"); err != nil {
				t.Error(err)
			}
		})
	}
	wg.Wait()
	if calls.Load() != 3 {
		t.Fatalf("calls = %d, want 3", calls.Load())
	}
}
