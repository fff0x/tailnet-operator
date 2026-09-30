package headscale

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestNodeLastSeenDecoding(t *testing.T) {
	for _, tc := range []struct {
		name, field string
		known, bad  bool
	}{
		{"timestamp", `,"lastSeen":"2026-09-01T00:00:00Z"`, true, false},
		{"null", `,"lastSeen":null`, false, false},
		{"missing", "", false, false},
		{"invalid-redacted", `,"lastSeen":"private-fixture-marker"`, false, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Method != http.MethodGet || r.URL.Path != "/api/v1/node" {
					w.WriteHeader(http.StatusNotFound)
					return
				}
				_, _ = io.WriteString(w, `{"nodes":[{"id":"1","givenName":"fixture","online":false`+tc.field+`}]}`)
			}))
			defer server.Close()
			nodes, err := New(server.URL, "synthetic-test-token").ListNodes(context.Background())
			if tc.bad {
				if err == nil || strings.Contains(err.Error(), "private-fixture-marker") {
					t.Fatal("invalid timestamp was accepted or leaked through the error boundary")
				}
				return
			}
			if err != nil || len(nodes) != 1 || (nodes[0].LastSeen != nil) != tc.known {
				t.Fatal("unexpected node timestamp decode result")
			}
			if tc.known && !nodes[0].LastSeen.Equal(time.Date(2026, 9, 1, 0, 0, 0, 0, time.UTC)) {
				t.Fatal("decoded timestamp differs")
			}
		})
	}
}
