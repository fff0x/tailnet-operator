package main

import (
	"context"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestWebSocketControlRoutes(t *testing.T) {
	calls := 0
	h := controlHandler(nil, nil, func(_ context.Context, input l4ProbeInput) webSocketProbeResult {
		calls++
		if input.Target != "100.64.0.1" {
			t.Fatal("control changed target")
		}
		return webSocketProbeResult{}
	}, nil)
	for _, tc := range []struct {
		method, path, body string
		status             int
	}{
		{"POST", "/probe-websocket", `{"target":"100.64.0.1"}`, 200},
		{"GET", "/probe-websocket", "", 405},
		{"POST", "/probe-websocket?x=1", "", 404},
		{"POST", "/probe-websocket/", "", 404},
		{"POST", "/probe-websocket", `{"target":"127.0.0.1"}`, 400},
		{"POST", "/probe-websocket", `{"target":"100.64.0.1","target":"100.64.0.2"}`, 400},
		{"POST", "/probe-websocket", `{"target":"100.64.0.1","port":80}`, 400},
		{"POST", "/probe-websocket", `{"target":"100.64.0.1","path":"/other"}`, 400},
		{"POST", "/probe-websocket", `{"target":"100.64.0.1","http2":true}`, 400},
	} {
		w := httptest.NewRecorder()
		h.ServeHTTP(w, httptest.NewRequest(tc.method, tc.path, strings.NewReader(tc.body)))
		if w.Code != tc.status {
			t.Fatalf("control status %d, want %d", w.Code, tc.status)
		}
		if tc.status == 200 && (w.Header().Get("Content-Type") != "application/json" || w.Header().Get("Cache-Control") != "no-store" || w.Body.Len() > 150) {
			t.Fatal("unbounded or cacheable control response")
		}
	}
	if calls != 1 {
		t.Fatal("invalid request reached WebSocket probe")
	}
}
