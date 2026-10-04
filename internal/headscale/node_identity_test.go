package headscale

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestListNodesDecodesGatewayPublicIdentity(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/node" || r.Method != http.MethodGet || r.Header.Get("Authorization") != "Bearer synthetic-token" {
			t.Error("unexpected Headscale request")
			w.WriteHeader(http.StatusForbidden)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"nodes":[{"id":"17","machineKey":"mkey:synthetic-public","nodeKey":"nodekey:synthetic-public","givenName":"router","online":true,"tags":["tag:fabric"],"ipAddresses":["100.64.0.17"],"preAuthKey":{"id":"9","ephemeral":false}}]}`))
	}))
	defer server.Close()
	nodes, err := New(server.URL, "synthetic-token").ListNodes(context.Background())
	if err != nil || len(nodes) != 1 || nodes[0].MachineKey != "mkey:synthetic-public" || nodes[0].NodeKey != "nodekey:synthetic-public" || nodes[0].PreAuthKey == nil || nodes[0].PreAuthKey.ID != "9" || nodes[0].PreAuthKey.Ephemeral {
		t.Fatal("Headscale public identity was not decoded")
	}
}
