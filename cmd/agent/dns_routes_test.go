package main

import (
	"encoding/json"
	"net/http/httptest"
	"reflect"
	"testing"

	"tailscale.com/types/dnstype"
)

func TestNormalizeDNSRoutes(t *testing.T) {
	got := normalizeDNSRoutes(map[string][]*dnstype.Resolver{
		"Prod-1.Tailnet.Example.Internal.": {{Addr: "10.0.0.17"}, {Addr: "10.0.0.18:53"}, nil},
		"corp.example":                     {{Addr: "https://dns.example.com/dns-query"}},
		"empty.example":                    {},
	})
	want := map[string][]string{
		"prod-1.tailnet.example.internal": {"10.0.0.17", "10.0.0.18"},
		"corp.example":                    {"dns.example.com"},
		"empty.example":                   {},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %v want %v", got, want)
	}
}

func TestDNSEndpointGatesOnFirstNetmap(t *testing.T) {
	dr := &dnsRoutes{}
	fw := &forwarder{mode: "ingress", run: map[string]running{}}
	mux := healthMux(fixedStatus("Running"), fw, &prober{results: map[string]probeResult{}}, dr)

	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, httptest.NewRequest("GET", "/dns", nil))
	if rr.Code != 503 {
		t.Fatalf("before netmap: code %d", rr.Code)
	}

	dr.set(map[string][]*dnstype.Resolver{"z.example.": {{Addr: "10.0.0.17"}}})
	rr = httptest.NewRecorder()
	mux.ServeHTTP(rr, httptest.NewRequest("GET", "/dns", nil))
	if rr.Code != 200 {
		t.Fatalf("after netmap: code %d", rr.Code)
	}
	var body struct {
		Routes map[string][]string `json:"routes"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &body); err != nil || !reflect.DeepEqual(body.Routes, map[string][]string{"z.example": {"10.0.0.17"}}) {
		t.Fatalf("body %s err %v", rr.Body.String(), err)
	}
}
