package gatewayprobe

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestConfig(t *testing.T) {
	good := `{"targetIPv4":"10.244.0.9","gatewayIPv4":"100.64.0.2"}`
	if _, err := DecodeConfig([]byte(good)); err != nil {
		t.Fatal(err)
	}
	for _, b := range []string{
		`{}`, `null`, good + `{}`, strings.Replace(good, `"targetIPv4":`, `"targetIPv4":"10.0.0.1","targetIPv4":`, 1),
		strings.Replace(good, `"targetIPv4"`, `"TargetIPv4"`, 1),
		strings.Replace(good, `}`, `,"endpoint":"evil"}`, 1),
		strings.Replace(good, `"10.244.0.9"`, `null`, 1),
		strings.Replace(good, `10.244.0.9`, `127.0.0.1`, 1),
		strings.Replace(good, `10.244.0.9`, `198.51.100.9`, 1),
		strings.Replace(good, `10.244.0.9`, `::ffff:10.244.0.9`, 1),
		strings.Replace(good, `100.64.0.2`, `10.0.0.1`, 1),
		strings.Replace(good, `100.64.0.2`, `100.128.0.1`, 1),
	} {
		if _, err := DecodeConfig([]byte(b)); err == nil {
			t.Errorf("accepted %s", b)
		}
	}
}

func TestResultSchema(t *testing.T) {
	successful := Result{Mode: "forward", Connected: true, TargetVerified: true, SourceIPv4: "10.244.0.5", RouteSelected: true}
	good, _ := json.Marshal(successful)
	for _, b := range [][]byte{good, append(good, '\n')} {
		if got, err := DecodeResult(b); err != nil || got != successful {
			t.Fatalf("decode: %+v %v", got, err)
		}
	}
	for _, b := range []string{
		`{}`, `null`, string(good) + `{}`, strings.Replace(string(good), `"connected":true`, `"connected":true,"connected":true`, 1),
		strings.Replace(string(good), `,"error":""`, ``, 1),
		strings.Replace(string(good), `"dnsVerified":false`, `"dnsVerified":null`, 1),
		strings.Replace(string(good), `}`, `,"unknown":false}`, 1),
		strings.Replace(string(good), `"mode"`, `"Mode"`, 1),
	} {
		if _, err := DecodeResult([]byte(b)); err == nil {
			t.Errorf("accepted %s", b)
		}
	}
}

func TestContradictoryResults(t *testing.T) {
	for _, r := range []Result{
		{Mode: "other", Error: ErrorDial},
		{Mode: "forward", Connected: true, TargetVerified: true, SourceIPv4: "10.0.0.3"},
		{Mode: "forward", RouteSelected: true, Error: ErrorNoRoute},
		{Mode: "underlay", Error: ErrorNoRoute},
		{Mode: "underlay", Connected: true, Error: ErrorDial},
		{Mode: "underlay", Error: "raw secret"},
		{Mode: "underlay", TargetVerified: true, SourceIPv4: "10.0.0.3"},
		{Mode: "underlay", Connected: true, TargetVerified: true},
		{Mode: "underlay", Connected: true, SourceIPv4: "10.0.0.3"},
		{Mode: "underlay", Connected: true, TargetVerified: true, SourceIPv4: "0.0.0.0"},
		{Mode: "underlay", Connected: true, TargetVerified: true, SourceIPv4: "::ffff:10.0.0.3"},
		{Mode: "underlay", Connected: true, TargetVerified: true, SourceIPv4: "10.0.0.3", Error: ErrorReply},
		{Mode: "underlay", Connected: true, DNSVerified: true, AnswerIPv4: DNSAnswer},
		{Mode: "dns-tcp", Connected: true, DNSVerified: true, AnswerIPv4: "198.51.100.9"},
		{Mode: "dns-udp", Connected: true, DNSVerified: true, AnswerIPv4: DNSAnswer, RouteSelected: true},
		{Mode: "dns-tcp", Connected: true},
		{Mode: "forward", Error: ErrorDial},
	} {
		b, _ := json.Marshal(r)
		if _, err := DecodeResult(b); err == nil {
			t.Errorf("accepted %+v", r)
		}
	}
}

func TestValidResultsAndRequestBodies(t *testing.T) {
	for _, mode := range []string{"underlay", "forward", "dns-udp", "dns-tcp"} {
		var parsed struct {
			Mode string `json:"mode"`
		}
		if json.Unmarshal([]byte(RequestBody(mode)), &parsed) != nil || parsed.Mode != mode {
			t.Fatal(mode)
		}
		r := Result{Mode: mode, Connected: true}
		if mode == "underlay" || mode == "forward" {
			r.TargetVerified = true
			r.SourceIPv4 = "10.244.0.5"
			r.RouteSelected = mode == "forward"
		} else {
			r.DNSVerified = true
			r.AnswerIPv4 = DNSAnswer
		}
		b, _ := json.Marshal(r)
		if _, err := DecodeResult(b); err != nil {
			t.Fatalf("rejected %+v", r)
		}
	}
	if RequestBody("else") != "" {
		t.Fatal("unknown mode")
	}
	for _, r := range []Result{
		{Mode: "forward", Error: ErrorNoRoute}, {Mode: "forward", Error: ErrorState},
		{Mode: "forward", RouteSelected: true, Error: ErrorDial},
		{Mode: "forward", RouteSelected: true, Error: ErrorRandom},
		{Mode: "underlay", Connected: true, Error: ErrorExchange},
		{Mode: "dns-tcp", Connected: true, Error: ErrorReply},
	} {
		b, _ := json.Marshal(r)
		if _, err := DecodeResult(b); err != nil {
			t.Fatalf("rejected %+v", r)
		}
	}
}
