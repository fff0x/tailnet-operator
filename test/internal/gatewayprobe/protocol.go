// Package gatewayprobe defines the private gateway-forwarding fixture protocol.
package gatewayprobe

import (
	"bytes"
	"encoding/json"
	"errors"
	"net/netip"
)

const (
	TargetPort    = 8081
	DNSName       = "app.tail.example."
	DNSAnswer     = "198.51.100.8"
	ErrorNoRoute  = "noRoute"
	ErrorState    = "stateUnavailable"
	ErrorDial     = "dialFailed"
	ErrorExchange = "exchangeFailed"
	ErrorReply    = "invalidReply"
	ErrorRandom   = "randomFailed"
)

var errInvalid = errors.New("gatewayprobe: invalid protocol data")

type Config struct {
	TargetIPv4  string `json:"targetIPv4"`
	GatewayIPv4 string `json:"gatewayIPv4"`
}

type Result struct {
	Mode           string `json:"mode"`
	Connected      bool   `json:"connected"`
	TargetVerified bool   `json:"targetVerified"`
	SourceIPv4     string `json:"sourceIPv4"`
	RouteSelected  bool   `json:"routeSelected"`
	DNSVerified    bool   `json:"dnsVerified"`
	AnswerIPv4     string `json:"answerIPv4"`
	Error          string `json:"error"`
}

// The private protocol uses encoding/json's struct field order and spelling.
// Whitespace is insignificant; every field (including false/empty) is required.
// Comparing canonical encodings rejects duplicates, nulls, unknowns and omissions.
func decode(data []byte, out any) error {
	if len(data) > 1024 || json.Unmarshal(data, out) != nil {
		return errInvalid
	}
	canonical, err := json.Marshal(out)
	var compact bytes.Buffer
	if err != nil || json.Compact(&compact, data) != nil || !bytes.Equal(compact.Bytes(), canonical) {
		return errInvalid
	}
	return nil
}

func DecodeConfig(data []byte) (Config, error) {
	var c Config
	if decode(data, &c) != nil {
		return Config{}, errInvalid
	}
	target, te := netip.ParseAddr(c.TargetIPv4)
	gateway, ge := netip.ParseAddr(c.GatewayIPv4)
	if te != nil || !target.Is4() || !target.IsPrivate() || target.String() != c.TargetIPv4 ||
		ge != nil || !gateway.Is4() || !netip.MustParsePrefix("100.64.0.0/10").Contains(gateway) || gateway.String() != c.GatewayIPv4 {
		return Config{}, errInvalid
	}
	return c, nil
}

// RequestBody returns an exact fixed-mode request, or empty for an unknown mode.
func RequestBody(mode string) string {
	switch mode {
	case "underlay", "forward", "dns-udp", "dns-tcp":
		return `{"mode":"` + mode + `"}`
	default:
		return ""
	}
}

func DecodeResult(data []byte) (Result, error) {
	var r Result
	if decode(data, &r) != nil || !validResult(r) {
		return Result{}, errInvalid
	}
	return r, nil
}

func validResult(r Result) bool {
	if RequestBody(r.Mode) == "" {
		return false
	}
	dns := r.Mode == "dns-udp" || r.Mode == "dns-tcp"
	if r.RouteSelected && r.Mode != "forward" {
		return false
	}
	if r.Mode == "forward" && r.Connected && !r.RouteSelected {
		return false
	}
	if r.TargetVerified != (r.SourceIPv4 != "") || r.DNSVerified != (r.AnswerIPv4 != "") {
		return false
	}
	if r.TargetVerified {
		ip, err := netip.ParseAddr(r.SourceIPv4)
		if err != nil || !ip.Is4() || ip.IsUnspecified() || ip.IsMulticast() || ip == netip.MustParseAddr("255.255.255.255") || ip.String() != r.SourceIPv4 || dns || !r.Connected {
			return false
		}
	}
	if r.DNSVerified && (!dns || !r.Connected || r.AnswerIPv4 != DNSAnswer) {
		return false
	}
	if r.Error == "" {
		return r.Connected && ((dns && r.DNSVerified) || (!dns && r.TargetVerified))
	}
	if r.TargetVerified || r.DNSVerified {
		return false
	}
	switch r.Error {
	case ErrorNoRoute, ErrorState:
		return r.Mode != "underlay" && !r.Connected && !r.RouteSelected
	case ErrorDial, ErrorRandom:
		return !r.Connected && (r.Mode != "forward" || r.RouteSelected)
	case ErrorExchange, ErrorReply:
		return r.Connected
	default:
		return false
	}
}
