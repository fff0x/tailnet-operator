// httppeer is an independent tsnet peer and strict HTTP/TCP backend for the isolated
// p1.8 fixture. The host must release the Pod's separate init gate before startup.
package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/netip"
	"os"
	"os/signal"
	"runtime"
	"strings"
	"syscall"
	"time"
	"unicode"

	"tailscale.com/ipn/ipnstate"
	"tailscale.com/ipn/store/mem"
	"tailscale.com/logtail"
	"tailscale.com/tsnet"
)

const (
	publicDNS    = "http-agent.fixture.test"
	virtualDNS   = "admin.fixture.test"
	virtualAlias = "admin-tailnet-system.fixture.test"
	// MagicDNS of a node renamed to "renamed-agent": the fixture control plane serves
	// <givenName>.fixture.test. Dialable like publicDNS, but never a valid SNI or Host — the rename
	// gate probes L4, so widening allowedHTTPName would buy nothing.
	renamedDNS      = "renamed-agent.fixture.test"
	controlURL      = "https://fixture-headscale.tailnet-system.svc:8443"
	rootPath        = "/control-ca/ca.pem"
	servingRootPath = "/serving-ca/ca.pem"
	maxCABytes      = 64 << 10
	maxProbeBytes   = 1 << 10
	maxHeaderBytes  = 16 << 10
	probeTimeout    = 5 * time.Second
	backendBody     = "p1.8 fixture backend\n"
)

var errRejected = errors.New("httppeer: fixture operation failed")

type dependencies struct {
	getenv func(string) string
	setenv func(string, string) error
	open   func(string) (io.ReadCloser, error)
	start  func(string, *x509.CertPool, bool) error
}

func main() {
	err := run(os.Args[1:], runtime.GOOS, os.Geteuid(), dependencies{
		getenv: os.Getenv, setenv: os.Setenv,
		open:  func(path string) (io.ReadCloser, error) { return os.Open(path) },
		start: startFixture,
	})
	if err != nil {
		fmt.Fprintln(os.Stderr, errRejected)
		os.Exit(2)
	}
}

// No file, environment, signal, tsnet or listener operation precedes the guard.
// Tests inject every side effect; there is no runtime endpoint/path override.
func run(args []string, goos string, euid int, d dependencies) error {
	// Only these fixed combinations are supported; no arbitrary identity or CA path.
	both := len(args) == 3 && args[1] == "--identity=denied" && args[2] == "--serving-ca=cert-manager"
	separateServingCA := both || (len(args) == 2 && args[1] == "--serving-ca=cert-manager")
	denied := both || (len(args) == 2 && args[1] == "--identity=denied")
	if goos != "linux" || euid != 65532 || (len(args) != 1 && !separateServingCA && !denied) || args[0] != "--fixture=p1.8-http" {
		return errRejected
	}
	key := d.getenv("TS_AUTHKEY")
	if key == "" || len(key) > 4096 || strings.ContainsFunc(key, unicode.IsSpace) {
		return errRejected
	}
	// Set before tsnet (or any system-root user) is constructed. Peer requests
	// below use a separate, explicit pool containing only this validated CA.
	if d.setenv("SSL_CERT_FILE", rootPath) != nil || d.setenv("SSL_CERT_DIR", "/control-ca") != nil {
		return errRejected
	}
	roots, err := readRoot(d.open, rootPath)
	if err != nil {
		return errRejected
	}
	if separateServingCA {
		// Only peer-to-agent HTTPS trusts this issuer. Headscale/tsnet retains
		// its separately mounted, validated control CA through SSL_CERT_FILE.
		roots, err = readRoot(d.open, servingRootPath)
		if err != nil {
			return errRejected
		}
	}
	if d.start(key, roots, denied) != nil {
		return errRejected
	}
	return nil
}

func readRoot(open func(string) (io.ReadCloser, error), path string) (*x509.CertPool, error) {
	f, err := open(path)
	if err != nil {
		return nil, errRejected
	}
	data, err := io.ReadAll(io.LimitReader(f, maxCABytes+1))
	closeErr := f.Close()
	if err != nil || closeErr != nil || len(data) > maxCABytes {
		return nil, errRejected
	}
	return parseRoot(data, time.Now())
}

func parseRoot(data []byte, now time.Time) (*x509.CertPool, error) {
	block, rest := pem.Decode(data)
	if len(data) > maxCABytes || block == nil || block.Type != "CERTIFICATE" || len(block.Headers) != 0 || len(rest) != 0 ||
		!bytes.Equal(data, pem.EncodeToMemory(block)) {
		return nil, errRejected
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil || !cert.BasicConstraintsValid || !cert.IsCA || cert.KeyUsage&x509.KeyUsageCertSign == 0 ||
		len(cert.UnhandledCriticalExtensions) != 0 || now.Before(cert.NotBefore) || !now.Before(cert.NotAfter) ||
		!bytes.Equal(cert.RawSubject, cert.RawIssuer) || cert.CheckSignatureFrom(cert) != nil {
		return nil, errRejected
	}
	roots := x509.NewCertPool()
	roots.AddCert(cert)
	return roots, nil
}

func peerServer(key string, denied bool) *tsnet.Server {
	hostname := "http-peer"
	if denied {
		hostname = "denied-peer"
	}
	return &tsnet.Server{
		Hostname: hostname, ControlURL: controlURL, AuthKey: key,
		Dir: "/state", Store: new(mem.Store), Ephemeral: true,
		Logf: func(string, ...any) {}, UserLogf: func(string, ...any) {},
	}
}

func peerIPv4(status *ipnstate.Status) (string, error) {
	if status != nil && status.BackendState == "Running" {
		for _, ip := range status.TailscaleIPs {
			if tailnetIPv4(ip) {
				return ip.String(), nil
			}
		}
	}
	return "", errRejected
}

func startFixture(key string, roots *x509.CertPool, denied bool) error {
	log.SetOutput(io.Discard)
	logtail.Disable() // Never upload raw tsnet logs from the isolated fixture.
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	peer := peerServer(key, denied)
	defer peer.Close()
	upCtx, cancel := context.WithTimeout(ctx, 90*time.Second)
	status, err := peer.Up(upCtx)
	cancel()
	if err != nil {
		return errRejected
	}
	ip, err := peerIPv4(status)
	if err != nil || ctx.Err() != nil {
		return errRejected
	}
	// These are Pod-network listeners, not tsnet listeners. The actual agent
	// dials this backend through its separately configured fixture Service.
	backendListener, err := net.Listen("tcp", ":8080")
	if err != nil {
		return errRejected
	}
	defer backendListener.Close()
	controlListener, err := net.Listen("tcp", ":9081")
	if err != nil {
		return errRejected
	}
	defer controlListener.Close()
	l4Listener, err := net.Listen("tcp", l4BackendAddr)
	if err != nil {
		return errRejected
	}
	defer l4Listener.Close()
	// An egress agent dials this peer over the tailnet, which the Pod-network listener above cannot
	// serve: tsnet hands inbound TCP only to listeners registered on its own stack.
	tailnetL4Listener, err := peer.Listen("tcp", l4BackendAddr)
	if err != nil {
		return errRejected
	}
	defer tailnetL4Listener.Close()
	backendMux := http.NewServeMux()
	backendMux.Handle("/socket", webSocketBackendHandler(ip))
	backendMux.Handle("/", backendHandler(ip))
	backend := boundedServer(backendMux)
	control := boundedServer(controlHandler(func(ctx context.Context, input probeInput) probeResult {
		client, tr := probeClient(roots, peer.Dial, input)
		defer tr.CloseIdleConnections()
		return probe(ctx, input, client.Do)
	}, func(ctx context.Context, input l4ProbeInput) l4ProbeResult {
		return probeL4(ctx, input, peer.Dial)
	}, func(ctx context.Context, input l4ProbeInput) webSocketProbeResult {
		return probeWebSocket(ctx, input, roots, peer.Dial)
	}, func(ctx context.Context, input probeInput) httpACLProbeResult {
		return probeHTTPACL(ctx, input, roots, peer.Dial)
	}))
	errs := make(chan error, 4)
	go func() { errs <- backend.Serve(backendListener) }()
	go func() { errs <- control.Serve(controlListener) }()
	l4Ctx, cancelL4 := context.WithCancel(ctx)
	defer cancelL4()
	l4Done := serveL4Listeners(l4Ctx, errs, l4Listener, tailnetL4Listener)
	var result error
	select {
	case <-ctx.Done():
	case err := <-errs:
		if err != nil {
			result = errRejected
		}
	}
	cancelL4()
	l4Done() // Includes closure of every active TCP backend connection.
	shutdown, cancelShutdown := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancelShutdown()
	// Close also terminates connections remaining after the graceful deadline.
	_ = control.Shutdown(shutdown)
	_ = backend.Shutdown(shutdown)
	_ = control.Close()
	_ = backend.Close()
	return result
}

func boundedServer(handler http.Handler) *http.Server {
	return &http.Server{
		Handler: handler, ReadHeaderTimeout: 2 * time.Second, ReadTimeout: 3 * time.Second,
		WriteTimeout: 8 * time.Second, IdleTimeout: 5 * time.Second,
		MaxHeaderBytes: maxHeaderBytes, ErrorLog: log.New(io.Discard, "", 0),
	}
}

type probeInput struct {
	Target string
	HTTP2  bool
	SNI    string
	Host   string
}

// Only fixed fixture identities may vary; the destination port/path and dial
// allowlist remain unchanged. Empty fields preserve the original strict probe.
func allowedHTTPName(name string) bool {
	return name == publicDNS || name == virtualDNS || name == virtualAlias
}

func (input probeInput) names() (sni, host string, ok bool) {
	if input.SNI == "" && input.Host == "" {
		return publicDNS, publicDNS, true
	}
	return input.SNI, input.Host, allowedHTTPName(input.SNI) && allowedHTTPName(input.Host)
}

type probeResult struct {
	OK              bool   `json:"ok"`
	Status          int    `json:"status"`
	HTTPMajor       int    `json:"httpMajor"`
	ALPN            string `json:"alpn"`
	LeafSHA256      string `json:"leafSHA256"`
	BackendVerified bool   `json:"backendVerified"`
}

func tailnetIPv4(ip netip.Addr) bool {
	return ip.Is4() && netip.MustParsePrefix("100.64.0.0/10").Contains(ip)
}

func allowedTarget(target string) bool {
	if target == publicDNS || target == renamedDNS {
		return true
	}
	ip, err := netip.ParseAddr(target)
	return err == nil && tailnetIPv4(ip)
}

func decodeProbe(reader io.Reader) (probeInput, error) {
	var input probeInput
	data, err := io.ReadAll(io.LimitReader(reader, maxProbeBytes+1))
	if err != nil || len(data) > maxProbeBytes {
		return input, errRejected
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	if token, err := dec.Token(); err != nil || token != json.Delim('{') {
		return input, errRejected
	}
	seen := make(map[string]bool)
	for dec.More() {
		token, err := dec.Token()
		name, ok := token.(string)
		if err != nil || !ok || seen[name] || (name != "target" && name != "http2" && name != "sni" && name != "host") {
			return input, errRejected
		}
		seen[name] = true
		value, err := dec.Token()
		if err != nil {
			return input, errRejected
		}
		switch name {
		case "target":
			input.Target, ok = value.(string)
		case "http2":
			input.HTTP2, ok = value.(bool)
		case "sni":
			input.SNI, ok = value.(string)
		case "host":
			input.Host, ok = value.(string)
		}
		if !ok {
			return input, errRejected
		}
	}
	if token, err := dec.Token(); err != nil || token != json.Delim('}') || !seen["target"] || !seen["http2"] {
		return input, errRejected
	}
	if _, err := dec.Token(); err != io.EOF || !allowedTarget(input.Target) {
		return input, errRejected
	}
	if seen["sni"] || seen["host"] {
		if !seen["sni"] || !seen["host"] || !allowedHTTPName(input.SNI) || !allowedHTTPName(input.Host) {
			return input, errRejected
		}
	}
	return input, nil
}

func controlHandler(doProbe func(context.Context, probeInput) probeResult, doL4Probe func(context.Context, l4ProbeInput) l4ProbeResult, doWebSocketProbe func(context.Context, l4ProbeInput) webSocketProbeResult, doACLProbe func(context.Context, probeInput) httpACLProbeResult) http.Handler {
	slots := make(chan struct{}, 4)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.RequestURI() {
		case "/readyz":
			if r.Method != http.MethodGet {
				http.Error(w, "rejected", http.StatusMethodNotAllowed)
				return
			}
			w.WriteHeader(http.StatusNoContent)
		case "/probe", "/probe-l4", "/probe-websocket", "/probe-http-acl":
			if r.Method != http.MethodPost {
				http.Error(w, "rejected", http.StatusMethodNotAllowed)
				return
			}
			var input probeInput
			var l4Input l4ProbeInput
			var err error
			if r.URL.Path == "/probe-l4" || r.URL.Path == "/probe-websocket" {
				l4Input, err = decodeL4Probe(r.Body)
			} else {
				input, err = decodeProbe(r.Body)
			}
			if err != nil {
				http.Error(w, "rejected", http.StatusBadRequest)
				return
			}
			select {
			case slots <- struct{}{}:
				defer func() { <-slots }()
			default:
				http.Error(w, "busy", http.StatusServiceUnavailable)
				return
			}
			w.Header().Set("Content-Type", "application/json")
			w.Header().Set("Cache-Control", "no-store")
			switch r.URL.Path {
			case "/probe-l4":
				_ = json.NewEncoder(w).Encode(doL4Probe(r.Context(), l4Input))
			case "/probe-websocket":
				_ = json.NewEncoder(w).Encode(doWebSocketProbe(r.Context(), l4Input))
			case "/probe-http-acl":
				_ = json.NewEncoder(w).Encode(doACLProbe(r.Context(), input))
			default:
				_ = json.NewEncoder(w).Encode(doProbe(r.Context(), input))
			}
		default:
			http.Error(w, "rejected", http.StatusNotFound)
		}
	})
}

type dialFunc func(context.Context, string, string) (net.Conn, error)
type requestFunc func(*http.Request) (*http.Response, error)

func probeClient(roots *x509.CertPool, dial dialFunc, input probeInput) (*http.Client, *http.Transport) {
	sni, _, namesOK := input.names()
	protocols := new(http.Protocols)
	protocols.SetHTTP1(!input.HTTP2)
	protocols.SetHTTP2(input.HTTP2)
	alpn := "http/1.1"
	if input.HTTP2 {
		alpn = "h2"
	}
	tr := &http.Transport{
		Proxy: nil, Protocols: protocols, ForceAttemptHTTP2: input.HTTP2,
		DisableKeepAlives: true, DisableCompression: true,
		TLSClientConfig:     &tls.Config{RootCAs: roots, ServerName: sni, MinVersion: tls.VersionTLS12, NextProtos: []string{alpn}},
		TLSHandshakeTimeout: probeTimeout, ResponseHeaderTimeout: probeTimeout,
		MaxResponseHeaderBytes: maxHeaderBytes,
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			if !allowedTarget(input.Target) || !namesOK {
				return nil, errRejected
			}
			return dial(ctx, "tcp", net.JoinHostPort(input.Target, "443"))
		},
	}
	return &http.Client{
		Transport: tr, Timeout: probeTimeout,
		CheckRedirect: func(*http.Request, []*http.Request) error { return errRejected },
	}, tr
}

func probe(ctx context.Context, input probeInput, request requestFunc) probeResult {
	var result probeResult
	sni, host, namesOK := input.names()
	if !allowedTarget(input.Target) || !namesOK {
		return result
	}
	ctx, cancel := context.WithTimeout(ctx, probeTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://"+sni+"/accept?fixed=1", nil)
	if err != nil {
		return result
	}
	req.Host = host
	for _, name := range []string{"Forwarded", "X-Forwarded-For", "X-Forwarded-Host", "X-Forwarded-Proto", "X-Forwarded-Port", "X-Forwarded-Arbitrary"} {
		req.Header.Set(name, "fixture-spoof")
	}
	resp, err := request(req)
	if resp != nil && resp.Body != nil {
		defer resp.Body.Close()
	}
	if err != nil || ctx.Err() != nil || resp == nil {
		return result // Pollable failure, never an error/address/certificate dump.
	}
	result.Status = resp.StatusCode
	result.HTTPMajor = resp.ProtoMajor
	if resp.Body == nil {
		return result
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, int64(len(backendBody)+1)))
	if err != nil || ctx.Err() != nil {
		return result
	}
	result.BackendVerified = exactHeader(resp.Header, "X-Fixture-Verified", "yes") && bytes.Equal(body, []byte(backendBody))
	if resp.TLS == nil || len(resp.TLS.PeerCertificates) == 0 || len(resp.TLS.VerifiedChains) == 0 {
		return result
	}
	leaf := resp.TLS.PeerCertificates[0]
	digest := sha256.Sum256(leaf.Raw)
	result.LeafSHA256 = hex.EncodeToString(digest[:])
	// Only known, bounded ALPN values are exposed, even with injected transports.
	switch resp.TLS.NegotiatedProtocol {
	case "", "h2", "http/1.1":
		result.ALPN = resp.TLS.NegotiatedProtocol
	default:
		return result
	}
	protocolOK := result.HTTPMajor == 1 && (result.ALPN == "http/1.1" || result.ALPN == "")
	if input.HTTP2 {
		protocolOK = result.HTTPMajor == 2 && result.ALPN == "h2"
	}
	result.OK = result.Status == http.StatusOK && protocolOK && result.BackendVerified
	return result
}

func exactHeader(headers http.Header, name, value string) bool {
	values := headers.Values(name)
	return len(values) == 1 && values[0] == value
}

func backendHandler(peerIP string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		valid := r.Method == http.MethodGet && r.URL.RequestURI() == "/accept?fixed=1" &&
			r.Host == publicDNS && r.TLS == nil &&
			exactHeader(r.Header, "Forwarded", fmt.Sprintf("for=%q;proto=https;host=%q", peerIP, publicDNS)) &&
			exactHeader(r.Header, "X-Forwarded-For", peerIP) &&
			exactHeader(r.Header, "X-Forwarded-Host", publicDNS) &&
			exactHeader(r.Header, "X-Forwarded-Proto", "https")
		for name := range r.Header {
			name = strings.ToLower(name)
			if strings.HasPrefix(name, "x-forwarded-") && name != "x-forwarded-for" && name != "x-forwarded-host" && name != "x-forwarded-proto" {
				valid = false
			}
		}
		if !valid {
			http.Error(w, "rejected", http.StatusBadRequest)
			return
		}
		w.Header().Set("X-Fixture-Verified", "yes")
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w, backendBody)
	})
}
