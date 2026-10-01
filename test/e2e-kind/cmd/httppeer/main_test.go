package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"reflect"
	"strings"
	"testing"
	"time"

	"golang.org/x/net/http2"
	"tailscale.com/ipn/ipnstate"
	"tailscale.com/ipn/store/mem"
)

func makeCA(t *testing.T, mutate func(*x509.Certificate)) ([]byte, *x509.Certificate, ed25519.PrivateKey) {
	t.Helper()
	pub, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "fixture CA"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign,
	}
	if mutate != nil {
		mutate(tmpl)
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, pub, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), cert, key
}

func makeLeaf(t *testing.T, root *x509.Certificate, key ed25519.PrivateKey, name string) tls.Certificate {
	t.Helper()
	pub, leafKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(2), DNSNames: []string{name},
		NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().Add(time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, root, pub, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: leafKey, Leaf: cert}
}

func TestGuardBeforeIO(t *testing.T) {
	for _, tc := range []struct {
		os   string
		uid  int
		args []string
	}{
		{"darwin", 65532, []string{"--fixture=p1.8-http"}},
		{"linux", 0, []string{"--fixture=p1.8-http"}},
		{"linux", 65533, []string{"--fixture=p1.8-http"}},
		{"linux", 65532, nil},
		{"linux", 65532, []string{"--fixture", "p1.8-http"}},
		{"linux", 65532, []string{"--fixture=p1.8-http", "extra"}},
		{"linux", 65532, []string{"--fixture=p1.8-http "}},
	} {
		// Nil dependencies panic on any access, including environment reads.
		if err := run(tc.args, tc.os, tc.uid, dependencies{}); err != errRejected {
			t.Fatalf("guard: %v", err)
		}
	}
}

func TestStartupInputsAndOrder(t *testing.T) {
	data, _, _ := makeCA(t, nil)
	var order []string
	d := dependencies{
		getenv: func(name string) string { order = append(order, name); return "fixture-secret" },
		setenv: func(name, value string) error { order = append(order, name+"="+value); return nil },
		open: func(path string) (io.ReadCloser, error) {
			order = append(order, path)
			return io.NopCloser(bytes.NewReader(data)), nil
		},
		start: func(key string, roots *x509.CertPool) error {
			order = append(order, "start")
			if key != "fixture-secret" || roots == nil {
				t.Fatal("bad startup inputs")
			}
			return nil
		},
	}
	if err := run([]string{"--fixture=p1.8-http"}, "linux", 65532, d); err != nil {
		t.Fatal(err)
	}
	want := []string{"TS_AUTHKEY", "SSL_CERT_FILE=/control-ca/ca.pem", "SSL_CERT_DIR=/control-ca", rootPath, "start"}
	if !reflect.DeepEqual(order, want) {
		t.Fatalf("order: %v", order)
	}
	for _, key := range []string{"", "has space", "has\nnewline", "\tkey", "a\u00a0b", strings.Repeat("k", 4097)} {
		if err := run([]string{"--fixture=p1.8-http"}, "linux", 65532, dependencies{getenv: func(string) string { return key }}); err != errRejected {
			t.Fatal("accepted invalid key")
		}
	}
	d.getenv = func(string) string { return strings.Repeat("k", 4096) }
	d.start = func(key string, _ *x509.CertPool) error {
		if len(key) != 4096 {
			t.Fatal("key length")
		}
		return errors.New("private key and raw address must not escape")
	}
	if err := run([]string{"--fixture=p1.8-http"}, "linux", 65532, d); err != errRejected {
		t.Fatal("unbounded startup error")
	}
	d.setenv = func(string, string) error { return errors.New("private") }
	d.open = nil
	if err := run([]string{"--fixture=p1.8-http"}, "linux", 65532, d); err != errRejected {
		t.Fatal("setenv failure")
	}
}

func TestRootValidation(t *testing.T) {
	data, root, _ := makeCA(t, nil)
	if _, err := parseRoot(data, time.Now()); err != nil {
		t.Fatal(err)
	}
	block, _ := pem.Decode(data)
	block.Headers = map[string]string{"Comment": "no"}
	for _, bad := range [][]byte{
		nil, []byte("junk"), append([]byte("junk\n"), data...), append(bytes.Clone(data), '\n'),
		append(bytes.Clone(data), data...), pem.EncodeToMemory(block),
		pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: root.Raw}),
		pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: []byte("bad DER")}),
		bytes.Repeat([]byte("x"), maxCABytes+1),
	} {
		if _, err := parseRoot(bad, time.Now()); err != errRejected {
			t.Fatal("accepted noncanonical CA")
		}
	}
	for _, mutate := range []func(*x509.Certificate){
		func(c *x509.Certificate) { c.IsCA = false },
		func(c *x509.Certificate) { c.KeyUsage = x509.KeyUsageDigitalSignature },
		func(c *x509.Certificate) { c.NotAfter = time.Now().Add(-time.Minute) },
		func(c *x509.Certificate) { c.NotBefore = time.Now().Add(time.Minute) },
		func(c *x509.Certificate) {
			c.ExtraExtensions = []pkix.Extension{{Id: []int{1, 2, 3, 4}, Critical: true, Value: []byte{5, 0}}}
		},
	} {
		bad, _, _ := makeCA(t, mutate)
		if _, err := parseRoot(bad, time.Now()); err != errRejected {
			t.Fatal("accepted invalid CA")
		}
	}
	if _, err := parseRoot(data, root.NotAfter); err != errRejected {
		t.Fatal("accepted expired CA")
	}
}

type countingReader struct{ n int }

func (r *countingReader) Read(p []byte) (int, error) {
	for i := range p {
		p[i] = 'x'
	}
	r.n += len(p)
	return len(p), nil
}
func (r *countingReader) Close() error { return nil }

func TestBoundedCARead(t *testing.T) {
	r := new(countingReader)
	d := dependencies{
		getenv: func(string) string { return "key" }, setenv: func(string, string) error { return nil },
		open: func(string) (io.ReadCloser, error) { return r, nil },
	}
	if err := run([]string{"--fixture=p1.8-http"}, "linux", 65532, d); err != errRejected {
		t.Fatal(err)
	}
	if r.n != maxCABytes+1 {
		t.Fatalf("read %d bytes", r.n)
	}
}

func TestPeerConfigurationAndRunningIP(t *testing.T) {
	p := peerServer("key") // Construction only; never Up, Start or Close.
	if p.Hostname != "http-peer" || p.ControlURL != controlURL || p.Dir != "/state" || !p.Ephemeral || p.AuthKey != "key" || p.Logf == nil || p.UserLogf == nil {
		t.Fatal("peer config")
	}
	if _, ok := p.Store.(*mem.Store); !ok {
		t.Fatal("not in-memory")
	}
	p.Logf("must not log %s", "secret")
	p.UserLogf("must not log %s", "secret")
	for _, state := range []string{"", "Starting", "Running"} {
		for _, address := range []string{"127.0.0.1", "100.63.255.255", "100.128.0.0", "fd7a:115c:a1e0::1", "::ffff:100.64.0.1", "100.64.0.1"} {
			got, err := peerIPv4(&ipnstate.Status{BackendState: state, TailscaleIPs: []netip.Addr{netip.MustParseAddr(address)}})
			want := state == "Running" && address == "100.64.0.1"
			if (err == nil) != want || (want && got != address) {
				t.Fatalf("state/IP %s %s", state, address)
			}
		}
	}
	if _, err := peerIPv4(nil); err != errRejected {
		t.Fatal("nil status")
	}
}

func TestStrictProbeInput(t *testing.T) {
	for _, body := range []string{
		`{"target":"100.64.0.1","http2":false}`,
		` {"http2":true, "target":"http-agent.fixture.test"} `,
	} {
		if _, err := decodeProbe(strings.NewReader(body)); err != nil {
			t.Fatal(err)
		}
	}
	for _, body := range []string{
		``, `null`, `[]`, `{}`, `{"target":"100.64.0.1"}`, `{"http2":false}`,
		`{"target":"100.64.0.1","http2":null}`, `{"target":null,"http2":false}`,
		`{"target":5,"http2":false}`, `{"target":"100.64.0.1","http2":"false"}`,
		`{"target":"100.64.0.1","http2":false,"other":1}`,
		`{"target":"100.64.0.1","target":"100.64.0.2","http2":false}`,
		`{"target":"100.64.0.1","http2":false,"http2":true}`,
		`{"target":"100.64.0.1","http2":false,"http\u0032":true}`,
		`{"Target":"100.64.0.1","http2":false}`,
		`{"target":"100.64.0.1","http2":false} {}`,
		`{"target":"100.64.0.1","http2":false} null`,
		`{"target":"100.64.0.1","http2":false,}`,
		`{"target":{},"http2":false}`, `{"target":"100.64.0.1","http2":[]}`,
		strings.Repeat(" ", maxProbeBytes+1),
	} {
		if _, err := decodeProbe(strings.NewReader(body)); err != errRejected {
			t.Fatalf("accepted %q", body)
		}
	}
	body := `{"target":"100.64.0.1","http2":false}`
	if _, err := decodeProbe(strings.NewReader(body + strings.Repeat(" ", maxProbeBytes-len(body)))); err != nil {
		t.Fatal("rejected exact bound")
	}
	r := new(countingReader)
	_, _ = decodeProbe(r)
	if r.n != maxProbeBytes+1 {
		t.Fatal("unbounded JSON read")
	}
}

func TestTargetAllowlist(t *testing.T) {
	for _, target := range []string{publicDNS, "100.64.0.0", "100.127.255.255", "100.99.1.2"} {
		if !allowedTarget(target) {
			t.Fatalf("rejected %s", target)
		}
	}
	for _, target := range []string{"", "100.63.255.255", "100.128.0.0", "127.0.0.1", "192.168.1.1", "::ffff:100.64.0.1", "100.064.0.1", "100.64.0.1:443", "100.64.0.1%zone", "https://" + publicDNS, publicDNS + ":443", publicDNS + ".", "HTTP-AGENT.fixture.test", " " + publicDNS, "elsewhere.fixture.test", "100.64.0.1/path"} {
		if allowedTarget(target) {
			t.Fatalf("accepted %q", target)
		}
		body, _ := json.Marshal(map[string]any{"target": target, "http2": false})
		if _, err := decodeProbe(bytes.NewReader(body)); err == nil {
			t.Fatalf("decoded %q", target)
		}
	}
}

func TestClientConfiguration(t *testing.T) {
	roots := x509.NewCertPool()
	for _, h2 := range []bool{false, true} {
		input := probeInput{Target: "100.64.0.9", HTTP2: h2}
		calls := 0
		client, tr := probeClient(roots, func(_ context.Context, network, addr string) (net.Conn, error) {
			calls++
			if network != "tcp" || addr != "100.64.0.9:443" {
				t.Fatal("dial override")
			}
			return nil, errRejected
		}, input)
		if tr.Proxy != nil || tr.DialTLSContext != nil || !tr.DisableKeepAlives || !tr.DisableCompression || tr.MaxResponseHeaderBytes != maxHeaderBytes || tr.ResponseHeaderTimeout != probeTimeout || tr.TLSHandshakeTimeout != probeTimeout || client.Timeout != probeTimeout {
			t.Fatal("transport bounds")
		}
		cfg := tr.TLSClientConfig
		if cfg.RootCAs != roots || cfg.ServerName != publicDNS || cfg.InsecureSkipVerify || cfg.MinVersion != tls.VersionTLS12 || cfg.VerifyConnection != nil || cfg.VerifyPeerCertificate != nil {
			t.Fatal("TLS config")
		}
		if tr.Protocols.HTTP1() == h2 || tr.Protocols.HTTP2() != h2 || tr.Protocols.UnencryptedHTTP2() || tr.ForceAttemptHTTP2 != h2 {
			t.Fatal("protocol config")
		}
		if err := client.CheckRedirect(nil, nil); err != errRejected {
			t.Fatal("redirect allowed")
		}
		_, _ = tr.DialContext(context.Background(), "udp", "attacker:80")
		if calls != 1 {
			t.Fatal("did not use injected tsnet dial")
		}
		tr.CloseIdleConnections()
	}
}

func validBackendRequest() *http.Request {
	r := httptest.NewRequest(http.MethodGet, "/accept?fixed=1", nil)
	r.Host = publicDNS
	r.Header.Set("Forwarded", fmt.Sprintf("for=%q;proto=https;host=%q", "100.64.0.2", publicDNS))
	r.Header.Set("X-Forwarded-For", "100.64.0.2")
	r.Header.Set("X-Forwarded-Host", publicDNS)
	r.Header.Set("X-Forwarded-Proto", "https")
	return r
}

func TestBackendValidation(t *testing.T) {
	h := backendHandler("100.64.0.2")
	good := httptest.NewRecorder()
	h.ServeHTTP(good, validBackendRequest())
	if good.Code != 200 || good.Header().Get("X-Fixture-Verified") != "yes" || good.Body.String() != backendBody {
		t.Fatal("valid backend rejected")
	}
	mutations := []func(*http.Request){
		func(r *http.Request) { r.Method = "HEAD" },
		func(r *http.Request) { r.URL.Path = "/other" },
		func(r *http.Request) { r.URL.RawQuery = "fixed=1&extra=1" },
		func(r *http.Request) { r.URL.RawQuery = "fixed=2" },
		func(r *http.Request) { r.URL.RawQuery = "" },
		func(r *http.Request) { r.URL.RawPath = "/%61ccept" },
		func(r *http.Request) { r.Host += ":443" },
		func(r *http.Request) { r.Host = "wrong.fixture.test" },
		func(r *http.Request) { r.TLS = &tls.ConnectionState{} },
		func(r *http.Request) { r.Header.Set("X-Forwarded-Port", "") },
		func(r *http.Request) { r.Header.Set("X-Forwarded-Arbitrary", "fixture-spoof") },
		func(r *http.Request) { r.Header.Set("X-Forwarded-Unknown", "no") },
	}
	for _, name := range []string{"Forwarded", "X-Forwarded-For", "X-Forwarded-Host", "X-Forwarded-Proto"} {
		mutations = append(mutations,
			func(r *http.Request) { r.Header.Set(name, "fixture-spoof") },
			func(r *http.Request) { r.Header.Add(name, r.Header.Get(name)) },
			func(r *http.Request) { r.Header.Del(name) })
	}
	for i, mutate := range mutations {
		r := validBackendRequest()
		mutate(r)
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		if w.Code != 400 || w.Header().Get("X-Fixture-Verified") != "" || w.Body.String() != "rejected\n" {
			t.Fatalf("backend negative %d: %d %s", i, w.Code, w.Body.String())
		}
	}
}

func TestControlRoutesAndBoundedErrors(t *testing.T) {
	h := controlHandler(func(ctx context.Context, input probeInput) probeResult {
		return probe(ctx, input, func(*http.Request) (*http.Response, error) {
			return nil, errors.New(strings.Repeat("private 100.64.0.9 ", 1000))
		})
	})
	for _, tc := range []struct {
		method, path, body string
		status             int
	}{
		{"GET", "/readyz", "", 204}, {"HEAD", "/readyz", "", 405}, {"GET", "/readyz?x=1", "", 404},
		{"GET", "/probe", "", 405}, {"POST", "/probe", "null", 400}, {"GET", "/other", "", 404},
		{"POST", "/probe", `{"target":"100.64.0.9","http2":false}`, 200},
	} {
		w := httptest.NewRecorder()
		h.ServeHTTP(w, httptest.NewRequest(tc.method, tc.path, strings.NewReader(tc.body)))
		if w.Code != tc.status || w.Body.Len() > 256 || strings.Contains(w.Body.String(), "100.64") || strings.Contains(w.Body.String(), "private") {
			t.Fatalf("route %s: %d %s", tc.path, w.Code, w.Body.String())
		}
		if tc.status == 200 && w.Body.String() != "{\"ok\":false,\"status\":0,\"httpMajor\":0,\"alpn\":\"\",\"leafSHA256\":\"\",\"backendVerified\":false}\n" {
			t.Fatal("failure shape")
		}
	}
	s := boundedServer(h)
	if s.MaxHeaderBytes != maxHeaderBytes || s.ReadHeaderTimeout <= 0 || s.ReadTimeout <= 0 || s.WriteTimeout <= probeTimeout || s.IdleTimeout <= 0 || s.ErrorLog.Writer() != io.Discard {
		t.Fatal("server bounds")
	}
}

func TestProbeResponseValidation(t *testing.T) {
	_, root, key := makeCA(t, nil)
	leaf := makeLeaf(t, root, key, publicDNS)
	for _, tc := range []struct {
		name           string
		h2             bool
		status, major  int
		alpn, verified string
		tls, chain, ok bool
	}{
		{"h1", false, 200, 1, "http/1.1", "yes", true, true, true},
		{"h1-no-alpn", false, 200, 1, "", "yes", true, true, true},
		{"h2", true, 200, 2, "h2", "yes", true, true, true},
		{"downgrade", true, 200, 1, "http/1.1", "yes", true, true, false},
		{"upgrade", false, 200, 2, "h2", "yes", true, true, false},
		{"status", false, 400, 1, "http/1.1", "yes", true, true, false},
		{"no-content", false, 204, 1, "http/1.1", "yes", true, true, false},
		{"backend", false, 200, 1, "http/1.1", "no", true, true, false},
		{"plaintext", false, 200, 1, "", "yes", false, false, false},
		{"unverified", false, 200, 1, "http/1.1", "yes", true, false, false},
		{"alpn", false, 200, 1, strings.Repeat("private", 1000), "yes", true, true, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := probe(context.Background(), probeInput{Target: publicDNS, HTTP2: tc.h2}, func(req *http.Request) (*http.Response, error) {
				if req.Method != "GET" || req.URL.String() != "https://"+publicDNS+"/accept?fixed=1" || req.Host != publicDNS {
					t.Fatal("request route")
				}
				deadline, ok := req.Context().Deadline()
				if !ok || time.Until(deadline) > probeTimeout {
					t.Fatal("deadline")
				}
				for _, name := range []string{"Forwarded", "X-Forwarded-For", "X-Forwarded-Host", "X-Forwarded-Proto", "X-Forwarded-Port", "X-Forwarded-Arbitrary"} {
					if !exactHeader(req.Header, name, "fixture-spoof") {
						t.Fatalf("spoof %s", name)
					}
				}
				r := &http.Response{StatusCode: tc.status, ProtoMajor: tc.major, Header: http.Header{"X-Fixture-Verified": []string{tc.verified}}, Body: io.NopCloser(strings.NewReader(backendBody))}
				if tc.tls {
					r.TLS = &tls.ConnectionState{NegotiatedProtocol: tc.alpn, PeerCertificates: []*x509.Certificate{leaf.Leaf}}
					if tc.chain {
						r.TLS.VerifiedChains = [][]*x509.Certificate{{leaf.Leaf, root}}
					}
				}
				return r, nil
			})
			if got.OK != tc.ok {
				t.Fatalf("result: %+v", got)
			}
			encoded, _ := json.Marshal(got)
			if len(encoded) > 256 || strings.Contains(string(encoded), "private") {
				t.Fatal("unbounded response")
			}
			if tc.ok {
				hash := sha256.Sum256(leaf.Leaf.Raw)
				if got.LeafSHA256 != hex.EncodeToString(hash[:]) {
					t.Fatal("not presented leaf hash")
				}
			}
		})
	}
}

type probeBodyReader func([]byte) (int, error)

func (f probeBodyReader) Read(p []byte) (int, error) { return f(p) }

type trackedProbeBody struct {
	io.Reader
	closed bool
}

func (b *trackedProbeBody) Close() error {
	b.closed = true
	return nil
}

func TestProbeBodyValidation(t *testing.T) {
	_, root, key := makeCA(t, nil)
	leaf := makeLeaf(t, root, key, publicDNS)
	oversized := new(countingReader)
	for _, tc := range []struct {
		name   string
		reader func(context.CancelFunc) io.Reader
	}{
		{"wrong", func(context.CancelFunc) io.Reader { return strings.NewReader("private backend body") }},
		{"empty", func(context.CancelFunc) io.Reader { return strings.NewReader("") }},
		{"oversized", func(context.CancelFunc) io.Reader {
			return io.MultiReader(strings.NewReader(backendBody), oversized)
		}},
		{"read-error", func(context.CancelFunc) io.Reader {
			return probeBodyReader(func(p []byte) (int, error) {
				return copy(p, backendBody), errors.New("private body read error")
			})
		}},
		{"nil", func(context.CancelFunc) io.Reader { return nil }},
		{"canceled-body", func(cancel context.CancelFunc) io.Reader {
			return probeBodyReader(func(p []byte) (int, error) {
				cancel()
				return copy(p, backendBody), io.EOF
			})
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			var body *trackedProbeBody
			got := probe(ctx, probeInput{Target: publicDNS}, func(*http.Request) (*http.Response, error) {
				resp := &http.Response{
					StatusCode: http.StatusOK, ProtoMajor: 1,
					Header: http.Header{"X-Fixture-Verified": []string{"yes"}},
					TLS: &tls.ConnectionState{
						NegotiatedProtocol: "http/1.1", PeerCertificates: []*x509.Certificate{leaf.Leaf},
						VerifiedChains: [][]*x509.Certificate{{leaf.Leaf, root}},
					},
				}
				if reader := tc.reader(cancel); reader != nil {
					body = &trackedProbeBody{Reader: reader}
					resp.Body = body
				}
				return resp, nil
			})
			if got.OK || got.BackendVerified {
				t.Fatalf("accepted invalid body: %+v", got)
			}
			if body != nil && !body.closed {
				t.Fatal("body not closed")
			}
			encoded, err := json.Marshal(got)
			if err != nil || len(encoded) > 256 || strings.Contains(string(encoded), "private") || strings.Contains(string(encoded), "fixture backend") {
				t.Fatal("body or raw error escaped into JSON")
			}
		})
	}
	if oversized.n != 1 {
		t.Fatalf("read %d excess body bytes; want exactly one", oversized.n)
	}
}

// TLS and both wire protocols run exclusively over net.Pipe. No host listener,
// DNS, tsnet startup, packet capture, or httptest.NewServer is used by this suite.
func TestRealTLSOverInMemoryDial(t *testing.T) {
	data, root, key := makeCA(t, nil)
	roots, err := parseRoot(data, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name               string
		h2                 bool
		wrongName, wrongCA bool
		body               string
	}{
		{"h1", false, false, false, backendBody}, {"h2", true, false, false, backendBody},
		{"h1-wrong-body", false, false, false, "wrong backend\n"}, {"h2-wrong-body", true, false, false, "wrong backend\n"},
		{"wrong-name", false, true, false, backendBody}, {"wrong-ca", false, false, true, backendBody},
	} {
		t.Run(tc.name, func(t *testing.T) {
			name := publicDNS
			if tc.wrongName {
				name = "wrong.fixture.test"
			}
			leaf := makeLeaf(t, root, key, name)
			pool := roots
			if tc.wrongCA {
				pool = x509.NewCertPool()
			}
			done := make(chan struct{})
			dial := func(_ context.Context, network, addr string) (net.Conn, error) {
				if network != "tcp" || addr != "100.64.0.8:443" {
					t.Error("wrong destination")
				}
				clientConn, serverConn := net.Pipe()
				go func() {
					defer close(done)
					defer serverConn.Close()
					_ = serverConn.SetDeadline(time.Now().Add(3 * time.Second))
					alpn := "http/1.1"
					if tc.h2 {
						alpn = "h2"
					}
					server := tls.Server(serverConn, &tls.Config{Certificates: []tls.Certificate{leaf}, NextProtos: []string{alpn}, MinVersion: tls.VersionTLS12})
					if err := server.Handshake(); err != nil {
						return
					}
					if server.ConnectionState().ServerName != publicDNS {
						t.Error("wrong SNI")
					}
					handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
						if r.Method != "GET" || r.Host != publicDNS || r.URL.RequestURI() != "/accept?fixed=1" || r.Header.Get("Forwarded") != "fixture-spoof" {
							t.Error("wrong wire request")
						}
						w.Header().Set("X-Fixture-Verified", "yes")
						w.WriteHeader(200)
						_, _ = io.WriteString(w, tc.body)
					})
					if tc.h2 {
						(&http2.Server{}).ServeConn(server, &http2.ServeConnOpts{Handler: handler})
						return
					}
					req, err := http.ReadRequest(bufio.NewReader(server))
					if err != nil {
						t.Error(err)
						return
					}
					defer req.Body.Close()
					w := httptest.NewRecorder()
					handler.ServeHTTP(w, req)
					response := w.Result()
					defer response.Body.Close()
					_ = response.Write(server)
				}()
				return clientConn, nil
			}
			input := probeInput{Target: "100.64.0.8", HTTP2: tc.h2}
			client, tr := probeClient(pool, dial, input)
			got := probe(context.Background(), input, client.Do)
			tr.CloseIdleConnections()
			want := !tc.wrongName && !tc.wrongCA && tc.body == backendBody
			if got.OK != want {
				t.Errorf("result: %+v", got)
			}
			select {
			case <-done:
			case <-time.After(4 * time.Second):
				t.Fatal("in-memory server did not stop")
			}
		})
	}
}
