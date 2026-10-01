package main

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"errors"
	"io"
	"math/big"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"tsunaro.io/tailnet-operator/test/internal/kindfixture"
)

var fixtureArgs = []string{"--fixture=p1.8-http"}

func authority(t *testing.T, now time.Time) *kindfixture.Authority {
	t.Helper()
	a, err := kindfixture.NewAuthority(now)
	if err != nil {
		t.Fatal(err)
	}
	return a
}

func memoryOpen(t *testing.T, data []byte) openFunc {
	t.Helper()
	return func(path string) (io.ReadCloser, error) {
		if path != "/control-ca/ca.pem" {
			t.Fatalf("unexpected root path %q", path)
		}
		return io.NopCloser(bytes.NewReader(data)), nil
	}
}

func TestGuardBeforeIO(t *testing.T) {
	cases := []struct {
		name string
		args []string
		os   string
		uid  int
	}{
		{"missing", nil, "linux", 65532},
		{"wrong marker", []string{"--fixture=p1.8-layered-isolation"}, "linux", 65532},
		{"split marker", []string{"--fixture", "p1.8-http"}, "linux", 65532},
		{"extra argument", []string{"--fixture=p1.8-http", "--url=https://example.com"}, "linux", 65532},
		{"duplicate", []string{"--fixture=p1.8-http", "--fixture=p1.8-http"}, "linux", 65532},
		{"help", []string{"--help"}, "linux", 65532},
		{"root", fixtureArgs, "linux", 0},
		{"wrong nonroot", fixtureArgs, "linux", 65534},
		{"unsupported uid", fixtureArgs, "linux", -1},
		{"darwin", fixtureArgs, "darwin", 65532},
		{"windows", fixtureArgs, "windows", 65532},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var out bytes.Buffer
			err := run(tc.args, tc.os, tc.uid, func(string) (io.ReadCloser, error) {
				t.Fatal("file I/O before guard")
				return nil, nil
			}, func(*http.Client, *http.Request) (*http.Response, error) {
				t.Fatal("request before guard")
				return nil, nil
			}, &out)
			assertRejected(t, err, out.String())
		})
	}
}

func assertRejected(t *testing.T, err error, output string) {
	t.Helper()
	if err != errRejected || err.Error() != "controlprobe: verified control request failed" || output != "" {
		t.Fatalf("expected fixed error and no success output: err=%v output=%q", err, output)
	}
}

func TestStrictPEM(t *testing.T) {
	now := time.Now()
	valid := authority(t, now).PublicPEM()
	block, _ := pem.Decode(valid)
	withHeaders := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Headers: map[string]string{"Comment": "forbidden"}, Bytes: block.Bytes})
	key := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: []byte("not a certificate")})
	cases := map[string][]byte{
		"empty":              nil,
		"garbage":            []byte("not PEM"),
		"DER only":           block.Bytes,
		"malformed DER":      pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: []byte("invalid")}),
		"multiple DER":       pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: append(append([]byte{}, block.Bytes...), block.Bytes...)}),
		"private key":        key,
		"key before root":    append(append([]byte{}, key...), valid...),
		"key after root":     append(append([]byte{}, valid...), key...),
		"two roots":          append(append([]byte{}, valid...), valid...),
		"leading garbage":    append([]byte("ignored\n"), valid...),
		"leading whitespace": append([]byte("\n"), valid...),
		"trailing garbage":   append(append([]byte{}, valid...), []byte("ignored")...),
		"trailing newline":   append(append([]byte{}, valid...), '\n'),
		"skipped malformed":  append([]byte("-----BEGIN CERTIFICATE-----\n!invalid!\n-----END CERTIFICATE-----\n"), valid...),
		"headers":            withHeaders,
		"wrong type":         pem.EncodeToMemory(&pem.Block{Type: "TRUSTED CERTIFICATE", Bytes: block.Bytes}),
		"CRLF":               []byte(strings.ReplaceAll(string(valid), "\n", "\r\n")),
		"no final newline":   valid[:len(valid)-1],
	}
	for name, data := range cases {
		t.Run(name, func(t *testing.T) {
			var out bytes.Buffer
			err := run(fixtureArgs, "linux", 65532, memoryOpen(t, data), func(*http.Client, *http.Request) (*http.Response, error) {
				t.Fatal("invalid root reached request")
				return nil, nil
			}, &out)
			assertRejected(t, err, out.String())
		})
	}
	if _, err := parseRoot(valid, now); err != nil {
		t.Fatalf("actual fixture root rejected: %v", err)
	}
}

func rootCertificate(t *testing.T, now time.Time, mutate func(*x509.Certificate), badSignature bool) []byte {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	cert := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "test-root"},
		NotBefore: now.Add(-time.Minute), NotAfter: now.Add(time.Hour),
		BasicConstraintsValid: true, IsCA: true, KeyUsage: x509.KeyUsageCertSign,
	}
	mutate(cert)
	public := &key.PublicKey
	if badSignature {
		other, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		public = &other.PublicKey
	}
	parent := *cert
	if cert.Issuer.CommonName != "" {
		parent.Subject = cert.Issuer
	}
	der, err := x509.CreateCertificate(rand.Reader, cert, &parent, public, key)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}

func TestRootConstraints(t *testing.T) {
	now := time.Now().Truncate(time.Second)
	cases := map[string]func(*x509.Certificate){
		"expired":        func(c *x509.Certificate) { c.NotAfter = now.Add(-time.Second) },
		"future":         func(c *x509.Certificate) { c.NotBefore = now.Add(time.Second) },
		"not CA":         func(c *x509.Certificate) { c.IsCA = false },
		"no constraints": func(c *x509.Certificate) { c.BasicConstraintsValid = false },
		"no cert sign":   func(c *x509.Certificate) { c.KeyUsage = x509.KeyUsageDigitalSignature },
		"no usage":       func(c *x509.Certificate) { c.KeyUsage = 0 },
		"unknown critical extension": func(c *x509.Certificate) {
			c.ExtraExtensions = []pkix.Extension{{Id: asn1.ObjectIdentifier{1, 2, 3, 4}, Critical: true, Value: []byte{5, 0}}}
		},
		"different issuer": func(c *x509.Certificate) {
			c.Issuer = pkix.Name{CommonName: "different"}
		},
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := parseRoot(rootCertificate(t, now, mutate, false), now); err != errRejected {
				t.Fatalf("invalid CA accepted: %v", err)
			}
		})
	}
	if _, err := parseRoot(rootCertificate(t, now, func(*x509.Certificate) {}, true), now); err != errRejected {
		t.Fatal("non-self-signed CA accepted")
	}
}

// No sockets: these verify the independent trust pool against actual fixture PKI.
func TestFixtureTrustAndHostname(t *testing.T) {
	now := time.Now()
	a := authority(t, now)
	roots, err := parseRoot(a.PublicPEM(), now)
	if err != nil {
		t.Fatal(err)
	}
	block, _ := pem.Decode(a.PublicPEM())
	root, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	expected := x509.NewCertPool()
	expected.AddCert(root)
	if !roots.Equal(expected) {
		t.Fatal("root pool is not exactly the fixture CA")
	}
	for _, tc := range []struct {
		name   string
		issuer *kindfixture.Authority
		dns    string
		wantOK bool
	}{
		{"fixture", a, "fixture-headscale.tailnet-system.svc", true},
		{"wrong hostname", a, "wrong.tailnet-system.svc", false},
		{"untrusted issuer", authority(t, now), "fixture-headscale.tailnet-system.svc", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			leafPEM, _, _, err := tc.issuer.Issue(tc.dns, now, now.Add(time.Minute))
			if err != nil {
				t.Fatal(err)
			}
			b, _ := pem.Decode(leafPEM)
			leaf, err := x509.ParseCertificate(b.Bytes)
			if err != nil {
				t.Fatal(err)
			}
			_, err = leaf.Verify(x509.VerifyOptions{Roots: roots, DNSName: "fixture-headscale.tailnet-system.svc", CurrentTime: now})
			if (err == nil) != tc.wantOK {
				t.Fatalf("verification error=%v, want success=%v", err, tc.wantOK)
			}
		})
	}
}

type trackedBody struct {
	io.Reader
	closed bool
	read   int
}

func (b *trackedBody) Read(p []byte) (int, error) {
	n, err := b.Reader.Read(p)
	b.read += n
	return n, err
}
func (b *trackedBody) Close() error { b.closed = true; return nil }

type errorReader struct{}

func (errorReader) Read([]byte) (int, error) { return 0, errors.New("sensitive read detail") }

func TestRootReadBoundAndErrors(t *testing.T) {
	for _, size := range []int{maxCABytes, maxCABytes + 100} {
		file := &trackedBody{Reader: strings.NewReader(strings.Repeat("x", size))}
		_, err := readRoot(func(path string) (io.ReadCloser, error) {
			if path != rootPath {
				t.Fatal("wrong path")
			}
			return file, nil
		})
		if err != errRejected || file.read != maxCABytes || !file.closed {
			t.Fatalf("root read unbounded or unclosed: err=%v bytes=%d closed=%v", err, file.read, file.closed)
		}
	}
	for name, open := range map[string]openFunc{
		"open error": func(string) (io.ReadCloser, error) { return nil, errors.New("sensitive path detail") },
		"read error": func(string) (io.ReadCloser, error) { return io.NopCloser(errorReader{}), nil },
	} {
		t.Run(name, func(t *testing.T) {
			var out bytes.Buffer
			err := run(fixtureArgs, "linux", 65532, open, func(*http.Client, *http.Request) (*http.Response, error) {
				t.Fatal("root I/O failure reached request")
				return nil, nil
			}, &out)
			assertRejected(t, err, out.String())
		})
	}
}

func TestResponses(t *testing.T) {
	root := authority(t, time.Now()).PublicPEM()
	cases := []struct {
		name        string
		status      int
		body        io.Reader
		err         error
		nilResponse bool
		wantOK      bool
	}{
		{"OK", 200, strings.NewReader("healthy"), nil, false, true},
		{"empty", 200, strings.NewReader(""), nil, false, true},
		{"body limit", 200, strings.NewReader(strings.Repeat("x", maxBody)), nil, false, true},
		{"oversize", 200, strings.NewReader(strings.Repeat("x", maxBody+100)), nil, false, false},
		{"body error", 200, errorReader{}, nil, false, false},
		{"nil body", 200, nil, nil, false, false},
		{"nil response", 0, nil, nil, true, false},
		{"request error", 0, nil, errors.New("sensitive TLS detail"), true, false},
		{"response with error", 200, strings.NewReader("healthy"), errors.New("sensitive detail"), false, false},
		{"created", 201, strings.NewReader(""), nil, false, false},
		{"no content", 204, strings.NewReader(""), nil, false, false},
		{"redirect", 302, strings.NewReader(""), nil, false, false},
		{"unauthorized", 401, strings.NewReader(""), nil, false, false},
		{"server error", 503, strings.NewReader(""), nil, false, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var out bytes.Buffer
			var body *trackedBody
			err := run(fixtureArgs, "linux", 65532, memoryOpen(t, root), func(*http.Client, *http.Request) (*http.Response, error) {
				if tc.nilResponse {
					return nil, tc.err
				}
				resp := &http.Response{StatusCode: tc.status}
				if tc.body != nil {
					body = &trackedBody{Reader: tc.body}
					resp.Body = body
				}
				return resp, tc.err
			}, &out)
			if tc.wantOK {
				if err != nil || out.String() != "{\"verifiedControlTLS\":true}\n" {
					t.Fatalf("unexpected result err=%v output=%q", err, out.String())
				}
			} else {
				assertRejected(t, err, out.String())
			}
			if body != nil && (!body.closed || body.read > maxBody+1) {
				t.Fatalf("unclosed/unbounded body: closed=%v read=%d", body.closed, body.read)
			}
		})
	}
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func TestUntrustedExitCategory(t *testing.T) {
	root := authority(t, time.Now()).PublicPEM()
	for _, tc := range []struct {
		err  error
		code int
	}{
		{&url.Error{Op: "Get", URL: "https://private.invalid", Err: &tls.CertificateVerificationError{Err: x509.UnknownAuthorityError{Cert: &x509.Certificate{}}}}, 3},
		{errors.New("sensitive timeout or DNS details"), 2},
		{x509.HostnameError{Certificate: &x509.Certificate{}, Host: "private.invalid"}, 2},
	} {
		var out bytes.Buffer
		err := run(fixtureArgs, "linux", 65532, memoryOpen(t, root), func(client *http.Client, req *http.Request) (*http.Response, error) {
			client.Transport = roundTripFunc(func(*http.Request) (*http.Response, error) { return nil, tc.err })
			return client.Do(req)
		}, &out)
		if exitCode(err) != tc.code || err.Error() != errRejected.Error() || out.Len() != 0 {
			t.Fatal("transport category leaked details or conflated trust failure")
		}
	}
	if exitCode(nil) != 0 || exitCode(errRejected) != 2 {
		t.Fatal("exit categories changed")
	}
}

func TestFixedRequestAndTransport(t *testing.T) {
	for _, key := range []string{"HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "http_proxy", "https_proxy", "all_proxy"} {
		t.Setenv(key, "http://forbidden.invalid:1234")
	}
	t.Setenv("SSL_CERT_FILE", "/forbidden/root")
	t.Setenv("SSL_CERT_DIR", "/forbidden/roots")
	root := authority(t, time.Now()).PublicPEM()
	var out bytes.Buffer
	calls := 0
	err := run(fixtureArgs, "linux", 65532, memoryOpen(t, root), func(client *http.Client, req *http.Request) (*http.Response, error) {
		calls++
		if req.URL.String() != "https://fixture-headscale.tailnet-system.svc:8443/health" || req.Method != http.MethodGet || req.Body != nil || req.URL.User != nil || len(req.Header) != 0 {
			t.Fatal("request is not the fixed unauthenticated GET")
		}
		deadline, ok := req.Context().Deadline()
		if !ok || time.Until(deadline) <= 0 || time.Until(deadline) > 5*time.Second || client.Timeout != 5*time.Second {
			t.Fatal("missing total HTTP time bounds")
		}
		tr, ok := client.Transport.(*http.Transport)
		if !ok {
			t.Fatal("unexpected transport")
		}
		if tr.Proxy != nil || tr.DialContext == nil || tr.DialTLSContext != nil || tr.DialTLS != nil || tr.Dial != nil {
			t.Fatal("unexpected proxy/dial override")
		}
		dialer := controlDialer()
		if dialer.Timeout != 3*time.Second || dialer.KeepAlive != -1 || tr.ResponseHeaderTimeout != 3*time.Second || tr.TLSHandshakeTimeout != 3*time.Second {
			t.Fatal("dial/header/TLS time bounds or keepalive changed")
		}
		if !tr.DisableKeepAlives || !tr.DisableCompression || tr.MaxResponseHeaderBytes != 4096 || tr.ForceAttemptHTTP2 || tr.TLSNextProto == nil || len(tr.TLSNextProto) != 0 {
			t.Fatal("unbounded headers, keepalive, compression, or alternate protocols")
		}
		config := tr.TLSClientConfig
		expected, err := parseRoot(root, time.Now())
		if err != nil {
			t.Fatal(err)
		}
		if config == nil || config.InsecureSkipVerify || config.MinVersion != tls.VersionTLS12 || config.ServerName != "" || config.RootCAs == nil || !config.RootCAs.Equal(expected) || config.VerifyConnection != nil || config.VerifyPeerCertificate != nil || len(config.Certificates) != 0 {
			t.Fatal("TLS verification or independent roots changed")
		}
		if client.Jar != nil || client.CheckRedirect == nil || client.CheckRedirect(req, nil) != errRejected {
			t.Fatal("cookies or redirects enabled")
		}
		return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader("ok"))}, nil
	}, &out)
	if err != nil || calls != 1 {
		t.Fatalf("request failed: %v calls=%d", err, calls)
	}
}

func TestRedirectNeverFollowed(t *testing.T) {
	root := authority(t, time.Now()).PublicPEM()
	var out bytes.Buffer
	calls := 0
	err := run(fixtureArgs, "linux", 65532, memoryOpen(t, root), func(client *http.Client, req *http.Request) (*http.Response, error) {
		// Replace the complete transport before Do: no host network, even if
		// redirect policy regresses. A second synthetic call fails the test.
		client.Transport = roundTripFunc(func(r *http.Request) (*http.Response, error) {
			calls++
			return &http.Response{StatusCode: 302, Header: http.Header{"Location": {"https://forbidden.invalid/"}}, Body: io.NopCloser(strings.NewReader("")), Request: r}, nil
		})
		return client.Do(req)
	}, &out)
	assertRejected(t, err, out.String())
	if calls != 1 {
		t.Fatalf("redirect followed: %d requests", calls)
	}
}
