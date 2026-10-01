// controlprobe verifies fixture Headscale HTTPS through its Kubernetes Service.
// It is not evidence of peer connectivity, tsnet operation, or tailnet isolation.
package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"runtime"
	"time"
)

const (
	controlURL = "https://fixture-headscale.tailnet-system.svc:8443/health"
	rootPath   = "/control-ca/ca.pem"
	maxCABytes = 1 << 20
	maxBody    = 4 << 10
	resultJSON = "{\"verifiedControlTLS\":true}\n"
)

var errRejected = errors.New("controlprobe: verified control request failed")
var errUntrusted = errors.New("controlprobe: verified control request failed")

// Only the bounded exit code distinguishes a real chain rejection from setup,
// DNS, API/exec transport or other failures. Neither exposes the raw error.
func exitCode(err error) int {
	if err == nil {
		return 0
	}
	if err == errUntrusted {
		return 3
	}
	return 2
}

type openFunc func(string) (io.ReadCloser, error)
type requestFunc func(*http.Client, *http.Request) (*http.Response, error)

func main() {
	err := run(os.Args[1:], runtime.GOOS, os.Geteuid(), func(path string) (io.ReadCloser, error) {
		return os.Open(path)
	}, func(client *http.Client, req *http.Request) (*http.Response, error) {
		return client.Do(req)
	}, os.Stdout)
	if err != nil {
		fmt.Fprintln(os.Stderr, errRejected)
		os.Exit(exitCode(err))
	}
}

// All file and request dependencies are injected so unit tests never dial the
// host network. Production has no environment, path, URL, or transport override.
func run(args []string, goos string, euid int, open openFunc, request requestFunc, out io.Writer) error {
	if goos != "linux" || euid != 65532 || len(args) != 1 || args[0] != "--fixture=p1.8-http" {
		return errRejected
	}
	data, err := readRoot(open)
	if err != nil {
		return errRejected
	}
	roots, err := parseRoot(data, time.Now())
	if err != nil {
		return errRejected
	}
	client, transport := controlClient(roots)
	defer transport.CloseIdleConnections()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, controlURL, nil)
	if err != nil {
		return errRejected
	}
	resp, err := request(client, req)
	if resp != nil && resp.Body != nil {
		defer resp.Body.Close()
	}
	var untrusted x509.UnknownAuthorityError
	if err != nil && errors.As(err, &untrusted) {
		return errUntrusted
	}
	if err != nil || resp == nil || resp.Body == nil || resp.StatusCode != http.StatusOK {
		return errRejected
	}
	// One sentinel byte distinguishes a complete 4 KiB body from truncation.
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxBody+1))
	if err != nil || len(body) > maxBody || ctx.Err() != nil {
		return errRejected
	}
	if n, err := io.WriteString(out, resultJSON); err != nil || n != len(resultJSON) {
		return errRejected
	}
	return nil
}

func readRoot(open openFunc) ([]byte, error) {
	file, err := open(rootPath)
	if err != nil {
		return nil, errRejected
	}
	defer file.Close()
	// Never read more than 1 MiB. A saturated read is rejected rather than
	// probing beyond the bound or accepting potentially truncated material.
	data, err := io.ReadAll(io.LimitReader(file, maxCABytes))
	if err != nil || len(data) >= maxCABytes {
		return nil, errRejected
	}
	return data, nil
}

func parseRoot(data []byte, now time.Time) (*x509.CertPool, error) {
	block, rest := pem.Decode(data)
	// Decode alone skips leading material and malformed PEM. Exact canonical
	// re-encoding rejects all skipped bytes, headers, extra blocks, and keys.
	if block == nil || block.Type != "CERTIFICATE" || len(block.Headers) != 0 || len(rest) != 0 ||
		!bytes.Equal(data, pem.EncodeToMemory(block)) {
		return nil, errRejected
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil || !cert.BasicConstraintsValid || !cert.IsCA || cert.KeyUsage&x509.KeyUsageCertSign == 0 ||
		len(cert.UnhandledCriticalExtensions) != 0 || now.Before(cert.NotBefore) || now.After(cert.NotAfter) ||
		!bytes.Equal(cert.RawSubject, cert.RawIssuer) || cert.CheckSignatureFrom(cert) != nil {
		return nil, errRejected
	}
	roots := x509.NewCertPool() // Deliberately not SystemCertPool or AppendCertsFromPEM.
	roots.AddCert(cert)
	return roots, nil
}

func controlDialer() *net.Dialer {
	return &net.Dialer{Timeout: 3 * time.Second, KeepAlive: -1}
}

func controlClient(roots *x509.CertPool) (*http.Client, *http.Transport) {
	dialer := controlDialer()
	transport := &http.Transport{
		Proxy:                  nil,
		DialContext:            dialer.DialContext,
		TLSClientConfig:        &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS12},
		TLSHandshakeTimeout:    3 * time.Second,
		ResponseHeaderTimeout:  3 * time.Second,
		MaxResponseHeaderBytes: 4 << 10,
		DisableKeepAlives:      true,
		DisableCompression:     true,
		// No HTTP/2 connection reuse or alternate protocol configuration.
		TLSNextProto: make(map[string]func(string, *tls.Conn) http.RoundTripper),
	}
	return &http.Client{
		Transport: transport,
		Timeout:   5 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return errRejected
		},
	}, transport
}
