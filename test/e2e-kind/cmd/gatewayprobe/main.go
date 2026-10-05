// gatewayprobe is a guarded, independent gateway forwarding/DNS fixture.
package main

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"runtime"
	"strings"
	"syscall"
	"time"
	"unicode"

	"tailscale.com/ipn"
	"tailscale.com/ipn/store/mem"
	"tailscale.com/logtail"
	"tailscale.com/tsnet"
	proof "tsunaro.io/tailnet-operator/test/internal/gatewayprobe"
)

const controlURL = "https://fixture-headscale.tailnet-system.svc:8443"
const rootPath = "/control-ca/ca.pem"
const configPath = "/probe/config.json"
const maxCABytes = 64 << 10

var errRejected = errors.New("gatewayprobe: fixture operation failed")

type dependencies struct {
	getenv func(string) string
	setenv func(string, string) error
	open   func(string) (io.ReadCloser, error)
	start  func(string, string, proof.Config) error
}

func main() {
	if run(os.Args[1:], runtime.GOOS, os.Geteuid(), dependencies{
		getenv: os.Getenv, setenv: os.Setenv,
		open:  func(path string) (io.ReadCloser, error) { return os.Open(path) },
		start: startFixture,
	}) != nil {
		fmt.Fprintln(os.Stderr, errRejected)
		os.Exit(2)
	}
}

// The Linux/UID/argument guard precedes ALL environment, file, listener, signal
// and tsnet effects. Target never reads credentials, CA, or peer configuration.
func run(args []string, goos string, uid int, d dependencies) error {
	if goos != "linux" || uid != 65532 || len(args) != 2 || args[0] != "--fixture=gateway-forwarding" ||
		(args[1] != "--role=peer" && args[1] != "--role=target") {
		return errRejected
	}
	if args[1] == "--role=target" {
		if d.start("target", "", proof.Config{}) != nil {
			return errRejected
		}
		return nil
	}
	key := d.getenv("TS_AUTHKEY")
	if key == "" || len(key) > 4096 || strings.ContainsFunc(key, unicode.IsSpace) {
		return errRejected
	}
	root, err := readBounded(d.open, rootPath, maxCABytes)
	if err != nil || validateRoot(root, time.Now()) != nil {
		return errRejected
	}
	data, err := readBounded(d.open, configPath, 1024)
	if err != nil {
		return errRejected
	}
	config, err := proof.DecodeConfig(data)
	if err != nil {
		return errRejected
	}
	if d.setenv("SSL_CERT_FILE", rootPath) != nil || d.setenv("SSL_CERT_DIR", "/control-ca") != nil {
		return errRejected
	}
	// Configuration is copied once. Requests cannot reload or override it.
	if d.start("peer", key, config) != nil {
		return errRejected
	}
	return nil
}

func readBounded(open func(string) (io.ReadCloser, error), path string, size int64) ([]byte, error) {
	f, err := open(path)
	if err != nil {
		return nil, errRejected
	}
	data, err := io.ReadAll(io.LimitReader(f, size+1))
	closeErr := f.Close()
	if err != nil || closeErr != nil || int64(len(data)) > size {
		return nil, errRejected
	}
	return data, nil
}

func validateRoot(data []byte, now time.Time) error {
	block, rest := pem.Decode(data)
	if len(data) > maxCABytes || block == nil || block.Type != "CERTIFICATE" || len(block.Headers) != 0 || len(rest) != 0 || !bytes.Equal(data, pem.EncodeToMemory(block)) {
		return errRejected
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil || !cert.BasicConstraintsValid || !cert.IsCA || cert.KeyUsage&x509.KeyUsageCertSign == 0 ||
		len(cert.UnhandledCriticalExtensions) != 0 || now.Before(cert.NotBefore) || !now.Before(cert.NotAfter) ||
		!bytes.Equal(cert.RawSubject, cert.RawIssuer) || cert.CheckSignatureFrom(cert) != nil {
		return errRejected
	}
	return nil
}

func peerServer(key string) *tsnet.Server {
	return &tsnet.Server{
		Hostname: "gateway-proof-peer", ControlURL: controlURL, AuthKey: key,
		Dir: "/state", Store: new(mem.Store), Ephemeral: true,
		Logf: func(string, ...any) {}, UserLogf: func(string, ...any) {},
	}
}

func startFixture(role, key string, config proof.Config) error {
	log.SetOutput(io.Discard)
	logtail.Disable()
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	var handler http.Handler
	if role == "peer" {
		peer := peerServer(key)
		defer peer.Close()
		upCtx, upCancel := context.WithTimeout(ctx, 90*time.Second)
		status, err := peer.Up(upCtx)
		upCancel()
		if err != nil || status == nil || status.BackendState != "Running" {
			return errRejected
		}
		local, err := peer.LocalClient()
		if err != nil {
			return errRejected
		}
		prefCtx, prefCancel := context.WithTimeout(ctx, probeTimeout)
		prefs, err := local.EditPrefs(prefCtx, &ipn.MaskedPrefs{Prefs: ipn.Prefs{RouteAll: true}, RouteAllSet: true})
		if err == nil && prefs != nil && prefs.RouteAll {
			prefs, err = local.GetPrefs(prefCtx)
		}
		prefCancel()
		if err != nil || prefs == nil || !prefs.RouteAll {
			return errRejected
		}
		d := probeDeps{native: (&net.Dialer{}).DialContext, overlay: peer.Dial, status: local.Status, prefs: local.GetPrefs}
		handler = controlHandler(func(ctx context.Context, mode string) proof.Result { return probe(ctx, config, mode, d) })
		return serveFixture(ctx, cancel, handler, false)
	}
	handler = controlHandler(nil)
	return serveFixture(ctx, cancel, handler, true)
}

func serveFixture(ctx context.Context, cancel context.CancelFunc, handler http.Handler, target bool) error {
	errs := make(chan error, 2)
	var targetDone chan struct{}
	if target {
		listener, err := net.Listen("tcp4", ":8081")
		if err != nil {
			return errRejected
		}
		defer listener.Close()
		targetDone = make(chan struct{})
		go func() { defer close(targetDone); errs <- serveTarget(ctx, listener) }()
		defer func() { cancel(); <-targetDone }()
	}
	listener, err := net.Listen("tcp4", ":9081")
	if err != nil {
		return errRejected
	}
	defer listener.Close()
	server := &http.Server{
		Handler: handler, ReadHeaderTimeout: 2 * time.Second, ReadTimeout: 3 * time.Second,
		WriteTimeout: 8 * time.Second, IdleTimeout: 5 * time.Second, MaxHeaderBytes: 16 << 10,
		ErrorLog: log.New(io.Discard, "", 0), BaseContext: func(net.Listener) context.Context { return ctx },
	}
	defer server.Close()
	go func() { errs <- server.Serve(listener) }()
	var result error
	select {
	case <-ctx.Done():
	case <-errs:
		result = errRejected
	}
	cancel()
	shutdown, stop := context.WithTimeout(context.Background(), probeTimeout)
	defer stop()
	_ = server.Shutdown(shutdown)
	return result
}
