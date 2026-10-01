// fixture is a test-only admission server, not an ownership or isolation proof.
package main

import (
	"context"
	"crypto/tls"
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

	"k8s.io/apimachinery/pkg/util/validation"

	"this-is-fine.io/tailnet-operator/internal/certificates"
	"this-is-fine.io/tailnet-operator/test/internal/kindfixture"
)

const (
	listenAddress   = ":9443"
	certificatePath = "/fixture-tls/tls.crt"
	keyPath         = "/fixture-tls/tls.key"
	shutdownTimeout = 5 * time.Second
	maxPEMBytes     = 1 << 20
)

var (
	errConfig   = errors.New("fixture: configuration rejected")
	errTLS      = errors.New("fixture: TLS rejected")
	errListen   = errors.New("fixture: listener failed")
	errServe    = errors.New("fixture: server failed")
	errShutdown = errors.New("fixture: shutdown failed")
)

type config struct {
	mode, fixture, namespace, agentImage, caConfigMap, certPath, keyPath, networkGateImage string
}

// Required server arguments have no defaults or environment fallbacks. The
// network init gate is optional and must be explicitly selected. Positional
// arguments and duplicate flags are rejected. The runtime gate precedes all
// file access and listener creation. It does not
// prove namespace ownership; the isolated fixture harness must establish that.
func parseConfig(args []string, goos string, euid int) (config, error) {
	var cfg config
	if goos != "linux" || euid != 65532 || len(args) < 7 || len(args) > 8 {
		return cfg, errConfig
	}
	fields := map[string]*string{
		"--mode": &cfg.mode, "--fixture": &cfg.fixture,
		"--namespace": &cfg.namespace, "--agent-image": &cfg.agentImage,
		"--ca-config-map": &cfg.caConfigMap, "--tls-cert": &cfg.certPath, "--tls-key": &cfg.keyPath,
		"--network-gate-image": &cfg.networkGateImage,
	}
	for _, arg := range args {
		name, value, ok := strings.Cut(arg, "=")
		dst, known := fields[name]
		if !ok || !known || name == "--network-gate-image" && value == "" {
			return config{}, errConfig
		}
		*dst = value
		delete(fields, name)
	}
	if err := validateConfig(cfg); err != nil {
		return config{}, err
	}
	return cfg, nil
}

func validateConfig(cfg config) error {
	if cfg.networkGateImage != "" && !kindfixture.ValidNetworkGateImage(cfg.networkGateImage) {
		return errConfig
	}
	if cfg.mode != "admission" || cfg.fixture != "p1.8-http" ||
		len(validation.IsDNS1123Label(cfg.namespace)) != 0 ||
		len(validation.IsDNS1123Subdomain(cfg.caConfigMap)) != 0 ||
		cfg.certPath != certificatePath || cfg.keyPath != keyPath ||
		cfg.agentImage == "" || len(cfg.agentImage) > 512 ||
		strings.ContainsAny(cfg.agentImage, " \t\r\n*?[]\\") {
		return errConfig
	}
	for _, c := range cfg.agentImage {
		if c < 33 || c > 126 {
			return errConfig
		}
	}
	return nil
}

// The harness must issue the certificate and configure the webhook Service
// using this same name. No production serving names or TLS paths are reused.
func (cfg config) serviceDNS() string { return "fixture-admission." + cfg.namespace + ".svc" }

func validAt(pair *tls.Certificate, now time.Time) bool {
	return !now.Before(pair.Leaf.NotBefore) && now.Before(pair.Leaf.NotAfter)
}

// newServer is pure with respect to files, listeners and process identity.
func newServer(cfg config, certPEM, keyPEM []byte) (*http.Server, error) {
	if err := validateConfig(cfg); err != nil {
		return nil, err
	}
	if len(certPEM) > maxPEMBytes || len(keyPEM) > maxPEMBytes {
		return nil, errTLS
	}
	pair, err := certificates.ParseServingPair(certPEM, keyPEM, cfg.serviceDNS())
	if err != nil || !validAt(pair, time.Now()) {
		return nil, errTLS
	}
	admission := kindfixture.AgentCAHandler(kindfixture.AgentCAConfig{
		Namespace: cfg.namespace, Image: cfg.agentImage, ConfigMap: cfg.caConfigMap, NetworkGateImage: cfg.networkGateImage,
	})
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/readyz":
			if r.Method != http.MethodGet {
				w.Header().Set("Allow", http.MethodGet)
				http.Error(w, "fixture: method rejected", http.StatusMethodNotAllowed)
				return
			}
			if !validAt(pair, time.Now()) || r.Context().Err() != nil {
				http.Error(w, "fixture: unavailable", http.StatusServiceUnavailable)
				return
			}
			w.Header().Set("Content-Type", "text/plain; charset=utf-8")
			_, _ = io.WriteString(w, "ready\n")
		case "/mutate-agent":
			admission.ServeHTTP(w, r)
		default:
			http.Error(w, "fixture: route rejected", http.StatusNotFound)
		}
	})
	return &http.Server{
		Addr: listenAddress, Handler: handler,
		ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 10 * time.Second,
		WriteTimeout: 10 * time.Second, IdleTimeout: 30 * time.Second,
		MaxHeaderBytes: 16 << 10, ErrorLog: log.New(io.Discard, "", 0),
		TLSConfig: &tls.Config{
			MinVersion: tls.VersionTLS12,
			// Keep only the callback so every new handshake checks the cached
			// leaf's lifetime without re-reading the mounted files.
			GetCertificate: func(*tls.ClientHelloInfo) (*tls.Certificate, error) {
				if !validAt(pair, time.Now()) {
					return nil, errTLS
				}
				return pair, nil
			},
		},
	}, nil
}

func readPEM(path string) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, errTLS
	}
	defer f.Close()
	b, err := io.ReadAll(io.LimitReader(f, maxPEMBytes+1))
	if err != nil || len(b) > maxPEMBytes {
		return nil, errTLS
	}
	return b, nil
}

// serve owns the listener, including on cancellation before ServeTLS starts.
func serve(ctx context.Context, server *http.Server, listener net.Listener) error {
	defer listener.Close()
	if ctx.Err() != nil {
		return nil
	}
	server.BaseContext = func(net.Listener) context.Context { return ctx }
	done := make(chan error, 1)
	go func() { done <- server.ServeTLS(listener, "", "") }()
	select {
	case <-done:
		_ = server.Close()
		return errServe
	case <-ctx.Done():
		shutdownCtx, cancel := context.WithTimeout(context.Background(), shutdownTimeout)
		defer cancel()
		err := server.Shutdown(shutdownCtx)
		if err != nil {
			_ = server.Close()
		}
		<-done
		if err != nil {
			return errShutdown
		}
		return nil
	}
}

func run(ctx context.Context, cfg config) error {
	certPEM, err := readPEM(cfg.certPath)
	if err != nil {
		return err
	}
	keyPEM, err := readPEM(cfg.keyPath)
	if err != nil {
		return err
	}
	server, err := newServer(cfg, certPEM, keyPEM)
	if err != nil {
		return err
	}
	if ctx.Err() != nil {
		return nil
	}
	listener, err := net.Listen("tcp", listenAddress)
	if err != nil {
		return errListen
	}
	return serve(ctx, server, listener)
}

func main() {
	cfg, err := parseConfig(os.Args[1:], runtime.GOOS, os.Geteuid())
	if err == nil {
		ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
		err = run(ctx, cfg)
		stop()
	}
	if err != nil {
		// Only fixed categories, never request data, certificate diagnostics or paths.
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
}
