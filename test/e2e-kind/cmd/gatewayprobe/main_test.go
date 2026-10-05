package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"io"
	"math/big"
	"strings"
	"testing"
	"time"

	proof "tsunaro.io/tailnet-operator/test/internal/gatewayprobe"
)

func TestGuardPrecedesEffects(t *testing.T) {
	for _, tc := range []struct {
		args []string
		os   string
		uid  int
	}{
		{nil, "linux", 65532}, {[]string{"--fixture=gateway-forwarding"}, "linux", 65532},
		{[]string{"--fixture=gateway-forwarding", "--role=peer"}, "darwin", 65532},
		{[]string{"--fixture=gateway-forwarding", "--role=target"}, "linux", 0},
		{[]string{"--fixture=gateway-forwarding", "--role=peer", "--endpoint=evil"}, "linux", 65532},
		{[]string{"--fixture=other", "--role=peer"}, "linux", 65532},
		{[]string{"--fixture=gateway-forwarding", "--role=other"}, "linux", 65532},
	} {
		// Any attempted effect calls a nil function and fails the test.
		if err := run(tc.args, tc.os, tc.uid, dependencies{}); err != errRejected {
			t.Fatal("guard")
		}
	}
}

func TestTargetNeedsNoPeerInputs(t *testing.T) {
	called := false
	err := run([]string{"--fixture=gateway-forwarding", "--role=target"}, "linux", 65532, dependencies{
		start: func(role, key string, c proof.Config) error {
			called = true
			if role != "target" || key != "" || c != (proof.Config{}) {
				t.Fatal("target peer data")
			}
			return nil
		},
	})
	if err != nil || !called {
		t.Fatal(err)
	}
}

func testCA(t *testing.T, isCA bool) []byte {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	template := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "fixture"}, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour), IsCA: isCA, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	der, err := x509.CreateCertificate(rand.Reader, template, template, pub, priv)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}

func TestValidatedPeerStartup(t *testing.T) {
	ca := testCA(t, true)
	called := false
	env := map[string]string{}
	err := run([]string{"--fixture=gateway-forwarding", "--role=peer"}, "linux", 65532, dependencies{
		getenv: func(name string) string {
			if name != "TS_AUTHKEY" {
				t.Fatal(name)
			}
			return "test-key"
		},
		setenv: func(k, v string) error { env[k] = v; return nil },
		open: func(path string) (io.ReadCloser, error) {
			switch path {
			case rootPath:
				return io.NopCloser(bytes.NewReader(ca)), nil
			case configPath:
				return io.NopCloser(strings.NewReader(`{"targetIPv4":"10.244.0.8","gatewayIPv4":"100.64.0.2"}`)), nil
			default:
				t.Fatal(path)
				return nil, errRejected
			}
		},
		start: func(role, key string, c proof.Config) error {
			called = true
			if role != "peer" || key != "test-key" || c.TargetIPv4 != "10.244.0.8" || c.GatewayIPv4 != "100.64.0.2" {
				t.Fatal("startup inputs")
			}
			return nil
		},
	})
	if err != nil || !called || env["SSL_CERT_FILE"] != rootPath || env["SSL_CERT_DIR"] != "/control-ca" {
		t.Fatal("startup")
	}
	server := peerServer("test-key")
	if server.Hostname != "gateway-proof-peer" || server.ControlURL != controlURL || server.Dir != "/state" || !server.Ephemeral || server.Store == nil || server.Logf == nil || server.UserLogf == nil {
		t.Fatal("tsnet conventions")
	}
}

func TestInvalidRootAndKey(t *testing.T) {
	ca := testCA(t, true)
	if validateRoot(ca, time.Now()) != nil {
		t.Fatal("valid root")
	}
	for _, data := range [][]byte{nil, []byte("private key"), append(append([]byte{}, ca...), ca...), append(ca, ' '), testCA(t, false)} {
		if validateRoot(data, time.Now()) == nil {
			t.Fatal("invalid CA accepted")
		}
	}
	if validateRoot(ca, time.Now().Add(2*time.Hour)) == nil {
		t.Fatal("expired CA")
	}
	for _, key := range []string{"", "a b", "a\nb", strings.Repeat("a", 4097)} {
		if run([]string{"--fixture=gateway-forwarding", "--role=peer"}, "linux", 65532, dependencies{getenv: func(string) string { return key }}) != errRejected {
			t.Fatal("invalid key")
		}
	}
	if run([]string{"--fixture=gateway-forwarding", "--role=target"}, "linux", 65532, dependencies{start: func(string, string, proof.Config) error { return errors.New("secret") }}) != errRejected {
		t.Fatal("raw error escaped")
	}
}
