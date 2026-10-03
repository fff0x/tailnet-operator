package main

import (
	"bytes"
	"crypto/x509"
	"errors"
	"io"
	"reflect"
	"testing"
	"time"
)

func TestSeparateServingTrustDoesNotReplaceControlTrust(t *testing.T) {
	control, _, _ := makeCA(t, nil)
	serving, _, _ := makeCA(t, nil)
	want, err := parseRoot(serving, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	var opened []string
	env := map[string]string{}
	started := false
	d := dependencies{
		getenv: func(string) string { return "fixture-auth" },
		setenv: func(k, v string) error { env[k] = v; return nil },
		open: func(path string) (io.ReadCloser, error) {
			opened = append(opened, path)
			switch path {
			case rootPath:
				return io.NopCloser(bytes.NewReader(control)), nil
			case servingRootPath:
				return io.NopCloser(bytes.NewReader(serving)), nil
			default:
				t.Fatal("unexpected trust path")
				return nil, errors.New("rejected")
			}
		},
		start: func(_ string, pool *x509.CertPool, denied bool) error {
			started = true
			if !pool.Equal(want) || denied {
				t.Fatal("serving roots not isolated")
			}
			return nil
		},
	}
	if run([]string{"--fixture=p1.8-http", "--serving-ca=cert-manager"}, "linux", 65532, d) != nil || !started {
		t.Fatal("separate serving CA rejected")
	}
	if !reflect.DeepEqual(opened, []string{rootPath, servingRootPath}) || !reflect.DeepEqual(env, map[string]string{"SSL_CERT_FILE": rootPath, "SSL_CERT_DIR": "/control-ca"}) {
		t.Fatal("control trust changed")
	}
	for _, badPath := range []string{rootPath, servingRootPath} {
		started = false
		d.open = func(path string) (io.ReadCloser, error) {
			if path == badPath {
				return io.NopCloser(bytes.NewReader([]byte("invalid"))), nil
			}
			return io.NopCloser(bytes.NewReader(control)), nil
		}
		if run([]string{"--fixture=p1.8-http", "--serving-ca=cert-manager"}, "linux", 65532, d) != errRejected || started {
			t.Fatal("invalid CA reached startup")
		}
	}
}

func TestServingTrustModeGuardBeforeIO(t *testing.T) {
	for _, args := range [][]string{
		{"--fixture=p1.8-http", "--serving-ca=/private/path"},
		{"--fixture=p1.8-http", "--serving-ca=cert-manager", "extra"},
		{"--fixture=wrong", "--serving-ca=cert-manager"},
		{"--serving-ca=cert-manager", "--fixture=p1.8-http"},
	} {
		if run(args, "linux", 65532, dependencies{}) != errRejected {
			t.Fatal("invalid trust mode accepted")
		}
	}
	for _, uid := range []int{0, 65534} {
		if run([]string{"--fixture=p1.8-http", "--serving-ca=cert-manager"}, "linux", uid, dependencies{}) != errRejected {
			t.Fatal("trust mode bypassed uid guard")
		}
	}
}
